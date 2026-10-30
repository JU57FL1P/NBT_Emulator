"""VM-only GLES2 RPC endpoint using an actual local ANGLE renderer.

All GL work, including initialization, runs on one worker thread. Guest thread
IDs select independent EGL current bindings. This is an experimental adapter,
not a model of the NBT NVIDIA GPU or proof that iDrive is fully operational.
"""
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import socket
import struct
import time
import traceback
import zlib

P, I, U, F = C.c_void_p, C.c_int, C.c_uint, C.c_float
MAX_PAYLOAD = 64 * 1024 * 1024
ROOT = Path(__file__).resolve().parent

def pack(*values):
    return struct.pack('<'+'I'*len(values), *(int(v)&0xffffffff for v in values))

def decode_compressed(payload):
    if len(payload)<5:raise ValueError('short compressed envelope')
    original,=struct.unpack_from('<I',payload)
    if not 1<=original<=MAX_PAYLOAD:raise ValueError('compressed output bounds')
    decoder=zlib.decompressobj()
    result=decoder.decompress(payload[4:],original+1)
    if len(result)!=original or not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError('compressed length or stream mismatch')
    return result

def encode_compressed(payload):
    if len(payload)<4096:return None
    data=pack(len(payload))+zlib.compress(payload,1)
    return data if len(data)<len(payload) else None

def reply(ret=0, outputs=()):
    return pack(ret, len(outputs)) + b''.join(pack(i,len(data))+data for i,data in outputs)

def unpack_args(payload):
    if len(payload)<4: raise ValueError('short API envelope')
    count, = struct.unpack_from('<I',payload)
    if count>32: raise ValueError('argument count')
    result=[]; offset=4
    for _ in range(count):
        if offset+12>len(payload): raise ValueError('short argument')
        tag,bits,length=struct.unpack_from('<III',payload,offset); offset+=12
        if tag>5 or length>MAX_PAYLOAD: raise ValueError('argument bounds')
        data=b''
        if tag in (2,4):
            if offset+length>len(payload): raise ValueError('short blob')
            data=payload[offset:offset+length]; offset+=length
        result.append({'tag':tag,'bits':bits,'len':length,'data':data})
    if offset!=len(payload): raise ValueError('trailing payload')
    return result

class Renderer:
    def __init__(self, connection, logdir, display_format='png', graphics_backend=None):
        self.connection=connection
        if display_format not in ('png','bmp'):raise ValueError('Unknown capture format')
        self.display_format=display_format
        if connection.family in (socket.AF_INET, socket.AF_INET6):
            connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.logdir=Path(logdir); self.logdir.mkdir(parents=True,exist_ok=True)
        self.trace=(self.logdir/'graphics-rpc.jsonl').open('a',encoding='utf-8',buffering=1)
        self.handles={}; self.reverse={}; self.next_token=0x10000
        self.bindings={}; self.active=None; self.windows={}; self.surface_sizes={}
        self.client_buffers={}; self.frames=0; self.calls=0; self.zone=0
        self.functions={}; self.shaders={}; self.compiled_shaders={}
        self.shader_labels={}; self.diag_counts={}; self.diag_contexts={}
        self.input_offset=0; self.pending_input=[]
        self.transport_calls=0; self.last_frame_time=None; self.last_frame_calls=0
        self.graphics_diagnostics=os.environ.get('NBT_VM_GL_DIAGNOSTICS','0')=='1'
        self.last_frame_mailbox={}
        self.api={x['opcode']:x for x in json.loads((ROOT/'graphics-bridge/guest-gl-api.json').read_text())}
        self.batch_ops={op for op,spec in self.api.items() if spec['name'].startswith('gl')
                        and spec['return_type']=='void'
                        and not spec['name'].startswith(('glGet','glGen','glRead','glFinish'))}
        folder=Path(os.environ.get('NBT_EMULATOR_ANGLE',str(ROOT/'tools/angle'))).resolve()
        self.dll_search=os.add_dll_directory(str(folder))
        self.egl=C.WinDLL(str(folder/'libEGL.dll'))
        self.gl=C.WinDLL(str(folder/'libGLESv2.dll'))
        getproc=self.fn('eglGetProcAddress',P,C.c_char_p)
        getplatform=C.WINFUNCTYPE(P,U,P,C.POINTER(I))(getproc(b'eglGetPlatformDisplayEXT'))
        self.major,self.minor=I(),I()
        requested=(graphics_backend or os.environ.get('NBT_VM_GRAPHICS_BACKEND','warp')).lower()
        if requested not in ('auto','hardware','warp'):raise ValueError('Unknown ANGLE backend')
        for backend in (('hardware','warp') if requested=='auto' else (requested,)):
            attrs=(I*5)(0x3203,0x3208,0x3209,0x320a if backend=='hardware' else 0x320b,0x3038)
            self.display=getplatform(0x3202,None,attrs)
            if self.display and self.fn('eglInitialize',U,P,P,P)(self.display,C.byref(self.major),C.byref(self.minor)):
                self.backend=backend;break
            self.log(event='backend_initialization_failed',backend=backend)
        else:raise RuntimeError('ANGLE D3D11 display initialization failed')
        if not self.fn('eglBindAPI',U,U)(0x30a0): raise RuntimeError('GLES API bind failed')
        self.display_token=self.token('display',self.display)
        self.load_shaders()
        self.log(event='renderer_ready',backend='ANGLE D3D11 '+self.backend,egl=[self.major.value,self.minor.value],nbt_frame=False,
                 graphics_diagnostics=self.graphics_diagnostics,display_format=self.display_format)

    def log(self, **record):
        record['time']=time.time(); self.trace.write(json.dumps(record)+'\n')

    def fn(self,name,result,*args):
        key=(name,result,args)
        if key not in self.functions:
            f=getattr(self.egl if name.startswith('egl') else self.gl,name)
            f.restype=result; f.argtypes=list(args); self.functions[key]=f
        return self.functions[key]

    def diagnostic(self,event,limit=256,**record):
        """Bound diagnostic output independently of native RPC/frame counts."""
        count=self.diag_counts.get(event,0)
        self.diag_counts[event]=count+1
        if count<limit:self.log(event=event,**record)
        elif count==limit:self.log(event='diagnostic_limit',category=event,limit=limit)

    def diagnostic_context(self,tid):
        context=self.bindings[tid][3]
        if context not in self.diag_contexts and len(self.diag_contexts)>=32:return None
        return self.diag_contexts.setdefault(context,{'shaders':{},'programs':{},'textures':{},'clients':{}})

    def diagnostic_integer(self,pname):
        value=I();self.fn('glGetIntegerv',None,U,P)(pname,C.byref(value))
        return value.value

    def diagnose_gl(self,name,args,value,outputs,tid):
        """Read-only observations; never call glGetError or change GL state here.

        Uniform/client bytes are submitted values, not invented bindings or a
        claim that a void GL operation succeeded. Draw attributes and current
        program/binding are queried from GL; only known valid objects are queried.
        """
        state=self.diagnostic_context(tid)
        if state is None:return
        v=[a['bits'] for a in args];context=self.bindings[tid][3]
        base={'tid':tid,'context':context,'call':self.calls}
        programs=state['programs']
        if name=='glGetError' and value:
            self.diagnostic('native_gl_error',limit=100,error=int(value),**base)
        elif name=='glCreateProgram' and value and len(programs)<1024:
            programs[int(value)]={'shaders':[],'attributes':{},'uniforms':{},'submitted_uniforms':{}}
        elif name=='glDeleteProgram':programs.pop(v[0],None)
        elif name=='glAttachShader' and v[0] in programs:
            shaders=programs[v[0]]['shaders']
            if v[1] not in shaders and len(shaders)<16:shaders.append(v[1])
            self.diagnostic('native_program_attach',limit=512,program=v[0],shader=v[1],**base)
        elif name=='glLinkProgram' and v[0] in programs:
            status=I();self.fn('glGetProgramiv',None,U,U,P)(v[0],0x8b82,C.byref(status))
            self.diagnostic('native_program_link',limit=256,program=v[0],link_status=status.value,
                            shaders=programs[v[0]]['shaders'],**base)
        elif name=='glGetProgramiv' and v[1]==0x8b82:
            result=next((buf.raw[:size] for index,buf,size in outputs if index==2),b'')
            self.diagnostic('native_program_link_query',limit=256,program=v[0],
                            link_status=struct.unpack('<i',result)[0] if len(result)==4 else None,**base)
        elif name in ('glGetAttribLocation','glGetUniformLocation'):
            label=args[1]['data'][:-1].decode('utf-8',errors='replace')
            location=int(value)
            if v[0] in programs and location>=0:
                table=programs[v[0]]['attributes' if name=='glGetAttribLocation' else 'uniforms']
                if len(table)<256:table[location]=label[:256]
            self.diagnostic('native_location',limit=1024,function=name,program=v[0],name=label[:256],location=location,**base)
        elif name=='glUseProgram':
            self.diagnostic('native_program_use',limit=256,requested_program=v[0],
                            current_program=self.diagnostic_integer(0x8b8d),**base)
        elif name.startswith('glUniform'):
            program=self.diagnostic_integer(0x8b8d)
            if program in programs and I(v[0]).value>=0:
                location=I(v[0]).value;table=programs[program]['submitted_uniforms']
                data=args[3 if name.startswith('glUniformMatrix') else 2]['data']
                count=min(len(data)//4,16);kind='i' if name.endswith('iv') else 'f'
                if len(table)<256 or location in table:
                    table[location]={'function':name,'count':I(v[1]).value,
                                     'values':list(struct.unpack('<'+kind*count,data[:count*4]))}
        elif name in ('glBindTexture','glActiveTexture'):
            unit=self.diagnostic_integer(0x84e0)-0x84c0
            if 0<=unit<32:state['textures'][unit]=self.diagnostic_integer(0x8069)
        elif name in ('glTexImage2D','glTexSubImage2D','glCompressedTexImage2D'):
            if self.diag_counts.get('native_texture',0)>256:return
            compressed=name=='glCompressedTexImage2D';sub=name=='glTexSubImage2D'
            wi,hi=(4,5) if sub else (3,4);pi=7 if compressed else 8
            data=args[pi]['data'];unit=self.diagnostic_integer(0x84e0)-0x84c0
            texture=self.diagnostic_integer(0x8069)
            self.diagnostic('native_texture',limit=256,function=name,target=v[0],level=I(v[1]).value,
                width=I(v[wi]).value,height=I(v[hi]).value,
                format=v[2] if compressed else v[6],pixel_type=None if compressed else v[7],
                internal_format=None if sub else v[2],active_unit=unit,texture_2d_binding=texture,
                null_data=args[pi]['tag']==1,data_bytes=len(data),nonzero_bytes=len(data)-data.count(0),
                sha256=hashlib.sha256(data).hexdigest() if data else None,**base)
        elif name.startswith('glDraw'):
            program=self.diagnostic_integer(0x8b8d);info=programs.get(program,{})
            shaders=[state['shaders'].get(s,{'shader':s}) for s in info.get('shaders',[])]
            labels=' '.join(str(s.get('labels',[]))+' '+s.get('source','') for s in shaders).lower()
            relevant=any(word in labels for word in ('font','glyph','text','luminance','draw2d'))
            category='native_text_draw' if relevant else 'native_other_draw';limit=100 if relevant else 24
            if self.diag_counts.get(category,0)>limit:return
            maximum=self.diagnostic_integer(0x8869);attributes=[]
            indices=set(info.get('attributes',{}))|set(state['clients'])
            for index in sorted(i for i in indices if 0<=i<min(maximum,16)):
                entry={'index':index,'name':info.get('attributes',{}).get(index)}
                for label,pname in [('enabled',0x8622),('size',0x8623),('stride',0x8624),('type',0x8625),('normalized',0x886a),('buffer',0x889f)]:
                    result=I();self.fn('glGetVertexAttribiv',None,U,U,P)(index,pname,C.byref(result));entry[label]=result.value
                if index in state['clients']:entry['last_client_submission']=state['clients'][index]
                attributes.append(entry)
            self.diagnostic(category,limit=limit,function=name,arguments=v,program=program,shaders=shaders,
                attributes=attributes,uniform_locations=info.get('uniforms',{}),
                submitted_uniforms=info.get('submitted_uniforms',{}),
                observed_texture_bindings=state['textures'],active_unit=self.diagnostic_integer(0x84e0)-0x84c0,
                texture_2d_binding=self.diagnostic_integer(0x8069),**base)

    def safe_diagnose_gl(self,*args):
        # Diagnostic bookkeeping must never turn a completed native RPC into a failure.
        if not self.graphics_diagnostics:return
        try:self.diagnose_gl(*args)
        except Exception as exc:self.diagnostic('graphics_diagnostic_error',limit=8,error=repr(exc))

    def token(self,kind,handle):
        if not handle:return 0
        key=(kind,int(handle))
        if key not in self.reverse:
            t=self.next_token; self.next_token+=1
            self.handles[t]=key; self.reverse[key]=t
        return self.reverse[key]

    def native(self,token,kind):
        if not token:return None
        found=self.handles.get(token)
        if found is None or found[0]!=kind: raise ValueError(f'unknown {kind} token {token:#x}')
        return found[1]

    def load_shaders(self):
        # Firmware wrappers carry a little-endian size followed by NVuc. Map the
        # exact byte stream to its adjacent, matching GLSL source, never guess.
        folder=ROOT/'rootfs-staging/tree/opt/hmi/data/ro/common/shader'
        if not folder.exists():
            candidates=list((ROOT/'rootfs-staging').glob('**/common/shader'))
            folder=candidates[0] if candidates else folder
        for binary in folder.glob('*.shd'):
            source=binary.with_suffix('.glsl')
            if not source.exists():continue
            data=binary.read_bytes()
            for candidate in (data,data[4:]):
                if candidate.startswith(b'NVuc'):
                    digest=hashlib.sha256(candidate).hexdigest()
                    self.shaders[digest]=(source.read_bytes(),str(source))
                    self.shader_labels[digest]=[source.stem]
        self.log(event='shader_catalog',count=len(self.shaders),folder=str(folder))
        manifest=ROOT/'hmi/shader-audit/native-shader-map.json'
        if manifest.exists():
            rows=json.loads(manifest.read_text())['entries']
            added=0
            for row in rows:
                binary=Path(row['binary_path']).resolve();source=Path(row['glsl_path']).resolve()
                if not binary.is_relative_to(ROOT) or not source.is_relative_to(ROOT):
                    raise ValueError('native shader paths must stay in VM workspace')
                data=binary.read_bytes();text=source.read_bytes()
                digest=hashlib.sha256(data).hexdigest()
                if digest!=row['binary_sha256'] or hashlib.sha256(text).hexdigest()!=row['glsl_sha256']:
                    raise ValueError('native shader/source hash mismatch')
                if not data.startswith(b'NVuc') or len(data)!=row['binary_length'] or not text or b'\0' in text:
                    raise ValueError('native shader/source format mismatch')
                if digest in self.shaders and self.shaders[digest][0].rstrip()!=text.rstrip():
                    raise ValueError('ambiguous native shader/source mapping: '+digest)
                self.shaders[digest]=(text,str(source));added+=1
                self.shader_labels[digest]=sorted({r['provenance']['program_name'] for r in row.get('factory_aliases',[row])})
            self.log(event='native_shader_catalog',entries=added,total=len(self.shaders),manifest=str(manifest))

    def activate(self,tid):
        binding=self.bindings.get(tid)
        if not binding or not binding[3]:raise ValueError('GLES call without guest current context')
        if self.active!=binding:
            d,draw,read,ctx=binding
            if not self.fn('eglMakeCurrent',U,P,P,P,P)(self.native(d,'display'),self.native(draw,'surface'),self.native(read,'surface'),self.native(ctx,'context')):
                raise RuntimeError('failed to restore guest EGL context')
            self.active=binding

    def egl_call(self,name,args,tid):
        v=[a['bits'] for a in args]
        def attributes(index):
            a=args[index]
            if a['tag']==1:return [0x3038]
            if a['tag']!=2 or a['len']!=len(a['data']) or not 4<=a['len']<=1028 or a['len']%4:
                raise ValueError('EGL attribute buffer bounds')
            values=list(struct.unpack('<'+'i'*(a['len']//4),a['data']))
            if len(values)%2!=1 or values[-1]!=0x3038 or 0x3038 in values[:-1:2]:
                raise ValueError('EGL attribute termination')
            return values
        if name=='eglGetDisplay':
            if v[0]:raise ValueError('only the default guest display is mapped')
            return reply(self.display_token)
        if name=='eglInitialize':
            self.native(v[0],'display')
            return reply(1,[(i,pack(value)) for i,value in ((1,self.major.value),(2,self.minor.value)) if args[i]['tag']!=1])
        if name=='eglGetCurrentContext':return reply(self.bindings.get(tid,(0,0,0,0))[3])
        if name=='eglGetCurrentDisplay':return reply(self.bindings.get(tid,(0,0,0,0))[0])
        if name=='eglGetCurrentSurface':
            if v[0] not in (0x3059,0x305a):raise ValueError('invalid EGL current surface selector')
            return reply(self.bindings.get(tid,(0,0,0,0))[1 if v[0]==0x3059 else 2])
        if name=='eglBindAPI':return reply(self.fn(name,U,U)(v[0]))
        if name=='eglGetError':return reply(self.fn(name,U)())
        if name=='eglChooseConfig':
            attrs=attributes(1)
            # Offscreen window substitution: retain all color/depth requirements.
            for i in range(0,len(attrs)-1,2):
                if attrs[i]==0x3033:attrs[i+1]=(attrs[i+1]&~4)|1
            n=I(v[3]).value
            if n<0 or n>4096 or args[2]['tag'] not in (1,3) or (args[2]['tag']!=1 and args[2]['len']<n*4):raise ValueError('config output size')
            if args[4]['tag']!=3 or args[4]['len']!=4:raise ValueError('config count output size')
            configs=(P*max(n,1))(); count=I()
            ok=self.fn(name,U,P,P,P,I,P)(self.native(v[0],'display'),(I*len(attrs))(*attrs),configs if args[2]['tag']!=1 else None,n,C.byref(count))
            out=[]
            if args[2]['tag']!=1:out.append((2,b''.join(pack(self.token('config',configs[i])) for i in range(min(n,count.value)))))
            if args[4]['tag']!=1:out.append((4,pack(count.value)))
            return reply(ok,out)
        if name=='eglCreateContext':
            attrs=attributes(3)
            ctx=self.fn(name,P,P,P,P,P)(self.native(v[0],'display'),self.native(v[1],'config'),self.native(v[2],'context'),(I*len(attrs))(*attrs))
            return reply(self.token('context',ctx))
        if name=='eglMakeCurrent':
            binding=tuple(v)
            ok=self.fn(name,U,P,P,P,P)(self.native(v[0],'display'),self.native(v[1],'surface'),self.native(v[2],'surface'),self.native(v[3],'context'))
            if ok:self.bindings[tid]=binding;self.active=binding
            return reply(ok)
        if name=='eglSwapBuffers':
            self.activate(tid);self.capture(v[1],tid)
            return reply(self.fn(name,U,P,P)(self.native(v[0],'display'),self.native(v[1],'surface')))
        if name in ('eglDestroyContext','eglDestroySurface'):
            kind='context' if name.endswith('Context') else 'surface'
            ok=self.fn(name,U,P,P)(self.native(v[0],'display'),self.native(v[1],kind))
            return reply(ok)
        if name=='eglTerminate':
            # This is the one actual display owned by the bridge; terminating it
            # ends all associated contexts just as on the guest.
            return reply(self.fn(name,U,P)(self.native(v[0],'display')))
        raise ValueError('unimplemented EGL operation '+name)

    def wal_call(self,opcode,args):
        v=[a['bits'] for a in args]
        if opcode==20:
            ident,d,c,w,h=v[:5]
            window=self.windows.setdefault(ident,{})
            w,h=window.get('w',w),window.get('h',h)
            if not (0<w<=4096 and 0<h<=4096):raise ValueError('window dimensions')
            surf=self.fn('eglCreatePbufferSurface',P,P,P,P)(self.native(d,'display'),self.native(c,'config'),(I*5)(0x3057,w,0x3056,h,0x3038))
            if not surf:raise RuntimeError('real pbuffer creation failed')
            surface=self.token('surface',surf); native=self.token('window',ident or 0x100000000)
            window.update(surface=surface,native=native,w=w,h=h)
            for key,value in (('x',0),('y',0),('alpha',255),('visible',True),('order',0)):
                window.setdefault(key,value)
            self.surface_sizes[surface]=(w,h)
            self.log(event='window_created',id=ident,surface=surface,width=w,height=h)
            return reply(0,[(5,pack(native)),(6,pack(surface))])
        if opcode==21:
            window=self.windows.get(v[0],{})
            if window.get('surface') and not self.fn('eglDestroySurface',U,P,P)(self.display,self.native(window['surface'],'surface')):raise RuntimeError('pbuffer destroy failed')
            self.windows.pop(v[0],None)
        elif opcode==22:
            window=self.windows.setdefault(v[0],{})
            if window.get('surface') and (v[3],v[4])!=(window['w'],window['h']):
                raise ValueError('native surface resizing not implemented')
            window.update(x=I(v[1]).value,y=I(v[2]).value,w=v[3],h=v[4])
        elif opcode==23:self.windows.setdefault(v[0],{})['alpha']=v[1]&255
        elif opcode==24:self.windows.setdefault(v[0],{})['visible']=bool(v[1])
        elif opcode==25:
            if args[1]['len']!=v[0]*8:raise ValueError('WAL order length')
            for at in range(0,args[1]['len'],8):
                ident,order,_=struct.unpack_from('<IHH',args[1]['data'],at)
                self.windows.setdefault(ident,{})['order']=order
        elif opcode==26:self.zone=v[0]
        else:raise ValueError('unknown WAL opcode')
        return reply()

    def capture(self,surface,tid):
        capture_started=time.perf_counter()
        from PIL import Image
        w,h=self.surface_sizes[surface]
        binding=self.bindings[tid]
        if binding[1]!=surface or binding[2]!=surface:
            if not self.fn('eglMakeCurrent',U,P,P,P,P)(self.native(binding[0],'display'),self.native(surface,'surface'),self.native(surface,'surface'),self.native(binding[3],'context')):
                raise RuntimeError('cannot select swapped surface for capture')
            self.active=(binding[0],surface,surface,binding[3])
        fbo=I(); alignment=I()
        self.fn('glGetIntegerv',None,U,P)(0x8ca6,C.byref(fbo))
        self.fn('glGetIntegerv',None,U,P)(0x0d05,C.byref(alignment))
        self.fn('glBindFramebuffer',None,U,U)(0x8d40,0)
        self.fn('glPixelStorei',None,U,I)(0x0d05,1)
        data=C.create_string_buffer(w*h*4)
        self.fn('glReadPixels',None,I,I,I,I,U,U,P)(0,0,w,h,0x1908,0x1401,data)
        self.fn('glPixelStorei',None,U,I)(0x0d05,alignment.value)
        self.fn('glBindFramebuffer',None,U,U)(0x8d40,fbo.value)
        self.activate(tid)
        readback_done=time.perf_counter()
        frame=Image.frombytes('RGBA',(w,h),data.raw).transpose(Image.Transpose.FLIP_TOP_BOTTOM)
        if self.graphics_diagnostics:
            frame.save(self.logdir/f'surface-{surface}.png',compress_level=1)
        for window in self.windows.values():
            if window.get('surface')==surface:window['frame']=frame
        visible=sorted((window for window in self.windows.values()
                        if window.get('visible') and 'frame' in window),key=lambda x:x.get('order',0))
        full=visible[0] if len(visible)==1 else None
        if (full and full.get('alpha',255)==255 and full.get('x',0)==full.get('y',0)==0
                and full['frame'].size==(1280,480) and full['frame'].getextrema()[3]==(255,255)):
            canvas=full['frame']
        else:
            canvas=Image.new('RGBA',(1280,480),(0,0,0,255))
            for window in visible:
                overlay=window['frame'];alpha=window.get('alpha',255)
                if alpha!=255:
                    overlay=overlay.copy();overlay.putalpha(overlay.getchannel('A').point(lambda x:x*alpha//255))
                canvas.alpha_composite(overlay,(window.get('x',0),window.get('y',0)))
        # The live display needs pixels, not compression. BMP avoids encoding
        # two PNGs on the guest's synchronous swap path. Publish atomically so
        # the viewer always opens a complete, genuine GL readback.
        output=self.logdir/('latest-frame.'+self.display_format)
        temporary=output.with_suffix('.tmp')
        canvas.convert('RGB').save(temporary,format=self.display_format.upper(),compress_level=1)
        published=False
        for attempt in range(101):
            try:
                os.replace(temporary,output);published=True;break
            except PermissionError as exc:
                # Windows readers may briefly omit FILE_SHARE_DELETE. Display
                # publication must not turn a real successful GL swap into an
                # EGL failure. Readers in this lab close before image decoding.
                if attempt==100:
                    self.diagnostic('display_publish_error',limit=16,error=repr(exc))
                    break
                time.sleep(.001)
        self.frames+=1
        now=time.perf_counter()
        mailbox=dict(getattr(self.connection,'stats',{}))
        frame_gaps=dict(getattr(self.connection,'frame_gaps',{}))
        if hasattr(self.connection,'frame_gaps'):self.connection.frame_gaps.clear()
        mailbox_delta={k:v-self.last_frame_mailbox.get(k,0) for k,v in mailbox.items()}
        self.last_frame_mailbox=mailbox
        self.log(event='frame_timing',frame=self.frames,calls=self.calls,
                 transport_calls=self.transport_calls,
                 guest_request_gaps=frame_gaps,
                 display_published=published,
                 capture_seconds=now-capture_started,readback_seconds=readback_done-capture_started,
                 image_output_seconds=now-readback_done,mailbox_since_last_frame=mailbox_delta,
                 calls_since_last_frame=self.calls-self.last_frame_calls,
                 seconds_since_last_frame=None if self.last_frame_time is None else now-self.last_frame_time)
        self.last_frame_time=now;self.last_frame_calls=self.calls
        if self.frames<=3 or self.frames%30==0:self.log(event='frame',frame=self.frames,surface=surface,sha256=hashlib.sha256(data.raw).hexdigest(),extrema=frame.getextrema())

    def gl_call(self,spec,args,tid):
        self.activate(tid)
        name=spec['name']
        sizes=self.validate_gl_pointers(name,args)
        if name in ('glGetIntegerv','glGetFloatv','glGetBooleanv') and args[0]['bits'] in (0x8df8,0x8df9):
            # This bridge accepts catalogued NVuc binaries by compiling their
            # exact matching GLSL. Advertise that implemented bridge format,
            # not the underlying ANGLE driver's unrelated binary formats.
            values=([0x890b] if self.shaders else []) if args[0]['bits']==0x8df8 else [int(bool(self.shaders))]
            data=(bytes(bool(v) for v in values) if name=='glGetBooleanv' else
                  struct.pack('<'+'f'*len(values),*values) if name=='glGetFloatv' else pack(*values))
            return reply(0,[(1,data)] if args[1]['tag']!=1 else [])
        if name=='glShaderBinary':
            if args[2]['bits']!=0x890b or args[4]['bits']!=len(args[3]['data']):raise ValueError('native shader format/length')
            digest=hashlib.sha256(args[3]['data']).hexdigest()
            if digest not in self.shaders:
                folder=self.logdir/'unknown-shaders';folder.mkdir(exist_ok=True)
                (folder/(digest+'.bin')).write_bytes(args[3]['data'])
                raise ValueError('unknown native shader hash '+digest)
            source,path=self.shaders[digest]
            shader_ids=struct.unpack('<'+'I'*(len(args[1]['data'])//4),args[1]['data'])
            if len(shader_ids)!=args[0]['bits']:raise ValueError('shader count')
            for shader in shader_ids:
                text=C.c_char_p(source);size=I(len(source))
                self.fn('glShaderSource',None,U,I,P,P)(shader,1,C.byref(text),C.byref(size))
                self.fn('glCompileShader',None,U)(shader)
                ok=I();self.fn('glGetShaderiv',None,U,U,P)(shader,0x8b81,C.byref(ok))
                info=C.create_string_buffer(16384);n=I()
                self.fn('glGetShaderInfoLog',None,U,I,P,P)(shader,len(info),C.byref(n),info)
                self.log(event='shader_compile',shader=shader,source=path,success=bool(ok.value),info=info.value.decode(errors='replace'))
                self.compiled_shaders[shader]=bool(ok.value)
                state=self.diagnostic_context(tid)
                if state is not None and len(state['shaders'])<1024:
                    state['shaders'][shader]={'shader':shader,'source':path,'binary_sha256':digest,
                                             'labels':self.shader_labels.get(digest,[])}
                    self.diagnostic('native_shader_source',limit=256,tid=tid,context=self.bindings[tid][3],
                                    **state['shaders'][shader])
                if not ok.value:raise RuntimeError('matching GLSL compilation failed: '+info.value.decode(errors='replace'))
            return reply()
        types=[];values=[];buffers=[];outputs=[]
        for index,(param,a) in enumerate(zip(spec['params'],args)):
            typ=param['type'];tag=a['tag']
            if '*' in typ:
                types.append(P)
                if tag==1:values.append(None)
                elif tag==5:values.append(P(a['bits']))
                elif tag in (2,3,4):
                    # Validation derives the native extent from the actual
                    # API count/format, never from an arbitrary safety cushion.
                    allocation=max(sizes[index],1)
                    if allocation>MAX_PAYLOAD:raise ValueError('native buffer bounds')
                    buf=C.create_string_buffer(allocation)
                    if a['data']:C.memmove(buf,a['data'],len(a['data']))
                    buffers.append(buf);values.append(buf)
                    if tag in (3,4):outputs.append((index,buf,sizes[index]))
                else:raise ValueError('pointer tag mismatch')
            else:
                if tag!=0:raise ValueError('scalar tag mismatch')
                native_type={'GLfloat':F,'GLclampf':F,'GLboolean':C.c_ubyte,'GLint':I,'GLsizei':I,'GLsizeiptr':C.c_ssize_t,'GLintptr':C.c_ssize_t}.get(typ,U)
                types.append(native_type)
                values.append(struct.unpack('<f',pack(a['bits']))[0] if native_type==F else I(a['bits']).value if native_type in (I,C.c_ssize_t) else a['bits'])
        # Pointers to undersized pixel blobs must not reach a native driver.
        if name in ('glReadPixels','glTexImage2D','glTexSubImage2D'):
            wi,hi,fi,ti,pi=(2,3,4,5,6) if name=='glReadPixels' else (3,4,6,7,8) if name=='glTexImage2D' else (4,5,6,7,8)
            if args[pi]['tag']!=1:
                w,h=I(args[wi]['bits']).value,I(args[hi]['bits']).value
                components={0x1906:1,0x1909:1,0x1902:1,0x190a:2,0x1907:3,0x1908:4,0x80e1:4}.get(args[fi]['bits'])
                unit={0x1401:1,0x1403:2,0x140b:2,0x8d61:2,0x1405:4,0x1406:4}.get(args[ti]['bits'])
                if args[ti]['bits'] in (0x8363,0x8033,0x8034):components,unit=1,2
                if w<0 or h<0 or components is None or unit is None:raise ValueError('pixel format/size')
                alignment=I();self.fn('glGetIntegerv',None,U,P)(0x0d05 if name=='glReadPixels' else 0x0cf5,C.byref(alignment))
                row=w*components*unit;stride=(row+alignment.value-1)&~(alignment.value-1)
                need=(h-1)*stride+row if w and h else 0
                if need>args[pi]['len']:raise ValueError('undersized pixel buffer')
        if name=='glGetString':
            ptr=self.fn(name,C.c_char_p,*types)(*values)
            return reply(1 if ptr else 0,[(0xffffffff,ptr+b'\0')] if ptr else [])
        rt=spec['return_type']
        restype={'void':None,'GLint':I,'GLboolean':C.c_ubyte}.get(rt,U)
        value=self.fn(name,restype,*types)(*values)
        self.safe_diagnose_gl(name,args,value,outputs,tid)
        if name.startswith('glDraw') and self.calls<1000:self.log(event='draw',name=name,arguments=[a['bits'] for a in args])
        return reply(value or 0,[(index,buf.raw[:size]) for index,buf,size in outputs])

    def query_count(self,pname):
        if pname in (0x0b70,0x0d3a,0x846d,0x846e):return 2
        if pname in (0x0ba2,0x0c10,0x0c22,0x0c23,0x8005):return 4
        if pname==0x8df8:return int(bool(self.shaders))
        if pname==0x86a3:
            count=I();self.fn('glGetIntegerv',None,U,P)(0x86a2,C.byref(count))
            if not 0<=count.value<=4096:raise ValueError('native query vector bounds')
            return count.value
        return 1

    def validate_gl_pointers(self,name,args):
        """Derive every native memory span before invoking the C driver."""
        sizes={}
        def signed(index):return I(args[index]['bits']).value
        def need(index,n,direction=2,nullable=False):
            a=args[index]
            if n<0 or n>MAX_PAYLOAD:raise ValueError(name+': native span bounds')
            if a['tag']==1:
                if n and not nullable:raise ValueError(name+': null required buffer')
                sizes[index]=0;return
            if a['tag']!=direction or a['len']!=n or (direction==2 and len(a['data'])!=n):
                raise ValueError(name+': declared buffer length/tag mismatch')
            sizes[index]=n
        if name in ('glBufferData','glBufferSubData'):
            size=signed(1 if name=='glBufferData' else 2)
            if name=='glBufferSubData' and signed(1)<0:raise ValueError('negative buffer offset')
            need(2 if name=='glBufferData' else 3,size,nullable=name=='glBufferData')
        elif name=='glCompressedTexImage2D':need(7,signed(6))
        elif name in ('glDeleteBuffers','glDeleteFramebuffers','glDeleteRenderbuffers','glDeleteTextures'):
            need(1,signed(0)*4)
        elif name in ('glGenBuffers','glGenFramebuffers','glGenRenderbuffers','glGenTextures'):
            need(1,signed(0)*4,3)
        elif name in ('glGetAttribLocation','glGetUniformLocation'):
            a=args[1]
            if a['tag']!=2 or not a['data'] or a['data'][-1]!=0 or b'\0' in a['data'][:-1]:raise ValueError(name+': unterminated name')
            need(1,len(a['data']))
        elif name=='glGetActiveUniform':
            for i in (3,4,5):need(i,4,3,nullable=i==3)
            need(6,signed(2),3)
        elif name in ('glGetBooleanv','glGetFloatv','glGetIntegerv'):
            need(1,self.query_count(args[0]['bits'])*(1 if name=='glGetBooleanv' else 4),3)
        elif name=='glGetProgramiv':need(2,4,3)
        elif name=='glGetVertexAttribiv':need(2,16 if args[1]['bits']==0x8626 else 4,3)
        elif name=='glShaderBinary':need(1,signed(0)*4);need(3,signed(4))
        elif name.startswith('glUniformMatrix'):
            dimension=int(name[len('glUniformMatrix')]);need(3,signed(1)*dimension*dimension*4)
        elif name.startswith('glUniform'):
            need(2,signed(1)*int(name[len('glUniform')])*4)
        elif name in ('glReadPixels','glTexImage2D','glTexSubImage2D'):
            wi,hi,fi,ti,pi=(2,3,4,5,6) if name=='glReadPixels' else (3,4,6,7,8) if name=='glTexImage2D' else (4,5,6,7,8)
            w,h=signed(wi),signed(hi)
            components={0x1906:1,0x1909:1,0x1902:1,0x190a:2,0x1907:3,0x1908:4,0x80e1:4}.get(args[fi]['bits'])
            unit={0x1401:1,0x1403:2,0x140b:2,0x8d61:2,0x1405:4,0x1406:4}.get(args[ti]['bits'])
            if args[ti]['bits'] in (0x8363,0x8033,0x8034):components,unit=1,2
            if w<0 or h<0 or components is None or unit is None:raise ValueError('pixel format/size')
            alignment=I();self.fn('glGetIntegerv',None,U,P)(0x0d05 if name=='glReadPixels' else 0x0cf5,C.byref(alignment))
            if alignment.value not in (1,2,4,8):raise ValueError('pixel alignment')
            row=w*components*unit;stride=(row+alignment.value-1)&~(alignment.value-1)
            need(pi,(h-1)*stride+row if w and h else 0,3 if name=='glReadPixels' else 2,nullable=name=='glTexImage2D')
        elif name=='glDrawElements':
            count=signed(1);unit={0x1401:1,0x1403:2,0x1405:4}.get(args[2]['bits'])
            if count<0 or unit is None:raise ValueError('index count/type')
            binding=I();self.fn('glGetIntegerv',None,U,P)(0x8895,C.byref(binding))
            if binding.value:
                if args[3]['tag']!=5:raise ValueError('index buffer requires offset')
            else:need(3,count*unit)
        elif name=='glVertexAttribPointer':
            binding=I();self.fn('glGetIntegerv',None,U,P)(0x8894,C.byref(binding))
            if not binding.value or args[5]['tag']!=5:raise ValueError('vertex pointer requires uploaded/bound VBO')
        return sizes

    def upload_client(self,payload,tid):
        self.activate(tid)
        if len(payload)<24:raise ValueError('short vertex upload')
        index,size,typ,norm,stride,length=struct.unpack_from('<6I',payload)
        if length!=len(payload)-24 or index>=16 or size<1 or size>4:raise ValueError('vertex upload bounds')
        context=self.bindings[tid][3];key=(context,index)
        saved=I();self.fn('glGetIntegerv',None,U,P)(0x8894,C.byref(saved))
        if key not in self.client_buffers:
            buffer=U();self.fn('glGenBuffers',None,I,P)(1,C.byref(buffer));self.client_buffers[key]=buffer.value
        self.fn('glBindBuffer',None,U,U)(0x8892,self.client_buffers[key])
        blob=C.create_string_buffer(payload[24:])
        self.fn('glBufferData',None,U,C.c_ssize_t,P,U)(0x8892,length,blob,0x88e0)
        self.fn('glVertexAttribPointer',None,U,I,U,C.c_ubyte,I,P)(index,size,typ,norm,stride,None)
        self.fn('glBindBuffer',None,U,U)(0x8892,saved.value)
        try:
            state=self.diagnostic_context(tid)
            if state is not None:
                state['clients'][index]={'size':size,'type':typ,'normalized':norm,'stride':stride,'bytes':length,
                    'buffer':self.client_buffers[key],'sha256':hashlib.sha256(payload[24:]).hexdigest(),
                    'first_32_bytes_hex':payload[24:56].hex()}
                self.diagnostic('native_client_upload',limit=256,tid=tid,context=context,index=index,
                                **state['clients'][index])
        except Exception as exc:self.diagnostic('graphics_diagnostic_error',limit=8,error=repr(exc))
        return b''

    def recv_exact(self,length,progress=False):
        chunks=[]
        total=length;reported=0
        while length:
            try:data=self.connection.recv(min(length,1048576))
            except socket.timeout:continue
            if not data:raise EOFError()
            chunks.append(data);length-=len(data)
            if progress and (total-length-reported>=65536 or not length):
                reported=total-length
                self.log(event='receive_progress',received=reported,total=total)
        return b''.join(chunks)

    def send_response(self,data):
        if getattr(self.connection,'bulk_transport',False):
            self.connection.sendall(data)
            return
        # QEMU's TCP chardev can inject faster than the guest 16550 RX FIFO
        # and original QNX driver drain it. Bound large reply bursts to one
        # 16-byte FIFO per millisecond; small replies keep their existing path.
        if len(data)<=256:
            self.connection.sendall(data)
            return
        for offset in range(0,len(data),16):
            self.connection.sendall(data[offset:offset+16])
            time.sleep(0.001)

    def poll_controller(self,payload):
        if payload:raise ValueError('controller poll must be empty')
        path=self.logdir/'controller-input.jsonl'
        if path.exists():
            with path.open('rb') as stream:
                stream.seek(self.input_offset);data=stream.read(65536)
            complete=data.rfind(b'\n')+1
            self.input_offset+=complete
            names={'menu':1,'back':2,'option':3,'enter':8,'up':9,'down':10,'left':11,'right':12,'cw':13,'ccw':14}
            for line in data[:complete].splitlines():
                try:
                    row=json.loads(line);key=names[row['key']]
                    if len(self.pending_input)>=64:raise ValueError('controller queue full')
                    events=[(key,0,1,0)] if key in (13,14) else [(key,1,1,0),(key,0,1,0)]
                    self.pending_input.extend(events)
                    self.log(event='controller_queued',key=row['key'])
                except (ValueError,KeyError,TypeError) as exc:
                    self.log(event='controller_rejected',reason=str(exc))
        selected=self.pending_input[:4];del self.pending_input[:4]
        return pack(len(selected))+b''.join(pack(*row) for row in selected)

    def execute_batch(self,payload,final_call=False):
        if len(payload)<4 or len(payload)>256*1024:raise ValueError('batch size')
        count,=struct.unpack_from('<I',payload);offset=4;commands=[]
        if not 1<=count<=512+int(final_call):raise ValueError('batch count')
        for index in range(count):
            if offset+12>len(payload):raise ValueError('short batch record')
            opcode,tid,length=struct.unpack_from('<III',payload,offset);offset+=12
            if not 1<=tid<=65535 or length>len(payload)-offset:raise ValueError('batch record bounds')
            data=payload[offset:offset+length];offset+=length
            last=final_call and index==count-1
            if last:
                if opcode not in self.api:raise ValueError('unknown final batch call')
                args=unpack_args(data)
                if len(args)!=len(self.api[opcode]['params']):raise ValueError('final call argument count')
            elif opcode==40:
                if len(data)<24:raise ValueError('short batch client upload')
                args=None
            else:
                if opcode not in self.batch_ops:raise ValueError('synchronous opcode in batch')
                args=unpack_args(data)
                if len(args)!=len(self.api[opcode]['params']) or any(a['tag'] in (3,4) for a in args):
                    raise ValueError('batch output or argument count')
            commands.append((opcode,tid,data,args))
        if offset!=len(payload):raise ValueError('trailing batch data')
        # Parsing completes before the first command executes. Calls retain
        # their original order, native thread/context and real GL behavior.
        result=b''
        for index,(opcode,tid,data,args) in enumerate(commands):
            self.calls+=1
            result=(self.upload_client(data,tid) if opcode==40 else
                    self.egl_call(self.api[opcode]['name'],args,tid) if opcode<200 else
                    self.gl_call(self.api[opcode],args,tid))
            if not (final_call and index==count-1) and result not in (b'',pack(0,0)):
                raise ValueError('unexpected batch result')
        self.diagnostic('batch_executed',limit=128,commands=count,bytes=len(payload),calls=self.calls,final_call=bool(final_call))
        return result if final_call else b''

    def run(self):
        compressed_peer=False
        try:
            while True:
                magic,opcode,length,request_id=struct.unpack('<IIII',self.recv_exact(16))
                if magic not in (0x4e425447,0x4e42545a) or length>MAX_PAYLOAD:raise ValueError('RPC header invalid')
                if self.calls<150 or length>=65536:
                    self.log(event='request_header',number=self.calls+1,opcode=opcode,bytes=length,tid=request_id>>16)
                payload=self.recv_exact(length,progress=length>=65536);tid=request_id>>16;self.calls+=1;self.transport_calls+=1
                if magic==0x4e42545a:
                    payload=decode_compressed(payload);compressed_peer=True
                    self.log(event='request_decompressed',number=self.calls,wire_bytes=length,original_bytes=len(payload))
                status=0
                try:
                    if opcode==0:result=payload
                    elif opcode==56:result=self.execute_batch(payload)
                    elif opcode==57:result=self.execute_batch(payload,final_call=True)
                    elif opcode==40:result=self.upload_client(payload,tid)
                    elif opcode==41:result=self.poll_controller(payload)
                    elif opcode==42:
                        if len(payload)!=12:raise ValueError('controller acknowledgement length')
                        reported,status_code,key=struct.unpack('<IiI',payload)
                        self.log(event='controller_status',tid=reported,status=status_code,key=key)
                        result=b''
                    elif opcode in (43,44):
                        if len(payload)!=20:raise ValueError('language diagnostic length')
                        reported,manager,previous,current,language_status=struct.unpack('<IIIIi',payload)
                        self.log(event='native_language' if opcode==43 else 'engine_language',tid=reported,manager=hex(manager),previous=previous,current=current,status=language_status)
                        result=b''
                    elif opcode==45:
                        if len(payload)!=12:raise ValueError('idle diagnostic length')
                        reported,idle_status,phase=struct.unpack('<IiI',payload)
                        self.log(event='native_idle_input',tid=reported,status=idle_status,phase=phase)
                        if phase==1 and idle_status==0:
                            (self.logdir/'controller-ready.json').write_text(json.dumps({'ready':True,'tid':reported}))
                        result=b''
                    elif opcode==47:
                        if len(payload)!=36:raise ValueError('string cache diagnostic length')
                        manager,cache,vtable,count,primary,secondary,font_handle,font_count,phase=struct.unpack('<IIIIIIIII',payload)
                        self.log(event='native_string_cache',manager=hex(manager),cache=hex(cache),vtable=hex(vtable),count=count,primary=primary,secondary=secondary,font_handle=hex(font_handle),font_count=font_count,phase=phase)
                        result=b''
                    elif opcode==48:
                        if len(payload)!=20:raise ValueError('language refresh diagnostic length')
                        reported,manager,state,initialized,result_code=struct.unpack('<IIIII',payload)
                        self.log(event='native_language_refresh',tid=reported,manager=hex(manager),state=hex(state),initialized=initialized,result=result_code)
                        result=b''
                    elif opcode==49:
                        if len(payload)!=16:raise ValueError('last wait diagnostic length')
                        reported,return_pc,condition,mutex=struct.unpack('<IIII',payload)
                        self.log(event='native_last_wait',tid=reported,return_pc=hex(return_pc),condition=hex(condition),mutex=hex(mutex))
                        result=b''
                    elif opcode==50:
                        if len(payload)!=24:raise ValueError('native state diagnostic length')
                        reported,manager,state,handler,vtable,typeinfo=struct.unpack('<IIIIII',payload)
                        self.log(event='native_state_handler',tid=reported,manager=hex(manager),state=hex(state),handler=hex(handler),vtable=hex(vtable),typeinfo=hex(typeinfo))
                        result=b''
                    elif opcode==51:
                        if len(payload)!=36:raise ValueError('menu chooser diagnostic length')
                        values=struct.unpack('<9I',payload)
                        names=('activity','list_view','list_vtable','carsharing_button','carsharing_vtable','main_button','main_vtable','resource_a','resource_b')
                        self.log(event='native_menu_chooser',**{name:hex(value) for name,value in zip(names,values)})
                        result=b''
                    elif opcode==52:
                        if len(payload)!=112:raise ValueError('regular main menu diagnostic length')
                        values=struct.unpack('<28I',payload)
                        self.log(event='native_main_menu',activity=hex(values[0]),
                                 fields={hex(0x8c+index*4):hex(value) for index,value in enumerate(values[1:22])},
                                 root=dict(zip(('pointer','vtable','typeinfo'),map(hex,values[22:25]))),
                                 list_widget=dict(zip(('pointer','vtable','typeinfo'),map(hex,values[25:28]))))
                        result=b''
                    elif opcode==53:
                        if len(payload)!=20:raise ValueError('menu rebuild diagnostic length')
                        activity,widget,model,before,after=struct.unpack('<5I',payload)
                        self.log(event='native_main_menu_rebuild',activity=hex(activity),widget=hex(widget),
                                 model=hex(model),rows_before=before,rows_after=after)
                        result=b''
                    elif opcode==54:
                        if len(payload)!=16:raise ValueError('menu activation diagnostic length')
                        reported,manager,state,status_code=struct.unpack('<4I',payload)
                        self.log(event='native_main_menu_activate',tid=reported,manager=hex(manager),
                                 state=hex(state),status=status_code)
                        result=b''
                    elif opcode==55:
                        if len(payload)!=16:raise ValueError('home input diagnostic length')
                        reported,home,before,after=struct.unpack('<4I',payload)
                        self.log(event='native_home_input_listener',tid=reported,home=hex(home),
                                 enabled_before=before,enabled_after=after)
                        result=b''
                    elif opcode==46:
                        if len(payload)!=28:raise ValueError('text provider diagnostic length')
                        provider,vtable,fd,header_magic,index_offset,index_count,node=struct.unpack('<IIiIIII',payload)
                        self.log(event='native_text_provider',provider=hex(provider),vtable=hex(vtable),fd=fd,
                                 header_magic=hex(header_magic),language2_index_offset=index_offset,
                                 registered_index_count=index_count,node=hex(node))
                        result=b''
                    else:
                        args=unpack_args(payload)
                        if 20<=opcode<=26:result=self.wal_call(opcode,args)
                        else:
                            spec=self.api[opcode]
                            if len(args)!=len(spec['params']):raise ValueError('API argument count mismatch')
                            result=self.egl_call(spec['name'],args,tid) if opcode<200 else self.gl_call(spec,args,tid)
                    if self.calls<=150 or 42<=opcode<=55 or self.graphics_diagnostics:
                        self.log(event='rpc',number=self.calls,opcode=opcode,name=self.api.get(opcode,{}).get('name'),tid=tid,bytes=length)
                except Exception as exc:
                    status=1;result=b'';self.log(event='rpc_error',opcode=opcode,error=repr(exc),traceback=traceback.format_exc())
                compressed=encode_compressed(result) if compressed_peer else None
                if compressed is not None:
                    self.log(event='response_compressed',number=self.calls,wire_bytes=len(compressed),original_bytes=len(result))
                    self.send_response(pack(0x4e425443,status,len(compressed),request_id)+compressed)
                else:
                    self.send_response(pack(0x4e425452,status,len(result),request_id)+result)
        except (EOFError,ConnectionError,OSError) as exc:
            self.log(event='connection_closed',reason=str(exc),calls=self.calls,frames=self.frames)
        finally:
            self.trace.close()

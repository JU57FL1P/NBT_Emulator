"""Build/audit base, rendering smoke, and opt-in native-controller VM DSOs."""
from pathlib import Path
import hashlib,json,struct,subprocess,sys,os
here=Path(__file__).resolve().parent
vm=here.parent
sys.path.insert(0,str(vm/'compiler-probe'))
from restore_linker_sections import restore
tools=Path(os.environ['NBT_EMULATOR_LLVM'])
libc=vm/'ifs-analysis/files/3221225508-boot_lib_libc.so.3'
libz=vm/'rootfs-staging/tree/lib/libz.so.2'
link_libc=here/'link-only-libc.so.3'
link_libz=here/'link-only-libz.so.2'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
original_hash=sha(libc)
original_libz_hash=sha(libz)
restore(libc,link_libc)
restore(libz,link_libz)
names=['guest_transport','guest_gl','wal_adapter','wal_hooks','kd_entry','input_bridge']
idle_source=vm/'hmi/service-audit/input_idle_wait.c'
input_source=vm/'hmi/service-audit/input_hooks.c'
sources=[here/(name+'.c') for name in names]+[idle_source]
commands=[]
for source in sources:
    command=[str(tools/'clang.exe'),'--target=i386-unknown-none-elf',
        '-std=c11','-ffreestanding','-fPIC','-fno-builtin','-fno-stack-protector',
        '-fno-unwind-tables','-fno-asynchronous-unwind-tables','-mstackrealign',
        '-nostdinc','-Wall','-Wextra','-Werror','-O2','-c',str(source),'-o',str(source.with_suffix('.o'))]
    commands.append(command);subprocess.run(command,check=True,cwd=here)
sys.path.insert(0,str(vm/'hmi'))
from elf_abi_inspect import ELF32
elf=ELF32(vm/'hmi/HmiMain3D.elf')
imports=[name for name,value in elf.syms.items() if value['section']==0]
evidence={'egl_imports':[n for n in imports if n.startswith('egl')],
 'gles_imports':[n for n in imports if n.startswith('gl') and len(n)>2 and n[2].isupper()],
 'wal_imports':[n for n in imports if n.startswith('_ZN3wal')]}
expected=set(evidence['egl_imports']+evidence['gles_imports']+evidence['wal_imports']+['NvKdLaunch'])
allowed_imports={'open','read','write','close','malloc','free','usleep','gettid','sched_yield','memcpy','memset',
                 'compressBound','compress2','uncompress','getenv','pthread_self','pthread_getspecific','clock_gettime','mmap_device_memory','perror'}
outputs=[]
for variant in ('controller',):
    smoke=variant=='smoke'
    controller=variant=='controller'
    output=here/f'libnbt_graphics_{variant}.so'
    objects=[here/(name+'.o') for name in names]
    if smoke:objects.append(here/'pipeline_smoke.o')
    if controller:objects.append(idle_source.with_suffix('.o'))
    command=[str(tools/'ld.lld.exe'),'-m','elf_i386','-shared','--nostdlib',
        '--hash-style=sysv','--build-id=none','--no-rosegment','-z','max-page-size=4096',
        '--no-undefined','-soname',output.name,'-o',str(output),*map(str,objects),str(link_libc),str(link_libz)]
    if smoke:command+=['-init','nbt_pipeline_smoke_init']
    commands.append(command);subprocess.run(command,check=True,cwd=here)
    data=output.read_bytes();header=struct.unpack_from('<16sHHIIIIIHHHHHH',data)
    assert data[:8]==b'\x7fELF\x01\x01\x01\x00' and header[1:3]==(3,3)
    segments=[struct.unpack_from('<IIIIIIII',data,header[5]+n*header[9]) for n in range(header[10])]
    assert not any(s[0]==3 for s in segments),'DSO must not request a host loader'
    def offset(address):return next(s[1]+address-s[2] for s in segments if s[0]==1 and s[2]<=address<s[2]+s[4])
    dynamic=next(s for s in segments if s[0]==2)
    entries=[struct.unpack_from('<II',data,n) for n in range(dynamic[1],dynamic[1]+dynamic[4],8)]
    tags=dict(entries);assert 4 in tags and 0x6ffffef5 not in tags
    assert (12 in tags)==smoke
    strings=offset(tags[5])
    def name(n):return data[strings+n:data.index(0,strings+n)].decode('ascii')
    needed=[name(value) for tag,value in entries if tag==1]
    assert needed==['libc.so.3','libz.so.2'],needed
    imports=[];exports=[];bindings={}
    count=struct.unpack_from('<II',data,offset(tags[4]))[1]
    for n in range(count):
        symbol=struct.unpack_from('<IIIBBH',data,offset(tags[6])+n*tags[11])
        if not symbol[0]:continue
        (imports if symbol[5]==0 else exports).append(name(symbol[0]))
        if symbol[5]:bindings[name(symbol[0])]=symbol[3]>>4
    assert set(imports)<=allowed_imports,imports
    assert {'compressBound','compress2','uncompress'}<=set(imports),imports
    assert expected<=set(exports),sorted(expected-set(exports))
    assert ('pthread_cond_wait' in exports)==controller
    assert ('TimerTimeout_r' in exports)==controller
    assert 'TimerTimeout_r' not in imports
    assert bindings['nbt_idle_arm_after_swap']==(1 if controller else 2),bindings
    assert {'nbt_input_on_app_thread','nbt_input_verified_app_proc_unit','nbt_controller_poll_idle'}<=set(exports)
    assert 'dlsym' not in imports
    assert ('clock_gettime' in imports)==controller
    if controller:
        # Function-address anchor must be eager GLOB_DAT, never a lazy PLT
        # lookup that could consume a pending QNX TimerTimeout_r deadline.
        relocations=[]
        for rel_tag,size_tag in ((17,18),(23,2)):
            if rel_tag not in tags:continue
            for pos in range(offset(tags[rel_tag]),offset(tags[rel_tag])+tags[size_tag],8):
                location,info=struct.unpack_from('<II',data,pos)
                symbol=struct.unpack_from('<IIIBBH',data,offset(tags[6])+(info>>8)*tags[11])
                if symbol[0] and name(symbol[0])=='clock_gettime':
                    relocations.append({'address':location,'type':info&255})
        assert len(relocations)==1 and relocations[0]['type']==6,relocations
    audit=[str(tools/'llvm-readobj.exe'),'--file-headers','--program-headers','--dynamic-table','--dyn-symbols','--relocations',str(output)]
    (here/(output.stem+'-audit.txt')).write_text(subprocess.check_output(audit,text=True))
    outputs.append({'path':str(output),'sha256':sha(output),'bytes':len(data),
        'needed':needed,'imports':imports,'export_count':len(exports),
        'required_native_exports_verified':len(expected),
        'variant':variant,'idle_wait_interposer':controller,
        'preserved_native_timer_interposer':controller,
        'idle_arm_symbol_binding':'GLOBAL' if controller else 'WEAK',
        'libc_clock_anchor_relocation':'R_386_GLOB_DAT' if controller else None,
        'init':'nbt_pipeline_smoke_init' if smoke else None,
        'purpose':('Real EGL/Wal/GLES pipeline smoke; not iDrive' if smoke else
                   'Native HmiMain3D with guarded controller delivery during idle' if controller else
                   'Interposer for unchanged native HmiMain3D; swap-only controller delivery')})
assert sha(libc)==original_hash
assert sha(libz)==original_libz_hash
subprocess.run([sys.executable,str(vm/'compiler-probe/build_probe.py'),
    '--clang',str(tools/'clang.exe'),'--lld',str(tools/'ld.lld.exe'),
    '--readobj',str(tools/'llvm-readobj.exe'),'--objdump',str(tools/'llvm-objdump.exe'),
    '--source',str(vm/'timing/tick_10ms.c'),'--stem','libnbt_tick_10ms'],check=True,
    stdout=subprocess.DEVNULL)
extra=[here/name for name in ('wal_adapter.h','guest_transport.h','guest_gl.h','guest_gl_core.inc')]+[input_source,vm/'timing/tick_10ms.c']
manifest={'status':'built and ELF-audited; actual VM rendering test pending',
    'firmware_unchanged':True,'original_libc_sha256':original_hash,
    'original_libz_sha256':original_libz_hash,
    'compression':{'threshold':4096,'level':1,'max_payload':64*1024*1024,
                   'request_magic':'0x4e42545a','response_magic':'0x4e425443',
                   'runtime_library':'original /lib/libz.so.2; never the link-only copy'},
    'source_hashes':{str(p):sha(p) for p in sources+extra},'commands':commands,'outputs':outputs}
(here/'bridge-build.json').write_text(json.dumps(manifest,indent=2))
print(json.dumps({'status':manifest['status'],'outputs':outputs},indent=2))

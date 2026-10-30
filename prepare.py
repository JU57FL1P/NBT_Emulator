"""Prepare a private runtime from user-supplied firmware and external tools.

This script never writes firmware or generated binaries inside the repository.
"""
from pathlib import Path
import argparse,array,hashlib,json,os,shutil,struct,subprocess,sys,time

REPO=Path(__file__).resolve().parent
PACKAGES=('btld_00001275.bin.003_013_001','swfl_00001280.bin.003_013_001',
          'swfl_00001e6b.bin.003_013_001','swfl_000021d2.bin.003_013_001')
HMI_SHA='554b67d4d6317cfb1715d544874fae8ddd2c975be503c9e2514e2dc2f3a0d693'

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def private_path(value):
    p=Path(value).expanduser().resolve()
    if p.is_relative_to(REPO):raise ValueError('Choose a runtime folder OUTSIDE the GitHub source repository.')
    return p
def index_package(source):
    rows=[];descriptor='';size=source.stat().st_size
    with source.open('rb') as f:
        prefix=f.read(10)
        while f.tell()+9<=size:
            offset=f.tell();header=f.read(9);length=struct.unpack_from('<I',header,3)[0]
            if offset+9+length>size:break  # signed trailer is not a payload record
            row={'offset':offset,'type_hex':header[:3].hex(),'length':length,'payload_offset':offset+9}
            if header[0]==2:
                if length>32768:raise ValueError('Oversized firmware descriptor')
                descriptor=f.read(length).decode('ascii').rstrip('\0')
            if header[0] in (2,4):row['descriptor']=descriptor
            rows.append(row);f.seek(offset+9+length)
    return {'source':str(source),'size':size,'prefix_hex':prefix.hex(),'records':rows}
def find_package(root,name):
    for folder in (root,root/'swe/btld',root/'swe/swfl',root/'btld',root/'swfl'):
        p=folder/name
        if p.is_file():return p.resolve()
    raise FileNotFoundError(f'Missing supported firmware package: {name}')
def copy_tree(source,dest):
    for p in source.rglob('*'):
        if p.is_file() and '__pycache__' not in p.parts:
            q=dest/p.relative_to(source);q.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,q)
def pack_bridge(runtime):
    """A tiny, independently checked, read-only ImageFS containing two addons."""
    def align(n,a=4096):return (n+a-1)&~(a-1)
    def attrs(n,i,m):return struct.pack('<HHIIIII',n,0,i,m,0,0,0)
    items=[('libnbt_graphics_controller.so',runtime/'graphics-bridge/libnbt_graphics_controller.so'),
           ('libnbt_tick_10ms.so',runtime/'compiler-probe/libnbt_tick_10ms.so')]
    header=bytearray(88);header[:8]=b'imagefs\x06';header+=b'/dev/bridge\0';header+=bytes(align(len(header),4)-len(header))
    records=[bytearray((attrs(28,1,0o40755)+b'\0').ljust(28,b'\0'))]
    for i,(name,p) in enumerate(items,2):
        b=p.read_bytes();assert b[:6]==b'\x7fELF\x01\x01'
        n=align(33+len(name),4);records.append(bytearray((attrs(n,i,0o100555)+struct.pack('<II',0,len(b))+name.encode()+b'\0').ljust(n,b'\0')))
    start=len(header);end=start+sum(map(len,records))+4;pos=align(end)
    for rec,(_,p) in zip(records[1:],items):struct.pack_into('<I',rec,24,pos);pos=align(pos+p.stat().st_size)
    size=align(pos+4);struct.pack_into('<III',header,8,size,end,start);image=bytearray(size);image[:len(header)]=header
    pos=start
    for rec in records:image[pos:pos+len(rec)]=rec;pos+=len(rec)
    for rec,(_,p) in zip(records[1:],items):pos=struct.unpack_from('<I',rec,24)[0];image[pos:pos+p.stat().st_size]=p.read_bytes()
    words=array.array('I');words.frombytes(image);struct.pack_into('<I',image,size-4,(-sum(words))&0xffffffff)
    words=array.array('I');words.frombytes(image);assert sum(words)&0xffffffff==0
    for rec,(_,p) in zip(records[1:],items):pos,n=struct.unpack_from('<II',rec,24);assert image[pos:pos+n]==p.read_bytes()
    p=runtime/'graphics-bridge/nbt-bridge.ifs';p.write_bytes(image);return p
def make_profiles(runtime):
    boot='minimal/nbt-qnx-minimal-mount-uncompressed.ifs'
    payloads=[('rootfs-staging/nbt-runtime-core.ifs',0x40000000),('rootfs-staging/nbt-runtime-hmi-images.ifs',0x50000000),('graphics-bridge/nbt-bridge.ifs',0x60000000)]
    preloads=[{'path':p,'address':hex(a),'sha256':sha(runtime/p)} for p,a in payloads]
    base={'ifs':boot,'floppy':'loader/nbt-minimal-mount-whpx-floppy.img','memory_mib':2304,
          'rpc_renderer':True,'preloads':preloads,'controller_input':True,'icount_shift':0,
          'icount_sleep':False,'display_format':'bmp','graphics_backend':'warp',
          'rpc_ram':True,'rpc_ram_direct':True,'accelerator':'whpx'}
    (runtime/'profile-whpx.json').write_text(json.dumps(base,indent=2))
    tcg=dict(base,accelerator='tcg',icount_shift=5,icount_sleep=True,floppy='loader/nbt-minimal-mount-tcg-floppy.img')
    (runtime/'profile-tcg.json').write_text(json.dumps(tcg,indent=2))
    lines=['# Native regular NBT; all writable state resides in guest RAM.']
    for path,address in payloads:
        mount='/dev/bridge' if address==0x60000000 else '/fs/sda0'
        lines.append(f'/boot/bin/mount -tifs -o offset=0x{address:x},size=0x{(runtime/path).stat().st_size:x} /dev/mem {mount}')
    lines.insert(2,'export PATH=/boot/bin:/bin:/opt/sys/bin; export LD_LIBRARY_PATH=/boot/lib:/lib:/opt/sys/lib:/opt/hmi/lib:/opt/hmi/otf:/opt/car/lib:/opt/mm/lib')
    # This template is authored shell setup, not a script extracted from firmware.
    lines += (runtime/'setup-tail.txt').read_text().splitlines()
    (runtime/'setup-tcg.txt').write_text('\n'.join(lines)+'\n')
    at=next(i for i,l in enumerate(lines) if '/dev/bridge' in l)
    lines.insert(at+1,"LD_PRELOAD=/dev/bridge/libnbt_tick_10ms.so /boot/bin/ksh -c 'print NBT_VM_TICK_READY'")
    lines=[l.replace('NBT_VM_RPC_RAM=1','NBT_VM_RPC_RAM=1 NBT_VM_RAM_LONG_POLL=1') for l in lines]
    (runtime/'setup-whpx.txt').write_text('\n'.join(lines)+'\n')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--firmware-dir',required=True,type=Path)
    p.add_argument('--runtime',required=True,type=private_path)
    p.add_argument('--qemu-dir',required=True,type=Path)
    p.add_argument('--angle-dir',required=True,type=Path)
    p.add_argument('--llvm-bin',required=True,type=Path)
    p.add_argument('--nasm',required=True,type=Path)
    p.add_argument('--whpx-tsc-hz',type=int,help='Measured guest TSC Hz for this host; enables WHPX by default. Without it, use portable TCG timing.')
    a=p.parse_args();r=a.runtime;r.mkdir(parents=True,exist_ok=True)
    tool_inputs=[a.qemu_dir/'qemu-system-x86_64.exe',a.qemu_dir/'liblzo2-2.dll',a.angle_dir/'libEGL.dll',a.angle_dir/'libGLESv2.dll',a.nasm]
    tool_inputs += [a.llvm_bin/n for n in ('clang.exe','ld.lld.exe','llvm-readobj.exe','llvm-objdump.exe')]
    for t in tool_inputs:
        if not t.is_file():raise FileNotFoundError(f'Missing external dependency: {t}')
    print('Preparing private runtime outside the source repository:',r,flush=True)
    copy_tree(REPO/'src',r)
    # Copy only runtime dependencies, no downloaded installers or unrelated apps.
    q=r/'tools/qemu';q.mkdir(parents=True,exist_ok=True)
    if a.qemu_dir.resolve()!=q.resolve():
        for f in a.qemu_dir.iterdir():
            if f.is_file() and (f.suffix.lower()=='.dll' or f.name in ('qemu-system-i386.exe','qemu-system-x86_64.exe')):shutil.copyfile(f,q/f.name)
        copy_tree(a.qemu_dir/'share',q/'share')
    angle=r/'tools/angle';angle.mkdir(parents=True,exist_ok=True)
    for name in ('libEGL.dll','libGLESv2.dll','d3dcompiler_47.dll','dxcompiler.dll','dxil.dll'):
        f=a.angle_dir/name
        if f.is_file() and f.resolve()!=(angle/name).resolve():shutil.copyfile(f,angle/name)
    env=dict(os.environ,NBT_EMULATOR_LLVM=str(a.llvm_bin.resolve()),NBT_EMULATOR_QEMU=str(q.resolve()))
    log=r/'prepare.log';log.write_text('Private firmware preparation log. Do not upload.\n')
    def run(script,*args):
        print('Building:',script,flush=True)
        with log.open('a',encoding='utf-8') as out:
            result=subprocess.run([sys.executable,str(r/script),*map(str,args)],env=env,cwd=r,stdout=out,stderr=subprocess.STDOUT)
        if result.returncode:raise RuntimeError(f'{script} failed. See private log: {log}')
    indexes=r/'firmware-indexes';indexes.mkdir(exist_ok=True);docs=[]
    for name in PACKAGES:
        source=find_package(a.firmware_dir,name);d=index_package(source);docs.append(d)
        (indexes/(name+'.index.json')).write_text(json.dumps(d,indent=2))
    boot=docs[0];row=next(x for x in boot['records'] if x['type_hex'].startswith('04') and 'Name=appimage.ifs;' in x.get('descriptor','') and 'CPU=Intel;' in x['descriptor'])
    images=r/'images';images.mkdir(exist_ok=True)
    with Path(boot['source']).open('rb') as f:f.seek(row['payload_offset']);(images/'nbt-intel-original.ifs').write_bytes(f.read(row['length']))
    (r/'ifs-analysis').mkdir(exist_ok=True)
    run('ifs-analysis/analyze_ifs.py')
    run('stage_runtime.py')
    hmi=r/'rootfs-staging/tree/opt/hmi/bin/HmiMain3D'
    if sha(hmi)!=HMI_SHA:raise ValueError('Unsupported HMI image; native ABI guards require the pinned 003.013.001 executable.')
    shutil.copyfile(hmi,r/'hmi/HmiMain3D.elf')
    assets=r/'ifs-analysis/runtime-assets';assets.mkdir(exist_ok=True)
    shutil.copyfile(r/'rootfs-staging/tree/bin/ksh',assets/'ksh')
    (r/'ifs-analysis/runtime-assets.json').write_text(json.dumps([{'name':'ksh','sha256':sha(assets/'ksh')}]))
    run('minimal/build_minimal_ifs.py');run('minimal/build_mount_variant.py')
    if a.whpx_tsc_hz is not None and not 1000000<=a.whpx_tsc_hz<=4000000000:raise ValueError('TSC Hz must be 1 MHz..4 GHz')
    for mode,hz in [('whpx',a.whpx_tsc_hz or 1800000000),('tcg',1000000000)]:
        ifs=r/'minimal/nbt-qnx-minimal-mount-uncompressed.ifs'
        run('loader/build_bootstrap.py','--nasm',a.nasm.resolve(),'--ifs',ifs,'--single-cpu','--qemu-clocks',
            '--rootfs-reserve','--tsc-hz',hz,'--expected-sha256',sha(ifs),'--output-stem','nbt-minimal-mount-'+mode)
    run('build_secondary_ifs.py','--subset','core');run('build_secondary_ifs.py','--subset','hmi-images')
    run('hmi/shader-audit/decode_nfx.py');run('hmi/shader-audit/extract_nfx_shaders.py')
    run('graphics-bridge/build_bridge.py');pack_bridge(r);make_profiles(r)
    for mode in ('whpx','tcg'):run('console_runtime.py','--config',r/('profile-'+mode+'.json'),'--setup-file','setup-'+mode+'.txt','--validate-only')
    manifest={'prepared_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'python':sys.executable,
              'preferred_mode':'whpx' if a.whpx_tsc_hz else 'tcg','whpx_tsc_hz':a.whpx_tsc_hz,
              'hmi_sha256':sha(hmi),'source_repository':str(REPO),'firmware_files':[d['source'] for d in docs],
              'private_runtime':True,'validation_passed':True,'qemu_sha256':sha(q/'qemu-system-x86_64.exe')}
    manifest['source_hashes']={str(f.relative_to(REPO/'src')):sha(f) for f in (REPO/'src').rglob('*') if f.is_file() and '__pycache__' not in f.parts}
    (r/'runtime.json').write_text(json.dumps(manifest,indent=2))
    print('Private runtime prepared and validated. Firmware was not changed. Start with Start.ps1.',flush=True)

if __name__=='__main__':main()

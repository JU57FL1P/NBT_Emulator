"""Build a standalone VM-only ELF32 DSO from plain C and the owned QNX libc."""
from pathlib import Path
import argparse, hashlib, json, subprocess, struct
from restore_linker_sections import restore

here=Path(__file__).resolve().parent
vm=here.parent
p=argparse.ArgumentParser()
p.add_argument('--clang',type=Path,required=True)
p.add_argument('--lld',type=Path,required=True)
p.add_argument('--readobj',type=Path,required=True)
p.add_argument('--objdump',type=Path,required=True)
p.add_argument('--source',type=Path,default=here/'probe.c')
p.add_argument('--stem',default='libnbt_vm_probe')
p.add_argument('--no-init',action='store_true',help='Diagnostic interposer exports an API, without DT_INIT')
args=p.parse_args()
assert args.stem and all(c.isalnum() or c=='_' for c in args.stem)
libc=vm/'ifs-analysis/files/3221225508-boot_lib_libc.so.3'
source=args.source.resolve()
is_base=args.stem=='libnbt_vm_probe'
obj=here/('probe.o' if is_base else args.stem+'.o')
dso=here/(args.stem+'.so')
prefix='' if is_base else args.stem+'-'
def digest(path): return hashlib.sha256(path.read_bytes()).hexdigest()
libc_before=digest(libc)
link_libc=here/'link-only-libc.so.3'
link_metadata=restore(libc,link_libc)
commands=[
    [str(args.clang),'--target=i386-unknown-none-elf','-std=c11','-ffreestanding',
     '-fPIC','-fno-builtin','-fno-stack-protector','-fno-unwind-tables',
     '-fno-asynchronous-unwind-tables','-mstackrealign','-nostdinc',
     '-Wall','-Wextra','-Werror','-O1','-c',str(source),'-o',str(obj)],
    [str(args.lld),'-m','elf_i386','-shared','--nostdlib','--hash-style=sysv','--build-id=none',
     '--no-rosegment','-z','max-page-size=4096','--no-undefined',
     '-soname',args.stem+'.so',
     *([] if args.no_init else ['-init','nbt_vm_probe_init']),
     '-o',str(dso),str(obj),str(link_libc)]
]
for command in commands:
    subprocess.run(command,check=True,cwd=here)
assert digest(libc)==libc_before, 'Owned libc must remain unchanged'
b=dso.read_bytes()
assert b[:8]==b'\x7fELF\x01\x01\x01\x00'
h=struct.unpack_from('<16sHHIIIIIHHHHHH',b)
assert h[1:3]==(3,3), 'Expected ET_DYN / EM_386'
ph=[struct.unpack_from('<IIIIIIII',b,h[5]+i*h[9]) for i in range(h[10])]
assert not any(q[0]==3 for q in ph), 'DSO must not depend on an executable interpreter'
def at(v): return next(q[1]+v-q[2] for q in ph if q[0]==1 and q[2]<=v<q[2]+q[4])
q=next(q for q in ph if q[0]==2)
pairs=[struct.unpack_from('<II',b,i) for i in range(q[1],q[1]+q[4],8)]
ds=dict(pairs)
st=at(ds[5])
def string(v): return b[st+v:b.find(b'\0',st+v)].decode('ascii')
needed=[string(v) for t,v in pairs if t==1]
assert needed==['libc.so.3'], needed
assert 4 in ds and 0x6ffffef5 not in ds, 'Require SysV hash'
assert args.no_init or (12 in ds and ds[12]), 'Require explicit DT_INIT'
assert not any(t in ds for t in [35,36,37]), 'No RELR packing'
versions={}
for label,exe in [('clang',args.clang),('lld',args.lld)]:
    versions[label]=subprocess.check_output([str(exe),'--version'],text=True).strip()
readcmd=[str(args.readobj),'--file-headers','--program-headers','--dynamic-table',
         '--dyn-symbols','--relocations',str(dso)]
(here/(prefix+'elf-audit.txt')).write_text(subprocess.check_output(readcmd,text=True))
discmd=[str(args.objdump),'-d','--no-show-raw-insn',str(dso)]
(here/(prefix+'disassembly.txt')).write_text(subprocess.check_output(discmd,text=True))
manifest={'source':str(source),'source_sha256':digest(source),'owned_libc_sha256':libc_before,
          'linker_only_libc':link_metadata,
          'dso_sha256':digest(dso),'dso_bytes':len(b),'needed':needed,
          'versions':versions,'commands':commands,'audit_command':readcmd,
          'disassembly_command':discmd,'status':'built; guest execution not yet tested'}
(here/(prefix+'build.json')).write_text(json.dumps(manifest,indent=2))
print(json.dumps(manifest,indent=2))

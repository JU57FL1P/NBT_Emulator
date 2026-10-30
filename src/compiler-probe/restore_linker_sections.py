"""Restore minimal ELF section metadata in a LINKER-ONLY copy of owned libc.

QNX boot packaging removed normal section headers but retained the loader's
PT_DYNAMIC tables. LLD expects SHT_DYNSYM. This copy is never put in the guest.
Original bytes are not modified. No invented implementation or function address.
"""
from pathlib import Path
import hashlib, json, struct

def restore(source, destination):
    original=source.read_bytes()
    b=bytearray(original)
    h=list(struct.unpack_from('<16sHHIIIIIHHHHHH',b))
    assert b[:6]==b'\x7fELF\x01\x01' and h[1:3]==[3,3]
    ph=[struct.unpack_from('<IIIIIIII',b,h[5]+i*h[9]) for i in range(h[10])]
    def at(v): return next(q[1]+v-q[2] for q in ph if q[0]==1 and q[2]<=v<q[2]+q[4])
    dyn=next(q for q in ph if q[0]==2)
    ds=dict(struct.unpack_from('<II',b,i) for i in range(dyn[1],dyn[1]+dyn[4],8))
    assert 4 in ds and not any(t in ds for t in [0x6ffffff0,0x6ffffffc,0x6ffffffe]), 'Only unversioned SysV libc supported'
    nbucket,nchain=struct.unpack_from('<II',b,at(ds[4]))
    rx=next(q for q in ph if q[0]==1 and q[6]&1)
    rw=next(q for q in ph if q[0]==1 and q[6]&2)
    sh=[(0,0,0,0,0,0,0,0,0,0)]
    shnames=bytearray(b'\0')
    def add(name,typ,flags,addr,off,size,link=0,info=0,align=4,entsize=0):
        nameoff=len(shnames)
        shnames.extend(name.encode()+b'\0')
        sh.append((nameoff,typ,flags,addr,off,size,link,info,align,entsize))
    add('.dynstr',3,2,ds[5],at(ds[5]),ds[10],align=1)
    add('.dynsym',11,2,ds[6],at(ds[6]),nchain*ds[11],link=1,info=1,entsize=16)
    add('.hash',5,2,ds[4],at(ds[4]),(2+nbucket+nchain)*4,link=2,entsize=4)
    add('.dynamic',6,3,dyn[2],dyn[1],dyn[4],link=1,entsize=8)
    add('.text',1,6,rx[2],rx[1],rx[4])
    add('.data',1,3,rw[2],rw[1],rw[4])
    add('.bss',8,3,rw[2]+rw[4],rw[1]+rw[4],rw[5]-rw[4])
    mapped=0
    for i in range(nchain):
        off=at(ds[6])+i*16
        name,val,size,info,other,idx=struct.unpack_from('<IIIBBH',b,off)
        if 0<idx<0xff00:
            if rx[2]<=val<rx[2]+rx[5]: idx=5
            elif rw[2]<=val<rw[2]+rw[4]: idx=6
            elif rw[2]+rw[4]<=val<rw[2]+rw[5]: idx=7
            else: raise ValueError(f'Symbol value outside load extents: {val:x}')
            struct.pack_into('<H',b,off+14,idx)
            mapped+=1
    # Add names before writing final .shstrtab entry, then serialize new headers.
    names_off=len(b)
    nameoff=len(shnames)
    shnames.extend(b'.shstrtab\0')
    sh.append((nameoff,3,0,0,names_off,len(shnames),0,0,1,0))
    b.extend(shnames)
    b.extend(bytes((-len(b))%4))
    h[6]=len(b); h[11]=40; h[12]=len(sh); h[13]=len(sh)-1
    b.extend(b''.join(struct.pack('<IIIIIIIIII',*x) for x in sh))
    struct.pack_into('<16sHHIIIIIHHHHHH',b,0,*h)
    destination.write_bytes(b)
    assert source.read_bytes()==original
    details={'source':str(source),'source_sha256':hashlib.sha256(original).hexdigest(),
             'linker_only_copy':str(destination),'copy_sha256':hashlib.sha256(b).hexdigest(),
             'dynsym_count':nchain,'mapped_section_indices':mapped,
             'note':'Only ELF header/section metadata and symbol section indices changed; never install this linker-only copy in guest'}
    destination.with_suffix(destination.suffix+'.json').write_text(json.dumps(details,indent=2))
    return details

if __name__=='__main__':
    here=Path(__file__).resolve().parent
    print(json.dumps(restore(here.parent/'ifs-analysis/files/3221225508-boot_lib_libc.so.3',
                             here/'link-only-libc.so.3'),indent=2))

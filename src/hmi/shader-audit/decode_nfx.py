"""Read-only decoder transcribed from HmiMain3D 0x08d49cac..0x08d4a036.

No firmware modification or execution. Writes expanded copies beneath this audit.
"""
from pathlib import Path
import hashlib, json, struct, sys

HERE=Path(__file__).resolve().parent
VM=HERE.parent.parent

def decode_stream(src, expected):
    pos=0; bitbuf=0; previous_offset=1; out=bytearray()
    def byte():
        nonlocal pos
        if pos>=len(src):raise ValueError('Truncated source')
        b=src[pos];pos+=1;return b
    def bit():
        nonlocal bitbuf
        bitbuf=(bitbuf<<1)&0xffffffff
        if not bitbuf&0xff:bitbuf=byte()*2+1
        return bitbuf>>8&1
    while True:
        while bit():
            if len(out)>=expected:raise ValueError('Literal exceeds expected output')
            out.append(byte())
        offset=1
        while True:
            offset=(offset*2+bit())&0xffffffff
            if bit():break
            offset=(offset*2+bit()-2)&0xffffffff
        if offset==2:
            offset=previous_offset
            length=bit()
        else:
            offset=((offset-3)*256+byte())&0xffffffff
            if offset==0xffffffff:break
            length=int(not (offset&1))
            offset=(offset>>1)+1
            previous_offset=offset
        length=length*2+bit()
        if length==0:
            length=1
            while True:
                length=length*2+bit()
                if bit():break
            length+=2
        length+=int(offset>0x500)
        if not 0<offset<=len(out):raise ValueError(('Invalid lookback',offset,len(out)))
        if len(out)+length+1>expected:raise ValueError('Match exceeds expected output')
        for _ in range(length+1):out.append(out[-offset])
    assert pos==len(src),('trailing data',pos,len(src))
    assert len(out)==expected,('wrong expanded length',len(out),expected)
    return bytes(out)

def decode_nfx(b):
    assert b[:2]==b'ME'
    assert struct.unpack_from('>I',b,2)[0]==len(b)-6
    n=struct.unpack_from('<I',b,6)[0]
    assert 0<n<=128*1024*1024
    return decode_stream(b[10:],n)

def main():
    root=VM/'rootfs-staging/tree/opt/hmi/data/ro/bmw/scene'
    rows=[]
    for p in sorted(root.rglob('*.nfx')):
        b=p.read_bytes();out=decode_nfx(b)
        dest=HERE/'expanded'/p.relative_to(root);dest.parent.mkdir(parents=True,exist_ok=True);dest.write_bytes(out)
        row={'input':str(p),'output':str(dest),'compressed_size':len(b),'expanded_size':len(out),
             'input_sha256':hashlib.sha256(b).hexdigest(),'output_sha256':hashlib.sha256(out).hexdigest(),
             'NVuc_count':out.count(b'NVuc'),'void_main_count':out.count(b'void main')}
        rows.append(row);print(json.dumps(row))
    (HERE/'expanded-nfx.json').write_text(json.dumps(rows,indent=2))

if __name__=='__main__':main()

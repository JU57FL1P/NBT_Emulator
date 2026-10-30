"""Read-only HB LZO container decoder; source inputs are never modified."""
import argparse
import ctypes
import hashlib
import json
import os
import struct
import zlib
from pathlib import Path

def decode_hb_lzo(data, dll_path=None):
    if dll_path is None:
        dll_path=Path(os.environ.get('NBT_EMULATOR_QEMU',str(Path(__file__).resolve().parent.parent/'tools/qemu')))/'liblzo2-2.dll'
    dll_path=Path(dll_path).resolve()
    assert data[:8]==bytes.fromhex('00e94c5a4fff1aac'), 'Not HB LZO format'
    version,flags,method,level,blocksize,total=struct.unpack_from('<6I',data,8)
    assert version==1 and method==1 and flags==1
    assert 1024<=blocksize<=8*1024*1024 and 0<total<=1024*1024*1024
    directory=os.add_dll_directory(str(dll_path.parent))
    lib=ctypes.CDLL(str(dll_path))
    decode=lib.lzo1x_decompress_safe
    decode.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p,ctypes.POINTER(ctypes.c_size_t),ctypes.c_void_p]
    decode.restype=ctypes.c_int
    pos=32
    parts=[]
    seen=0
    while True:
        outlen=struct.unpack_from('>I',data,pos)[0];pos+=4
        if outlen==0:break
        inlen=struct.unpack_from('>I',data,pos)[0];pos+=4
        assert 0<inlen<=outlen<=blocksize and pos+inlen<=len(data)
        piece=data[pos:pos+inlen];pos+=inlen
        if inlen!=outlen:
            inp=ctypes.create_string_buffer(piece)
            dst=ctypes.create_string_buffer(outlen)
            n=ctypes.c_size_t(outlen)
            status=decode(inp,inlen,dst,ctypes.byref(n),None)
            assert status==0 and n.value==outlen,(status,n.value,outlen)
            piece=dst.raw[:n.value]
        seen+=len(piece)
        assert seen<=total
        parts.append(piece)
    result=b''.join(parts)
    assert len(result)==total
    stored_checksum=struct.unpack_from('>I',data,pos)[0];pos+=4
    assert zlib.adler32(result)&0xffffffff==stored_checksum
    assert pos==len(data),(pos,len(data))
    directory.close()
    return result

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--input',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    assert args.input.resolve()!=args.output.resolve()
    raw=args.input.read_bytes()
    decoded=decode_hb_lzo(raw)
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_bytes(decoded)
    print(json.dumps({'input_md5':hashlib.md5(raw).hexdigest(),'input_sha256':hashlib.sha256(raw).hexdigest(),
                      'output_sha256':hashlib.sha256(decoded).hexdigest(),'output_size':len(decoded),
                      'adler32_verified':True}))

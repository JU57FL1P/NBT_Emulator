"""Read-only parsing of original NBT IFS; outputs separate data for analysis.

Format references: public sys/image.h and dumpifs from askac/dumpifs; LZO block
framing confirmed against lclevy/dumpifs. No target executable is run.
"""
import ctypes
import hashlib
import json
import os
import re
import struct
from pathlib import Path

out = Path(__file__).resolve().parent
root = out.parent
source = root / 'images/nbt-intel-original.ifs'
blob = source.read_bytes()
assert hashlib.sha256(blob).hexdigest() == '034c2c37f60b86c40eb43e77636a8d84903ee77d1f2df250cdd9a98b134cfe8b'
assert blob[:4] == bytes.fromhex('eb7eff00') and blob[6] == 9
startup_size, stored_size, _, image_size = struct.unpack_from('<4I', blob, 0x20)
os.add_dll_directory(os.environ.get('NBT_EMULATOR_QEMU',str(root / 'tools/qemu')))
lzo = ctypes.CDLL(str(Path(os.environ.get('NBT_EMULATOR_QEMU',str(root/'tools/qemu')))/'liblzo2-2.dll'))
decode = lzo.lzo1x_decompress_safe
decode.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p]
decode.restype = ctypes.c_int
cursor = startup_size
blocks = []
parts = []
while True:
    n = struct.unpack_from('>H', blob, cursor)[0]
    cursor += 2
    if not n:
        break
    assert cursor + n <= stored_size
    src = ctypes.create_string_buffer(blob[cursor:cursor+n])
    dst = ctypes.create_string_buffer(65536)
    size = ctypes.c_size_t(65536)
    status = decode(src, n, dst, ctypes.byref(size), None)
    assert status == 0, (cursor, n, status)
    parts.append(dst.raw[:size.value])
    blocks.append({'offset': cursor, 'compressed': n, 'decompressed': size.value})
    cursor += n
image = b''.join(parts)
assert len(image) == image_size and image[:7] == b'imagefs'
(out / 'imagefs-decompressed.bin').write_bytes(image)
header = struct.unpack_from('<7sBIII4III40sI', image)
declared_size, hdr_dir_size, directory_offset = header[2:5]
assert declared_size == len(image)
script_inode = header[9]
entries = []
cursor = directory_offset

def zstr(data, start, end):
    return data[start:data.index(0, start, end)].decode('utf-8', errors='replace')

while cursor < hdr_dir_size:
    size, extattr, ino, mode, gid, uid, mtime = struct.unpack_from('<HH5I', image, cursor)
    if size == 0:
        break
    assert size >= 24 and cursor + size <= hdr_dir_size
    pos, end = cursor + 24, cursor + size
    kind = mode & 0xF000
    entry = {'inode': ino, 'kind': kind, 'mode': oct(mode), 'dir_offset': cursor}
    if kind == 0x8000:
        offset, length = struct.unpack_from('<II', image, pos)
        name = zstr(image, pos + 8, end)
        assert offset + length <= len(image)
        payload = image[offset:offset+length]
        entry.update(offset=offset, size=length, sha256=hashlib.sha256(payload).hexdigest(), elf=payload[:4] == b'\x7fELF')
        # Flatten extracted names; never create image-provided paths/symlinks.
        dest = out / 'files' / (str(ino) + '-' + name.replace('/', '_').replace('\\', '_'))
        dest.parent.mkdir(exist_ok=True)
        dest.write_bytes(payload)
        entry['local_file'] = dest.name
    elif kind == 0x4000:
        name = zstr(image, pos, end)
    elif kind == 0xA000:
        sym_offset, sym_size = struct.unpack_from('<HH', image, pos)
        name = zstr(image, pos + 4, end)
        entry['target'] = image[pos+4+sym_offset:pos+4+sym_offset+sym_size].rstrip(b'\0').decode('utf-8', errors='replace')
    else:
        name = zstr(image, pos + 8, end)
    entry['name'] = name
    entries.append(entry)
    cursor += size

scripts = []
for entry in entries:
    if entry['inode'] != script_inode or 'size' not in entry:
        continue
    script = image[entry['offset']:entry['offset']+entry['size']]
    pos = 0
    while pos + 4 <= len(script):
        size, typ, spare = struct.unpack_from('<HBB', script, pos)
        if size == 0:
            break
        assert pos + size <= len(script)
        data = script[pos:pos+size]
        row = {'offset': pos, 'type': typ, 'size': size}
        if typ == 0:
            values = data[12:].split(b'\0')
            argc, envc = data[10:12]
            row.update(command=values[0].decode(), argv=[x.decode() for x in values[1:1+argc]],
                       environment=[x.decode() for x in values[1+argc:1+argc+envc]], flags=data[5])
        elif typ in (1, 2):
            row.update(checks=struct.unpack_from('<H', data, 4)[0], path=data[6:].split(b'\0')[0].decode())
        else:
            row['strings'] = [x.decode(errors='replace') for x in data[4:].split(b'\0') if x]
        scripts.append(row)
        pos += size

doc = {'source_sha256': hashlib.sha256(blob).hexdigest(), 'image_size': len(image),
       'image_word_sum': hex(sum(struct.unpack('<'+'I'*(len(image)//4), image)) & 0xffffffff),
       'block_count': len(blocks), 'script_inode': script_inode, 'entries': entries, 'script': scripts}
(out / 'ifs-files.json').write_text(json.dumps(doc, indent=2))
(out / 'boot-script.json').write_text(json.dumps(scripts, indent=2))
(out / 'file-list.txt').write_text('\n'.join(f"{e['name']}  {e.get('size', '')}  {e.get('target', '')}" for e in entries))
print(json.dumps({k:v for k,v in doc.items() if k not in ('entries','script')}))
print((out / 'file-list.txt').read_text())
print(json.dumps(scripts, indent=2))

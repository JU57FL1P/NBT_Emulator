"""Append owned mount to a separate VM-only IFS; preserve working shell image."""
from pathlib import Path
import hashlib, json, struct, ast

root = Path(__file__).resolve().parent
source = root/'nbt-qnx-minimal-shell-uncompressed.ifs'
blob = source.read_bytes()
assert hashlib.sha256(blob).hexdigest() == '6752a54c96f12cd0b1e17ab3aa917f52f33572fe6a91439ca5c028046b84adda'
mount_path = root.parent/'rootfs-staging/tree/bin/mount'
mount = mount_path.read_bytes()
assert mount[:4] == b'\x7fELF'
startup_size = struct.unpack_from('<I',blob,32)[0]
startup = bytearray(blob[:startup_size])
image = bytearray(blob[startup_size:-4])
meta = json.loads((root.parent/'ifs-analysis/ifs-files.json').read_text())
slot = next(e for e in meta['entries'] if e['name'] == 'boot/bin/msr-read')
new_offset = ((startup_size+len(image)+4095)&~4095)-startup_size
image += bytes(new_offset-len(image))+mount
image += bytes((-len(image))%4)
d = slot['dir_offset']
size = struct.unpack_from('<H',image,d)[0]
name = b'boot/bin/mount\0'
assert len(name) <= size-32
struct.pack_into('<I',image,d+4,slot['inode']&0x1fffffff)
struct.pack_into('<II',image,d+24,new_offset,len(mount))
image[d+32:d+size] = name.ljust(size-32,b'\0')
def checksum(data):
    return sum(struct.unpack('<'+'I'*(len(data)//4),data))&0xffffffff
image += bytes(4)
struct.pack_into('<I',image,8,len(image))
struct.pack_into('<I',image,len(image)-4,(-checksum(image))&0xffffffff)
total = startup_size+len(image)
struct.pack_into('<I',startup,28,total)
struct.pack_into('<I',startup,36,total)
struct.pack_into('<I',startup,44,len(image))
struct.pack_into('<I',startup,startup_size-4,0)
struct.pack_into('<I',startup,startup_size-4,(-checksum(startup))&0xffffffff)
assert checksum(startup)==checksum(image)==0
for e in meta['entries']:
    if 'offset' in e:
        start,end = e['offset'],e['offset']+e['size']
        assert image[start:end] == blob[startup_size+start:startup_size+end],e['name']
result = bytes(startup)+bytes(image)
target = root/'nbt-qnx-minimal-mount-uncompressed.ifs'
target.write_bytes(result)
report = {'purpose':'VM-only shell plus mount; not vehicle firmware or full iDrive',
          'source':str(source),'source_sha256':hashlib.sha256(blob).hexdigest(),
          'path':str(target),'sha256':hashlib.sha256(result).hexdigest(),'size':len(result),
          'mount_source':str(mount_path),'mount_size':len(mount),
          'mount_sha256':hashlib.sha256(mount).hexdigest(),
          'mount_imagefs_offset':new_offset,'mount_processed_elf':False,
          'reused_directory_slot':'boot/bin/msr-read','script_unchanged':True,
          'all_existing_payloads_unchanged':True,'checksums_valid':True,
          'runtime_status':'Not yet booted; invoke /boot/bin/mount manually after shell ready'}
(root/'minimal-mount-build.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))

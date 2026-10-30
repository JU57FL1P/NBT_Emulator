"""Build a read-only, nonbootable QNX ImageFS from VM runtime staging.

All ELF files stay unprocessed and are loaded normally by the guest loader.
No host symlinks/devices are created. No source firmware file is changed.
"""
from pathlib import Path, PurePosixPath
import array
import argparse
import hashlib
import json
import struct

base = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--subset', choices=['full', 'core', 'hmi-images'], default='full')
args = parser.parse_args()
stage = base/'rootfs-staging'
entries = json.loads((stage/'runtime-manifest.json').read_text())
large_images = {'opt/hmi/data/ro/bmw/db/images-vehicle.db',
                'opt/hmi/data/ro/common/db/images.db'}
if args.subset == 'core':
    prefixes = ('bin/', 'lib/', 'etc/', 'opt/sys/', 'opt/hmi/bin/', 'opt/hmi/lib/',
                'opt/hmi/otf/', 'opt/hmi/data/', 'opt/car/bin/', 'opt/car/lib/',
                'opt/car/etc/', 'opt/mm/lib/')
    entries = [e for e in entries if e['path'].startswith(prefixes) and e['path'] not in large_images]
elif args.subset == 'hmi-images':
    entries = [e for e in entries if e['path'] in large_images]
dir_meta = json.loads((stage/'directory-metadata.json').read_text())
suffix = '' if args.subset == 'full' else '-'+args.subset
image_path = stage/('nbt-runtime'+suffix+'.ifs')
physical = 0x50000000 if args.subset == 'hmi-images' else 0x40000000
records = []
paths = {e['path'] for e in entries}
assert len(paths) == len(entries)
dirs = {''}
for e in entries:
    p = PurePosixPath(e['path'])
    assert not p.is_absolute() and '..' not in p.parts
    for parent in p.parents:
        dirs.add('' if str(parent) == '.' else str(parent))
assert not (paths & dirs)

def align(n, boundary=4):
    return (n+boundary-1) & ~(boundary-1)

def attrs(size, inode, mode, uid=0, gid=0):
    return struct.pack('<HHIIIII', size, 0, inode, mode, gid, uid, 0)

inode = 1
for name in sorted(dirs, key=lambda n: (n.count('/'), n)):
    encoded = name.encode('ascii')+b'\0'
    size = align(24+len(encoded))
    meta = dir_meta.get(name, {})
    mode = int(meta.get('mod', '755'), 8) | 0o40000
    body = attrs(size, inode, mode, int(meta.get('uid', 0)), int(meta.get('gid', 0))) + encoded
    records.append(bytearray(body.ljust(size, b'\0')))
    inode += 1
file_records = []
for entry in sorted(entries, key=lambda e: e['path']):
    encoded = entry['path'].encode('ascii')+b'\0'
    size = align(32+len(encoded))
    body = attrs(size, inode, entry['mode'] | 0o100000, entry['uid'], entry['gid'])
    body += struct.pack('<II', 0, entry['size']) + encoded
    record = bytearray(body.ljust(size, b'\0'))
    records.append(record)
    file_records.append((entry, record))
    inode += 1

header = bytearray(88)
header[:8] = b'imagefs\x06'  # read-only, inode flag bits valid, little endian
header += b'/fs/sda0\0'
header += bytes(align(len(header))-len(header))
directory_offset = len(header)
directory_size = sum(len(r) for r in records)+4
directory_end = directory_offset+directory_size
position = align(directory_end, 4096)
for entry, record in file_records:
    struct.pack_into('<I', record, 24, position)
    entry['ifs_offset'] = position
    position = align(position+entry['size'], 4096)
image_size = align(position+4, 4096)
assert image_size < 0x40000000, f'Image exceeds reserved 1 GiB: {image_size}'
if args.subset != 'full':
    assert image_size < 0x10000000, 'Subset image must fit its separate 256 MiB slot'
struct.pack_into('<III', header, 8, image_size, directory_end, directory_offset)
total_sum = 0
def add_sum(data):
    global total_sum
    data += bytes((-len(data)) % 4)
    values = array.array('I')
    values.frombytes(data)
    total_sum = (total_sum+sum(values)) & 0xffffffff

with image_path.open('wb') as output:
    output.write(header)
    add_sum(header)
    for record in records:
        output.write(record)
        add_sum(record)
    output.write(bytes(4))
    for entry, record in file_records:
        target = entry['ifs_offset']
        assert output.tell() <= target
        output.write(bytes(target-output.tell()))
        sha = hashlib.sha256()
        with (stage/'tree'/entry['path']).open('rb') as source:
            while True:
                blob = source.read(1024*1024)
                if not blob:
                    break
                output.write(blob)
                sha.update(blob)
                add_sum(blob)
        assert sha.hexdigest() == entry['sha256'], ('Staging changed', entry['path'])
        assert output.tell() == target+entry['size']
    assert output.tell() <= image_size-4
    output.write(bytes(image_size-4-output.tell()))
    output.write(struct.pack('<I', (-total_sum) & 0xffffffff))

# Independently read the complete finished image for hash and checksum.
sha = hashlib.sha256()
verify_sum = 0
with image_path.open('rb') as check:
    while True:
        block = check.read(1024*1024)
        if not block:
            break
        sha.update(block)
        vals = array.array('I')
        vals.frombytes(block)
        verify_sum = (verify_sum+sum(vals)) & 0xffffffff
assert verify_sum == 0
report = {'image': str(image_path), 'image_bytes': image_size, 'image_sha256': sha.hexdigest(),
          'checksum_sum': verify_sum, 'files': len(file_records), 'directories': len(dirs),
          'elf_processed': False, 'subset': args.subset, 'mountpoint': '/fs/sda0', 'physical_address': hex(physical),
          'reserved_bytes': 0x40000000, 'mount_command':
          f'/boot/bin/mount -tifs -o offset=0x{physical:x},size=0x{image_size:x} /dev/mem /fs/sda0',
          'source_scope': 'Matching owned factory runtime payloads; credential files excluded',
          'runtime_status': 'Built and statically verified; not yet guest mounted'}
(stage/('secondary-ifs'+suffix+'.json')).write_text(json.dumps(report, indent=2))
(stage/('secondary-file-layout'+suffix+'.json')).write_text(json.dumps(entries, indent=2))
print(json.dumps(report, indent=2))

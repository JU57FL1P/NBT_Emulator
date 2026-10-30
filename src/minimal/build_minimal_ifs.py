"""Build an experimental VM-only QNX serial-shell IFS from owned NBT files.

Not a vehicle update or full iDrive image. Original startup/kernel and existing
processed-ELF positions are retained. The stock hardware init is not run.
QNX sys/image.h defines records and flags; see ../ifs-analysis/image.h.
"""
import hashlib
import json
import struct
from pathlib import Path

out = Path(__file__).resolve().parent
root = out.parent
original = (root / 'images/nbt-intel-original.ifs').read_bytes()
original_hash = hashlib.sha256(original).hexdigest()
assert original_hash == '034c2c37f60b86c40eb43e77636a8d84903ee77d1f2df250cdd9a98b134cfe8b'
analysis = root / 'ifs-analysis'
original_fs = (analysis / 'imagefs-decompressed.bin').read_bytes()
meta = json.loads((analysis / 'ifs-files.json').read_text())
assert meta['source_sha256'] == original_hash
assert original_fs[:7] == b'imagefs'

def checksum(data):
    assert len(data) % 4 == 0
    return sum(struct.unpack('<'+'I'*(len(data)//4), data)) & 0xffffffff

assert checksum(original_fs) == 0
startup_size = struct.unpack_from('<I', original, 32)[0]
assert startup_size == 105816
startup = bytearray(original[:startup_size])
assert checksum(startup) == 0
image = bytearray(original_fs[:-4]) # replace the final checksum after extension
byname = {e['name']: e for e in meta['entries']}
script_entry = byname['proc/boot/.startupscript']
sysinit_entry = byname['boot/bin/sysinit']
kernel_entry = byname['proc/boot/procnto-smp-instr']
ksh = (analysis / 'runtime-assets/ksh').read_bytes()
assets = json.loads((analysis / 'runtime-assets.json').read_text())
expected_ksh_hash = next(r['sha256'] for r in assets if r['name'] == 'ksh')
assert hashlib.sha256(ksh).hexdigest() == expected_ksh_hash

def strings(values):
    return b''.join(value.encode('ascii') + b'\0' for value in values)

def record(kind, payload):
    size = (4 + len(payload) + 3) & ~3
    return struct.pack('<HBB', size, kind, 0) + payload + bytes(size-4-len(payload))

env = ['PATH=/boot/bin:/proc/boot', 'LD_LIBRARY_PATH=/boot/lib', 'HOME=/', 'TERM=ansi', 'PS1=NBTVM> ']
def external(path, argv, flags=0):
    # cpu, flags, two ext-scheduler bytes, policy, priority, argc, envc.
    body = bytes([0, flags, 0, 0, 0, 10, len(argv), len(env)])
    return record(0, body + strings([path] + argv + env))

script = record(3, strings(['NBT experimental VM-only QNX shell test\n']))
script += external('/boot/bin/devc-ser8250',
                   ['devc-ser8250', '-e', '-S', '-F', '-b115200', '3f8,4'], 0x20)
script += record(1, struct.pack('<H', 50) + strings(['/dev/ser1']))
script += record(4, strings(['/dev/ser1', '/dev/console']))
script += record(2, struct.pack('<H', 50) + strings(['/dev/ser1']))
script += record(3, strings(['NBT_VM_CONSOLE_READY\n']))
script += external('/boot/bin/ksh', ['ksh', '-c',
    'echo NBT_VM_SHELL_READY; /boot/bin/pidin info; /boot/bin/ls /proc/boot; exec /boot/bin/ksh -i'], 0x02)
script += b'\0\0\0\0'
assert len(script) <= script_entry['size'], (len(script), script_entry['size'])
script_position = script_entry['offset']
image[script_position:script_position+script_entry['size']] = script.ljust(script_entry['size'], b'\0')

# Preserve all original payload positions. The old sysinit bytes remain inert;
# only its existing directory slot changes to the new /boot/bin/ksh file.
new_offset = ((startup_size + len(image) + 4095) & ~4095) - startup_size
assert (0x200000 + startup_size + new_offset) % 4096 == 0
image += bytes(new_offset - len(image)) + ksh
image += bytes((-len(image)) % 4)
directory_pos = sysinit_entry['dir_offset']
directory_size = struct.unpack_from('<H', image, directory_pos)[0]
name = b'boot/bin/ksh\0'
assert len(name) <= directory_size - 32
struct.pack_into('<I', image, directory_pos+4, sysinit_entry['inode'] & 0x1fffffff)
struct.pack_into('<II', image, directory_pos+24, new_offset, len(ksh))
image[directory_pos+32:directory_pos+directory_size] = name.ljust(directory_size-32, b'\0')
image += bytes(4)
struct.pack_into('<I', image, 8, len(image))
struct.pack_into('<I', image, len(image)-4, (-checksum(image)) & 0xffffffff)
assert checksum(image) == 0

# Uncompressed, same startup placement/entry. The VM loader must copy this
# entire uncompressed image to physical 0x200000 before entering startup.
startup[6] &= ~0x1c
total = startup_size + len(image)
struct.pack_into('<I', startup, 28, total)       # ram_size
struct.pack_into('<I', startup, 36, total)       # stored_size
struct.pack_into('<I', startup, 40, 0)           # imagefs_paddr: loader supplies it
struct.pack_into('<I', startup, 44, len(image))  # imagefs_size
struct.pack_into('<I', startup, startup_size-4, 0)
struct.pack_into('<I', startup, startup_size-4, (-checksum(startup)) & 0xffffffff)
assert checksum(startup) == 0
result = bytes(startup) + bytes(image)
assert len(result) == total

# Every existing payload except the intentionally rewritten startup script
# remains byte-identical and at the same ImageFS offset, including kernel/libc.
preserved = []
for entry in meta['entries']:
    if 'offset' not in entry or entry['name'] == 'proc/boot/.startupscript':
        continue
    a, b = entry['offset'], entry['offset'] + entry['size']
    assert image[a:b] == original_fs[a:b], entry['name']
    preserved.append(entry['name'])
target = out / 'nbt-qnx-minimal-shell-uncompressed.ifs'
target.write_bytes(result)
manifest = {
    'purpose': 'Experimental PC VM serial-shell test; not full iDrive; never install on NBT',
    'path': str(target), 'sha256': hashlib.sha256(result).hexdigest(), 'size': total,
    'original_sha256': original_hash, 'startup_size': startup_size,
    'startup_entry': hex(struct.unpack_from('<I', startup, 12)[0]),
    'required_load_address': '0x200000', 'compression': 'none',
    'imagefs_size': len(image), 'ksh_offset_in_imagefs': new_offset,
    'ksh_processed_elf_flag': False, 'script_bytes': len(script),
    'startup_checksum_sum': checksum(startup), 'imagefs_checksum_sum': checksum(image),
    'kernel_offset_unchanged': kernel_entry['offset'], 'preserved_payloads': preserved,
    'runtime_status': 'Unexecuted when built; requires compatible startup hardware configuration'
}
(out/'minimal-build.json').write_text(json.dumps(manifest, indent=2))
(out/'minimal-startupscript.bin').write_bytes(script)
print(json.dumps({k:v for k,v in manifest.items() if k != 'preserved_payloads'}))

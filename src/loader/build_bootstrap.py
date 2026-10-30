"""Build a VM-only boot floppy; preserve exact source firmware bytes."""
from pathlib import Path
import argparse, hashlib, json, struct, subprocess

parser = argparse.ArgumentParser()
parser.add_argument('--nasm', required=True, type=Path)
parser.add_argument('--ifs', type=Path, default=Path(__file__).resolve().parents[1] / 'images/nbt-intel-original.ifs')
parser.add_argument('--single-cpu', action='store_true', help='VM-only RAM argument adaptation: -P2 becomes -P1')
parser.add_argument('--qemu-clocks', action='store_true', help='RAM clock data for QEMU TCG icount nanosecond clock only')
parser.add_argument('--tsc-hz',type=int,default=1000000000,help='Explicit virtual CPU/TSC Hz; default is TCG icount nanoseconds')
parser.add_argument('--rootfs-reserve', action='store_true', help='RAM startup -r argument reserves 1 GiB at 0x40000000 for a secondary IFS')
parser.add_argument('--expected-sha256', help='Required exact hash for a separately authored VM image')
parser.add_argument('--output-stem', default=None, help='Simple output stem, e.g. nbt-minimal-singlecpu')
args = parser.parse_args()
root = Path(__file__).resolve().parent
blob = args.ifs.read_bytes()
original_hash = '034c2c37f60b86c40eb43e77636a8d84903ee77d1f2df250cdd9a98b134cfe8b'
expected = args.expected_sha256 or original_hash
assert len(expected) == 64 and all(c in '0123456789abcdef' for c in expected)
assert hashlib.sha256(blob).hexdigest() == expected, 'Unexpected IFS: refuse guessed boot parameters'
assert struct.unpack_from('<I', blob, 0)[0] == 0x00ff7eeb
assert struct.unpack_from('<H', blob, 10)[0] == 3
entry = struct.unpack_from('<I', blob, 12)[0]
destination = struct.unpack_from('<I', blob, 24)[0]
startup_size = struct.unpack_from('<I', blob, 32)[0]
assert destination == 0x200000 and entry == 0x209410 and startup_size == 105816
source = 0x01000000
compressed = bool(blob[6] & 0x1c)
stored_size = struct.unpack_from('<I', blob, 36)[0]
assert startup_size <= stored_size <= len(blob)
copy_size = startup_size if compressed else stored_size
assert destination + copy_size < source, 'Copy destination must not overlap source'
runtime_source = source if compressed else destination
assert not args.qemu_clocks or args.single_cpu, 'Clock profile requires --single-cpu'
assert args.qemu_clocks or args.tsc_hz==1000000000
assert 1000000<=args.tsc_hz<=4000000000
assert args.tsc_hz==1000000000 or args.output_stem, 'Use a separate profile for a host TSC clock'
assert not args.rootfs_reserve or args.qemu_clocks, 'Rootfs profile requires --qemu-clocks'
stem = args.output_stem or ('nbt-bootstrap-qemuclocks' if args.qemu_clocks else ('nbt-bootstrap-singlecpu' if args.single_cpu else 'nbt-bootstrap'))
if args.rootfs_reserve and not args.output_stem:
    stem += '-rootfs'
assert stem and all(c.isalnum() or c in '-_' for c in stem), 'Use a simple output stem'
if expected != original_hash:
    assert args.output_stem, 'A separate VM image requires a distinct output stem'
sector = root / (stem + '.bin')
defines = []
patches = []
clock_seeds = []
if args.qemu_clocks:
    for addr in [0x219c10, 0x219bcc, 0x219b70]:
        assert struct.unpack_from('<I', blob, addr - destination)[0] == 0
        clock_seeds.append({'ram_address':hex(addr), 'before':0, 'after_hz':1000000000 if addr==0x219b70 else args.tsc_hz})
    defines.append('-DQEMU_CLOCKS=1')
    defines.append(f'-DQEMU_TSC_HZ={args.tsc_hz}')
if args.single_cpu:
    match = blob.find(b'startup-ids02\0-P2\0')
    assert match == 0x9460
    offset = match + len(b'startup-ids02\0-P')
    assert offset == 0x9470 and blob[offset] == ord('2')
    defines.append(f'-DSINGLE_CPU_PATCH={offset}')
    patches.append({'ram_address':hex(destination + offset), 'before':'2', 'after':'1',
                    'meaning':'startup argument -P2 to -P1; documented maximum CPU count'})
if args.rootfs_reserve:
    argument = b'-r0x40000000,0M,1\0'
    match = blob.find(argument)
    assert match == 0x9478, 'Unexpected reserve argument; no guessed offset patch'
    offset = match + len(b'-r0x40000000,')
    assert blob[offset:offset+2] == b'0M'
    defines.append(f'-DROOTFS_RESERVE_PATCH={offset}')
    patches.append({'ram_address':hex(destination + offset), 'before':'0M', 'after':'1G',
                    'meaning':'startup -r retains 1 GiB at physical 0x40000000 for secondary IFS'})
subprocess.run([str(args.nasm), '-f', 'bin', str(root / 'nbt_bootstrap.asm'),
                f'-DIFS_SOURCE={source}', f'-DIFS_DEST={destination}',
                f'-DIFS_ENTRY={entry}', f'-DSTARTUP_SIZE={startup_size}',
                f'-DCOPY_SIZE={copy_size}', f'-DRUNTIME_IMAGE_SOURCE={runtime_source}',
                *defines, '-l', str(root / (stem + '.lst')), '-o', str(sector)], check=True)
data = sector.read_bytes()
assert len(data) == 512 and data[510:] == b'\x55\xaa'
floppy = root / (stem + '-floppy.img')
floppy.write_bytes(data + bytes(1474560 - len(data)))
assert hashlib.sha256(args.ifs.read_bytes()).hexdigest() == expected
metadata = {'ifs_sha256':expected, 'ifs_preload_address':hex(source),
            'compressed_input':compressed, 'copy_size':copy_size,
            'runtime_image_source':hex(runtime_source),
            'runtime_image_paddr':hex(destination),
            'runtime_imagefs_paddr':hex(runtime_source + startup_size),
            'ram_argument_patches':patches,
            'ram_clock_seeds':clock_seeds,
            'secondary_ifs_reservation':({'base':'0x40000000', 'bytes':1073741824,
                                         'recommended_guest_ram_mb':2304,
                                         'required_max_secondary_ifs_bytes':1073741824}
                                        if args.rootfs_reserve else None),
            'required_clock_arguments':((['-accel','tcg,thread=single','-smp','1','-icount','shift=0,align=off,sleep=off'] if args.tsc_hz==1000000000 else ['-accel','whpx','-machine','pc,kernel-irqchip=off','-smp','1']) if args.qemu_clocks else []),
            'startup_copy_destination':hex(destination), 'startup_entry':hex(entry),
            'startup_size':startup_size, 'bootstrap_sha256':hashlib.sha256(data).hexdigest(),
            'floppy_sha256':hashlib.sha256(floppy.read_bytes()).hexdigest(),
            'assumptions':['32-bit protected mode with flat segments',
                           'BIOS E820 memory map supplied using Multiboot v1 EAX/EBX ABI',
                           'One actual E820 usable range translated to standard QNX startup_info_mem',
                           'No proprietary board-specific boot information supplied',
                           'Only RAM copy header image/imagefs fields and info area populated',
                           'VM-only diagnostic experiment; full NBT/iDrive emulation is not established']}
(root / (stem + '-build.json')).write_text(json.dumps(metadata, indent=2))
print(json.dumps(metadata, indent=2))

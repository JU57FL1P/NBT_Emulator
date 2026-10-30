# NBT Emulator

A firmware-based virtual machine for **regular BMW NBT**, with the original
QNX operating system and native `HmiMain3D` interface. The project supplies
the PC bootstrap, graphics bridge, controller delivery and display viewer.

The source distribution contains no firmware, extracted BMW assets, game ROMs,
third-party executables, or application modifications. Users supply their own
matching firmware and external dependencies. It does not need E-Sys, a car
connection, SSH access, or a running copy of the original development project.

## What works

- Booting the original QNX 6.5 i386 kernel under QEMU.
- Rendering the native NBT interface through an ANGLE GLES2 bridge.
- English main-menu labels, rotary navigation, Enter, Back, Menu and Options.
- Native menu navigation such as Settings and Time/date.
- A separate Windows display window and console; all guest writes use RAM disks.
- WHPX acceleration on a host with verified guest clock calibration, and TCG
  fallback with a guest clock independent of the host's TSC frequency.

This is **a working NBT interface VM, not complete head-unit hardware
emulation**. Vehicle ECUs, physical MOST devices, the DSP/amplifier, navigation
services and phone/USB hardware are not fully reproduced. Menus that need those
devices can be unavailable. Transitions are slower than hardware, and some
views can show rendering/layout differences. There is no guarantee that every
factory screen or vehicle feature works.

Run one NBT VM at a time while validating a host. Concurrent WHPX instances
have not been validated; an initial background/concurrent test stopped before
its first frame. The isolated interactive run passed the menu checks above.

## Supported firmware

**All four original binary packages below are required.** They are not
included in this repository. Keep their exact filenames and versions.

| Required firmware file | Used for |
| --- | --- |
| `btld_00001275.bin.003_013_001` | Intel QNX boot image and base runtime files, including the shell. |
| `swfl_00001280.bin.003_013_001` | Matching NBT HMI package and resources. |
| `swfl_00001e6b.bin.003_013_001` | Supporting native services and libraries used by the runtime. |
| `swfl_000021d2.bin.003_013_001` | HMI Common, including the compressed `HmiMain3D` executable. |

Supply these from your own firmware collection. A vehicle coding backup
(`SVT.xml`, FA or CAFD data) does not contain the executable/runtime payloads
needed to boot this VM. A map update or a single `HmiMain3D` file is also
insufficient for the current preparer.

For example, `--firmware-dir C:\Firmware\psdzdata` accepts this layout:

```text
C:\Firmware\psdzdata\
  swe\
    btld\
      btld_00001275.bin.003_013_001
    swfl\
      swfl_00001280.bin.003_013_001
      swfl_00001e6b.bin.003_013_001
      swfl_000021d2.bin.003_013_001
```

Alternatively, put all four files directly inside the directory passed to
`--firmware-dir`. The preparer also accepts `btld` and `swfl` immediately
beneath that directory. It does not search arbitrary nested directories or
download missing firmware.

Preparation verifies factory file checksums and this decoded HMI SHA-256:

```
554b67d4d6317cfb1715d544874fae8ddd2c975be503c9e2514e2dc2f3a0d693
```

NBT EVO and other HMI versions require separate ABI work. A newer integration
level string alone does not establish compatibility.

## Requirements

- Windows x64, **64-bit Python 3.11 or newer** with Tk, and
  `python -m pip install -r requirements.txt`.
- A compatible Windows QEMU installation with both `qemu-system-x86_64.exe`
  and `qemu-system-i386.exe`, its DLLs and `share` directory. Preparation also
  uses its `liblzo2-2.dll` to decode the supplied firmware.
- LLVM tools: `clang.exe`, `ld.lld.exe`, `llvm-readobj.exe`, `llvm-objdump.exe`.
- NASM (`nasm.exe`).
- A compatible ANGLE D3D11 directory containing `libEGL.dll` and
  `libGLESv2.dll`, plus their dependencies. These are supplied locally; the
  repository does not fetch an arbitrary application or DLL package.
- At least 2304 MiB available guest memory, plus host/rendering overhead.
  Allow several GiB of disk space for the private extracted runtime.

Use the upstream QEMU, LLVM, NASM and ANGLE projects to obtain/build the tools.
The runtime was developed with QEMU 11.1.0 (v11.1.0-12130-ge470268ff4),
Clang/LLD 20 and NASM 3.02. Other versions should be tested before assuming
equivalent boot, clock or rendering behavior.

### Exact external tool files

The paths below are examples. Pass your actual installation paths to
`prepare.py`. Preserve dependency DLLs from each tool's installation; copying
only an EXE can leave it unable to start.

| Argument / component | Required files or directories | When needed |
| --- | --- | --- |
| Python | `python.exe`, Tk support, and the Pillow package from `requirements.txt`. `pythonw.exe` is used for the viewer when present. | Preparation and running. |
| `--qemu-dir C:\Tools\qemu` | `qemu-system-x86_64.exe`, `qemu-system-i386.exe`, `liblzo2-2.dll`, the QEMU dependency DLLs, and `share\` containing the PC BIOS/VGA ROM files. | Preparation; a runtime copy is made for running. |
| `--angle-dir C:\Tools\angle` | Matching **x64** `libEGL.dll` and `libGLESv2.dll` from the same ANGLE build, plus any required dependency DLLs. | A runtime copy is made for rendering. |
| `--llvm-bin C:\Tools\llvm\bin` | `clang.exe`, `ld.lld.exe`, `llvm-readobj.exe`, `llvm-objdump.exe`, and their installation dependencies. | Preparation/rebuilding only. |
| `--nasm C:\Tools\nasm\nasm.exe` | `nasm.exe`. This argument names the executable, not its directory. | Preparation/rebuilding only. |

The QEMU layout expected by this project includes, for example:

```text
C:\Tools\qemu\
  qemu-system-x86_64.exe
  qemu-system-i386.exe
  liblzo2-2.dll
  ... other QEMU dependency DLLs ...
  share\
    bios-256k.bin
    vgabios-stdvga.bin
    ... remaining machine firmware files ...
```

Keep the complete compatible `share` directory. If your QEMU distribution puts
these files elsewhere, arrange the directory above before preparing, since
the runner passes `tools\qemu\share` as QEMU's machine-firmware directory.

The preparer also copies `d3dcompiler_47.dll`, `dxcompiler.dll` and `dxil.dll`
from the supplied ANGLE directory **if present**. These are build-dependent
dependencies, not a requirement to download all three separately. The tested
renderer uses ANGLE D3D11 WARP. There is no GPU passthrough setup to perform.

A separate QNX SDK is not used by this build: the bridge uses the matching
firmware libraries and the authored ABI declarations in `src`.

## Prepare your private runtime

Keep the runtime **outside this repository**. For example, put this repository
in `C:\NBT\nbt-emulator` and use `C:\NBT\NBT-Emulator-Private` for generated
files. The script refuses a runtime path inside the repository.

From the repository directory, with your own firmware and dependency paths:

```powershell
python -m pip install -r requirements.txt
python prepare.py `
  --firmware-dir C:\Firmware\psdzdata `
  --runtime C:\NBT\NBT-Emulator-Private `
  --qemu-dir C:\Tools\qemu `
  --angle-dir C:\Tools\angle `
  --llvm-bin C:\Tools\llvm\bin `
  --nasm C:\Tools\nasm\nasm.exe
```

The backticks above are PowerShell line continuations. Run this command from
the extracted source folder containing `prepare.py`, and quote paths that
contain spaces. Preparation must finish successfully before using `Start.cmd`.

The firmware directory can contain the four files directly or use the usual
`swe\btld` and `swe\swfl` subdirectories. Preparation reads them as data; it
does not flash hardware or execute extracted programs on Windows. It extracts
factory files, builds the VM boot/runtime images, extracts paired original
shader sources, compiles the authored bridge, and checks the resulting inputs.
Its log and generated binaries remain in the private runtime directory.

### What preparation creates

Keep the generated private directory together; the boot images alone do not
contain everything the Windows renderer needs.

| Private output | Purpose |
| --- | --- |
| `runtime.json` | Preparation result, Python location and default CPU mode used by the launcher. |
| `minimal\nbt-qnx-minimal-mount-uncompressed.ifs` | Guest QNX boot image. |
| `loader\nbt-minimal-mount-tcg-floppy.img`, `loader\nbt-minimal-mount-whpx-floppy.img` | PC bootstrap images for the two CPU modes. |
| `rootfs-staging\nbt-runtime-core.ifs` | Extracted native runtime, applications and supporting files. |
| `rootfs-staging\nbt-runtime-hmi-images.ifs` | Native HMI image databases. |
| `graphics-bridge\nbt-bridge.ifs` | Authored graphics/input bridge and WHPX tick helper. |
| `rootfs-staging\tree\...\common\shader\`, `hmi\shader-audit\` | Extracted original shader sources and their generated mapping catalog. |
| `tools\qemu\`, `tools\angle\` | Private copies of the supplied runtime dependencies. |
| `profile-*.json`, `setup-*.txt`, Python helper files | VM launch settings, guest setup and host renderer/viewer. |

After successful preparation, normal running uses this private directory and
the recorded Python environment. It does not reread the four input firmware
packages or invoke LLVM/NASM. Retain those inputs if you want to rebuild.

Generated catalogs contain absolute paths. If you move the private runtime,
change the Python installation, or prepare for another computer, run preparation
again for the new paths rather than copying a few generated files by hand.

Without additional configuration, the prepared launcher uses slower TCG.
For WHPX, enable Windows Hypervisor Platform and determine the guest TSC
frequency on the host. Pass that measured value as `--whpx-tsc-hz NUMBER`
when preparing. The development host was calibrated at `1800000000`; that
number is **host-specific**. Verify guest clock progression and sleeps against
wall time before using a different host's WHPX profile. This project does not
automatically change Windows features or security settings.

## Run

Double-click **Start.cmd**, or run:

```powershell
python nbt_emulator.py check --runtime C:\NBT\NBT-Emulator-Private
python nbt_emulator.py run --runtime C:\NBT\NBT-Emulator-Private
```

`Start.cmd` defaults to a sibling directory named `NBT-Emulator-Private`.
Override it with `Start.cmd -Runtime C:\Your\PrivateRuntime`.
The prepared runtime records the Python used for preparation, so the Windows
launcher does not depend on a hardcoded developer installation path.

Use `--software` (or `Start.cmd -Software`) to force TCG. Use `--hardware`
only after preparing a WHPX profile with the correct host TSC frequency.

Click the viewer for keyboard focus. Page Up/Page Down rotate the controller;
Enter selects, Escape goes back, `M` opens the main menu, and `O` opens Options.
The viewer also supplies buttons. Type `:quit` in the VM console to stop it.
Closing the display alone leaves the VM running. Running the launcher again
requests the existing display rather than starting a second VM for that runtime.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `Missing supported firmware package` | All four exact filenames are present in one of the accepted layouts. Renaming a different firmware version does not make it compatible. |
| `Missing external dependency` | The supplied argument points to the right directory/file and contains the named EXE or DLL. Keep its supporting DLLs too. |
| QEMU cannot load a PC BIOS | The copied QEMU `share` directory contains `bios-256k.bin` and the remaining machine ROM files. |
| `Unsupported HMI image` or a checksum mismatch | Use the supported package set. Do not disable the version/hash checks to run an unknown HMI binary. |
| `Runtime missing` / `Prepare a private runtime first` | Preparation completed, and the runtime path is the same one supplied when launching. |
| Python moved | Re-run preparation with the Python environment you will use to run the emulator. |
| Blank display | Allow initial shader compilation; then inspect the latest run's renderer and QEMU logs. Check that the ANGLE DLLs are a matching x64 set. |
| Very slow transitions | TCG is the default portable fallback. WHPX requires the Windows feature and a verified host-specific TSC frequency, as described above. |
| WHPX unavailable or timing is wrong | Launch with `Start.cmd -Software`; do not reuse another computer's TSC value without verification. |

Preparation failures are recorded in `NBT-Emulator-Private\prepare.log`.
Run logs are under `NBT-Emulator-Private\logs\console-<timestamp>\`:

- `stderr.txt`: QEMU diagnostics.
- `serial.txt`: guest boot/setup console.
- `graphics-rpc.jsonl` and, on a host renderer failure, `rpc-error.txt`:
  rendering/transport diagnostics.
- `controller-ready.json`: native controller initialization reached ready state.
- `latest-frame.bmp`: the latest actual NBT renderer capture.
- `result.json`: exit result after the VM stops.

Keep logs, guest dumps and screenshots private; they are not part of the source
release. `check` validates the inputs and hashes without starting a VM; it is
not an end-to-end boot or menu test.

## Publish the source

Run `python release.py`. It audits a fixed public-file allowlist and writes a
source ZIP beside the repository. Upload that ZIP's contents or this source
repository to GitHub. **Do not upload the private runtime**, firmware packages,
generated shaders, screenshots, guest dumps or logs. The `.gitignore` is an
additional safeguard; it does not protect files dragged into a web upload.

For a web upload, extract `NBT-Emulator-GitHub.zip` and upload only the contents
of its `nbt-emulator` source folder. Do not upload its parent directory alongside
`NBT-Emulator-Private`. The public files are the README, license, launchers,
preparation/release scripts, requirements, authored `src` tree and tests listed
in `public-files.json`.

Each new user prepares their own private runtime. Downloading the GitHub source
alone does not include a preinstalled NBT operating system or BMW interface assets.

The MIT license covers the authored framework. External tools and firmware
retain their respective ownership and licenses.

"""Isolated NBT QNX console and bounded guest-only RPC experiments."""
import argparse
import hashlib
import importlib.util
import json
import queue
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INPUT_HMI_SHA256 = '554b67d4d6317cfb1715d544874fae8ddd2c975be503c9e2514e2dc2f3a0d693'

def verify_input_hmi(preloads):
    image=next(Path(p['path']) for p in preloads if Path(p['path']).name=='nbt-runtime-core.ifs')
    with image.open('rb') as stream:
        header=stream.read(20)
        end,start=struct.unpack_from('<II',header,12)
        cursor=start
        while cursor+4<=end:
            stream.seek(cursor);size=struct.unpack('<H',stream.read(2))[0]
            if not size:break
            if size<24 or size%4 or cursor+size>end:raise ValueError('Controller image directory invalid')
            stream.seek(cursor);record=stream.read(size)
            mode=struct.unpack_from('<I',record,8)[0]
            if mode&0o170000==0o100000:
                offset,length=struct.unpack_from('<II',record,24)
                name=record[32:].split(b'\0',1)[0]
                if name==b'opt/hmi/bin/HmiMain3D':
                    if offset+length>image.stat().st_size:raise ValueError('Controller HMI extent invalid')
                    stream.seek(offset);data=stream.read(length)
                    if hashlib.sha256(data).hexdigest()!=INPUT_HMI_SHA256:
                        raise ValueError('Controller input only supports the verified original HMI')
                    return INPUT_HMI_SHA256
            cursor+=size
    raise ValueError('Verified native HMI not found in core image')


def workspace_file(value):
    path = (ROOT / value).resolve()
    if not path.is_relative_to(ROOT.resolve()) or not path.is_file():
        raise ValueError('Input must be an existing file under the VM workspace: ' + str(path))
    if ',' in path.as_posix():
        raise ValueError('QEMU loader paths cannot contain commas')
    return path


def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def validate_preloads(config, memory_mib):
    entries = list(config.get('preloads', []))
    if config.get('secondary_ifs'):
        entries.insert(0, {'path': config['secondary_ifs'], 'address': '0x40000000'})
    if len(entries) > 4:
        raise ValueError('At most four supplemental ImageFS inputs are supported')
    if entries and memory_mib < 2049:
        raise ValueError('Reserved1GiB ImageFS region requires at least2049MiB guest RAM')
    checked = []
    for entry in entries:
        path = workspace_file(entry['path'])
        address = int(entry['address'], 0) if isinstance(entry['address'], str) else entry['address']
        length = path.stat().st_size
        if not isinstance(address, int) or address % 4096 or length < 4096:
            raise ValueError('ImageFS address must be page-aligned and image nonempty')
        if address < 0x40000000 or address + length > 0x80000000:
            raise ValueError('Supplemental ImageFS must fit the reserved1..2GiB region')
        if address + length > memory_mib * 1024 * 1024:
            raise ValueError('ImageFS does not fit guest physical RAM')
        with path.open('rb') as stream:
            header = stream.read(20)
        if header[:8] != b'imagefs\x06' or struct.unpack_from('<I', header, 8)[0] != length:
            raise ValueError('Supplemental file is not a complete expected ImageFS: ' + str(path))
        digest = file_hash(path)
        expected = entry.get('sha256')
        if expected and (not re.fullmatch('[0-9a-fA-F]{64}', expected) or digest != expected.lower()):
            raise ValueError('Supplemental ImageFS SHA256 mismatch: ' + str(path))
        checked.append({'path': str(path), 'address': address, 'bytes': length, 'sha256': digest})
    ordered = sorted(checked, key=lambda e: e['address'])
    for before, after in zip(ordered, ordered[1:]):
        if before['address'] + before['bytes'] > after['address']:
            raise ValueError('Supplemental ImageFS physical ranges overlap')
    return checked


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', type=Path, default=ROOT / 'minimal-console.json')
    parser.add_argument('--setup-file', type=Path, help='Workspace text file of guest shell commands only')
    parser.add_argument('--run-seconds', type=float, help='Unattended run, bounded1..3600 seconds after cont')
    parser.add_argument('--setup-timeout', type=float, default=45, help='Maximum seconds per guest command')
    parser.add_argument('--exit-after-setup', action='store_true', help='Stop after all guest setup commands complete')
    parser.add_argument('--interactive-after-setup', action='store_true',
                        help='Bound setup to300 seconds, then keep the interactive console open')
    parser.add_argument('--validate-only', action='store_true', help='Validate inputs without starting QEMU')
    args = parser.parse_args()
    config = json.loads(args.config.read_text())
    accelerator=config.get('accelerator','tcg')
    if accelerator not in ('tcg','whpx'):raise ValueError('accelerator must be tcg or whpx')
    qemu=workspace_file('tools/qemu/qemu-system-x86_64.exe' if accelerator=='whpx' else 'tools/qemu/qemu-system-i386.exe')
    ifs = workspace_file(config['ifs'])
    floppy = workspace_file(config['floppy'])
    memory_mib = config.get('memory_mib', 512)
    if not isinstance(memory_mib, int) or not 128 <= memory_mib <= 4096:
        raise ValueError('Guest RAM must be an integer between128 and4096MiB')
    icount_shift = config.get('icount_shift', 0)
    if icount_shift != 'auto' and (type(icount_shift) is not int or not 0 <= icount_shift <= 8):
        raise ValueError('icount_shift must be auto or an integer between 0 and 8')
    icount_sleep=config.get('icount_sleep',False)
    if type(icount_sleep) is not bool:raise ValueError('icount_sleep must be boolean')
    display_format=config.get('display_format','png')
    if display_format not in ('png','bmp'):raise ValueError('display_format must be png or bmp')
    graphics_backend=config.get('graphics_backend')
    if graphics_backend not in (None,'auto','hardware','warp'):raise ValueError('Unknown graphics_backend')
    preloads = validate_preloads(config, memory_mib)
    controller_input=config.get('controller_input',False)
    if not isinstance(controller_input,bool):raise ValueError('controller_input must be boolean')
    input_hmi_hash=verify_input_hmi(preloads) if controller_input else None
    rpc_enabled = config.get('rpc_renderer', False)
    ram_transport = config.get('rpc_ram', False)
    direct_ram = config.get('rpc_ram_direct', False)
    if not isinstance(direct_ram,bool) or (direct_ram and not ram_transport):
        raise ValueError('rpc_ram_direct requires the reserved-RAM transport')
    if not isinstance(ram_transport, bool) or (ram_transport and not rpc_enabled):
        raise ValueError('rpc_ram requires the graphics renderer')
    if ram_transport:
        if memory_mib < 2049 or not (ROOT/'ram_transport.py').is_file():
            raise ValueError('RAM graphics transport requires reserved guest RAM and ram_transport.py')
        if direct_ram and not (ROOT/'direct_ram_transport.py').is_file():
            raise ValueError('Direct mailbox backend is missing')
        if any(p['address'] < 0x78001000 and p['address']+p['bytes'] > 0x70000000 for p in preloads):
            raise ValueError('Supplemental image overlaps graphics transport mailboxes')
    if not isinstance(rpc_enabled, bool):
        raise ValueError('rpc_renderer must be true or false')
    renderer_path = ROOT / 'host_renderer.py'
    if rpc_enabled and not renderer_path.is_file():
        raise ValueError('Fixed host_renderer.py is not ready')
    setup_path = args.setup_file or config.get('setup_file')
    setup_lines = []
    if setup_path:
        setup_path = workspace_file(setup_path)
        if setup_path.stat().st_size > 256 * 1024:
            raise ValueError('Guest setup file exceeds256KiB')
        for line in setup_path.read_text(encoding='utf-8').splitlines():
            if line.strip() and not line.lstrip().startswith('#'):
                if '\x00' in line or len(line.encode('utf-8')) > 16384:
                    raise ValueError('Invalid or oversized guest setup command')
                setup_lines.append(line)
        if args.run_seconds is None and not args.interactive_after_setup:
            args.run_seconds = 300
    if args.run_seconds is not None and not 1 <= args.run_seconds <= 3600:
        raise ValueError('run-seconds must be between1 and3600')
    if not 1 <= args.setup_timeout <= 120:
        raise ValueError('setup-timeout must be between1 and120')
    if args.exit_after_setup and not setup_lines:
        raise ValueError('exit-after-setup requires a nonempty setup file')
    if args.interactive_after_setup:
        if not setup_lines or args.exit_after_setup or args.run_seconds is not None:
            raise ValueError('interactive-after-setup requires setup and excludes run-seconds/exit-after-setup')
    input_manifest = {'ifs': {'path': str(ifs), 'sha256': file_hash(ifs)},
                      'floppy': {'path': str(floppy), 'sha256': file_hash(floppy)},
                      'preloads': preloads, 'rpc_renderer': rpc_enabled, 'rpc_ram': ram_transport, 'rpc_ram_direct':direct_ram,'memory_mib': memory_mib,
                      'icount_shift': icount_shift,'icount_sleep':icount_sleep,'display_format':display_format,
                      'graphics_backend':graphics_backend,'accelerator':accelerator,'qemu_sha256':file_hash(qemu),
                      'controller_input':controller_input,
                      'input_hmi_sha256':input_hmi_hash}
    if setup_path:
        input_manifest['setup'] = {'path': str(setup_path), 'sha256': file_hash(setup_path),
                                   'commands': len(setup_lines)}
    if args.validate_only:
        print(json.dumps(input_manifest, indent=2))
        return
    logs = ROOT / 'logs' / ('console-' + time.strftime('%Y%m%d-%H%M%S'))
    logs.mkdir(parents=True)
    (logs / 'inputs.json').write_text(json.dumps(input_manifest, indent=2))
    command = [str(qemu), '-L', str(ROOT / 'tools/qemu/share'),
               '-machine', 'pc', '-accel', 'tcg,thread=single', '-cpu', 'qemu32',
               '-m', str(memory_mib), '-smp', '1', '-nic', 'none',
               '-icount', f'shift={icount_shift},align=off,sleep={"on" if icount_sleep else "off"}', '-display', 'none',
               '-chardev', 'socket,id=serial0,host=127.0.0.1,port=0,server=on,wait=off',
               '-serial', 'chardev:serial0', '-monitor', 'none', '-qmp', 'stdio', '-S',
               '-no-reboot', '-no-shutdown',
               '-drive', 'file=' + floppy.as_posix() + ',format=raw,if=floppy,readonly=on',
               '-boot', 'order=a', '-device', 'loader,file=' + ifs.as_posix() + ',addr=0x01000000,force-raw=on']
    if accelerator=='whpx':
        command[command.index('-machine')+1]='pc,kernel-irqchip=off'
        command[command.index('-accel')+1]='whpx'
        index=command.index('-icount');del command[index:index+2]
    if rpc_enabled:
        command += ['-chardev', 'socket,id=serial1,host=127.0.0.1,port=0,server=on,wait=off,nodelay=on',
                    '-serial', 'chardev:serial1']
    ram_listener = None
    if ram_transport and not direct_ram:
        ram_listener=socket.socket();ram_listener.bind(('127.0.0.1',0));ram_listener.listen(1);ram_listener.settimeout(15)
        command += ['-qtest','tcp:127.0.0.1:'+str(ram_listener.getsockname()[1]),'-qtest-log','NUL']
    for preload in preloads:
        command += ['-device', 'loader,file=' + Path(preload['path']).as_posix()
                    + ',addr=' + hex(preload['address']) + ',force-raw=on']
    (logs / 'command.json').write_text(json.dumps(command, indent=2))
    events = queue.Queue()
    transcript = []
    serial_socket = rpc_socket = reader = rpc_worker = None
    stopping = threading.Event()
    serial_write_lock=threading.Lock()
    serial_condition = threading.Condition()
    serial_recent = bytearray()
    rpc_ready = threading.Event()
    rpc_state = {'enabled': rpc_enabled, 'ready': False}
    setup_results = []
    final_error = None
    with (logs / 'stderr.txt').open('wb') as error_log:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=error_log, text=True, encoding='utf-8', errors='replace')
        def qmp_reader():
            for line in process.stdout:
                transcript.append(line)
                try:
                    events.put(json.loads(line))
                except json.JSONDecodeError:
                    pass
        threading.Thread(target=qmp_reader, daemon=True).start()
        def receive(predicate, timeout=10):
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                if process.poll() is not None and events.empty():
                    raise RuntimeError('QEMU exited with ' + str(process.returncode))
                try:
                    message = events.get(timeout=0.1)
                    if predicate(message):
                        return message
                except queue.Empty:
                    pass
            raise TimeoutError('QMP response timed out')
        def qmp(name, arguments=None):
            request = {'execute': name, 'id': name}
            if arguments:
                request['arguments'] = arguments
            process.stdin.write(json.dumps(request) + '\n')
            process.stdin.flush()
            response = receive(lambda message: message.get('id') == name)
            if 'error' in response:
                raise RuntimeError(json.dumps(response['error']))
            return response.get('return')
        def connect_serial(label):
            channel = next(ch for ch in qmp('query-chardev') if ch['label'] == label)
            port = re.fullmatch(r'(?:disconnected:)?tcp:127\.0\.0\.1:(\d+)(?:,server=on)?', channel['filename'])
            if not port:
                raise RuntimeError('Serial channel must listen only on loopback: ' + str(channel))
            return socket.create_connection(('127.0.0.1', int(port.group(1))), timeout=5)
        def send_guest(line):
            data = line.encode('utf-8') + b'\r'
            with serial_write_lock:
                for offset in range(0, len(data), 16):
                    serial_socket.sendall(data[offset:offset+16])
                    time.sleep(0.01)
        def wait_serial(pattern, timeout):
            deadline = time.monotonic() + timeout
            with serial_condition:
                while time.monotonic() < deadline:
                    match = re.search(pattern, serial_recent)
                    if match:
                        return match
                    if process.poll() is not None or rpc_state.get('error'):
                        raise RuntimeError('VM or RPC worker stopped while awaiting guest output')
                    serial_condition.wait(timeout=min(0.2, max(0.001, deadline-time.monotonic())))
            raise TimeoutError('Guest output wait timed out: ' + repr(pattern))
        try:
            receive(lambda message: 'QMP' in message, timeout=45)
            qmp('qmp_capabilities')
            serial_socket = connect_serial('serial0')
            serial_socket.settimeout(0.2)
            def serial_reader():
                with (logs / 'serial.txt').open('ab', buffering=0) as serial_log:
                    while not stopping.is_set():
                        try:
                            data = serial_socket.recv(65536)
                            if not data:
                                break
                            serial_log.write(data)
                            with serial_condition:
                                serial_recent.extend(data)
                                if len(serial_recent) > 1024*1024:
                                    del serial_recent[:-1024*1024]
                                serial_condition.notify_all()
                            sys.stdout.write(data.decode('utf-8', errors='replace'))
                            sys.stdout.flush()
                        except socket.timeout:
                            pass
                        except OSError:
                            break
            reader = threading.Thread(target=serial_reader, daemon=True)
            reader.start()
            if rpc_enabled:
                if ram_transport:
                    if direct_ram:
                        from direct_ram_transport import DirectRamConnection,pc_ram_address
                        layout=qmp('human-monitor-command',{'command-line':'info ramblock'})
                        rpc_socket=DirectRamConnection(process.pid,pc_ram_address(layout,memory_mib*1024*1024),memory_mib*1024*1024,logs)
                    else:
                        from ram_transport import RamConnection
                        connection,_=ram_listener.accept();ram_listener.close()
                        rpc_socket=RamConnection(connection)
                else:
                    rpc_socket = connect_serial('serial1')
                    rpc_socket.settimeout(None)
                def serve_rpc():
                    renderer = None
                    try:
                        spec = importlib.util.spec_from_file_location('nbt_host_renderer', renderer_path)
                        module = importlib.util.module_from_spec(spec)
                        sys.modules[spec.name] = module
                        spec.loader.exec_module(module)
                        renderer = module.Renderer(rpc_socket, logs,display_format=display_format,graphics_backend=graphics_backend)
                        rpc_state['ready'] = True
                        rpc_ready.set()
                        renderer.run()
                    except Exception:
                        rpc_state['error'] = traceback.format_exc()
                        (logs / 'rpc-error.txt').write_text(rpc_state['error'])
                    finally:
                        rpc_state['finished'] = True
                        rpc_ready.set()
                        if renderer is not None and hasattr(renderer, 'close'):
                            try:
                                renderer.close()
                            except Exception:
                                pass
                rpc_worker = threading.Thread(target=serve_rpc, daemon=True)
                rpc_worker.start()
                if not rpc_ready.wait(timeout=45) or not rpc_state['ready'] or rpc_state.get('error'):
                    raise RuntimeError('Renderer initialization failed before guest execution: ' + str(rpc_state))
            print('Local QNX VM console. Commands go ONLY to the guest.', flush=True)
            print('Host commands: :quit, :status, :registers, :screenshot, :key NAME. Ctrl+C sends interrupt to guest.', flush=True)
            print('Logs: ' + str(logs), flush=True)
            qmp('cont')
            deadline = time.monotonic() + args.run_seconds if args.run_seconds else None
            if args.interactive_after_setup:
                deadline = time.monotonic() + 300
            if setup_lines:
                wait_serial(rb'(?:^|[\r\n])# ', min(45, max(1, deadline-time.monotonic())))
                nonce = str(time.monotonic_ns())
                for index, line in enumerate(setup_lines):
                    remaining = deadline-time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('Bounded VM run expired during setup')
                    marker = '__NBT_VM_STEP_' + nonce + '_' + str(index) + '__'
                    send_guest(line)
                    send_guest('echo ' + marker + ':$?')
                    match = wait_serial(rb'(?:^|[\r\n])' + marker.encode()
                                        + rb':([0-9]+)(?:[\r\n]|$)', min(args.setup_timeout, remaining))
                    result = {'index': index, 'command': line, 'exit_status': int(match.group(1))}
                    setup_results.append(result)
                    (logs / 'setup-results.json').write_text(json.dumps(setup_results, indent=2))
                    if result['exit_status']:
                        raise RuntimeError('Guest setup command failed: ' + json.dumps(result))
            if args.interactive_after_setup:
                deadline = None
                print('Guest setup completed; interactive console remains open.', flush=True)
            while process.poll() is None:
                if rpc_state.get('error'):
                    raise RuntimeError('RPC worker failed; see rpc-error.txt')
                if rpc_state.get('finished'):
                    raise RuntimeError('Graphics transport stopped unexpectedly; see graphics-rpc.jsonl')
                if args.exit_after_setup:
                    break
                if deadline:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(min(0.2, deadline-time.monotonic()))
                    continue
                try:
                    line = sys.stdin.readline()
                    if line == '':
                        break
                    line = line.rstrip('\r\n')
                    if line == ':quit':
                        break
                    if line == ':status':
                        print(json.dumps(qmp('query-status')), flush=True)
                    elif line.startswith(':key '):
                        key=line[5:].strip().lower()
                        if key not in ('menu','back','option','enter','up','down','left','right','cw','ccw'):
                            print('Unknown controller key.',flush=True)
                        else:
                            with (logs/'controller-input.jsonl').open('a',encoding='utf-8') as stream:
                                stream.write(json.dumps({'key':key})+'\n')
                            print('Queued native controller key: '+key,flush=True)
                    elif line == ':registers':
                        registers = qmp('human-monitor-command', {'command-line': 'info registers'})
                        (logs / ('registers-' + time.strftime('%H%M%S') + '.txt')).write_text(registers)
                        print(registers, flush=True)
                    elif line == ':screenshot':
                        shot = logs / ('display-' + time.strftime('%H%M%S') + '.ppm')
                        qmp('screendump', {'filename': str(shot)})
                        try:
                            from PIL import Image
                            Image.open(shot).save(shot.with_suffix('.png'))
                            print(str(shot.with_suffix('.png')), flush=True)
                        except ImportError:
                            print(str(shot), flush=True)
                    else:
                        send_guest(line)
                except KeyboardInterrupt:
                    serial_socket.sendall(b'\x03')
            if process.poll() is not None and process.returncode != 0:
                raise RuntimeError('QEMU exited unexpectedly with code ' + str(process.returncode) + '; see stderr.txt')
        except Exception as exc:
            final_error = str(exc)
            raise
        finally:
            stopping.set()
            if ram_listener:ram_listener.close()
            if process.poll() is None:
                try:
                    qmp('quit')
                    process.wait(timeout=5)
                except Exception:
                    process.kill()
                    process.wait(timeout=5)
            for connection in [serial_socket, rpc_socket]:
                if connection:
                    try:
                        connection.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    connection.close()
            for worker in [reader, rpc_worker]:
                if worker:
                    worker.join(timeout=2)
            (logs / 'qmp.jsonl').write_text(''.join(transcript))
            (logs / 'result.json').write_text(json.dumps({'exit_code': process.returncode,
                'error': final_error, 'rpc': rpc_state, 'setup_completed': len(setup_results)}, indent=2))
            print('\nVM stopped. Logs: ' + str(logs), flush=True)


if __name__ == '__main__':
    main()

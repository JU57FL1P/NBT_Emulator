"""Launch or validate a privately prepared regular-NBT runtime."""
from pathlib import Path
import argparse,ctypes as C,hashlib,json,os,subprocess,sys
from prepare import private_path

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('action',choices=('run','check','view'))
    p.add_argument('--runtime',type=private_path,default=Path(__file__).resolve().parent.parent/'NBT-Emulator-Private')
    p.add_argument('--software',action='store_true',help='Use slower TCG instead of WHPX')
    p.add_argument('--hardware',action='store_true',help='Use WHPX after host TSC calibration')
    p.add_argument('--seconds',type=int,help='Bounded console run for verification, 30..600 seconds')
    a=p.parse_args();r=a.runtime.resolve()
    if os.name!='nt':p.error('This renderer and direct-RAM transport currently require Windows.')
    if not (r/'runtime.json').is_file():p.error('Runtime missing. Run prepare.py with your firmware and dependency paths first.')
    settings=json.loads((r/'runtime.json').read_text())
    if a.hardware and a.software:p.error('Choose --hardware or --software')
    mode='tcg' if a.software else 'whpx' if a.hardware else settings.get('preferred_mode','tcg')
    if mode=='whpx' and not settings.get('whpx_tsc_hz'):p.error('WHPX timing requires preparation with --whpx-tsc-hz for this host; use --software otherwise.')
    command=[sys.executable,str(r/'console_runtime.py'),'--config',str(r/('profile-'+mode+'.json')),'--setup-file','setup-'+mode+'.txt','--setup-timeout','90']
    if a.action=='check':raise SystemExit(subprocess.call(command+['--validate-only'],cwd=r))
    def view():
        interpreter=Path(sys.executable).with_name('pythonw.exe')
        if not interpreter.exists():interpreter=Path(sys.executable)
        subprocess.Popen([str(interpreter),str(r/'viewer.py'),'--runtime',str(r)],cwd=r,creationflags=subprocess.CREATE_NO_WINDOW)
    if a.action=='view':view();return
    kernel=C.WinDLL('kernel32',use_last_error=True);kernel.CreateMutexW.argtypes=[C.c_void_p,C.c_int,C.c_wchar_p];kernel.CreateMutexW.restype=C.c_void_p
    handle=kernel.CreateMutexW(None,True,'Local\\NBTEmulatorVM-'+hashlib.sha256(str(r).lower().encode()).hexdigest()[:24])
    if not handle:raise C.WinError(C.get_last_error())
    already_running=C.get_last_error()==183
    if a.seconds is None:view()
    if already_running:print('NBT Emulator is already running; requested its display.');return
    if a.seconds is not None:
        if not 30<=a.seconds<=600:p.error('--seconds must be 30..600')
        command+=['--run-seconds',str(a.seconds)]
    else:command+=['--interactive-after-setup']
    print('Stock NBT emulation. Type :quit in this console to stop. Use the separate display for controls.',flush=True)
    raise SystemExit(subprocess.call(command,cwd=r))

if __name__=='__main__':main()

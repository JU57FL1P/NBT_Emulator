"""Viewer and controller for actual native NBT renderer frames."""
from pathlib import Path
from io import BytesIO
import argparse,ctypes as C,hashlib,json,os,time,tkinter as tk
from PIL import Image,ImageTk,ImageOps

p=argparse.ArgumentParser();p.add_argument('--runtime',type=Path,required=True);a=p.parse_args()
ROOT=a.runtime.resolve();kernel=C.WinDLL('kernel32',use_last_error=True)
kernel.CreateMutexW.argtypes=[C.c_void_p,C.c_int,C.c_wchar_p];kernel.CreateMutexW.restype=C.c_void_p
mutex=kernel.CreateMutexW(None,True,'Local\\NBTEmulatorViewer-'+hashlib.sha256(str(ROOT).lower().encode()).hexdigest()[:24])
if not mutex:raise C.WinError(C.get_last_error())
request=ROOT/'viewer-activate.txt'
if C.get_last_error()==183:
    request.write_text(str(time.time_ns()));raise SystemExit(0)
window=tk.Tk();window.title('NBT Emulator — native display');window.geometry('1280x600');window.minsize(640,280);window.configure(bg='#171717')
caption=tk.Label(window,text='Waiting for native NBT',bg='#171717',fg='white',anchor='w',padx=12,pady=8);caption.pack(fill='x')
screen=tk.Canvas(window,bg='black',highlightthickness=0);screen.pack(fill='both',expand=True)
status=tk.Label(window,text='Main menu: rotary, Enter, Back and Options. Closing the display leaves the VM running.',bg='#171717',fg='#bbbbbb',anchor='w',padx=12,pady=8);status.pack(fill='x')
controls=tk.Frame(window,bg='#171717');controls.pack(fill='x')
run=None;frame=None;photo=None;stamp=None;scan=0;folders=[];buttons=[];activation=0
def queue(key):
    if run is None:return
    try:
        with (run/'controller-input.jsonl').open('a') as f:f.write(json.dumps({'key':key})+'\n')
    except OSError:pass
for label,key in [('Menu','menu'),('Back','back'),('Rotate left','ccw'),('Enter','enter'),('Rotate right','cw'),('Up','up'),('Down','down'),('Left','left'),('Right','right'),('Options','option')]:
    b=tk.Button(controls,text=label,command=lambda k=key:queue(k),state='disabled');b.pack(side='left',padx=3,pady=5);buttons.append(b)
keys={'m':'menu','Escape':'back','Return':'enter','Up':'up','Down':'down','Left':'left','Right':'right','Prior':'ccw','Next':'cw','o':'option'}
window.bind('<KeyPress>',lambda e:queue(keys[e.keysym]) if e.keysym in keys else None)
def redraw(event=None):
    global photo
    if frame is None:return
    resized=ImageOps.contain(frame,(max(screen.winfo_width(),1),max(screen.winfo_height(),1)))
    photo=ImageTk.PhotoImage(resized);screen.delete('all');screen.create_image(screen.winfo_width()//2,screen.winfo_height()//2,image=photo)
def update():
    global run,frame,stamp,scan,folders,activation
    try:
        if request.exists() and request.stat().st_mtime_ns!=activation:
            activation=request.stat().st_mtime_ns;window.deiconify();window.lift();window.focus_force()
        if time.monotonic()-scan>1:
            folders=sorted((ROOT/'logs').glob('console-*'),reverse=True);scan=time.monotonic()
        latest=folders[0] if folders else None;run=None
        if latest and not (latest/'result.json').exists() and (latest/'controller-ready.json').exists():run=latest
        for b in buttons:b.configure(state='normal' if run else 'disabled')
        path=next((f/'latest-frame.bmp' for f in folders if (f/'latest-frame.bmp').exists()),None)
        if path:
            current=(str(path),path.stat().st_mtime_ns)
            if stamp!=current:
                # Close the read handle before decoding so Windows can replace
                # the live capture atomically without a sharing violation.
                with Image.open(BytesIO(path.read_bytes())) as im:frame=im.convert('RGB').copy()
                stamp=current;redraw()
            caption.configure(text=f'Native NBT · {frame.width} × {frame.height} · {max(0,int(time.time()-path.stat().st_mtime))}s since frame')
    except (OSError,ValueError,tk.TclError):pass
    window.after(50,update)
screen.bind('<Configure>',redraw);window.after(100,update);window.mainloop()

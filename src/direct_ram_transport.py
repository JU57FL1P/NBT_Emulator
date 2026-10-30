"""Access only the lab mailbox in the QEMU process spawned by this runner.

The base address is reported by QEMU itself. No process discovery, memory
scan, firmware patch, code execution or access to another app is performed.
"""
import ctypes as C
import socket
import struct
import threading
import time
import json
from pathlib import Path
from ram_transport import BASE, RESPONSE, LIMIT, MAGIC

SPAN=0x08001000

def pc_ram_address(layout,expected_bytes):
    rows=[line.split() for line in layout.splitlines() if line.split()[:1]==['pc.ram']]
    if len(rows)!=1:raise ValueError('QEMU must report exactly one pc.ram block')
    row=rows[0]
    if len(row)!=8 or row[7]!='rw' or int(row[3],16)!=0:
        raise ValueError('Unexpected QEMU RAM layout')
    if int(row[4],16)!=expected_bytes or int(row[5],16)<expected_bytes:
        raise ValueError('QEMU RAM size differs from the launched VM')
    return int(row[6],16)

class DirectRamConnection:
    family=socket.AF_UNSPEC
    bulk_transport=True

    def __init__(self,pid,host_address,ram_bytes,logdir=None):
        if ram_bytes<BASE+SPAN or host_address<65536:
            raise ValueError('Reserved mailbox does not fit the reported QEMU RAM')
        self.host_address=host_address
        self.pending=b'';self.stopped=False;self.lock=threading.Lock()
        self.profile_path=Path(logdir)/'mailbox-profile.json' if logdir else None
        self.stats={'transactions':0,'reads':0,'writes':0,'read_seconds':0.,'write_seconds':0.,'guest_gap_seconds':0.,'dispatch_seconds':0.}
        self.last_sent=None;self.received_at=None
        self.frame_gaps={}
        self.kernel=C.WinDLL('kernel32',use_last_error=True)
        self.kernel.OpenProcess.argtypes=[C.c_uint32,C.c_int,C.c_uint32]
        self.kernel.OpenProcess.restype=C.c_void_p
        for name in ('ReadProcessMemory','WriteProcessMemory'):
            fn=getattr(self.kernel,name)
            fn.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
            fn.restype=C.c_int
        self.kernel.CloseHandle.argtypes=[C.c_void_p];self.kernel.CloseHandle.restype=C.c_int
        self.nt=C.WinDLL('ntdll')
        self.nt.NtWriteVirtualMemory.argtypes=[C.c_void_p,C.c_void_p,C.c_void_p,C.c_size_t,C.POINTER(C.c_size_t)]
        self.nt.NtWriteVirtualMemory.restype=C.c_long
        self.handle=self.kernel.OpenProcess(0x10|0x20|0x8,False,pid)
        if not self.handle:raise C.WinError(C.get_last_error())

    def address(self,physical,length):
        if type(physical)!=int or type(length)!=int or length<0 or physical<BASE or physical+length>BASE+SPAN:
            raise ValueError('Access outside the reserved VM graphics mailbox')
        return self.host_address+physical

    def read(self,address,length):
        started=time.perf_counter()
        pointer=self.address(address,length)
        if not length:return b''
        buffer=C.create_string_buffer(length);copied=C.c_size_t()
        with self.lock:
            if self.stopped:raise EOFError('VM mailbox closed')
            if not self.kernel.ReadProcessMemory(self.handle,pointer,buffer,length,C.byref(copied)):
                raise C.WinError(C.get_last_error())
        if copied.value!=length:raise OSError('Short VM mailbox read')
        self.stats['reads']+=1;self.stats['read_seconds']+=time.perf_counter()-started
        return buffer.raw

    def write(self,address,data):
        started=time.perf_counter()
        pointer=self.address(address,len(data));copied=C.c_size_t()
        with self.lock:
            if self.stopped:raise EOFError('VM mailbox closed')
            status=self.nt.NtWriteVirtualMemory(self.handle,pointer,C.c_char_p(data),len(data),C.byref(copied))
            if status<0:raise OSError(f'VM mailbox write failed, NTSTATUS {status & 0xffffffff:#x}')
        if copied.value!=len(data):raise OSError('Short VM mailbox write')
        self.stats['writes']+=1;self.stats['write_seconds']+=time.perf_counter()-started

    def recv(self,length):
        if not self.pending:
            spins=0
            while True:
                control=self.read(BASE,16)
                magic,state,size,_=struct.unpack_from('<4I',control)
                if magic==MAGIC and state==1:break
                if magic==MAGIC and state==0xffffffff:raise EOFError('Guest mailbox failed')
                spins+=1
                if spins>=16:time.sleep(0.0001);spins=0
            if not 16<=size<=LIMIT:raise OSError('VM request mailbox bounds')
            # Acquire ownership before copying the body. Reading control and
            # data separately avoids a torn prefetch while the vCPU publishes
            # its next request; Windows calls are cheap on the direct path.
            self.pending=self.read(BASE+64,size)
            self.received_at=time.perf_counter()
            if self.last_sent is not None:
                gap=self.received_at-self.last_sent;self.stats['guest_gap_seconds']+=gap
                opcode=struct.unpack_from('<I',self.pending,4)[0]
                entry=self.frame_gaps.setdefault(opcode,{'count':0,'seconds':0.,'maximum_seconds':0.})
                entry['count']+=1;entry['seconds']+=gap;entry['maximum_seconds']=max(entry['maximum_seconds'],gap)
        result=self.pending[:length];self.pending=self.pending[length:]
        return result

    def sendall(self,data):
        if self.pending or not 16<=len(data)<=LIMIT:raise OSError('VM response mailbox bounds/order')
        if self.received_at is not None:self.stats['dispatch_seconds']+=time.perf_counter()-self.received_at
        self.write(RESPONSE,data)
        self.write(BASE+12,struct.pack('<I',len(data)))
        # Publish ownership only after all response bytes and size are copied.
        self.write(BASE+4,struct.pack('<I',2))
        self.last_sent=time.perf_counter();self.stats['transactions']+=1
        if self.profile_path and self.stats['transactions']%256==0:
            self.profile_path.write_text(json.dumps(self.stats,indent=2)+'\n')

    def shutdown(self,*args):
        with self.lock:self.stopped=True

    def close(self):
        with self.lock:
            self.stopped=True
            if self.profile_path:self.profile_path.write_text(json.dumps(self.stats,indent=2)+'\n')
            if self.handle:self.kernel.CloseHandle(self.handle);self.handle=None

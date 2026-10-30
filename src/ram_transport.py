"""VM-only request mailbox in RAM reserved by the original lab boot args.

QEMU's local qtest channel copies bytes; guest/host state words provide
ownership. No guest pause, firmware instruction patch or replay is used.
"""
import socket
import struct
import time

BASE=0x70000000
RESPONSE=BASE+0x04000100
LIMIT=64*1024*1024+16
MAGIC=0x4e425452

class RamConnection:
    family=socket.AF_UNSPEC
    bulk_transport=True

    def __init__(self,connection):
        self.connection=connection
        connection.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,1)
        connection.settimeout(None)
        self.stream=connection.makefile('rb')
        self.pending=b''

    def command(self,text):
        return self.commands([text])[0]

    def commands(self,commands):
        self.connection.sendall(('\n'.join(commands)+'\n').encode('ascii'))
        return [self.response() for _ in commands]

    def response(self):
        line=self.stream.readline(1024*1024)
        if not line:raise EOFError('VM memory transport closed')
        if not line.startswith(b'OK'):raise OSError('VM memory command failed: '+repr(line[:160]))
        return line.rstrip(b'\n')

    def read(self,address,length):
        chunks=[]
        for offset in range(0,length,65536):
            count=min(65536,length-offset)
            line=self.command(f'read {address+offset:#x} {count:#x}')
            if not line.startswith(b'OK 0x'):raise OSError('VM memory read framing')
            data=bytes.fromhex(line[5:].decode('ascii'))
            if len(data)!=count:raise OSError('VM memory read size')
            chunks.append(data)
        return b''.join(chunks)

    def write(self,address,data):
        self.commands(self.write_commands(address,data))

    def write_commands(self,address,data):
        result=[]
        for offset in range(0,len(data),65536):
            block=data[offset:offset+65536]
            result.append(f'write {address+offset:#x} {len(block):#x} 0x'+block.hex())
        return result

    def recv(self,length):
        if not self.pending:
            while True:
                block=self.read(BASE,4096)
                magic,state,size,_=struct.unpack_from('<4I',block)
                if magic==MAGIC and state==1:break
                if magic==MAGIC and state==0xffffffff:raise EOFError('Guest memory transport failed')
                time.sleep(0.001)
            if not 16<=size<=LIMIT:raise OSError('VM request mailbox bounds')
            available=min(size,len(block)-64)
            self.pending=block[64:64+available]+self.read(BASE+64+available,size-available)
        data=self.pending[:length];self.pending=self.pending[length:]
        return data

    def sendall(self,data):
        if self.pending or not 16<=len(data)<=LIMIT:raise OSError('VM response mailbox bounds/order')
        commands=self.write_commands(RESPONSE,data)
        commands+=self.write_commands(BASE+12,struct.pack('<I',len(data)))
        commands+=self.write_commands(BASE+4,struct.pack('<I',2))
        # A single TCP send removes intermediate round trips. The ready word
        # is still written last, after the complete response and its length.
        for at in range(0,len(commands),20):self.commands(commands[at:at+20])

    def shutdown(self,*args):
        self.connection.shutdown(*args)

    def close(self):
        self.stream.close();self.connection.close()

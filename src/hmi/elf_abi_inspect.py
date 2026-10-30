"""Read ELF32 symbols/relocations and disassemble selected bytes, never execute them."""
from pathlib import Path
import struct, argparse, json, subprocess, re

class ELF32:
    def __init__(self,path):
        self.path=Path(path); self.b=self.path.read_bytes()
        assert self.b[:6]==b'\x7fELF\x01\x01'
        self.h=struct.unpack_from('<16sHHIIIIIHHHHHH',self.b)
        self.sections=[struct.unpack_from('<10I',self.b,self.h[6]+i*self.h[11]) for i in range(self.h[12])]
        shstr=self.data(self.h[13]); self.names=[self.string(shstr,s[0]) for s in self.sections]
        self.syms={}; self.symtab={}
        for idx,s in enumerate(self.sections):
            if s[1] not in (2,11):continue
            strings=self.data(s[6]); entries=[]
            for pos in range(s[4],s[4]+s[5],s[9] or 16):
                n,v,z,info,other,si=struct.unpack_from('<IIIBBH',self.b,pos)
                row={'name':self.string(strings,n),'value':v,'size':z,'info':info,'section':si}
                entries.append(row)
                if row['name']:self.syms[row['name']]=row
            self.symtab[idx]=entries
        self.labels={s['value']:s['name'] for s in self.syms.values() if s['section']!=0}
        self.relocs={}
        for idx,s in enumerate(self.sections):
            if s[1]!=9:continue
            for pos in range(s[4],s[4]+s[5],s[9] or 8):
                addr,info=struct.unpack_from('<II',self.b,pos)
                sym=self.symtab[s[6]][info>>8]
                self.relocs[addr]={'type':info&255,'symbol':sym['name']}
        # x86 classic PLT is one 16-byte initial slot and 16 bytes per relocation.
        if '.plt' in self.names:
            s=self.sections[self.names.index('.plt')]
            for i in range(16,s[5],16):
                op=self.b[s[4]+i:s[4]+i+6]
                if op[:2]==b'\xff\x25':
                    got=struct.unpack_from('<I',op,2)[0]
                    if got in self.relocs:self.labels[s[3]+i]=self.relocs[got]['symbol']+'@plt'
                elif op[:2]==b'\xff\xa3':
                    gotname='.got.plt' if '.got.plt' in self.names else '.got'
                    gotbase=self.sections[self.names.index(gotname)][3] if gotname in self.names else 0
                    got=gotbase+struct.unpack_from('<i',op,2)[0]
                    if got in self.relocs:self.labels[s[3]+i]=self.relocs[got]['symbol']+'@plt'
    def data(self,idx):
        s=self.sections[idx]; return self.b[s[4]:s[4]+s[5]]
    @staticmethod
    def string(b,n):return b[n:].split(b'\0',1)[0].decode('ascii','replace')
    def at(self,addr,size):
        for s in self.sections:
            if s[3]<=addr<s[3]+s[5] and s[1]!=8:
                p=s[4]+addr-s[3]; return self.b[p:p+size]
        raise ValueError(hex(addr))
    def disassemble(self,addr,size,out,name):
        raw=self.at(addr,size); rawpath=out/(name+'.bin'); rawpath.write_bytes(raw)
        exe=Path(__file__).resolve().parents[1]/'tools/nasm/nasm-3.02/ndisasm.exe'
        result=subprocess.run([str(exe),'-b','32','-o',str(addr),str(rawpath)],check=True,capture_output=True,text=True)
        lines=[]
        for line in result.stdout.splitlines():
            annotations=[]
            for value in re.findall(r'0x([0-9a-f]+)',line):
                x=int(value,16)
                if x in self.labels:annotations.append(self.labels[x])
                if x in self.relocs:annotations.append('GOT:'+self.relocs[x]['symbol'])
            lines.append(line+(' ; '+', '.join(annotations) if annotations else ''))
        (out/(name+'.asm')).write_text('\n'.join(lines)+'\n')
        return lines

if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('input',type=Path);p.add_argument('--symbols',nargs='*',default=[]);p.add_argument('--out',type=Path,required=True)
    args=p.parse_args();args.out.mkdir(parents=True,exist_ok=True);e=ELF32(args.input)
    report={'file':str(args.input),'elf_entry':e.h[4],'selected_symbols':{}}
    for name in args.symbols:
        s=e.syms.get(name)
        report['selected_symbols'][name]=s
        if s and s['section'] and s['size']:
            e.disassemble(s['value'],s['size'],args.out,re.sub(r'[^a-zA-Z0-9_.-]','_',name))
    (args.out/'symbols.json').write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))

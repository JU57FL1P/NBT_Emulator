"""Audit and archive the fixed public-source allowlist; never zip runtime data."""
from pathlib import Path,PurePosixPath
import argparse,hashlib,json,re,zipfile
ROOT=Path(__file__).resolve().parent
def audit(root=ROOT):
    allowed=json.loads((root/'public-files.json').read_text())['files']
    if len(allowed)!=len(set(allowed)):raise ValueError('Duplicate public file')
    approved=[]
    for name in allowed:
        rel=PurePosixPath(name)
        if rel.is_absolute() or '..' in rel.parts:raise ValueError('Invalid public path')
        p=root.joinpath(*rel.parts)
        if p.is_symlink() or not p.resolve().is_relative_to(root.resolve()):raise ValueError('Public symlink/path escape')
        data=p.read_bytes()
        if b'\0' in data or data.startswith((b'MZ',b'\x7fELF',b'PK\x03\x04',b'imagefs')):raise ValueError('Binary payload in public tree: '+name)
        text=data.decode('utf-8')
        if re.search(r'(?:[A-Z]:[\\/]+Users[\\/]|[A-Z]:[\\/]+Data[\\/]|WBA[A-HJ-NPR-Z0-9]{14})',text,re.I):
            raise ValueError('Developer path or vehicle identifier in '+name)
        approved.append({'path':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()})
    actual={p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file() and not any(part in ('.git','__pycache__','.venv') for part in p.relative_to(root).parts)}
    if actual!=set(allowed):raise ValueError('Unreviewed files: '+repr(sorted(actual-set(allowed)))+'; missing: '+repr(sorted(set(allowed)-actual)))
    return approved
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--audit-only',action='store_true');a=p.parse_args()
    files=audit();out=ROOT.parent/'NBT-Emulator-GitHub.zip'
    if not a.audit_only:
        with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
            for f in files:z.write(ROOT/f['path'],'nbt-emulator/'+f['path'])
        with zipfile.ZipFile(out) as z:
            if z.testzip() is not None:raise ValueError('Archive integrity failure')
            if len(z.infolist())!=len(files):raise ValueError('Archive file count mismatch')
            for f in files:
                if hashlib.sha256(z.read('nbt-emulator/'+f['path'])).hexdigest()!=f['sha256']:raise ValueError('Archive hash mismatch')
        report={'files':files,'archive_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),'firmware_included':False,'runtime_included':False,'third_party_binaries_included':False}
        (ROOT.parent/'NBT-Emulator-release-audit.json').write_text(json.dumps(report,indent=2))
    print(json.dumps({'public_files':len(files),'source_bytes':sum(f['bytes'] for f in files),'audit_passed':True,'archive':str(out) if not a.audit_only else None},indent=2))
if __name__=='__main__':main()

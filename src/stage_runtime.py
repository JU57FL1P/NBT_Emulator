"""Read-only extraction of owned Intel factory file payloads into VM staging.

Never executes files, creates host symlinks, or changes the source packages.
Append=On records are concatenated in package order before hash verification.
"""
from pathlib import Path, PurePosixPath
import hashlib
import json
import re
import sys
import shutil
import xml.etree.ElementTree as ET

base = Path(__file__).resolve().parent
workspace = base.parents[1]
stage = base / 'rootfs-staging'
sys.path.insert(0, str(base/'hmi'))
from hblzo import decode_hb_lzo
tree = stage / 'tree'
indexes = [base/'firmware-indexes'/name for name in [
    'btld_00001275.bin.003_013_001.index.json',
    'swfl_00001280.bin.003_013_001.index.json',
    'swfl_00001e6b.bin.003_013_001.index.json',
    'swfl_000021d2.bin.003_013_001.index.json']]
prefix = '/fs/sda0/repository/istep/'
groups = {}
omitted = []
case_names = {}

for index in indexes:
    doc = json.loads(index.read_text(encoding='utf-8-sig'))
    source = Path(doc['source'])
    assert source.is_file()
    if 'size' in doc:
        assert source.stat().st_size == doc['size']
    for rec in doc['records']:
        if not rec.get('type_hex', '').startswith('04'):
            continue
        fields = dict(x.split('=', 1) for x in (rec.get('descriptor') or '').split(';') if '=' in x)
        if fields.get('Tag') != 'FIL' or fields.get('CPU') != 'Intel':
            continue
        original = fields.get('TargetPath', '') + fields.get('Name', '')
        if not original.startswith(prefix):
            omitted.append({'target': original, 'reason': 'outside software repository'})
            continue
        rel = original[len(prefix):]
        path = PurePosixPath(rel)
        assert not path.is_absolute() and path.parts and all(p not in ('', '.', '..') for p in path.parts)
        assert not re.search(r'[\\<>:"|?*\x00-\x1f]', rel), rel
        # The VM requires no SSH authentication or account secrets.
        lower = rel.lower()
        if lower.startswith('etc/ssh/') or lower in ('etc/passwd', 'etc/shadow') or re.search(r'(?:^|/)(?:.*private.*key|.*_key|.*\.p12|.*\.pfx)$', lower):
            omitted.append({'target': original, 'reason': 'credential material excluded'})
            continue
        if lower in case_names:
            assert case_names[lower] == rel, ('Windows case collision', rel, case_names[lower])
        case_names[lower] = rel
        chunk = {'source': str(source), 'offset': rec['payload_offset'], 'size': rec['length']}
        assert chunk['offset'] >= 0 and chunk['offset'] + chunk['size'] <= source.stat().st_size
        if fields.get('Append') == 'On':
            assert rel in groups, ('Append without base', rel)
            groups[rel].append(chunk)
        else:
            assert rel not in groups, ('Unexpected replacement', rel)
            groups[rel] = [chunk]

tree.mkdir(parents=True, exist_ok=True)
resolved_tree = tree.resolve()
manifest = []
for rel, chunks in groups.items():
    dest = tree.joinpath(*PurePosixPath(rel).parts)
    assert dest.resolve().is_relative_to(resolved_tree)
    dest.parent.mkdir(parents=True, exist_ok=True)
    sha, md5 = hashlib.sha256(), hashlib.md5()
    count = 0
    expected_size = sum(c['size'] for c in chunks)
    if '--reuse' in sys.argv and dest.is_file() and dest.stat().st_size == expected_size and not rel.startswith('info/'):
        with dest.open('rb') as source:
            while True:
                payload = source.read(1024*1024)
                if not payload:
                    break
                sha.update(payload)
                md5.update(payload)
                count += len(payload)
        manifest.append({'path': rel, 'runtime_path': '/'+rel, 'size': count,
                         'sha256': sha.hexdigest(), 'md5': md5.hexdigest(), 'chunks': chunks})
        continue
    with dest.open('wb') as output:
        for chunk in chunks:
            with Path(chunk['source']).open('rb') as source:
                source.seek(chunk['offset'])
                left = chunk['size']
                while left:
                    payload = source.read(min(left, 1024*1024))
                    assert payload
                    output.write(payload)
                    sha.update(payload)
                    md5.update(payload)
                    count += len(payload)
                    left -= len(payload)
    manifest.append({'path': rel, 'runtime_path': '/'+rel, 'size': count,
                     'sha256': sha.hexdigest(), 'md5': md5.hexdigest(), 'chunks': chunks})

rights = {}
dirs = {}
for xml in sorted((tree/'info').glob('manifest_*.xml')):
    root = ET.parse(xml).getroot()
    if root.tag != 'LinkManifest':
        continue
    def walk(element, parts=()):
        if element.tag == 'dir':
            parts += (element.attrib['name'],)
            dirs['/'.join(parts)] = element.attrib
        elif element.tag == 'file':
            path = '/'.join(parts+(element.attrib['name'],))
            assert path not in rights or rights[path] == element.attrib
            rights[path] = element.attrib
        for child in element:
            walk(child, parts)
    walk(root)
verified = 0
runtime = {}
for entry in manifest:
    r = rights.get(entry['path'], {})
    entry['mode'] = int(r.get('mod', '755' if '/bin/' in '/'+entry['path'] else '644'), 8)
    entry['uid'] = int(r.get('uid', '0'))
    entry['gid'] = int(r.get('gid', '0'))
    runtime_entry = dict(entry)
    if '/zipped/' in entry['path']:
        packed = (tree/entry['path']).read_bytes()
        decoded = packed if packed[:4] == b'\x7fELF' else decode_hb_lzo(packed)
        if isinstance(decoded, tuple):
            decoded = decoded[0]
        dest_rel = entry['path'].replace('/zipped/', '/')
        if dest_rel in groups:
            archived = stage/'wrapper-originals'/dest_rel
            archived.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(tree/dest_rel, archived)
        (tree/dest_rel).write_bytes(decoded)
        runtime_entry.update({'path': dest_rel, 'runtime_path': '/'+dest_rel,
                              'size': len(decoded), 'sha256': hashlib.sha256(decoded).hexdigest(),
                              'md5': hashlib.md5(decoded).hexdigest(), 'decoded_from': entry['path']})
        entry['decoded_md5'] = runtime_entry['md5']
    if 'md5' in r:
        assert r['md5'].lower() == runtime_entry['md5'], ('Factory manifest mismatch', entry['path'])
        verified += 1
        entry['factory_md5_verified'] = True
        runtime_entry['factory_md5_verified'] = True
    else:
        entry['factory_md5_verified'] = False
        runtime_entry['factory_md5_verified'] = False
    key = runtime_entry['path']
    if key not in runtime or 'decoded_from' in runtime_entry:
        runtime[key] = runtime_entry

runtime = list(runtime.values())

summary = {'files': len(manifest), 'bytes': sum(e['size'] for e in manifest),
           'factory_md5_verified': verified, 'omitted_records': len(omitted),
           'runtime_bytes': sum(e['size'] for e in runtime),
           'host_symlinks_created': False, 'files_executed': False,
           'sources': [str(p) for p in indexes]}
(stage/'payload-manifest.json').write_text(json.dumps(manifest, indent=2))
(stage/'runtime-manifest.json').write_text(json.dumps(runtime, indent=2))
(stage/'directory-metadata.json').write_text(json.dumps(dirs, indent=2))
(stage/'omitted.json').write_text(json.dumps(omitted, indent=2))
(stage/'staging-summary.json').write_text(json.dumps(summary, indent=2))
print(json.dumps(summary, indent=2))

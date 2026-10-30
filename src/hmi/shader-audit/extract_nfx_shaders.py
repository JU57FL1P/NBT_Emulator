"""Extract exact shader/source pairs from validated factory NFX SHDR chunks."""
from pathlib import Path
import collections,hashlib,json,re,struct

HERE=Path(__file__).resolve().parent
VM=HERE.parent.parent
def sha(b):return hashlib.sha256(b).hexdigest()
def u32(b,p):return struct.unpack_from('<I',b,p)[0]

# Manually reviewed source differences are preserved in source-alias-diffs.txt.
# Every alias is a source explicitly paired with the identical native payload
# in an original factory SHDR record; we do not manufacture replacement GLSL.
ALIAS_REVIEWS={
 '568f7933bbe5cae261b7d40241865e1d05decc362ba62b737376b328df7397b3':
   ('fx_background_right','Factory alternatives differ in comments and local precision: one inherits lowp; this original variant uses explicit mediump locals. Both package the identical native NVuc. Select the original explicit-mediump variant; host precision behavior may differ from NVIDIA.'),
 '70933eeb61345f6fa0db7e94c48cd2c3983f1ae18dc767c46324915a57c463f1':
   (None,'Only an inactive commented-out diagnostic gl_FragColor assignment differs.'),
 '1fe9d33ccb4a18160cf63824ee73628527aec946d87697bafed74cafbd5bc128':
   (None,'Whitespace plus equivalent highp default versus explicit highp position/MVP declarations; identical executable expressions.'),
 'd69c47c5c4cab7b3e50d26d1f7075ad868acd61029f6786955214c10a548cd8f':
   (None,'Comments/whitespace, separate versus grouped uniform declarations, and explicit mediump varying versus mediump default; identical executable expression.'),
 'd029a190ccfdd7d06d35b3995cc6d99dd0f943f8c724c0b7c137c38d085e6b03':
   (None,'Whitespace and explicit mediump varFade versus inherited mediump default; identical executable expressions.'),
 '79e4d8d54c2ff46e164e05b5c9d65600ecdf2e586ba9cb431c15ace376ba3067':
   (None,'Equivalent explicit/default mediump declarations; .xy on vec2 versus bare vec2, and scalar/vec4 multiplication operands reversed. Both have the identical packaged native payload.'),
 'd105a41871259580d374515262bb920b9754865a01c2f0c806d67e513db4d5e1':
   (None,'Whitespace only; original source bytes are retained without normalization.')
}

def extract(row):
    b=Path(row['output']).read_bytes()
    assert sha(b)==row['output_sha256']
    version=u32(b,0);assert version in (13,15),version
    entries=[];chunks=[]
    # SHDR is independently length-delimited. Other asset chunk formats need
    # their own native readers; some NGRD sizes do not advance to the next tag.
    # Validate every shader record in full, without claiming to parse those.
    for match in re.finditer(b'SHDR',b):
        pos=match.start()
        start=pos;tag=b[pos:pos+4];n=u32(b,pos+4);pos+=8;end=pos+n
        assert end<=len(b) and len(tag)==4
        chunks.append({'tag':tag.decode('ascii'),'offset':start,'length':n})
        if tag==b'SHDR':
            name_length=u32(b,pos);pos+=4;name=b[pos:pos+name_length];pos+=name_length
            assert name.endswith(b'\0') and name_length>=2
            name=name[:-1].decode('ascii')
            binary_block_length=u32(b,pos);pos+=4;binary_block_start=pos;binary_block_end=pos+binary_block_length
            assert binary_block_end<end
            if binary_block_length==0:
                chunks[-1]['source_only_program']=name
                # A source-only SHDR has no native payload to hash or map.
                continue
            binaries=[]
            for stage,stage_id in [('vertex',1),('fragment',2)]:
                count=u32(b,pos);pos+=4;offset=pos;blob=b[pos:pos+count];pos+=count
                assert pos<=binary_block_end and blob[:4]==b'NVuc'
                assert u32(blob,24)==count and struct.unpack_from('<H',blob,16)[0]==stage_id
                binaries.append((stage,offset,blob))
            # Third native binary is a separate vendor representation. Retain it
            # as provenance, but do not translate or infer GLSL from its contents.
            auxiliary=[]
            while pos<binary_block_end:
                third_length=u32(b,pos);pos+=4;third_offset=pos;pos+=third_length
                assert pos<=binary_block_end
                auxiliary.append({'offset':third_offset,'length':third_length})
            assert pos==binary_block_end,(name,pos,binary_block_end)
            for stage,offset,blob in binaries:
                count=u32(b,pos);pos+=4;source_offset=pos;source=b[pos:pos+count];pos+=count
                assert pos<=end and source.endswith(b'\0') and b'\0' not in source[:-1]
                source=source[:-1]
                assert b'void main' in source
                assert (b'gl_Position' if stage=='vertex' else b'gl_FragColor') in source
                assert all(c in b'\t\r\n' or 32<=c<127 for c in source)
                digest=sha(blob);source_digest=sha(source)
                binary_path=HERE/'extracted'/f'{digest}.shd'
                source_path=HERE/'extracted'/f'{digest}-{source_digest}.glsl'
                binary_path.parent.mkdir(parents=True,exist_ok=True)
                binary_path.write_bytes(blob);source_path.write_bytes(source)
                entries.append({'binary_sha256':digest,'binary_length':len(blob),'binary_path':str(binary_path),
                                'glsl_path':str(source_path),'glsl_sha256':source_digest,'stage':stage,
                                'gl_shader_type':0x8b31 if stage=='vertex' else 0x8b30,'shader_binary_format':0x890b,
                                'provenance':{'container':row['input'],'container_sha256':row['input_sha256'],
                                  'expanded_container':row['output'],'expanded_sha256':row['output_sha256'],
                                  'container_version':version,'chunk_offset':start,'chunk_length':n,'program_name':name,'binary_offset':offset,
                                  'binary_block_offset':binary_block_start,'binary_block_length':binary_block_length,
                                  'auxiliary_binaries':auxiliary,
                                  'glsl_offset':source_offset,'glsl_length_including_terminator':count}})
            assert pos==end,(name,pos,end)
        pos=end
    return entries,chunks

def main():
    entries=[];container_chunks={}
    for row in json.loads((HERE/'expanded-nfx.json').read_text()):
        es,chunks=extract(row);entries.extend(es);container_chunks[row['input']]=chunks
    groups=collections.defaultdict(list)
    for e in entries:groups[e['binary_sha256']].append(e)
    ambiguous=[]
    for digest,aliases in groups.items():
        sources={Path(e['glsl_path']).read_bytes() for e in aliases}
        if len(sources)>1:ambiguous.append({'binary_sha256':digest,'sources':len(sources),
                                         'programs':[e['provenance']['program_name'] for e in aliases]})
    captures={}  # Runtime captures are optional local diagnostics, never repository inputs.
    for digest,p in captures.items():assert sha(p.read_bytes())==digest
    matched=sorted(set(captures)&set(groups));unmatched=sorted(set(captures)-set(groups))
    assert {x['binary_sha256'] for x in ambiguous}==set(ALIAS_REVIEWS)
    unique=[]
    for digest,aliases in groups.items():
        entry=aliases[0].copy()
        if digest in ALIAS_REVIEWS:
            preferred,reason=ALIAS_REVIEWS[digest]
            if preferred:entry=next(e.copy() for e in aliases if e['provenance']['program_name']==preferred)
            entry['canonical_source_review']=reason
        entry['factory_aliases']=[{'glsl_path':e['glsl_path'],'glsl_sha256':e['glsl_sha256'],
                                  'provenance':e['provenance']} for e in aliases]
        unique.append(entry)
    report={'status':'Exact factory NFX SHDR binary/source pairs; no shader substitution',
            'decompressor_evidence':'HmiMain3D 0x08d49cac..0x08d4a036, native_nrv_decode.asm',
            'source_policy':'Exact original GLSL bytes, excluding only its stored terminating NUL; no source rewriting',
            'entry_count':len(unique),'pair_occurrences':len(entries),'unique_binary_count':len(groups),
            'captured_count':len(captures),'captured_exact_matches':len(matched),'captured_unmatched':unmatched,
            'captured_mapped_count':len(set(captures)&{e['binary_sha256'] for e in unique}),
            'source_aliases_reviewed':ambiguous,'ambiguous_source_aliases_excluded':[],
            'entries':unique}
    (HERE/'native-shader-map.json').write_text(json.dumps(report,indent=2))
    (HERE/'nfx-shader-pairs.json').write_text(json.dumps({'entries':entries,'chunks':container_chunks},indent=2))
    print(json.dumps({k:v for k,v in report.items() if k!='entries'},indent=2))

if __name__=='__main__':main()

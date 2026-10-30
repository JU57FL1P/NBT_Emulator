"""Firmware-free checks for package parsing, runtime isolation and release audit."""
from pathlib import Path
import array,json,struct,sys,tempfile,unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import prepare,release

class PreparationTests(unittest.TestCase):
    def test_public_tree_cannot_be_private_runtime(self):
        with self.assertRaises(ValueError):prepare.private_path(prepare.REPO/'runtime')
    def test_descriptor_payload_offsets_and_truncated_trailer(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();self.assertTrue(root.is_relative_to(Path(tempfile.gettempdir()).resolve()))
            file=root/'package';descriptor=b'TargetPath=/example/;Name=file;Tag=FIL;CPU=Intel;'
            def rec(kind,data):return bytes([kind,0,0])+struct.pack('<I',len(data))+b'\0\0'+data
            data=b'0123456789'+rec(2,descriptor)+rec(4,b'abc')+b'not-a-valid-trailer'
            file.write_bytes(data);doc=prepare.index_package(file)
            payload=next(r for r in doc['records'] if r['type_hex'].startswith('04'))
            self.assertEqual(data[payload['payload_offset']:payload['payload_offset']+payload['length']],b'abc')
            self.assertIn('Name=file;',payload['descriptor'])
    def test_bridge_image_extents_and_checksum(self):
        with tempfile.TemporaryDirectory() as folder:
            r=Path(folder).resolve();self.assertTrue(r.is_relative_to(Path(tempfile.gettempdir()).resolve()))
            for name in ['graphics-bridge/libnbt_graphics_controller.so','compiler-probe/libnbt_tick_10ms.so']:
                p=r/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(b'\x7fELF\x01\x01'+bytes(58))
            image=prepare.pack_bridge(r).read_bytes();words=array.array('I');words.frombytes(image)
            self.assertEqual(sum(words)&0xffffffff,0)
            size,end,start=struct.unpack_from('<III',image,8);self.assertEqual(size,len(image))
            pos=start;files=0
            while struct.unpack_from('<H',image,pos)[0]:
                n=struct.unpack_from('<H',image,pos)[0];mode=struct.unpack_from('<I',image,pos+8)[0]
                if mode&0o170000==0o100000:
                    off,length=struct.unpack_from('<II',image,pos+24);self.assertEqual(off%4096,0)
                    self.assertEqual(image[off:off+length],b'\x7fELF\x01\x01'+bytes(58));files+=1
                pos+=n
            self.assertEqual(files,2);self.assertEqual(pos+4,end)
    def test_public_allowlist(self):
        self.assertGreater(len(release.audit()),20)
    def test_unreviewed_firmware_is_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder).resolve();self.assertTrue(root.is_relative_to(Path(tempfile.gettempdir()).resolve()))
            (root/'public-files.json').write_text(json.dumps({'files':['public-files.json']}))
            (root/'firmware.ifs').write_bytes(b'imagefs\x06')
            with self.assertRaisesRegex(ValueError,'Unreviewed'):release.audit(root)

if __name__=='__main__':unittest.main()

import importlib.util,pathlib,tempfile,unittest,socket
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('merge',pathlib.Path(__file__).parents[1]/'scripts/merge.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
class MergeTests(unittest.TestCase):
    def test_preserves_domestic_and_never_network(self):
        d='#EXTM3U x-tvg-url="https://epg.example/test"\n#EXTINF:-1 tvg-id="A",A\nhttp://192.168.1.2/udp/233.1.1.1:1234\n#EXTINF:-1 tvg-id="A",A4K\nhttp://192.168.1.2/udp/233.1.1.2:1234\n'
        o='#EXTM3U\n#EXTINF:-1,B\nhttp://example.org/test\n'
        with tempfile.TemporaryDirectory() as tmp,patch.object(socket,'getaddrinfo',side_effect=AssertionError('network prohibited')):
            r=pathlib.Path(tmp);(r/'domestic.m3u').write_text(d);(r/'overseas.m3u').write_text(o)
            self.assertEqual(m.merge(r),(2,1));out=(r/'live.m3u').read_text()
            self.assertTrue(out.startswith(d.splitlines()[0]));self.assertIn('\n'.join(d.splitlines()[1:]),out)
            self.assertEqual(out.count('#EXTM3U'),1)
            (r/'overseas.m3u').write_text('#EXTM3U\n');self.assertEqual(m.merge(r),(2,0))
            self.assertIn('A4K',(r/'live.m3u').read_text())
    def test_malformed_keeps_previous(self):
        with tempfile.TemporaryDirectory() as tmp:
            r=pathlib.Path(tmp);(r/'domestic.m3u').write_text('#EXTM3U\nhttp://192.168.1.2/test\n');(r/'overseas.m3u').write_text('#EXTM3U\n');(r/'live.m3u').write_text('previous')
            with self.assertRaises(ValueError):m.merge(r)
            self.assertEqual((r/'live.m3u').read_text(),'previous')
    def test_checker_only_reads_overseas_sources(self):
        s=(pathlib.Path(__file__).parents[1]/'scripts/check.py').read_text()
        self.assertNotIn('domestic.m3u',s);self.assertNotIn("root/'live.m3u'",s)
        self.assertIn("root/'sources.m3u'",s);self.assertIn("root/'overseas.m3u'",s)

import importlib.util, pathlib, unittest, socket, hashlib, subprocess, shutil
from unittest.mock import patch
spec=importlib.util.spec_from_file_location('check',pathlib.Path(__file__).parents[1]/'scripts/check.py')
m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
class Tests(unittest.TestCase):
    def test_addresses(self):
        for address in ['127.0.0.1','10.0.0.1','172.16.1.1','192.168.1.1','169.254.169.254','100.64.0.1','0.0.0.0','::1','fc00::1','fe80::1','::ffff:127.0.0.1','2002:7f00:1::','224.0.0.1','ff02::1','64:ff9b::a00:1','64:ff9b:1::1']:
            self.assertFalse(m.public_address(address),address)
        self.assertTrue(m.public_address('8.8.8.8'))
    def test_mixed_dns_rejected(self):
        records=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,80)) for ip in ['8.8.8.8','127.0.0.1']]
        with patch.object(m.socket,'getaddrinfo',return_value=records):
            with self.assertRaises(m.UnsafeURL):m.resolve_public('http://example.test/live')
    def test_invalid_schemes(self):
        for url in ['file:///etc/passwd','http://user:password@example.com','ftp://example.com','http://example.com/#fragment']:
            with self.assertRaises(m.UnsafeURL):m.resolve_public(url)
    def test_redirect_validation(self):
        class Response:
            status=302
            def getheader(self,k):return 'http://127.0.0.1/private'
        class Connection:
            def __init__(self,*a):pass
            def request(self,*a,**kw):pass
            def getresponse(self):return Response()
            def close(self):pass
        def dns(host,port,**kw):
            return [(socket.AF_INET,socket.SOCK_STREAM,6,'',('127.0.0.1' if host=='127.0.0.1' else '8.8.8.8',port))]
        with patch.object(m.socket,'getaddrinfo',side_effect=dns),patch.object(m,'PinnedHTTP',Connection):
            with self.assertRaises(m.UnsafeURL):m.fetch('http://public.test/live')
    def test_parser(self):
        e=m.parse_entries('#EXTM3U\n#EXTINF:-1 tvg-id="A",Test\nhttp://example.com/a\n')
        self.assertEqual(e[0]['id'],'A')
        with self.assertRaises(ValueError):m.parse_entries('#EXTM3U')
    def test_retention(self):
        e={'id':'A','name':'A','info':'#EXTINF:-1,A','url':'http://8.8.8.8/a'}
        r={'url_hash':hashlib.sha256(e['url'].encode()).hexdigest(),'status':'fail'}
        chosen,s,_=m.select([e],[r],{}); self.assertEqual(len(chosen),1)
        chosen,s,_=m.select([e],[r],s);self.assertEqual(len(chosen),1)
        chosen,s,_=m.select([e],[r],s);self.assertEqual(len(chosen),0)
        r.update(status='pass',max_download_ratio=.1)
        chosen,s,_=m.select([e],[r],s);self.assertEqual(len(chosen),1);self.assertEqual(s['A']['failures'],0)
    def test_unsafe_never_retained(self):
        e={'id':'A','name':'A','url':'http://8.8.8.8/a','info':'#EXTINF:-1,A'}
        r={'url_hash':hashlib.sha256(e['url'].encode()).hexdigest(),'status':'unsafe'}
        chosen,_,_=m.select([e],[r],{});self.assertEqual(chosen,[])
    def test_unsupported_samples_are_untestable(self):
        e={'id':'A','name':'A','url':'http://8.8.8.8/a'}
        for tag in ['#EXT-X-KEY:METHOD=AES-128,URI="http://127.0.0.1/key"','#EXT-X-BYTERANGE:100@0']:
            with patch.object(m,'media_playlist',return_value=([tag],e['url'],0)),patch.object(m,'fetch') as fetch:
                self.assertEqual(m.sample(e)['status'],'untestable')
                fetch.assert_not_called()
    def test_access_denial_is_untestable(self):
        class Response: status=403
        class Connection:
            def __init__(self,*a): pass
            def request(self,*a,**kw): pass
            def getresponse(self): return Response()
            def close(self): pass
        records=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('8.8.8.8',80))]
        with patch.object(m.socket,'getaddrinfo',return_value=records),patch.object(m,'PinnedHTTP',Connection):
            with self.assertRaises(m.Untestable): m.fetch('http://example.test/live')
    def test_untestable_retained_without_claiming_success(self):
        e={'id':'A','name':'A','url':'http://8.8.8.8/a','info':'#EXTINF:-1,A'}
        r={'url_hash':hashlib.sha256(e['url'].encode()).hexdigest(),'status':'untestable'}
        state={'A':{'failures':3,'last_good_url':None}}
        for _ in range(5):
            chosen,state,notes=m.select([e],[r],state)
            self.assertEqual(chosen,[e]); self.assertEqual(state['A']['failures'],0)
            self.assertIsNone(state['A']['last_good_url']); self.assertIn('not established',notes[0])
        unsafe=dict(e,url='http://8.8.4.4/a')
        bad={'url_hash':hashlib.sha256(unsafe['url'].encode()).hexdigest(),'status':'unsafe'}
        chosen,_,_=m.select([unsafe,e],[bad,r],state); self.assertEqual(chosen,[e])
        good=dict(e,url='http://1.1.1.1/a')
        passed={'url_hash':hashlib.sha256(good['url'].encode()).hexdigest(),'status':'pass','max_download_ratio':.2}
        chosen,_,_=m.select([e,good],[r,passed],state); self.assertEqual(chosen,[good])
    def test_sample_pass_requires_decoded_frame(self):
        e={'id':'A','name':'A','url':'http://8.8.8.8/a'}
        lines=['#EXTM3U']+['#EXTINF:5,','a.ts']*3
        metadata=subprocess.CompletedProcess([],0,b'{"streams":[{"codec_type":"video","width":64,"height":64}]}')
        with patch.object(m,'media_playlist',return_value=(lines,e['url'],.1)),patch.object(m,'fetch',return_value=(b'sample',e['url'],.2)),patch.object(m.subprocess,'run',return_value=metadata):
            with patch.object(m,'decode_frame',side_effect=m.Untestable('no frame')):
                self.assertEqual(m.sample(e)['status'],'untestable')
            with patch.object(m,'decode_frame',return_value=1):
                result=m.sample(e)
                self.assertEqual(result['status'],'pass')
                self.assertEqual(result['decoded_frames'],1)
    def test_decode_rejects_metadata_without_frame(self):
        with patch.object(m.subprocess,'run',return_value=subprocess.CompletedProcess([],0,b'')) as run:
            with self.assertRaises(m.Untestable): m.decode_frame(b'headers-only')
            args=run.call_args.args[0]
            self.assertEqual(args[args.index('-protocol_whitelist')+1],'pipe')
            self.assertEqual(args[args.index('-format_whitelist')+1],'mpegts,mov')
            self.assertEqual(run.call_args.kwargs['timeout'],15)
        with patch.object(m.subprocess,'run',side_effect=subprocess.TimeoutExpired('ffmpeg',15)):
            with self.assertRaises(m.Untestable): m.decode_frame(b'bad')
    @unittest.skipUnless(shutil.which('ffmpeg'),'ffmpeg required for offline fixture')
    def test_real_offline_decode(self):
        # Synthetic fixture only, no source URL and no network access.
        generated=subprocess.run(['ffmpeg','-v','error','-f','lavfi','-i',
            'color=c=red:s=64x64:r=25','-frames:v','25','-c:v','mpeg2video',
            '-threads','1','-f','mpegts','pipe:1'],capture_output=True,timeout=15,check=True)
        self.assertEqual(m.decode_frame(generated.stdout),1)
        with self.assertRaises(m.Untestable): m.decode_frame(b'not a video')
        with self.assertRaises(m.Untestable):
            m.decode_frame(b'#EXTM3U\n#EXTINF:10,\nhttp://127.0.0.1/private\n')
    def test_multiple_candidates(self):
        a={'id':'A','name':'A','url':'http://8.8.8.8/a','info':'#EXTINF:-1,A'}
        b=dict(a,url='http://8.8.4.4/a')
        results=[{'url_hash':hashlib.sha256(e['url'].encode()).hexdigest(),'status':'pass','max_download_ratio':ratio} for e,ratio in [(a,.8),(b,.2)]]
        chosen,_,_=m.select([a,b],results,{});self.assertEqual(chosen,[b])
if __name__=='__main__':unittest.main()

import importlib.util, pathlib, unittest, socket, hashlib
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
    def test_multiple_candidates(self):
        a={'id':'A','name':'A','url':'http://8.8.8.8/a','info':'#EXTINF:-1,A'}
        b=dict(a,url='http://8.8.4.4/a')
        results=[{'url_hash':hashlib.sha256(e['url'].encode()).hexdigest(),'status':'pass','max_download_ratio':ratio} for e,ratio in [(a,.8),(b,.2)]]
        chosen,_,_=m.select([a,b],results,{});self.assertEqual(chosen,[b])
if __name__=='__main__':unittest.main()

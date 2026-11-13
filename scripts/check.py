#!/usr/bin/env python3
"""Bounded HLS sampling from public addresses, not a home-network speed guarantee."""
import argparse, concurrent.futures, datetime, hashlib, http.client, ipaddress, json, re
import socket, ssl, subprocess, time, sys
from pathlib import Path
from urllib.parse import urlsplit, urljoin

TIMEOUT = 12
class UnsafeURL(ValueError): pass

def public_address(value):
    ip = ipaddress.ip_address(value)
    return (ip.is_global and not ip.is_multicast and not ip.is_reserved
            and not (ip.version == 6 and (ip.ipv4_mapped or ip.sixtofour or ip.teredo
                or ip in ipaddress.ip_network('64:ff9b::/96')
                or ip in ipaddress.ip_network('64:ff9b:1::/48'))))

def resolve_public(url):
    u = urlsplit(url)
    if u.scheme not in ('http', 'https') or not u.hostname or u.username or u.password or u.fragment:
        raise UnsafeURL('unsupported or credential-bearing URL')
    port = u.port or (443 if u.scheme == 'https' else 80)
    addresses = socket.getaddrinfo(u.hostname, port, type=socket.SOCK_STREAM)
    if not addresses or any(not public_address(a[4][0]) for a in addresses):
        raise UnsafeURL('non-public destination')
    return u, addresses[0]

class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, u, addr):
        super().__init__(u.hostname, u.port or (443 if u.scheme == 'https' else 80), timeout=TIMEOUT)
        self.u, self.addr = u, addr
    def connect(self):
        family, kind, proto, _, sockaddr = self.addr
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(TIMEOUT)
            sock.connect(sockaddr)  # Uses validated IP, never re-resolves the hostname.
            if self.u.scheme == 'https':
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=self.u.hostname)
            self.sock = sock
        except BaseException:
            sock.close()
            raise

def fetch(url, limit=2*1024*1024):
    started = time.monotonic()
    for _ in range(6):
        u, address = resolve_public(url)  # Every redirect is revalidated and pinned.
        connection = PinnedHTTP(u, address)
        try:
            path = u.path or '/'
            if u.query: path += '?' + u.query
            connection.request('GET', path, headers={'User-Agent':'Personal-HLS-Healthcheck/1.0', 'Accept-Encoding':'identity'})
            response = connection.getresponse()
            if response.status in (301,302,303,307,308):
                destination = response.getheader('Location')
                if not destination: raise ValueError('redirect without location')
                url = urljoin(url, destination)
                continue
            if response.status != 200: raise ValueError('HTTP ' + str(response.status))
            chunks, size = [], 0
            while True:
                if time.monotonic() - started > 30: raise TimeoutError('total response deadline')
                part = response.read1(min(65536, limit + 1 - size))
                if not part: break
                chunks.append(part); size += len(part)
                if size > limit: raise ValueError('response size limit')
            return b''.join(chunks), url, time.monotonic() - started
        finally:
            connection.close()
    raise ValueError('too many redirects')

def parse_entries(text):
    entries, info = [], None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('#EXTINF:'): info = line
        elif line and not line.startswith('#') and info:
            if not line.startswith(('http://','https://')): raise ValueError('non-HTTP source')
            name = info.split(',',1)[-1]
            match = re.search(r'tvg-id="([^"]+)"', info)
            entries.append({'id':match[1] if match else name,'name':name,'info':info,'url':line})
            info = None
    if not entries: raise ValueError('empty playlist')
    return entries

def media_playlist(url):
    for _ in range(4):
        data, base, elapsed = fetch(url)
        text = data.decode('utf-8-sig')
        if not text.startswith('#EXTM3U'): raise ValueError('not HLS')
        lines = [x.strip() for x in text.splitlines() if x.strip()]
        variants = []
        for i, line in enumerate(lines[:-1]):
            if line.startswith('#EXT-X-STREAM-INF:') and not lines[i+1].startswith('#'):
                m = re.search(r'(?:^|,)BANDWIDTH=(\d+)',line.split(':',1)[1])
                variants.append((int(m[1]) if m else 0, urljoin(base,lines[i+1])))
        if variants:
            url = max(variants)[1]; continue
        return lines, base, elapsed
    raise ValueError('nested playlists limit')

def sample(entry):
    started=time.monotonic()
    result={'id':entry['id'],'name':entry['name'],'url_hash':hashlib.sha256(entry['url'].encode()).hexdigest()}
    try:
        lines, base, latency=media_playlist(entry['url'])
        if '#EXT-X-ENDLIST' in lines: raise ValueError('VOD/endlist, not a live playlist')
        if any(x.startswith('#EXT-X-KEY:') and 'METHOD=NONE' not in x for x in lines):
            raise ValueError('encrypted media is not tested')
        if any(x.startswith('#EXT-X-BYTERANGE:') for x in lines): raise ValueError('byte-range media unsupported')
        segments=[]; duration=None; init=b''
        for line in lines:
            if line.startswith('#EXT-X-MAP:'):
                match=re.search(r'URI="([^"]+)"',line)
                if match: init,_,_=fetch(urljoin(base,match[1]))
            elif line.startswith('#EXTINF:'):
                duration=float(line.split(':',1)[1].split(',')[0])
                if duration <= 0 or duration > 600: raise ValueError('invalid segment duration')
            elif not line.startswith('#') and duration:
                segments.append((duration,urljoin(base,line))); duration=None
        if len(segments)<3: raise ValueError('fewer than three live segments')
        samples=[]; first=None
        for duration,url in segments[-3:]:
            body,_,seconds=fetch(url,16*1024*1024)
            if not body: raise ValueError('empty segment')
            if first is None: first=init+body
            samples.append({'duration_s':duration,'download_s':round(seconds,3),'bytes':len(body)})
        # Offline parsing only. FFprobe must never follow embedded network references.
        probe=subprocess.run(['ffprobe','-v','error','-protocol_whitelist','pipe','-show_entries','stream=codec_type,width,height','-of','json','-i','pipe:0'],input=first,capture_output=True,timeout=15)
        streams=json.loads(probe.stdout or b'{}').get('streams',[])
        video=[s for s in streams if s.get('codec_type')=='video']
        if not video: raise ValueError('no decodable video track in sample')
        ratios=[s['download_s']/s['duration_s'] for s in samples]
        result.update(status='pass',playlist_response_ms=round(latency*1000),samples=samples,
                      max_download_ratio=round(max(ratios),3),width=video[0].get('width'),height=video[0].get('height'),
                      quality='slow' if max(ratios)>=1 else 'sample_ok')
    except UnsafeURL:
        result.update(status='unsafe',reason='non-public or unsupported destination')
    except Exception as error:
        # Avoid logging source URLs, signed query strings or credentials from exceptions.
        result.update(status='fail',reason=type(error).__name__ + ': ' + str(error)[:100] if isinstance(error,ValueError) else type(error).__name__)
    result['elapsed_s']=round(time.monotonic()-started,2)
    return result

def sample_bounded(entry):
    # A killed child cannot leave DNS, connect or slow-body I/O running in a worker.
    try:
        process = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--probe-json'],
                                 input=json.dumps(entry), text=True, capture_output=True, timeout=90)
        if process.returncode == 0:
            return json.loads(process.stdout)
        reason = 'probe subprocess failed'
    except subprocess.TimeoutExpired:
        reason = '90 second per-channel deadline'
    return {'id':entry['id'], 'name':entry['name'],
            'url_hash':hashlib.sha256(entry['url'].encode()).hexdigest(),
            'status':'fail', 'reason':reason}

def select(entries, results, prior):
    groups={}
    for entry in entries: groups.setdefault(entry['id'],[]).append(entry)
    lookup={r['url_hash']:r for r in results}
    state={}; selected=[]; statuses=[]
    for channel,candidates in groups.items():
        old=prior.get(channel,{})
        good=[e for e in candidates if lookup[hashlib.sha256(e['url'].encode()).hexdigest()]['status']=='pass']
        if good:
            chosen=min(good,key=lambda e:lookup[hashlib.sha256(e['url'].encode()).hexdigest()]['max_download_ratio'])
            state[channel]={'failures':0,'last_good_url':chosen['url']}; selected.append(chosen)
        else:
            failures=old.get('failures',0)+1
            previous=next((e for e in candidates if e['url']==old.get('last_good_url')),None)
            fallback=previous or candidates[0]
            unsafe=lookup[hashlib.sha256(fallback['url'].encode()).hexdigest()]['status']=='unsafe'
            state[channel]={'failures':failures,'last_good_url':old.get('last_good_url')}
            if failures<3 and not unsafe:
                selected.append(fallback); statuses.append(channel + ': retained after temporary failure')
            else: statuses.append(channel + ': quarantined; available in sources.m3u')
    return selected,state,statuses

def main():
    parser=argparse.ArgumentParser(); parser.add_argument('--root',default='.'); args=parser.parse_args()
    root=Path(args.root); entries=parse_entries((root/'sources.m3u').read_text())
    oldpath=root/'state.json'; prior=json.loads(oldpath.read_text()) if oldpath.exists() else {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: results=list(pool.map(sample_bounded,entries))
    chosen,state,notes=select(entries,results,prior)
    timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat()
    # A broad outage should not empty the subscription or increment all failure counters.
    passes=sum(r['status']=='pass' for r in results)
    broad_outage=passes < max(1,len(entries)*0.3)
    if broad_outage:
        notes=['Broad outage: previous selection and failure counts retained; only unsafe destinations removed.']
    report={'checked_at_utc':timestamp,'runner':'cloud runner, not the viewer home network','scope':'3 HLS segments and one offline video probe; not long-term stability or channel-identity verification','broad_outage':broad_outage,'passed':passes,'total_urls':len(entries),'notes':notes,'channels':results}
    (root/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
    if broad_outage:
        # Still remove destinations proven unsafe even during a widespread outage.
        unsafe={r['url_hash'] for r in results if r['status']=='unsafe'}
        livepath=root/'live.m3u'
        if unsafe and livepath.exists():
            previous=parse_entries(livepath.read_text())
            safe=[e for e in previous if hashlib.sha256(e['url'].encode()).hexdigest() not in unsafe]
            livepath.write_text('#EXTM3U\n# Broad outage: previous selection retained except unsafe destinations.\n'+'\n'.join(e['info']+'\n'+e['url'] for e in safe)+'\n')
        print('Broad outage: previous selection and failure counts retained; unsafe destinations excluded.'); return
    header='#EXTM3U\n# Updated '+timestamp+'\n# Cloud sample checks; not guaranteed home-network performance or live identity.\n'
    (root/'live.m3u').write_text(header+'\n'.join(e['info']+'\n'+e['url'] for e in chosen)+'\n')
    oldpath.write_text(json.dumps(state,ensure_ascii=False,indent=2)+'\n')
    print(f'Checked {len(entries)} URLs; passed {passes}; published {len(chosen)} channels.')

if __name__=='__main__':
    if sys.argv[1:] == ['--probe-json']:
        print(json.dumps(sample(json.loads(sys.stdin.read()))))
    else:
        main()

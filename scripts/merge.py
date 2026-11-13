#!/usr/bin/env python3
"""Combine local IPTV metadata and cloud-checked overseas entries, without network I/O."""
from pathlib import Path
import argparse

def playlist(text):
    lines = text.lstrip('\ufeff').splitlines()
    if not lines or not lines[0].startswith('#EXTM3U'):
        raise ValueError('missing M3U header')
    pending = False
    count = 0
    for line in lines[1:]:
        if line.startswith('#EXTINF:'):
            if pending: raise ValueError('missing channel URL')
            pending = True
        elif line.strip() and not line.startswith('#'):
            if not pending: raise ValueError('orphan channel URL')
            if not line.startswith(('http://','https://')): raise ValueError('unsupported URL')
            pending = False
            count += 1
    if pending: raise ValueError('missing final URL')
    return lines[0], lines[1:], count

def merge(root):
    root = Path(root)
    header, domestic, n = playlist((root/'domestic.m3u').read_text(encoding='utf-8-sig'))
    _, overseas, m = playlist((root/'overseas.m3u').read_text(encoding='utf-8-sig'))
    output = header+'\n# Domestic IPTV is preserved as supplied; never cloud-probed.\n'+'\n'.join(domestic)+'\n# Overseas selection follows.\n'+'\n'.join(overseas)+'\n'
    playlist(output)
    temporary = root/'live.m3u.tmp'
    temporary.write_text(output,encoding='utf-8')
    temporary.replace(root/'live.m3u')
    return n,m

if __name__ == '__main__':
    p=argparse.ArgumentParser();p.add_argument('--root',default='.');a=p.parse_args()
    n,m=merge(a.root);print(f'Merged {n} domestic and {m} overseas entries; no network requests.')

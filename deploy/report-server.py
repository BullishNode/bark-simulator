#!/usr/bin/env python3
"""Serve only public recorder artifacts on loopback, never SQLite/wallet state."""
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from pathlib import Path
import argparse
ALLOWED={'/':'index.html','/index.html':'index.html','/report.json':'report.json','/report.md':'report.md','/observations.json':'observations.json','/capital.csv':'capital.csv'}

def handler(root):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            name=ALLOWED.get(self.path.split('?',1)[0]);path=root/name if name else None
            if path is None or not path.is_file() or path.is_symlink():self.send_error(404);return
            data=path.read_bytes()
            self.send_response(200)
            self.send_header('Content-Type',{'html':'text/html; charset=utf-8','json':'application/json','csv':'text/csv','md':'text/plain; charset=utf-8'}[path.suffix[1:]])
            self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def log_message(self,*args):pass
    return Handler
if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('root',type=Path);p.add_argument('--port',type=int,default=9180);a=p.parse_args()
    ThreadingHTTPServer(('127.0.0.1',a.port),handler(a.root.resolve())).serve_forever()

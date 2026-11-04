#!/usr/bin/env python3
"""Local Pages preview with the production /vault443/ URL prefix."""
import argparse
import io
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "dist"


class Handler(SimpleHTTPRequestHandler):
    no_js = False
    no_gsap = False
    section = None
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        if self.no_gsap and self.path.split("?")[0].endswith(("/gsap.min.js", "/ScrollTrigger.min.js")):
            self.send_error(404, "GSAP intentionally unavailable for fallback QA")
            return
        self.path = self.path.removeprefix("/vault443") if self.path.startswith("/vault443/") else self.path
        super().do_GET()

    def send_head(self):
        if self.section and self.path.split('?')[0] in ('/', '/ru/', '/index.html', '/ru/index.html'):
            page = ROOT / ('ru/index.html' if self.path.startswith('/ru') else 'index.html')
            css = '<style>main>:not(#' + self.section + '),.site-footer{display:none!important}</style>'
            body = page.read_text().replace('</head>', css + '</head>').encode()
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(body)))
            self.end_headers()
            return io.BytesIO(body)
        return super().send_head()

    def end_headers(self):
        if self.no_js:
            self.send_header("Content-Security-Policy", "script-src 'none'")
        super().end_headers()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--no-js", action="store_true", help="Preview identical HTML with script execution blocked by CSP")
    parser.add_argument("--no-gsap", action="store_true", help="Exercise enhancement without the animation library")
    parser.add_argument("--section", choices=('routes', 'screenshots', 'download'), help="Isolate one real section for reference overlays")
    args = parser.parse_args()
    Handler.no_js = args.no_js
    Handler.no_gsap = args.no_gsap
    Handler.section = args.section
    print(f"Preview: http://127.0.0.1:{args.port}/vault443/", flush=True)
    ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()

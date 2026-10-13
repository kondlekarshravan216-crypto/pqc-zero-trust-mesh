import http.server
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"service":"backend","status":"ok"}\n'
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
http.server.HTTPServer(("0.0.0.0", 8080), H).serve_forever()

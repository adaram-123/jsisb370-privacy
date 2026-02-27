# reads a text File
# implements a HTTP Server
# presents 2 ports
    # port 8080: webpage (html) that shows a text file of content in text file with no cipher (STATIC) 
    # port 8081: webpage (html) that shows the cipher text (STATIC) *reads text and cipher made, and presentes ciphered code

# go through wifi to another computer
# curl and browse port 8080 
    # and tells you what the text file says no cipher
# curl and browse port 8081
    # and tells you what the text file says with cipher

import sys
import ssl
import html
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

# --- Configuration ---
TEXT_FILE = sys.argv[1] if len(sys.argv) > 1 else "message.txt"
SHIFT = int(sys.argv[2]) if len(sys.argv) > 2 else 3
PORT_PLAIN = 8080
PORT_CIPHER = 8081
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

# --- Caesar Cipher Implementation ---
def caesar_cipher(text: str, shift: int) -> str:
    result =[]
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            result.append(chr((ord(ch) - base + shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

# --- Read source text file ---
try:
    with open(TEXT_FILE, "r", encoding="utf-8") as f:
        PLAIN_TEXT = f.read()
except FileNotFoundError:
    PLAIN_TEXT = (
        "Hello! This is a sample message. \n"
        "The Caesar Cipher shifts each letter by a fixed amount. \n"
        "With a shift of 3: A -> D, B -> E, Z -> C, etc. \n"
    )
    with open(TEXT_FILE, "w", encoding="utf-8") as f:
        f.write(PLAIN_TEXT)
    print(f"[INFO] '{TEXT_FILE}' not found - created a sample file.")

CIPHER_TEXT = caesar_cipher(PLAIN_TEXT, SHIFT)

# --- Load and render HTML ---
def load_html_template(filename: str, replacements: dict) -> bytes:
    path = Path("templates") / filename
    try:
        template = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        print(f"[ERROR] Template not found: {path}")
        sys.exit(1)
    
    for key, value in replacements.items():
        template = template.replace(f"{{{{{key}}}}}", value)
    return template.encode("utf-8")

replacements = {
    "PLAIN_TEXT": html.escape(PLAIN_TEXT),
    "CIPHER_TEXT": html.escape(CIPHER_TEXT),
    "FILENAME": TEXT_FILE,
    "SHIFT": str(SHIFT)
}

# pre-render startup
PAGE_PLAIN = load_html_template("plain.html", replacements)
PAGE_CIPHER = load_html_template("cipher.html", replacements)

CSS_PATH = Path("templates") / "styles.css"
try:
    CSS_BYTES = CSS_PATH.read_bytes()
except FileNotFoundError:
    print(f"[ERROR] styles.css not found at {CSS_PATH}")
    sys.exit(1)

print(f"[INFO] Templates loaded  : plain html, cipher.html, styles.css")

# --- serve css ---
def serve_css(handler):
    handler.send_response(200)
    handler.send_header("Content-Type", "text/css; charset=utf-8")
    handler.end_headers()
    handler.wfile.write(CSS_BYTES)

# --- Request HTML Handler ---
class PlainHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/templates/styles.css":
            serve_css(self)
        else: 
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(PAGE_PLAIN)

    def log_message(self, fmt, *args):
        print(f"[8080] {self.client_address[0]} - {fmt % args}")

class CipherHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/templates/styles.css":
            serve_css(self)
        elif self.path == "/raw":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(CIPHER_TEXT.encode("utf-8"))
        else:
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(PAGE_CIPHER)
    
    def log_message(self, fmt, *args):
        print(f"[8081] {self.client_address[0]} - {fmt % args}")

# --- TLS Context ---
def make_tls_context() -> ssl.SSLContext:
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
        return ctx
    except FileNotFoundError:
        print("[ERROR] cert.pem / key.pem not found.")
        print("        Run: pip install cryptography && python gen_cert.py")
        sys.exit(1)

# --- Start Servers ---
def start_server(handler_class, port, tls_ctx):
    server = HTTPServer(("0.0.0.0", port), handler_class)
    server.socket = tls_ctx.wrap_socket(server.socket, server_side=True)
    print(f"[INFO] HTTPs listening on port {port} -> https://0.0.0.0:{port}")
    server.serve_forever()

if __name__ == "__main__":
    print(f"[INFO] Text file    : {TEXT_FILE}")
    print(f"[INFO] Caesar shift : {SHIFT}")
    print(f"[INFO] TLS cert     : {CERT_FILE}")
    print()

    tls = make_tls_context()

    t1 = threading.Thread(target=start_server, args=(PlainHandler, PORT_PLAIN, tls), daemon=True)
    t2 = threading.Thread(target=start_server, args=(CipherHandler, PORT_CIPHER, tls), daemon=True)
    t1.start()
    t2.start()

    print("[INFO] Wireshark will only see encrypted TLS traffic - no readable content.")
    print("Press Crtl+C to stop. \n")
    try:
        t1.join()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down servers.")
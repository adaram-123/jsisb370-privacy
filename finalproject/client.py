# put ip address of other computer and the specific port they are on
# will retrieve the cipher text and return original text

# just to show

# any ceaser cipher (key or substitution)

import sys
import ssl
import urllib.request

# --- args ---
if len(sys.argv) < 2:
    print("Usage: python client.py <server_ip> <shift>")
    print("       python client.py 192.168.1.42 3")
    print("       python client.py 192.168.1.42 --bruteforce")
    sys.exit(1)

SERVER_IP = sys.argv[1]
PORT = 8081
URL = f"https://{SERVER_IP}:{PORT}/raw"
BRUTEFORCE = len(sys.argv) > 2 and sys.argv[2] == "--bruteforce"
SHIFT = None if BRUTEFORCE else int(sys.argv[2] if len(sys.argv) > 2 else None)

if not BRUTEFORCE and SHIFT is None:
    print("[ERROR] Please provide a shift value or use --bruteforce")
    print("Example: python client.py 192.168.1.42 3")
    sys.exit(1)

# --- caesar decrypt ---
def caesar_decrypt(text: str, shift: int) -> str:
    result = []
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.issupper() else ord('a')
            result.append(chr((ord(ch) - base - shift) % 26 + base))
        else:
            result.append(ch)
    return "".join(result)

# --- TLS context ---
tls_ctx = ssl.create_default_context()
tls_ctx.check_hostname = False
tls_ctx.verify_mode = ssl.CERT_NONE

# --- fetch from server ---
print(f"[INFO] Connecting to {URL} over TLS ...")

try:
    req = urllib.request.Request(URL, headers={"User-Agent": "caesar-client/2.0"})
    with urllib.request.urlopen(req, context=tls_ctx, timeout=10) as resp:
        cipher_text = resp.read().decode("utf-8")
except Exception as e:
    print(f"[ERROR] Could not reach the server: {e}")
    sys.exit(1)

print("[INFO] Connection successful - data was encrypted in transit (TLS). \n")

# --- decode & display ---
print("=" * 60)
print("CIPHER TEXT (received from server)")
print("=" * 60)
print(cipher_text)
print()

if BRUTEFORCE:
    print("=" * 60)
    print("BRUTE FORCE - all 25 possible shifts")
    print("=" * 60)
    for s in range(1, 26):
        decoded = caesar_decrypt(cipher_text, s)
        print(f"Shift {s:2d}: {decoded[:70].strip()}")
else:
    decoded = caesar_decrypt(cipher_text, SHIFT)
    print("=" * 60)
    print(f"DECODED TEXT (Caesar shift reversed by {SHIFT}")
    print("=" * 60)
    print(decoded)
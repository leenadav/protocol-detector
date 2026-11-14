"""One 32 MiB echo through a CONNECT tunnel (used for the splice tracing run)."""
import hashlib, random, socket, sys, threading
port = int(sys.argv[1]); payload = b"\x01\x02LAB" + random.Random(99).randbytes(32 << 20)
s = socket.create_connection(("127.0.0.1", port)); s.sendall(b"CONNECT origin.lab.test:9000 HTTP/1.1\r\nHost: origin.lab.test:9000\r\n\r\n")
head = b""
while b"\r\n\r\n" not in head: head += s.recv(1)
got = bytearray()
def rd():
    while len(got) < len(payload):
        c = s.recv(1 << 16)
        if not c: break
        got.extend(c)
t = threading.Thread(target=rd); t.start(); s.sendall(payload); t.join(60); s.close()
print("intact:", bytes(got) == payload, hashlib.sha256(bytes(got)).hexdigest()[:16])

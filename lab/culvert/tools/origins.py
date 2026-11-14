"""Synthetic lab origins on 203.0.113.10 (RFC 5737 TEST-NET-3, loopback only). No real traffic.

  80   HTTP/1.1          443  HTTPS (lab self-signed certificate)
  22   SSH-like: server-first banner, then echo      25  SMTP-like: 220 greeting, answers EHLO/QUIT
  9000 raw echo (byte-transparency tests)            9001 silent (accepts, never sends)
  5432 PostgreSQL-like: answers 'N' to an SSLRequest
"""
import asyncio, ssl, sys
HOST = "203.0.113.10"
CERTS = sys.argv[1]

async def http(r, w):
    try:
        while True:
            head = await r.readuntil(b"\r\n\r\n")
            path = head.split(b" ")[1].decode("latin1", "replace")
            body = ("lab origin says hello: " + path + "\n").encode()
            w.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            await w.drain()
    except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, IndexError):
        return  # a peer that goes away or sends something else ends this lab connection
    finally:
        w.close()

async def ssh(r, w):
    w.write(b"SSH-2.0-LabOrigin_1.0\r\n"); await w.drain()
    await echo(r, w)

async def smtp(r, w):
    try:
        w.write(b"220 origin.lab.test ESMTP lab\r\n"); await w.drain()
        while True:
            line = await r.readline()
            if not line: break
            cmd = line[:4].upper()
            if cmd in (b"EHLO", b"HELO"): w.write(b"250-origin.lab.test\r\n250 STARTTLS\r\n")
            elif cmd == b"QUIT": w.write(b"221 bye\r\n"); await w.drain(); break
            else: w.write(b"502 not implemented in the lab\r\n")
            await w.drain()
    except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, IndexError):
        return  # a peer that goes away or sends something else ends this lab connection
    finally:
        w.close()

async def echo(r, w):
    try:
        while True:
            data = await r.read(65536)
            if not data: break
            w.write(data); await w.drain()
    except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, IndexError):
        return  # a peer that goes away or sends something else ends this lab connection
    finally:
        w.close()

async def silent(r, w):
    try:
        await r.read()
    finally:
        w.close()

async def postgres(r, w):
    try:
        await r.readexactly(8); w.write(b"N"); await w.drain(); await r.read()
    except (OSError, asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, IndexError):
        return  # a peer that goes away or sends something else ends this lab connection
    finally:
        w.close()

async def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERTS + "/origin.crt", CERTS + "/origin.key")
    ctx.set_alpn_protocols(["http/1.1"])
    servers = [(80, http, None), (443, http, ctx), (22, ssh, None), (25, smtp, None), (9000, echo, None),
               (9001, silent, None), (5432, postgres, None)]
    for port, handler, tls in servers:
        await asyncio.start_server(handler, HOST, port, ssl=tls)
    print("origins up on", HOST, [p for p, _, _ in servers], flush=True)
    await asyncio.Event().wait()

asyncio.run(main())

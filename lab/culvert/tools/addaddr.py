"""Add an IPv4 /32 to the loopback interface over rtnetlink (the container has no `ip` binary)."""
import socket, struct, sys
RTM_NEWADDR, NLM_F = 20, 0x1 | 0x4 | 0x400 | 0x200  # REQUEST|ACK|CREATE|EXCL
IFA_LOCAL, IFA_ADDRESS = 2, 1
def add(addr, ifindex=1):
    raw = socket.inet_aton(addr)
    attrs = b"".join(struct.pack("HH", 8, t) + raw for t in (IFA_LOCAL, IFA_ADDRESS))
    body = struct.pack("BBBBi", socket.AF_INET, 32, 0, 0, ifindex) + attrs
    msg = struct.pack("IHHII", 16 + len(body), RTM_NEWADDR, NLM_F, 1, 0) + body
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0)
    s.send(msg)
    resp = s.recv(4096)
    err = struct.unpack("i", resp[16:20])[0]
    print(addr, "ok" if err in (0, -17) else f"errno {-err}")
for a in sys.argv[1:]:
    add(a)

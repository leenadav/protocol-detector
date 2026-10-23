"""SSH algorithm posture from one SSH_MSG_KEXINIT (RFC 4253 7.1), as closed classes (v0.58).

The KEXINIT name-lists say what a side is willing to negotiate. Only classes
derived from fixed tables leave this module; algorithm names, the cookie and the
lists themselves are never emitted. Nothing is negotiated or verified: a list
is an offer, and the other side's list decides what is selected.
"""

# Key exchange methods by family, strongest first in _KEX_RANK (RFC 4253, 4419, 5656, 8268, 8731, 9142,
# draft-ietf-sshm-mlkem-hybrid-kex, draft-josefsson-ntruprime-ssh).
_KEX = {}
for _name in (b"sntrup761x25519-sha512@openssh.com", b"sntrup761x25519-sha512", b"mlkem768x25519-sha256",
              b"mlkem768nistp256-sha256", b"mlkem1024nistp384-sha384"):
    _KEX[_name] = "pq-hybrid"
for _name in (b"curve25519-sha256", b"curve25519-sha256@libssh.org", b"curve448-sha512",
              b"ecdh-sha2-nistp256", b"ecdh-sha2-nistp384", b"ecdh-sha2-nistp521"):
    _KEX[_name] = "ecdh"
for _name in (b"diffie-hellman-group14-sha256", b"diffie-hellman-group15-sha512", b"diffie-hellman-group16-sha512",
              b"diffie-hellman-group17-sha512", b"diffie-hellman-group18-sha512", b"diffie-hellman-group-exchange-sha256"):
    _KEX[_name] = "dh-sha2"
for _name in (b"diffie-hellman-group1-sha1", b"diffie-hellman-group14-sha1", b"diffie-hellman-group-exchange-sha1"):
    _KEX[_name] = "dh-sha1"
del _name
_KEX_RANK = ("pq-hybrid", "ecdh", "dh-sha2", "dh-sha1")

# Weak offers as (class, names). The class order is the order rows are emitted in.
_WEAK = (
    ("kex-sha1", 0, frozenset(name for name, family in _KEX.items() if family == "dh-sha1")),
    ("hostkey-dss", 1, frozenset((b"ssh-dss", b"ssh-dss-cert-v01@openssh.com"))),
    ("hostkey-rsa-sha1", 1, frozenset((b"ssh-rsa", b"ssh-rsa-cert-v01@openssh.com"))),
    ("cipher-none", 2, frozenset((b"none",))),
    ("cipher-rc4", 2, frozenset((b"arcfour", b"arcfour128", b"arcfour256"))),
    ("cipher-3des-or-64-bit-block", 2, frozenset((b"3des-cbc", b"3des-ctr", b"blowfish-cbc", b"blowfish-ctr", b"cast128-cbc",
                                                  b"cast128-ctr", b"idea-cbc", b"des-cbc", b"des-cbc@ssh.com"))),
    ("cipher-cbc", 2, frozenset((b"aes128-cbc", b"aes192-cbc", b"aes256-cbc", b"rijndael-cbc@lysator.liu.se",
                                 b"twofish-cbc", b"twofish128-cbc", b"twofish192-cbc", b"twofish256-cbc", b"serpent128-cbc",
                                 b"serpent192-cbc", b"serpent256-cbc"))),
    ("mac-none", 4, frozenset((b"none",))),
    ("mac-md5", 4, frozenset((b"hmac-md5", b"hmac-md5-96", b"hmac-md5-etm@openssh.com", b"hmac-md5-96-etm@openssh.com"))),
    ("mac-truncated", 4, frozenset((b"hmac-sha1-96", b"hmac-sha1-96-etm@openssh.com", b"umac-32@openssh.com"))),
)
# Classes that never raise the weak-algorithm risk on their own: ssh-rsa (SHA-1 signatures) stays in many
# client defaults for compatibility; it is reported, and policy can act on it.
RISK_EXEMPT = frozenset(("hostkey-rsa-sha1", "cipher-none"))
_CBC_OR_64 = frozenset().union(*(names for label, _, names in _WEAK if label in ("cipher-cbc", "cipher-3des-or-64-bit-block")))
_STRICT = frozenset((b"kex-strict-c-v00@openssh.com", b"kex-strict-s-v00@openssh.com"))
_CHACHA = b"chacha20-poly1305@openssh.com"


def _names(value):
    """Names of one name-list; the parser has already rejected empty names (RFC 4251 section 6)."""
    return frozenset(value.split(b",")) if value else frozenset()


def _cbc_with_etm(ciphers, macs):
    return bool(ciphers & _CBC_OR_64) and any(name.endswith(b"-etm@openssh.com") for name in macs)


def kexinit_posture(lists):
    """Evidence rows (field, value) for one KEXINIT's ten name-lists; values from closed sets only.

    ssh_kex_class: the strongest key exchange family offered (pq-hybrid, ecdh, dh-sha2, dh-sha1) or other.
    ssh_weak_algorithm: one row per weak class offered in either direction's list.
    ssh_terrapin: strict (a strict-kex marker is offered), exposed (no marker, and ChaCha20-Poly1305 or an
    encrypt-then-MAC MAC with a CBC-mode cipher is offered: CVE-2023-48795), or not-applicable.
    """
    kex, hostkeys = _names(lists[0]), _names(lists[1])
    c2s_ciphers, s2c_ciphers = _names(lists[2]), _names(lists[3])
    c2s_macs, s2c_macs = _names(lists[4]), _names(lists[5])
    ciphers, macs = c2s_ciphers | s2c_ciphers, c2s_macs | s2c_macs
    by_list = {0: kex, 1: hostkeys, 2: ciphers, 4: macs}
    families = {_KEX[name] for name in kex if name in _KEX}
    rows = [("ssh_kex_class", next((family for family in _KEX_RANK if family in families), "other"))]
    rows.extend(("ssh_weak_algorithm", label) for label, index, names in _WEAK if by_list[index] & names)
    if kex & _STRICT:
        terrapin = "strict"
    elif _CHACHA in ciphers or _cbc_with_etm(c2s_ciphers, c2s_macs) or _cbc_with_etm(s2c_ciphers, s2c_macs):
        # Cipher and MAC are negotiated per direction, so CBC/64-bit-block plus EtM must meet in one direction
        # (v0.58 review round 1); ChaCha20-Poly1305 in either direction is enough.
        terrapin = "exposed"
    else:
        terrapin = "not-applicable"
    rows.append(("ssh_terrapin", terrapin))
    return tuple(rows)

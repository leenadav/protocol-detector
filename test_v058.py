"""v0.58: SSH algorithm posture from one KEXINIT (classes only), the SSH risks, and the default KEXINIT read."""
import random
import unittest

from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.risks import RISKS
from protocol_engine.ssh_posture import _KEX, _WEAK, kexinit_posture
from protocol_fixtures import SSH_LEGACY_STREAM, SSH_MODERN_STREAM, ssh_kexinit

BANNER = b"SSH-2.0-Placeholder_1.0\r\n"


def posture(observation):
    rows = {}
    for e in observation.evidence:
        if e.field in ("ssh_kex_class", "ssh_weak_algorithm", "ssh_terrapin"):
            rows.setdefault(e.field, []).append(e.value)
    return rows


def inspect(data, config=None):
    inspector = Inspector(config or Config())
    events = inspector.feed(data)
    return inspector, events


def risks(observation):
    return classify(observation, "tcp", 22).risks


class KexinitPostureTests(unittest.TestCase):
    def test_tables_follow_the_registered_names(self):
        # Families written from the RFC / draft names, independently of the module's tables.
        expected = {"pq-hybrid": {"sntrup761x25519-sha512@openssh.com", "sntrup761x25519-sha512", "mlkem768x25519-sha256",
                                  "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384"},
                    "ecdh": {"curve25519-sha256", "curve25519-sha256@libssh.org", "curve448-sha512", "ecdh-sha2-nistp256",
                             "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"},
                    "dh-sha2": {"diffie-hellman-group14-sha256", "diffie-hellman-group15-sha512", "diffie-hellman-group16-sha512",
                                "diffie-hellman-group17-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group-exchange-sha256"},
                    "dh-sha1": {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}}
        self.assertEqual({family: {name.decode() for name, value in _KEX.items() if value == family} for family in expected}, expected)
        self.assertEqual([label for label, _, _ in _WEAK],
                         ["kex-sha1", "hostkey-dss", "hostkey-rsa-sha1", "cipher-none", "cipher-rc4", "cipher-3des-or-64-bit-block",
                          "cipher-cbc", "mac-none", "mac-md5", "mac-truncated"])

    def test_kex_class_is_the_strongest_offered(self):
        cases = [(b"curve25519-sha256", "ecdh"), (b"diffie-hellman-group1-sha1,curve25519-sha256", "ecdh"),
                 (b"diffie-hellman-group14-sha1", "dh-sha1"), (b"diffie-hellman-group16-sha512,diffie-hellman-group14-sha1", "dh-sha2"),
                 (b"sntrup761x25519-sha512@openssh.com,curve25519-sha256", "pq-hybrid"), (b"mlkem768x25519-sha256", "pq-hybrid"),
                 (b"gss-group14-sha256-,x-unknown@example", "other"), (b"ext-info-c,kex-strict-c-v00@openssh.com", "other"), (b"", "other")]
        for kex, family in cases:
            lists = (kex, b"ssh-ed25519", b"aes128-ctr", b"aes128-ctr", b"hmac-sha2-256", b"hmac-sha2-256", b"none", b"none", b"", b"")
            self.assertEqual(dict(kexinit_posture(lists))["ssh_kex_class"], family, kex)

    def test_weak_classes_and_terrapin(self):
        def classes(**kwargs):
            base = dict(kex=b"curve25519-sha256", hostkeys=b"ssh-ed25519", c2s=b"aes128-ctr", s2c=b"aes128-ctr", m2s=b"hmac-sha2-256", ms2c=b"hmac-sha2-256")
            base.update(kwargs)
            lists = (base["kex"], base["hostkeys"], base["c2s"], base["s2c"], base["m2s"], base["ms2c"], b"none", b"none", b"", b"")
            rows = kexinit_posture(lists)
            return [value for field, value in rows if field == "ssh_weak_algorithm"], dict(rows)["ssh_terrapin"]
        self.assertEqual(classes(), ([], "not-applicable"))
        self.assertEqual(classes(hostkeys=b"ssh-dss"), (["hostkey-dss"], "not-applicable"))
        self.assertEqual(classes(hostkeys=b"rsa-sha2-512,ssh-rsa"), (["hostkey-rsa-sha1"], "not-applicable"))
        self.assertEqual(classes(s2c=b"aes128-ctr,none"), (["cipher-none"], "not-applicable"))      # either direction list counts
        self.assertEqual(classes(c2s=b"arcfour256"), (["cipher-rc4"], "not-applicable"))
        self.assertEqual(classes(c2s=b"blowfish-cbc,aes256-cbc"), (["cipher-3des-or-64-bit-block", "cipher-cbc"], "not-applicable"))
        self.assertEqual(classes(ms2c=b"none"), (["mac-none"], "not-applicable"))
        self.assertEqual(classes(m2s=b"hmac-md5-96"), (["mac-md5"], "not-applicable"))
        self.assertEqual(classes(m2s=b"hmac-sha1-96,umac-32@openssh.com"), (["mac-truncated"], "not-applicable"))
        self.assertEqual(classes(c2s=b"chacha20-poly1305@openssh.com"), ([], "exposed"))
        self.assertEqual(classes(c2s=b"aes128-cbc", m2s=b"hmac-sha2-256-etm@openssh.com"), (["cipher-cbc"], "exposed"))
        self.assertEqual(classes(c2s=b"aes128-ctr", m2s=b"hmac-sha2-256-etm@openssh.com"), ([], "not-applicable"))   # CTR with EtM: not affected
        self.assertEqual(classes(kex=b"curve25519-sha256,kex-strict-s-v00@openssh.com", c2s=b"chacha20-poly1305@openssh.com"), ([], "strict"))
        self.assertEqual(classes(kex=b"curve25519-sha256,kex-strict-c-v00@openssh.com", c2s=b"aes128-cbc", m2s=b"hmac-sha1-etm@openssh.com"),
                         (["cipher-cbc"], "strict"))
        self.assertEqual(classes(c2s=b"aes128-ctr,,aes256-ctr"), ([], "not-applicable"))           # empty names are ignored
        self.assertEqual(classes(c2s=b"AES128-CBC"), ([], "not-applicable"))                       # names are case-sensitive

    def test_default_read_events_and_risks(self):
        for stream, expected_risks in ((SSH_MODERN_STREAM, ()), (SSH_LEGACY_STREAM, ("ssh-terrapin-exposed", "ssh-weak-algorithm-offered"))):
            for config in (Config(), Config(fingerprints=True)):
                inspector, events = inspect(stream, config)
                self.assertEqual([event.kind for event in events], ["updated", "refined"])
                self.assertEqual((inspector.observation.status, inspector._parser, inspector.metrics.bytes_inspected), ("identified", None, len(stream)))
                self.assertEqual(risks(inspector.observation), expected_risks)
                self.assertEqual("hassh" in {e.field for e in inspector.observation.evidence}, config.fingerprints)
        self.assertEqual(posture(inspect(SSH_MODERN_STREAM)[0].observation),
                         {"ssh_kex_class": ["pq-hybrid"], "ssh_terrapin": ["strict"]})
        none = inspect(BANNER + ssh_kexinit(ciphers=b"aes128-ctr,none"))[0].observation
        self.assertEqual(risks(none), ("ssh-none-cipher-offered",))
        rsa_only = inspect(BANNER + ssh_kexinit(hostkeys=b"ssh-rsa"))[0].observation
        self.assertEqual((posture(rsa_only)["ssh_weak_algorithm"], risks(rsa_only)), (["hostkey-rsa-sha1"], ()))   # reported, not a risk alone
        client, server = inspect(SSH_MODERN_STREAM)[0].observation, inspect(SSH_LEGACY_STREAM)[0].observation
        verdict = session_verdict(client, server, "tcp", 22, 100, 100)
        self.assertEqual((verdict.app, verdict.risks), ("ssh", ("ssh-terrapin-exposed", "ssh-weak-algorithm-offered")))
        for name in ("ssh-weak-algorithm-offered", "ssh-none-cipher-offered", "ssh-terrapin-exposed"):
            self.assertIn(name, RISKS)
        text = repr(inspect(SSH_LEGACY_STREAM)[0].observation) + repr(inspect(SSH_MODERN_STREAM)[0].observation)
        for name in (b"diffie-hellman", b"chacha20", b"hmac-md5", b"ssh-dss", b"aes128-cbc", b"mlkem", b"kex-strict"):
            self.assertNotIn(name.decode(), text)

    def test_split_points_and_a_banner_alone(self):
        for stream in (SSH_MODERN_STREAM, SSH_LEGACY_STREAM):
            reference = posture(inspect(stream)[0].observation)
            for split in range(1, len(stream), 7):
                inspector = Inspector()
                kinds = [event.kind for event in inspector.feed(stream[:split]) + inspector.feed(stream[split:])]
                self.assertEqual((kinds, posture(inspector.observation)), (["updated", "refined"], reference), split)
            bytewise = Inspector()
            for index in range(len(stream)):
                bytewise.feed(stream[index:index + 1])
            self.assertEqual(posture(bytewise.observation), reference)
        alone, events = inspect(BANNER)
        self.assertEqual(([event.kind for event in events], alone.end(), posture(alone.observation)), (["updated"], (), {}))
        self.assertEqual((alone.observation.status, alone._parser), ("identified", None))

    def test_rejections_keep_the_identification(self):
        rejected = [ssh_kexinit(msg=21), ssh_kexinit(first_follows=2), ssh_kexinit(ciphers=b"aes\x7f"),
                    b"\x00\x00\x00\x05" + bytes(5), b"\x00\x00\x00\x10" + bytes(4), (40000).to_bytes(4, "big") + bytes(16),
                    ssh_kexinit(kex=b"k" * 4097)]
        for packet in rejected:
            inspector, events = inspect(BANNER + packet)
            inspector.end()
            observation = inspector.observation
            self.assertEqual((observation.status, observation.application_protocol, posture(observation)), ("identified", "ssh", {}), packet[:8].hex())
            self.assertLessEqual(inspector.metrics.bytes_inspected, len(BANNER + packet))
        budget = Inspector(Config(max_bytes=len(BANNER) + 40))
        budget.feed(SSH_LEGACY_STREAM)
        self.assertEqual((budget.observation.status, posture(budget.observation)), ("identified", {}))
        self.assertLessEqual(budget.metrics.bytes_inspected, len(BANNER) + 40)
        generator = random.Random(58)
        for _ in range(400):
            data = bytearray(SSH_LEGACY_STREAM)
            data[generator.randrange(len(b"SSH-2.0-LegacySSH_1.0\r\n"), len(data))] = generator.randrange(256)
            inspector, _ = inspect(bytes(data))
            inspector.end()
            self.assertEqual((inspector.observation.status, inspector._parser), ("identified", None))
            self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
            found = posture(inspector.observation)
            self.assertLessEqual(set(found.get("ssh_terrapin", [])), {"strict", "exposed", "not-applicable"})


if __name__ == "__main__":
    unittest.main()

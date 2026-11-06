"""ONC RPC v2: record marking, CALL/REPLY structures, authentication bounds, dispatch isolation, App-ID mapping."""
import random
import unittest

from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.datagram import VALIDATORS
from protocol_engine.rpc import MAX_AUTH, PROGRAMS
from protocol_fixtures import (DATAGRAM_CASES, MEMCACHED, ONC_RPC_CALL, ONC_RPC_REPLY, RPC_NFS_CALL, RPC_PORTMAP_CALL, RPC_REPLY,
                               RPC_REPLY_DENIED, auth_sys, rpc_call, rpc_record, xdr)


def values(observation):
    return {e.field: e.value for e in observation.evidence}


def stream(data, hint=None, config=None):
    inspector = Inspector(config, protocol_hint=hint)
    inspector.feed(data)
    return inspector


def datagram(data, config=None, hint=None):
    return DatagramInspector(config).inspect(data, hint)


class CallTests(unittest.TestCase):
    def test_portmap_call_over_tcp_and_udp(self):
        for observation in (stream(ONC_RPC_CALL).observation, datagram(RPC_PORTMAP_CALL)):
            self.assertEqual((observation.status, observation.application_protocol), ("identified", "onc-rpc/2"))
            fields = values(observation)
            self.assertEqual((fields["rpc_message"], fields["rpc_program"], fields["rpc_program_version"], fields["rpc_credential"]),
                             ("call", "portmap", "2", "auth-sys"))
            self.assertEqual({e.field: e.strength for e in observation.evidence}["rpc_credential"], "asserted")
            self.assertEqual(classify(observation).app, "portmapper")
            self.assertNotIn("client", repr(observation))      # AUTH_SYS machine name never emitted
        self.assertEqual(stream(ONC_RPC_CALL).observation.scope, "initial_message")
        self.assertEqual(stream(ONC_RPC_CALL).metrics.bytes_inspected, len(ONC_RPC_CALL))

    def test_program_labels_and_applications(self):
        expected = {"portmap": "portmapper", "nfs": "nfs", "mount": "nfs", "nlm": "nfs", "nsm": "nfs", "nfs-acl": "nfs", "rquota": "sun-rpc"}
        versions = {100000: 2, 100003: 3, 100005: 3, 100021: 4, 100024: 1, 100227: 3, 100011: 1}
        for program, label in PROGRAMS.items():
            observation = datagram(rpc_call(program, versions[program], 0))
            self.assertEqual(values(observation)["rpc_program"], label)
            self.assertEqual(classify(observation).app, expected[label], label)
        other = datagram(rpc_call(300000, 1, 1))
        self.assertEqual((values(other)["rpc_program"], classify(other).app), ("other", "sun-rpc"))
        verdict = classify(datagram(RPC_NFS_CALL))
        self.assertEqual((verdict.app, verdict.implicitly_uses), ("nfs", ("sun-rpc",)))
        self.assertEqual(verdict.port_usage, "unknown")
        self.assertEqual(classify(datagram(RPC_NFS_CALL), "udp", 2049).port_usage, "standard")
        self.assertEqual(classify(stream(ONC_RPC_CALL).observation, "tcp", 111).port_usage, "standard")

    def test_program_version_and_header_rules(self):
        for bad in (rpc_call(100000, 5, 3), rpc_call(100003, 1, 0), rpc_call(100005, 4, 0)):
            self.assertNotEqual(datagram(bad).status, "identified", bad)
            self.assertEqual(stream(rpc_record(bad)).observation.status, "unknown")
        for bad in (rpc_call(0, 1, 0), rpc_call(300000, 256, 0), rpc_call(300000, 1, 65536)):
            self.assertEqual(stream(rpc_record(bad)).observation.status, "malformed", bad)
        version3 = xdr(1, 0, 3, 100000, 2, 0) + xdr(0, 0) + xdr(0, 0)
        self.assertNotEqual(stream(rpc_record(version3)).observation.status, "identified")   # the 0x80 route needs version 2
        self.assertEqual(datagram(version3).status, "unknown")
        self.assertEqual(datagram(xdr(1, 2, 2, 100000, 2, 0) + xdr(0, 0) + xdr(0, 0)).status, "unknown")   # message type 2

    def test_authentication_structures(self):
        good = (xdr(0, 0), auth_sys(), auth_sys(b"a" * 255, gids=tuple(range(16))), xdr(2, 8) + bytes(8), xdr(3, 4) + bytes(4),
                xdr(6, 20) + bytes(20))
        for credential in good:
            observation = datagram(rpc_call(100003, 3, 0, credential))
            self.assertEqual(observation.status, "identified", credential)
        self.assertEqual(values(datagram(rpc_call(100003, 3, 0, xdr(6, 20) + bytes(20))))["rpc_credential"], "rpcsec-gss")
        bad = (xdr(0, 4) + bytes(4),                                   # AUTH_NONE with a body
               xdr(1, 8) + bytes(8),                                   # AUTH_SYS too short
               auth_sys(b"a" * 256),                                   # machine name too long
               auth_sys(gids=tuple(range(17))),                        # 17 gids
               auth_sys()[:-4],                                        # length disagrees with gid count
               xdr(1, 24) + xdr(0, 2) + b"ab\x00\x01" + xdr(0, 0, 0),  # non-zero padding
               xdr(1, 24) + xdr(0, 4) + b"a\x01bc" + xdr(0, 0, 0),     # control byte in the name
               xdr(6, MAX_AUTH + 4) + bytes(MAX_AUTH + 4),             # over the opaque_auth limit
               xdr(6, 6) + bytes(8),                                   # unaligned length
               xdr(6, 20) + bytes(16))                                 # truncated body
        for credential in bad:
            observation = datagram(rpc_call(100003, 3, 0, credential))
            self.assertEqual(observation.status, "malformed", credential)
        for flavor in (4, 5, 7, 400000):
            self.assertEqual(datagram(rpc_call(100003, 3, 0, xdr(flavor, 0))).status, "unknown", flavor)
        self.assertEqual(datagram(rpc_call(100003, 3, 0, verifier=auth_sys())).status, "unknown")   # AUTH_SYS never verifies

    def test_arguments_follow_without_inspection(self):
        with_args = rpc_call(100003, 3, 1, args=bytes(range(64)))
        observation = datagram(with_args)
        self.assertEqual(observation.status, "identified")
        self.assertNotIn("rpc_arguments", values(observation))
        self.assertEqual(stream(rpc_record(with_args)).observation.status, "identified")


class ReplyTests(unittest.TestCase):
    def test_accepted_and_denied_replies(self):
        observation = stream(ONC_RPC_REPLY).observation
        fields = values(observation)
        self.assertEqual((observation.scope, fields["rpc_message"], fields["rpc_reply"], fields["rpc_accept_status"]), ("response_header", "reply", "accepted", "success"))
        self.assertEqual(classify(observation).app, "sun-rpc")
        denied = datagram(RPC_REPLY_DENIED)
        self.assertEqual((values(denied)["rpc_reply"], values(denied)["rpc_reject_status"]), ("denied", "auth-error"))
        mismatch = datagram(xdr(1, 1, 1, 0, 2, 2))
        self.assertEqual(values(mismatch)["rpc_reject_status"], "rpc-mismatch")
        for status, label in enumerate(("success", "prog-unavail", "prog-mismatch", "proc-unavail", "garbage-args", "system-err")):
            data = xdr(1, 1, 0) + xdr(0, 0) + xdr(status) + (xdr(2, 4) if status == 2 else b"")
            self.assertEqual(values(datagram(data))["rpc_accept_status"], label)
        self.assertEqual(values(datagram(xdr(1, 1, 0) + xdr(6, 8) + bytes(8) + xdr(0)))["rpc_accept_status"], "success")

    def test_reply_rules(self):
        for bad in (xdr(1, 1, 0) + xdr(0, 0) + xdr(6),                  # accept status 6
                    xdr(1, 1, 0) + xdr(0, 0) + xdr(2, 4, 2),            # inverted version range
                    xdr(1, 1, 0) + xdr(0, 0) + xdr(1, 7),               # bytes after a non-success reply
                    xdr(1, 1, 1, 2, 0),                                 # reject status 2
                    xdr(1, 1, 1, 1, 0), xdr(1, 1, 1, 1, 15),            # auth status outside 1..14
                    xdr(1, 1, 1, 0, 3, 2),                              # inverted range on rpc-mismatch
                    xdr(1, 1, 1, 1, 2, 9)):                             # trailing bytes on a denied reply
            self.assertEqual(datagram(bad).status, "malformed", bad)
            self.assertEqual(stream(rpc_record(bad)).observation.status, "malformed", bad)
        self.assertEqual(datagram(xdr(1, 1, 0) + xdr(1, 0) + xdr(0)).status, "unknown")   # AUTH_SYS verifier
        self.assertEqual(datagram(xdr(1, 1, 2, 0, 0)).status, "unknown")                      # reply status 2 is never selected
        self.assertNotEqual(stream(rpc_record(xdr(1, 1, 2, 0, 0))).observation.status, "identified")

    def test_session_verdict_pairs_call_with_reply(self):
        client, server = stream(ONC_RPC_CALL).observation, stream(ONC_RPC_REPLY).observation
        verdict = session_verdict(client, server, "tcp", 111)
        self.assertEqual((verdict.app, verdict.client_protocol, verdict.server_protocol, verdict.port_usage), ("portmapper", "onc-rpc/2", "onc-rpc/2", "standard"))
        self.assertNotIn("Server direction identified as", " ".join(verdict.reasons))   # sun-rpc is portmapper's carrier, not a conflict


class FramingTests(unittest.TestCase):
    def test_record_marking(self):
        self.assertEqual(stream(rpc_record(RPC_PORTMAP_CALL)).observation.status, "identified")
        fragment = (len(RPC_PORTMAP_CALL)).to_bytes(4, "big") + RPC_PORTMAP_CALL          # last-fragment bit clear
        self.assertNotEqual(stream(fragment).observation.status, "identified")
        self.assertEqual(stream(fragment, hint="onc-rpc").observation.status, "unknown")
        short = (0x80000000 | 16).to_bytes(4, "big") + RPC_PORTMAP_CALL[:16]
        self.assertEqual(stream(short).observation.status, "malformed")
        long = (0x80000000 | (len(RPC_PORTMAP_CALL) + 4)).to_bytes(4, "big") + RPC_PORTMAP_CALL
        inspector = stream(long)
        self.assertEqual(inspector.observation.status, "detecting")
        inspector.feed(bytes(4))
        self.assertEqual(inspector.observation.status, "identified")
        huge = (0x80000000 | 70000).to_bytes(4, "big") + RPC_PORTMAP_CALL
        self.assertNotEqual(stream(huge).observation.status, "identified")   # first byte 0x80, second 0x01: memcached route, no RPC record
        large = (0x80000000 | 0x8000).to_bytes(4, "big") + RPC_PORTMAP_CALL          # 32 KiB record: waits within the budget
        self.assertEqual(stream(large).observation.status, "detecting")
        self.assertEqual(stream(large, config=Config(max_bytes=1024)).observation.status, "budget_exhausted")
        self.assertEqual(stream(rpc_record(RPC_PORTMAP_CALL), config=Config(max_bytes=64)).observation.status, "budget_exhausted")

    def test_every_split_point_and_truncation(self):
        for data in (ONC_RPC_CALL, ONC_RPC_REPLY, rpc_record(RPC_REPLY_DENIED)):
            expected = stream(data).observation
            for split in range(len(data) + 1):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                self.assertEqual(inspector.observation, expected, split)
            for end in range(len(data)):
                inspector = stream(data[:end])
                self.assertEqual(inspector.observation.status, "detecting", end)
        for data in (RPC_NFS_CALL, RPC_REPLY_DENIED, RPC_PORTMAP_CALL[:-16]):   # messages without arguments or results
            for end in range(len(data)):
                self.assertNotEqual(datagram(data[:end]).status, "identified", end)

    def test_memcached_neighbour_and_datagram_isolation(self):
        self.assertEqual(stream(MEMCACHED).observation.application_protocol, "memcached/binary")
        get = b"\x80\x00\x00\x18\x00\x00\x00\x00" + (24).to_bytes(4, "big") + xdr(0) + bytes(8) + b"k" * 24
        self.assertEqual(stream(get).observation.application_protocol, "memcached/binary")
        for payload in (RPC_PORTMAP_CALL, RPC_REPLY, RPC_REPLY_DENIED):
            for family in VALIDATORS:
                result = datagram(payload, hint=family)
                self.assertEqual(result.status == "identified", family == "onc-rpc", (family, result.status))
        for data, family in DATAGRAM_CASES:
            if family != "onc-rpc/2":
                self.assertNotEqual(datagram(data, hint="onc-rpc").status, "identified", family)

    def test_seeded_mutations_are_bounded(self):
        rng = random.Random(5151)
        for base in (ONC_RPC_CALL, ONC_RPC_REPLY, RPC_PORTMAP_CALL, RPC_REPLY_DENIED):
            for _ in range(500):
                data = bytearray(base)
                for _ in range(rng.randrange(1, 4)):
                    data[rng.randrange(len(data))] = rng.randrange(256)
                data = bytes(data)
                if base in (ONC_RPC_CALL, ONC_RPC_REPLY):
                    inspector = Inspector()
                    inspector.feed(data)
                    inspector.end()
                    self.assertIn(inspector.observation.status, ("identified", "unknown", "malformed", "incomplete", "budget_exhausted"))
                    self.assertLessEqual(inspector.metrics.bytes_inspected, len(data))
                    observation = inspector.observation
                else:
                    inspector = DatagramInspector()
                    observation = inspector.inspect(data)
                    self.assertLessEqual(inspector.metrics.parser_calls, 3)
                self.assertNotIn("client", repr(observation))


if __name__ == "__main__":
    unittest.main()

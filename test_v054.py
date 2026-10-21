"""v0.54: LDAP StartTLS shift, IRC family, TURN methods over STUN framing, DNS query-type classes and RPC over HTTP."""
import random
import unittest

from analyze_pcap import Analyzer
from make_sample_pcap import A, B, frame
from packets import decode_packet
from protocol_engine import Config, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.datagram import DatagramInspector
from protocol_engine.dispatch import select
from protocol_engine.irc import split_message
from protocol_engine.wire import dns_query_type_class
from protocol_fixtures import (DNS, DNS_SRV_QUERY, IRC_CAP_LS, IRC_NICK, IRC_PING, IRC_SERVER_NOTICE, IRC_SERVER_WELCOME, IRC_UNPREFIXED_NOTICE,
                               IRC_USER, LDAP, LDAP_STARTTLS_OID, LDAP_STARTTLS_REFUSED, LDAP_STARTTLS_REQUEST, LDAP_STARTTLS_RESPONSE,
                               LDAP_STARTTLS_UNNAMED, LDAP_WHOAMI_REQUEST, NBNS_QUERY, NBSTAT_QUERY, RPC_IN_DATA_REQUEST, STUN, TLS_SERVER13,
                               TURN_ALLOCATE, TURN_ALLOCATE_ERROR, TURN_CHANNEL_BIND, TURN_REFRESH, TURN_SEND_INDICATION, ldap_extended,
                               netbios_name, stun_message)
from proxy_demo import client_hello

HELLO = client_hello()


def stream(data, hint=None, **kwargs):
    inspector = Inspector(protocol_hint=hint, **kwargs)
    inspector.feed(data)
    inspector.end()
    return inspector.observation


def fields(observation, *names):
    return {e.field: e.value for e in observation.evidence if e.field in names}


def ldap_flow(response, client_after=HELLO, server_after=TLS_SERVER13, request=LDAP_STARTTLS_REQUEST):
    """SYN, SYN-ACK, client request, server response, then one more segment per direction."""
    cr, cs = 1000, 9000
    frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18),
              frame(A, B, cr, cs, 24, request), frame(B, A, cs, cr + len(request), 24, response),
              frame(A, B, cr + len(request), cs + len(response), 24, client_after)]
    if server_after:
        frames.append(frame(B, A, cs + len(response), cr + len(request) + len(client_after), 24, server_after))
    return frames


def analyze(frames):
    records = []
    analyzer = Analyzer(on_session=records.append)
    for number, data in enumerate(frames):
        analyzer.process(number, decode_packet(data))
    directions = analyzer.manager.connections[analyzer.manager.key(A, B)]["directions"]
    client, server = directions[A].inspector.observation, directions[B].inspector.observation
    analyzer.finish("done")
    return analyzer, client, server, records[0]


class LDAPStartTLSTests(unittest.TestCase):
    def test_request_alone_never_shifts_and_keeps_the_cleartext_risk(self):
        # Review round 1: the client must wait for the server's answer and may continue in plaintext after a
        # refusal, so the request announces no boundary by itself and does not clear the credential risk.
        request = stream(LDAP_STARTTLS_REQUEST)
        self.assertEqual((request.status, request.application_protocol, request.scope), ("identified", "ldap", "initial_message"))
        self.assertEqual(fields(request, "ldap_message", "ldap_extended", "shift", "shifted_payload"),
                         {"ldap_message": "extended_request", "ldap_extended": "starttls"})
        self.assertIn("cleartext-credential-protocol", classify(request, "tcp", 389).risks)
        followed = stream(LDAP_STARTTLS_REQUEST + HELLO)
        self.assertEqual((followed.application_protocol, followed.encryption, fields(followed, "shift")), ("ldap", None, {}))
        self.assertNotIn(LDAP_STARTTLS_OID.decode(), repr(request))

    def test_named_success_response_shifts_the_server_direction(self):
        response = stream(LDAP_STARTTLS_RESPONSE + TLS_SERVER13)
        self.assertEqual((response.status, response.encryption), ("identified", "tls"))
        self.assertEqual(fields(response, "shift", "shift_from", "selected_tls_version"), {"shift": "ldap-starttls", "shift_from": "ldap", "selected_tls_version": "1.3"})
        verdict = classify(response, "tcp", 389)
        self.assertEqual((verdict.app, verdict.shifted_from, "ldap" in verdict.implicitly_uses), ("ssl", "ldap", True))
        self.assertNotIn("cleartext-credential-protocol", verdict.risks)
        alone = stream(LDAP_STARTTLS_RESPONSE)
        self.assertEqual((alone.application_protocol, alone.scope), ("ldap", "negotiation_response"))
        self.assertEqual(fields(alone, "ldap_message", "ldap_extended", "ldap_result", "shift"),
                         {"ldap_message": "extended_response", "ldap_extended": "starttls", "ldap_result": "success", "shift": "ldap-starttls"})

    def test_unnamed_refused_and_other_extended_operations_do_not_shift(self):
        unnamed = stream(LDAP_STARTTLS_UNNAMED + TLS_SERVER13)
        self.assertEqual((unnamed.application_protocol, unnamed.encryption), ("ldap", None))
        self.assertEqual(fields(unnamed, "ldap_extended", "ldap_result", "shift"), {"ldap_extended": "unnamed", "ldap_result": "success"})
        refused = stream(LDAP_STARTTLS_REFUSED + TLS_SERVER13)
        self.assertEqual(fields(refused, "ldap_extended", "ldap_result", "shift"), {"ldap_extended": "starttls", "ldap_result": "unavailable"})
        whoami = stream(LDAP_WHOAMI_REQUEST)
        self.assertEqual((whoami.application_protocol, fields(whoami, "ldap_extended", "shift")), ("ldap", {"ldap_extended": "whoami"}))
        self.assertEqual(classify(whoami, "tcp", 389).app, "ldap")
        bind = stream(LDAP)
        self.assertEqual(fields(bind, "ldap_message"), {"ldap_message": "bind_request"})
        self.assertIn("cleartext-credential-protocol", classify(bind, "tcp", 389).risks)

    def test_extended_operation_rules(self):
        # requestName must be a numeric OID; StartTLS takes no value; trailing fields and controls are rejected or unsupported.
        self.assertEqual(stream(ldap_extended(1, 0x77, b"starttls")).status, "malformed")
        body = LDAP_STARTTLS_REQUEST[7:] + b"\x81\x01x"
        operation = b"\x77" + bytes((len(body),)) + body
        message = b"\x02\x01\x01" + operation
        self.assertEqual(stream(b"\x30" + bytes((len(message),)) + message).status, "malformed")
        other_value = ldap_extended(2, 0x77, b"1.3.6.1.4.1.4203.1.11.1")
        body = other_value[7:] + b"\x81\x0cVALUE-SECRET"
        operation = b"\x77" + bytes((len(body),)) + body
        message = b"\x02\x01\x02" + operation
        valued = stream(b"\x30" + bytes((len(message),)) + message)
        self.assertEqual((valued.status, fields(valued, "ldap_extended")), ("identified", {"ldap_extended": "password-modify"}))
        self.assertNotIn("VALUE-SECRET", repr(valued))
        body = LDAP_STARTTLS_RESPONSE[7:] + b"\x8b\x01x"
        operation = b"\x78" + bytes((len(body),)) + body
        message = b"\x02\x01\x01" + operation
        self.assertEqual(stream(b"\x30" + bytes((len(message),)) + message).status, "malformed")
        controls = LDAP_STARTTLS_REQUEST + b"\xa0\x00"
        controls = b"\x30" + bytes((controls[1] + 2,)) + controls[2:]
        self.assertEqual(stream(controls).status, "unknown")
        self.assertEqual(stream(ldap_extended(1, 0x78, LDAP_STARTTLS_OID, 124)).status, "malformed")
        self.assertEqual(stream(ldap_extended(1, 0x78, b"not.an.oid", 0)).status, "malformed")
        # The message id is private correlation metadata: readable by the host, never evidence.
        inspector = Inspector()
        inspector.feed(ldap_extended(7, 0x77, LDAP_STARTTLS_OID))
        self.assertEqual(inspector.correlation, {"ldap_message_id": 7})
        self.assertNotIn("7", "".join(e.value for e in inspector.observation.evidence))
        for split in range(1, len(LDAP_STARTTLS_RESPONSE + TLS_SERVER13)):
            inspector = Inspector()
            data = LDAP_STARTTLS_RESPONSE + TLS_SERVER13
            inspector.feed(data[:split])
            inspector.feed(data[split:])
            self.assertEqual(inspector.observation, stream(data), split)

    def test_analyzer_opens_both_directions_on_a_matching_success(self):
        for response in (LDAP_STARTTLS_UNNAMED, LDAP_STARTTLS_RESPONSE):
            analyzer, client, server, record = analyze(ldap_flow(response))
            self.assertEqual(analyzer.counts["ldap_starttls_correlated"], 1, response)
            self.assertEqual((client.encryption, server.encryption), ("tls", "tls"))
            self.assertEqual(fields(client, "shift", "shift_from"), {"shift": "ldap-starttls", "shift_from": "ldap"})
            self.assertEqual(fields(server, "shift", "shift_from", "selected_tls_version"), {"shift": "ldap-starttls", "shift_from": "ldap", "selected_tls_version": "1.3"})
            self.assertEqual((record["app"], record["shifted_from"], record["client_protocol"], record["server_protocol"]), ("ssl", "ldap", "tls", "tls"))
            self.assertNotIn("cleartext-credential-protocol", record["risks"])

    def test_analyzer_keeps_plaintext_ldap_after_a_refusal(self):
        # Review round 1: request, refusal, then an ordinary BindRequest and BindResponse in the clear.
        from protocol_fixtures import LDAP_BIND_RESPONSE
        analyzer, client, server, record = analyze(ldap_flow(LDAP_STARTTLS_REFUSED, client_after=LDAP, server_after=LDAP_BIND_RESPONSE))
        self.assertEqual(analyzer.counts["ldap_starttls_correlated"], 0)
        self.assertEqual((client.application_protocol, server.application_protocol, client.encryption, server.encryption), ("ldap", "ldap", None, None))
        self.assertEqual((fields(client, "shift", "shifted_payload"), fields(server, "shift", "shifted_payload")), ({}, {}))
        self.assertEqual((record["app"], record["shifted_from"]), ("ldap", None))
        self.assertIn("cleartext-credential-protocol", record["risks"])
        # A refusal followed by a ClientHello anyway: the client is not opened, the bytes are not inspected as TLS.
        analyzer, client, server, record = analyze(ldap_flow(LDAP_STARTTLS_REFUSED))
        self.assertEqual((analyzer.counts["ldap_starttls_correlated"], client.encryption, fields(client, "shift")), (0, None, {}))
        self.assertEqual(record["app"], "ldap")

    def test_capture_order_with_the_client_hello_before_the_answer_is_replayed(self):
        # Review round 2: the ClientHello segment is recorded before the server's success. The client inspector was
        # terminal and skipped it; the stream still holds it and replays it into the phase the answer opens.
        from protocol_fixtures import CONNECT_REQUEST, CONNECT_RESPONSE
        for response in (LDAP_STARTTLS_UNNAMED, LDAP_STARTTLS_RESPONSE):
            frames = ldap_flow(response)
            reordered = [frames[0], frames[1], frames[2], frames[4], frames[3], frames[5]]   # ClientHello before the answer
            analyzer, client, server, record = analyze(reordered)
            self.assertEqual(analyzer.counts["ldap_starttls_correlated"], 1, response)
            self.assertEqual((client.encryption, server.encryption), ("tls", "tls"), response)
            self.assertEqual(fields(client, "shift", "shift_from"), {"shift": "ldap-starttls", "shift_from": "ldap"})
            self.assertEqual((record["app"], record["shifted_from"], record["client_protocol"], record["server_protocol"]), ("ssl", "ldap", "tls", "tls"))
            self.assertNotIn("cleartext-credential-protocol", record["risks"])
        # Byte accounting: the replayed ClientHello is counted once, as received when first offered.
        records = []
        analyzer = Analyzer(on_session=records.append)
        frames = ldap_flow(LDAP_STARTTLS_UNNAMED)
        for number, data in enumerate([frames[0], frames[1], frames[2], frames[4], frames[3], frames[5]]):
            analyzer.process(number, decode_packet(data))
        stream = analyzer.manager.connections[analyzer.manager.key(A, B)]["directions"][A]
        self.assertEqual(stream.inspector.metrics.bytes_received, len(LDAP_STARTTLS_REQUEST) + len(HELLO))
        self.assertEqual(stream.inspector.boundary, len(LDAP_STARTTLS_REQUEST))
        self.assertLessEqual(stream.inspector.metrics.bytes_inspected, len(LDAP_STARTTLS_REQUEST) + len(HELLO))
        self.assertEqual([e.kind for e in stream.events], ["shifted"])     # the replay published the merged phase once
        analyzer.finish("done")
        # The request and the ClientHello coalesced in one client segment are split at the message boundary too.
        cr, cs = 1000, 9000
        coalesced = LDAP_STARTTLS_REQUEST + HELLO
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, cr, cs, 24, coalesced),
                  frame(B, A, cs, cr + len(coalesced), 24, LDAP_STARTTLS_UNNAMED),
                  frame(B, A, cs + len(LDAP_STARTTLS_UNNAMED), cr + len(coalesced), 24, TLS_SERVER13)]
        analyzer, client, server, record = analyze(frames)
        self.assertEqual((analyzer.counts["ldap_starttls_correlated"], client.encryption, server.encryption, record["app"]), (1, "tls", "tls", "ssl"))
        # A refusal recorded after the ClientHello still opens nothing: the retained bytes stay uninspected.
        frames = ldap_flow(LDAP_STARTTLS_REFUSED)
        analyzer, client, server, record = analyze([frames[0], frames[1], frames[2], frames[4], frames[3], frames[5]])
        self.assertEqual((analyzer.counts["ldap_starttls_correlated"], client.application_protocol, client.encryption, record["app"]), (0, "ldap", None, "ldap"))
        # The same replay serves the CONNECT correlation when the 2xx and the ServerHello share one segment (v0.33 gap).
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, cr, cs, 24, CONNECT_REQUEST),
                  frame(B, A, cs, cr + len(CONNECT_REQUEST), 24, CONNECT_RESPONSE + TLS_SERVER13),
                  frame(A, B, cr + len(CONNECT_REQUEST), cs + len(CONNECT_RESPONSE) + len(TLS_SERVER13), 24, HELLO)]
        analyzer, client, server, record = analyze(frames)
        self.assertEqual((analyzer.counts["connect_tunnels_correlated"], client.encryption, server.encryption, record["app"]), (1, "tls", "tls", "ssl"))
        self.assertEqual(fields(server, "shift", "selected_tls_version"), {"shift": "http-connect", "selected_tls_version": "1.3"})

    def test_replayed_events_reach_the_analyzer_and_live_output(self):
        # Review round 3: the replay publishes on the direction whose bytes were replayed; the analyzer
        # exposes it as a peer event (or extends the packet's events when it is the same direction) and
        # the live observer emits exactly one classification for it.
        from capture_stream import CaptureRecord
        from live_capture import CaptureMonitor
        from protocol_fixtures import CONNECT_REQUEST, CONNECT_RESPONSE
        frames = ldap_flow(LDAP_STARTTLS_UNNAMED)
        reordered = [frames[0], frames[1], frames[2], frames[4], frames[3], frames[5]]
        analyzer = Analyzer()
        seen = []
        for number, data in enumerate(reordered):
            analyzer.process(number, decode_packet(data))
            seen.append((tuple((e.kind, e.observation.encryption or e.observation.application_protocol) for e in analyzer.last_events),
                         tuple((src, dst, e.kind, e.observation.encryption) for src, dst, e in analyzer.peer_events)))
        # Packet 4 is the server's unnamed success: its own direction identifies LDAP, the client replay publishes TLS.
        self.assertEqual(seen[4], ((("updated", "ldap"),), ((A, B, "shifted", "tls"),)))
        self.assertEqual(seen[3], ((), ()))            # the early ClientHello itself published nothing
        self.assertEqual(seen[5][0], (("shifted", "tls"),))   # the ServerHello completes the server's own phase
        self.assertEqual(seen[5][1], ())
        self.assertEqual(sum(len(peer) for _, peer in seen), 1)
        analyzer.finish("done")
        # Live output: one TLS classification for the client direction, carried by the server packet's turn.
        events = []
        monitor = CaptureMonitor(events.append)
        for number, data in enumerate(reordered):
            monitor.accept(CaptureRecord(number, data, len(data), 1), number)
        monitor.analyzer.finish("done")
        classifications = [(e["source"], e["destination"], e["event"], e["protocol"], e["app"]) for e in events if e["type"] == "classification"]
        self.assertEqual(classifications.count((A, B, "shifted", "tls", "ssl")), 1)
        self.assertEqual(classifications.count((B, A, "shifted", "tls", "ssl")), 1)
        self.assertEqual([c for c in classifications if c[2] == "shifted"], [(A, B, "shifted", "tls", "ssl"), (B, A, "shifted", "tls", "ssl")])
        self.assertEqual(monitor.counts["identified"], 4)   # ldap request, ldap response, two TLS phases
        records = [e for e in events if e["type"] == "session"]
        self.assertEqual((len(records), records[0]["app"], records[0]["shifted_from"]), (1, "ssl", "ldap"))
        # CONNECT 2xx coalesced with the ServerHello: the replay is on the packet's own direction and extends its events.
        cr, cs = 1000, 9000
        frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18), frame(A, B, cr, cs, 24, CONNECT_REQUEST),
                  frame(B, A, cs, cr + len(CONNECT_REQUEST), 24, CONNECT_RESPONSE + TLS_SERVER13),
                  frame(A, B, cr + len(CONNECT_REQUEST), cs + len(CONNECT_RESPONSE) + len(TLS_SERVER13), 24, HELLO)]
        analyzer = Analyzer()
        for number, data in enumerate(frames):
            analyzer.process(number, decode_packet(data))
            if number == 3:
                self.assertEqual([(e.kind, e.observation.application_protocol or e.observation.encryption) for e in analyzer.last_events],
                                 [("updated", "http/1.1"), ("shifted", "tls")])
                self.assertEqual(analyzer.peer_events, ())
        events = []
        monitor = CaptureMonitor(events.append)
        for number, data in enumerate(frames):
            monitor.accept(CaptureRecord(number, data, len(data), 1), number)
        classifications = [(e["source"], e["destination"], e["event"], e["protocol"]) for e in events if e["type"] == "classification"]
        self.assertEqual(classifications.count((B, A, "shifted", "tls")), 1)

    def test_replay_preconditions(self):
        inspector = Inspector()
        inspector.feed(LDAP_STARTTLS_REQUEST)
        self.assertEqual(inspector.boundary, len(LDAP_STARTTLS_REQUEST))
        with self.assertRaises(ValueError):
            inspector.replay(HELLO)                      # no phase opened
        inspector.feed(HELLO)                            # skipped while terminal
        self.assertTrue(inspector.open_shift("ldap-starttls", "tls"))
        with self.assertRaises(ValueError):
            inspector.replay(HELLO + b"x")               # more than was skipped
        with self.assertRaises(TypeError):
            inspector.replay("text")
        events = inspector.replay(HELLO)
        self.assertEqual([e.kind for e in events], ["shifted"])
        self.assertEqual((inspector.observation.encryption, inspector.metrics.bytes_received), ("tls", len(LDAP_STARTTLS_REQUEST) + len(HELLO)))
        with self.assertRaises(ValueError):
            inspector.replay(HELLO)                      # the phase is finished
        own = Inspector()
        own.feed(LDAP_STARTTLS_RESPONSE)                 # the named success shifts by itself, not by the peer
        self.assertIsNone(own.boundary)
        with self.assertRaises(ValueError):
            own.replay(TLS_SERVER13)
        self.assertEqual(stream(LDAP_STARTTLS_RESPONSE + TLS_SERVER13).encryption, "tls")

    def test_analyzer_requires_the_same_message_id(self):
        # Review round 1: an unnamed success for another outstanding operation must not open TLS.
        other_success = ldap_extended(2, 0x78, None, 0)
        analyzer, client, server, record = analyze(ldap_flow(other_success, client_after=LDAP, server_after=ldap_extended(2, 0x78, None, 0)))
        self.assertEqual(analyzer.counts["ldap_starttls_correlated"], 0)
        self.assertEqual((client.application_protocol, server.application_protocol, fields(client, "shift"), fields(server, "shift")), ("ldap", "ldap", {}, {}))
        self.assertEqual(record["app"], "ldap")
        # The same mismatch with a named success: the server shifts by its own structure, the client stays LDAP.
        named_other = ldap_extended(2, 0x78, LDAP_STARTTLS_OID, 0)
        analyzer, client, server, record = analyze(ldap_flow(named_other))
        self.assertEqual((analyzer.counts["ldap_starttls_correlated"], client.encryption, fields(client, "shift")), (0, None, {}))
        self.assertEqual((server.encryption, fields(server, "shift")), ("tls", {"shift": "ldap-starttls"}))
        self.assertNotIn("ldap_message_id", repr(record))


class IRCTests(unittest.TestCase):
    CLIENT = ((IRC_NICK, "nick", "initial_message"), (IRC_CAP_LS, "cap", "initial_message"),
              (IRC_UNPREFIXED_NOTICE, "notice", "protocol_header"), (IRC_PING, "ping", "protocol_header"))
    SERVER = ((IRC_SERVER_NOTICE, "notice"), (IRC_SERVER_WELCOME, "numeric"), (b":irc.example.org PING :abc\r\n", "ping"),
              (b":irc.example.org CAP * LS :multi-prefix sasl\r\n", "cap"), (b":alice!~a@192.0.2.1 NICK :alice2\r\n", "nick"),
              (b":irc.example.org 433 * alice :Nickname is already in use\r\n", "numeric"))

    def test_registration_and_server_lines_identify_with_closed_labels(self):
        for data, label, scope in self.CLIENT:
            observation = stream(data)
            self.assertEqual((observation.status, observation.application_protocol, observation.scope), ("identified", "irc", scope), data)
            self.assertEqual(fields(observation, "irc_message"), {"irc_message": label})
            self.assertEqual(classify(observation, "tcp", 6667).app, "irc")
            self.assertEqual(classify(observation, "tcp", 6667).port_usage, "standard")
        for data, label in self.SERVER:
            observation = stream(data)
            self.assertEqual((observation.status, observation.application_protocol, observation.scope), ("identified", "irc", "protocol_header"), data)
            self.assertEqual(fields(observation, "irc_message"), {"irc_message": label})
            self.assertNotIn("alice", repr(observation.evidence))
            self.assertNotIn("example", repr(observation.evidence))
        self.assertEqual(select(b":"), "irc")
        pass_line = stream(b"PASS s3cret\r\n")
        self.assertEqual((pass_line.status, fields(pass_line, "ambiguous_candidates")), ("unknown", {"ambiguous_candidates": "ftp,pop3,irc"}))
        self.assertNotIn("s3cret", repr(pass_line))
        user = stream(b"USER alice\r\n")
        self.assertEqual(fields(user, "ambiguous_candidates"), {"ambiguous_candidates": "ftp,pop3"})
        self.assertEqual(session_verdict(stream(IRC_NICK), stream(IRC_SERVER_NOTICE), "tcp", 6667, 40, 60, True, None).app, "irc")

    def test_four_parameter_user_is_ambiguous_with_ftp_until_the_server_decides(self):
        # Review round 1: an FTP user name may contain spaces (RFC 959), so the IRC USER form is not disjoint from FTP.
        user = stream(IRC_USER)
        self.assertEqual((user.status, user.application_protocol), ("unknown", None))
        self.assertEqual([(e.field, e.value, e.strength) for e in user.evidence], [("ambiguous_candidates", "ftp,irc", "context")])
        self.assertNotIn("alice", repr(user))
        self.assertNotIn("Alice", repr(user))
        self.assertEqual(session_verdict(user, stream(IRC_SERVER_NOTICE), "tcp", 6667, 40, 60, True, None).app, "irc")
        ftp = session_verdict(user, stream(b"220 ftp.example.org FTP server ready\r\n"), "tcp", 21, 40, 60, True, None)
        self.assertEqual((ftp.app, ftp.status), ("ftp", "correlated"))
        self.assertEqual(session_verdict(user, None, "tcp", 6667, 40, 0, True, None).app, "unknown-tcp")
        hinted = stream(IRC_USER, "irc")
        self.assertEqual((hinted.application_protocol, fields(hinted, "irc_message")), ("irc", {"irc_message": "user"}))
        self.assertEqual(stream(b"USER a b c d e\r\n", "irc").status, "malformed")
        self.assertEqual(stream(b"USER alice 0 * :Alice Example extra words\r\n").status, "unknown")   # trailing parameter keeps it four

    def test_grammar_rules(self):
        malformed = (b"NICK\r\n", b"NICK 1abc\r\n", b"NICK a b\r\n", b"NICK " + b"a" * 65 + b"\r\n", b"USER a b c d e\r\n",
                     b"USER a b c :" + b"x" * 300 + b"\r\n", b"CAP\r\n", b"CAP FOO\r\n", b"CAP LS 30\r\n", b"CAP LS 302 x y\r\n",
                     b"NOTICE alice :hi\r\n", b"PING\r\n", b":irc.example.org 001\r\n", b":irc.example.org 001 #chan :x\r\n",
                     b": NOTICE * :x\r\n", b":irc.example.org\r\n", b":irc.example.org  NOTICE * :x\r\n", b":a!b PRIVMSG x :y\r\n",
                     b":irc.example.org NOTICE *\r\n", b":irc.example.org 001 alice " + b" ".join([b"p"] * 16) + b"\r\n",
                     b":irc.example.org NOTICE * :" + b"x" * 600 + b"\r\n", b"NICK alice\n")
        for data in malformed:
            observation = stream(data)
            self.assertIn(observation.status, ("malformed", "budget_exhausted"), (data, observation))
        unsupported = (b":irc.example.org FOOBAR x\r\n", b":alice!a@h TOPIC #c :t\r\n")
        for data in unsupported:
            self.assertEqual(stream(data).status, "unknown", data)
        prefix, command, params = split_message(b":nick!user@host PRIVMSG #chan :hello world")
        self.assertEqual((prefix, command, params), (b"nick!user@host", b"PRIVMSG", [b"#chan", b"hello world"]))
        self.assertEqual(stream(b"USER alice 0 * :Alice Example\r\n", "irc").application_protocol, "irc")
        self.assertEqual(stream(b"PASS secret\r\n", "irc").application_protocol, "irc")
        self.assertEqual(stream(b"GET / HTTP/1.1\r\n\r\n", "irc").status, "unknown")

    def test_split_points_and_mutations_are_bounded(self):
        rng = random.Random(54)
        for data, _, _ in self.CLIENT + tuple((d, label, "protocol_header") for d, label in self.SERVER):
            whole = stream(data)
            for split in range(1, len(data)):
                inspector = Inspector()
                inspector.feed(data[:split])
                inspector.feed(data[split:])
                inspector.end()
                self.assertEqual(inspector.observation, whole, (data, split))
            for _ in range(40):
                changed = bytearray(data)
                changed[rng.randrange(len(changed))] = rng.randrange(256)
                observation = stream(bytes(changed))
                self.assertIn(observation.status, ("identified", "unknown", "malformed", "incomplete", "budget_exhausted"))
                if observation.status == "identified" and observation.application_protocol == "irc":
                    self.assertNotIn("alice", repr(observation.evidence))
        self.assertEqual(stream(b":" + b"a" * 600).status, "malformed")      # 512-byte IRC line limit, before any newline
        self.assertEqual(stream(b":" + b"a" * 500).status, "incomplete")
        self.assertEqual(stream(b"NICK " + b"a" * 600, "irc").status, "malformed")   # the hinted parser enforces it too
        # Review round 1: the shared text route (NICK/USER/CAP without a hint) is bounded by max_line, not 512,
        # until the line completes; a complete line over 510 bytes is then malformed.
        for verb in (b"NICK ", b"USER ", b"CAP LS "):
            self.assertEqual(stream(verb + b"a" * 600).status, "incomplete", verb)
            self.assertEqual(stream(verb + b"a" * 600 + b"\r\n").status, "malformed", verb)
            self.assertEqual(stream(verb + b"a" * 9000).status, "budget_exhausted", verb)


class TURNTests(unittest.TestCase):
    def test_turn_methods_identify_with_method_and_class(self):
        expected = ((TURN_ALLOCATE, "allocate", "request"), (TURN_ALLOCATE_ERROR, "allocate", "error-response"), (TURN_REFRESH, "refresh", "request"),
                    (TURN_CHANNEL_BIND, "channel-bind", "request"), (TURN_SEND_INDICATION, "send", "indication"), (STUN, "binding", "request"))
        for data, method, klass in expected:
            datagram = DatagramInspector().inspect(data)
            self.assertEqual((datagram.status, datagram.application_protocol), ("identified", "stun"), data)
            self.assertEqual(fields(datagram, "stun_method", "stun_class"), {"stun_method": method, "stun_class": klass})
            self.assertEqual(classify(datagram, "udp", 3478).app, "turn" if method != "binding" else "stun")
            tcp = stream(data)
            self.assertEqual((tcp.application_protocol, fields(tcp, "stun_method", "stun_class")), ("stun", {"stun_method": method, "stun_class": klass}))
        self.assertNotIn("example.org", repr(DatagramInspector().inspect(TURN_ALLOCATE_ERROR)))
        self.assertNotIn("Unauthorized", repr(DatagramInspector().inspect(TURN_ALLOCATE_ERROR)))
        turn = classify(DatagramInspector().inspect(TURN_ALLOCATE), "udp", 3478)
        self.assertEqual((turn.port_usage, "stun" in turn.implicitly_uses), ("standard", True))

    def test_turn_attribute_and_class_rules(self):
        malformed = (stun_message(0x0006),                                             # Send as a request
                     stun_message(0x0007),                                             # Data as a request
                     stun_message(0x0013),                                             # Allocate as an indication
                     stun_message(0x0106),                                             # Send as a success response
                     stun_message(0x0003, b"\x00\x19\x00\x04\x05\x00\x00\x00"),          # REQUESTED-TRANSPORT neither UDP nor TCP
                     stun_message(0x0003, b"\x00\x19\x00\x04\x11\x01\x00\x00"),          # reserved bytes set
                     stun_message(0x0003, b"\x00\x19\x00\x08\x11\x00\x00\x00\x00\x00\x00\x00"),  # wrong size
                     stun_message(0x0009, b"\x00\x0c\x00\x04\x30\x00\x00\x00"),          # CHANNEL-NUMBER below 0x4000
                     stun_message(0x0009, b"\x00\x0c\x00\x04\x40\x00\x00\x01"),          # CHANNEL-NUMBER reserved bytes
                     stun_message(0x0003, b"\x00\x18\x00\x01\x01\x00\x00\x00"),          # EVEN-PORT reserved bits
                     stun_message(0x0113, b"\x00\x09\x00\x04\x00\x00\x07\x01"),          # ERROR-CODE class 7
                     stun_message(0x0113, b"\x00\x09\x00\x04\x00\x01\x04\x01"),          # ERROR-CODE reserved
                     stun_message(0x0113, b"\x00\x09\x00\x03\x00\x00\x04"),              # ERROR-CODE too short
                     stun_message(0x0003, b"\x00\x14\x00\x04abc"),                       # length past message
                     stun_message(0x0003, b"\x00\x06\x00\x04ab\x00\x00" + b"\x00\x06\x02\x02" + b"u" * 514 + b"\x00\x00"))
        for data in malformed:
            self.assertEqual(DatagramInspector().inspect(data).status, "malformed", data[:4].hex())
            self.assertNotEqual(stream(data).status, "identified", data[:4].hex())
        self.assertEqual(DatagramInspector().inspect(stun_message(0x000e)).status, "unknown")          # method 14 undefined
        binding_indication = DatagramInspector().inspect(stun_message(0x0011))                            # RFC 5389 keepalive
        self.assertEqual(fields(binding_indication, "stun_method", "stun_class"), {"stun_method": "binding", "stun_class": "indication"})
        self.assertEqual(classify(binding_indication, "udp", 3478).app, "stun")
        data_indication = stun_message(0x0017, b"\x00\x12\x00\x08\x00\x01\x30\x39\xe1\x12\xa4\x42" + b"\x00\x13\x00\x01x\x00\x00\x00")
        self.assertEqual(fields(DatagramInspector().inspect(data_indication), "stun_method", "stun_class"), {"stun_method": "data", "stun_class": "indication"})
        realm_too_long = stun_message(0x0003, b"\x00\x14\x03\x00" + b"r" * 768)
        self.assertEqual(DatagramInspector().inspect(realm_too_long).status, "malformed")
        connection_attempt = stun_message(0x001c, b"\x00\x2a\x00\x04\x00\x00\x00\x01" + b"\x00\x12\x00\x08\x00\x01\x30\x39\xe1\x12\xa4\x42")
        self.assertEqual(fields(DatagramInspector().inspect(connection_attempt), "stun_method", "stun_class"), {"stun_method": "connection-attempt", "stun_class": "indication"})


class DNSQueryTypeTests(unittest.TestCase):
    def test_netbios_name_service_is_told_from_dns_by_label_and_type(self):
        nbns = DatagramInspector().inspect(NBNS_QUERY)
        self.assertEqual((nbns.application_protocol, fields(nbns, "dns_query_type", "dns_message")), ("dns", {"dns_query_type": "nb", "dns_message": "query"}))
        self.assertEqual(classify(nbns, "udp", 137).app, "netbios-ns")
        self.assertEqual(classify(nbns, "udp", 137).port_usage, "standard")
        nbstat = DatagramInspector().inspect(NBSTAT_QUERY)
        self.assertEqual((fields(nbstat, "dns_query_type"), classify(nbstat, "udp", 137).app), ({"dns_query_type": "nbstat"}, "netbios-ns"))
        srv = DatagramInspector().inspect(DNS_SRV_QUERY)
        self.assertEqual((fields(srv, "dns_query_type"), classify(srv, "udp", 53).app), ({"dns_query_type": "srv"}, "dns"))
        self.assertEqual(fields(DatagramInspector().inspect(DNS), "dns_query_type"), {"dns_query_type": "a"})
        self.assertEqual(dns_query_type_class(b"example.com", 32), "other")
        self.assertEqual(dns_query_type_class(b"z" * 32 + b".example", 32), "other")        # 'z' is outside the A-P alphabet
        self.assertEqual(dns_query_type_class(b"a" * 32 + b".example", 32), "nb")           # expanded names are lowercase
        self.assertEqual(dns_query_type_class(b"z" * 32, 33), "srv")
        self.assertEqual(dns_query_type_class(b"", 1), "a")
        self.assertEqual(dns_query_type_class(b"x", 65), "https")
        self.assertEqual(dns_query_type_class(b"x", 99), "other")
        tcp = stream(b"\x00" + bytes((len(NBNS_QUERY),)) + NBNS_QUERY)
        self.assertEqual((tcp.application_protocol, fields(tcp, "dns_query_type")), ("dns", {"dns_query_type": "nb"}))
        self.assertNotIn("FILESERVER", repr(nbns))
        self.assertNotIn(netbios_name(b"FILESERVER")[1:33].decode(), repr(nbns))
        with_contexts = DatagramInspector(Config(retain_contexts=True)).inspect(NBNS_QUERY)
        self.assertEqual(fields(with_contexts, "dns_query_type"), {"dns_query_type": "nb"})


class RPCOverHTTPTests(unittest.TestCase):
    def test_rpc_methods_name_the_application(self):
        request = stream(RPC_IN_DATA_REQUEST)
        self.assertEqual((request.status, request.application_protocol, fields(request, "http_method")), ("identified", "http/1.1", {"http_method": "RPC_IN_DATA"}))
        verdict = classify(request, "tcp", 443)
        self.assertEqual((verdict.app, "web-browsing" in verdict.implicitly_uses, verdict.port_usage), ("ms-rpc-over-http", True, "standard"))
        for method in (b"RPC_OUT_DATA", b"RPC_CONNECT"):
            observation = stream(method + b" /rpc/rpcproxy.dll HTTP/1.1\r\nHost: mail.example.org\r\n\r\n")
            self.assertEqual((observation.application_protocol, classify(observation, "tcp", 80).app), ("http/1.1", "ms-rpc-over-http"))
        extension = stream(b"RPC_OTHER /x HTTP/1.1\r\nHost: h\r\n\r\n")
        self.assertEqual((fields(extension, "http_method"), classify(extension, "tcp", 80).app), ({"http_method": "extension"}, "web-browsing"))
        self.assertNotIn("rpcproxy", repr(request.evidence))


if __name__ == "__main__":
    unittest.main()

"""v0.33: the server side of a CONNECT tunnel is inspected once the host correlates both directions."""
import unittest

from analyze_pcap import Analyzer
from make_sample_pcap import A, B, frame
from packets import decode_packet
from protocol_engine import Config, Inspector
from protocol_engine.appid import session_verdict
from protocol_fixtures import CONNECT_REQUEST, CONNECT_RESPONSE, TLS_SERVER13
from proxy_demo import client_hello

HELLO = client_hello()
REQUEST = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
FORBIDDEN = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"


def flow(request=CONNECT_REQUEST, response=CONNECT_RESPONSE, client_tunnel=HELLO, server_tunnel=TLS_SERVER13, order=None):
    cr, cs = 1000, 9000
    frames = [frame(A, B, 999, 0, 2), frame(B, A, 8999, 1000, 18),
              frame(A, B, cr, cs, 24, request), frame(B, A, cs, cr + len(request), 24, response),
              frame(A, B, cr + len(request), cs + len(response), 24, client_tunnel),
              frame(B, A, cs + len(response), cr + len(request) + len(client_tunnel), 24, server_tunnel)]
    if order:
        frames = [frames[i] for i in order]
    return frames


def run(frames):
    records = []
    analyzer = Analyzer(on_session=records.append)
    kinds = []
    for number, data in enumerate(frames):
        analyzer.process(number, decode_packet(data))
        kinds.extend((event.kind, event.observation.transport) for event in analyzer.last_events)
    key = analyzer.manager.key(A, B)
    directions = analyzer.manager.connections[key]["directions"]
    client, server = directions[A].inspector, directions[B].inspector
    analyzer.finish("done")
    return analyzer, client, server, records[0] if records else None


def fields(observation, *names):
    return {e.field: (e.value, e.source) for e in observation.evidence if e.field in names}


class TunnelCorrelationTests(unittest.TestCase):
    def test_server_direction_inspects_the_tunnel_in_either_capture_order(self):
        for order in (None, [0, 1, 3, 2, 4, 5]):
            analyzer, client, server, record = run(flow(order=order))
            self.assertEqual(analyzer.counts["connect_tunnels_correlated"], 1)
            self.assertEqual((client.observation.encryption, server.observation.encryption), ("tls", "tls"))
            self.assertEqual(fields(client.observation, "shift"), {"shift": ("http-connect", "wire")})
            self.assertEqual(fields(server.observation, "shift", "shift_from"), {"shift": ("http-connect", "wire:peer"), "shift_from": ("http/1.1", "wire")})
            self.assertEqual(fields(server.observation, "selected_tls_version"), {"selected_tls_version": ("1.3", "wire:server_hello")})
            self.assertEqual((record["app"], record["shifted_from"], record["client_protocol"], record["server_protocol"], record["risks"]),
                             ("ssl", "http-proxy", "tls", "tls", ["http-proxy-tunnel"]))
            verdict = session_verdict(client.observation, server.observation, "tcp", 8080, 700, 200, True, None)
            self.assertEqual((verdict.app, verdict.shifted_from), ("ssl", "http-proxy"))

    def test_only_a_2xx_to_a_connect_opens_the_server_tunnel(self):
        analyzer, client, server, record = run(flow(response=FORBIDDEN))
        self.assertEqual(analyzer.counts["connect_tunnels_correlated"], 0)
        self.assertEqual((server.observation.application_protocol, fields(server.observation, "shift")), ("http/1.1", {}))
        self.assertEqual(fields(server.observation, "http_status"), {"http_status": ("403", "wire:status_line")})
        analyzer, client, server, record = run(flow(request=REQUEST, response=b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
        self.assertEqual(analyzer.counts["connect_tunnels_correlated"], 0)
        self.assertEqual((client.observation.application_protocol, fields(client.observation, "shift"), fields(server.observation, "shift")), ("http/1.1", {}, {}))
        self.assertEqual(record["app"], "web-browsing")
        analyzer, client, server, record = run(flow(server_tunnel=b"\xff" * 80))
        self.assertEqual(analyzer.counts["connect_tunnels_correlated"], 1)
        self.assertEqual((server.observation.application_protocol, fields(server.observation, "shifted_payload")), ("http/1.1", {"shifted_payload": ("unknown", "wire")}))
        self.assertEqual((record["app"], record["server_protocol"]), ("ssl", "http/1.1"))  # client tunnel still identifies TLS

    def test_open_shift_preconditions(self):
        detecting = Inspector()
        detecting.feed(b"HTTP/1.1 200 Connection established\r\n")
        self.assertFalse(detecting.open_shift("http-connect"))
        identified = Inspector()
        identified.feed(CONNECT_RESPONSE)
        self.assertTrue(identified.open_shift("http-connect"))
        self.assertFalse(identified.open_shift("http-connect"))  # already pending
        events = identified.feed(TLS_SERVER13)
        self.assertEqual([e.kind for e in events], ["shifted"])
        self.assertEqual(identified.observation.encryption, "tls")
        self.assertFalse(identified.open_shift("http-connect"))  # already shifted
        self.assertEqual(identified.feed(b"more"), ())
        shifted_client = Inspector()
        shifted_client.feed(CONNECT_REQUEST + HELLO)
        self.assertFalse(shifted_client.open_shift("http-connect"))
        unknown = Inspector()
        unknown.feed(b"\xfa\xfb" + bytes(30))
        self.assertFalse(unknown.open_shift("http-connect"))
        tight = Inspector(Config(max_bytes=len(CONNECT_RESPONSE) + 10))
        tight.feed(CONNECT_RESPONSE)
        self.assertFalse(tight.open_shift("http-connect"))  # fewer than 64 bytes of budget left
        with self.assertRaises(ValueError):
            identified.open_shift("")
        with self.assertRaises(ValueError):
            Inspector().open_shift("http-connect", "no-such-family")
        restricted = Inspector()
        restricted.feed(CONNECT_RESPONSE)
        self.assertTrue(restricted.open_shift("http-connect", "tls"))
        restricted.feed(REQUEST)
        restricted.end()
        self.assertEqual((restricted.observation.application_protocol, fields(restricted.observation, "shifted_payload")["shifted_payload"][0] in ("unknown", "malformed")), ("http/1.1", True))


if __name__ == "__main__":
    unittest.main()

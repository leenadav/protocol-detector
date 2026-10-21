"""HTTP/1 method, content-type and accept classes; dns-over-https over HTTP/1 and HTTP/2."""
import unittest

from protocol_engine import Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.media import accept_class, content_type_class
from make_sample_pcap import REQUEST
from protocol_fixtures import DOH_GET, DOH_POST, DOH_RESPONSE, H2_PREFACE, H2_SETTINGS, h2_frame, hpack_literal


def values(observation):
    return {e.field: e.value for e in observation.evidence}


def inspect(data, hint=None):
    inspector = Inspector(protocol_hint=hint)
    inspector.feed(data)
    return inspector.observation


def h2(*fields):
    return H2_PREFACE + H2_SETTINGS + h2_frame(1, b"".join(hpack_literal(name, value) for name, value in fields), flags=0x04, stream=1)


class ContentClassTests(unittest.TestCase):
    def test_classes(self):
        cases = (("application/dns-message", "dns"), ("application/grpc", "grpc"), ("application/grpc-web+proto", "grpc-web"),
                 ("application/json; charset=utf-8", "json"), ("application/ld+json", "json"), ("text/xml", "xml"), ("application/atom+xml", "xml"),
                 ("application/x-www-form-urlencoded", "form"), ("multipart/form-data; boundary=x", "multipart"), ("application/protobuf", "protobuf"),
                 ("application/octet-stream", "binary"), ("text/plain", "text"), ("image/png", "other"), ("", "other"))
        for value, label in cases:
            self.assertEqual(content_type_class(value.encode()), label, value)
        self.assertEqual(accept_class(b"application/dns-message, */*"), "dns")
        self.assertEqual(accept_class(b"*/*, application/dns-message"), "other")

    def test_http1_method_and_header_classes(self):
        observation = inspect(REQUEST)
        self.assertEqual(values(observation)["http_method"], REQUEST.split(b" ", 1)[0].decode())
        self.assertNotIn("http_content_type", values(observation))
        for method in (b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"TRACE", b"PATCH"):
            self.assertEqual(values(inspect(method + b" / HTTP/1.1\r\nHost: a.example\r\n\r\n"))["http_method"], method.decode())
        self.assertEqual(values(inspect(b"PROPFIND / HTTP/1.1\r\nHost: a.example\r\n\r\n"))["http_method"], "PROPFIND")
        self.assertEqual(values(inspect(b"BREW / HTTP/1.1\r\nHost: a.example\r\n\r\n"))["http_method"], "extension")
        self.assertEqual(values(inspect(b"get / HTTP/1.1\r\nHost: a.example\r\n\r\n"))["http_method"], "GET")
        connect = inspect(b"CONNECT a.example:443 HTTP/1.1\r\nHost: a.example:443\r\n\r\n")
        self.assertEqual((values(connect)["http_method"], classify(connect).app), ("CONNECT", "http-proxy"))
        self.assertNotIn("http_method", values(inspect(b"CONNECT / HTTP/1.1\r\nHost: a.example\r\n\r\n")))   # not authority-form: no tunnel
        request = inspect(b"POST /api HTTP/1.1\r\nHost: a.example\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\nContent-Length: 0\r\n\r\n")
        fields = values(request)
        self.assertEqual((fields["http_method"], fields["http_content_type"]), ("POST", "json"))
        self.assertEqual({e.field: e.strength for e in request.evidence}["http_content_type"], "asserted")
        self.assertEqual(sum(1 for e in request.evidence if e.field == "http_content_type"), 1)
        self.assertEqual(classify(request).app, "web-browsing")
        self.assertNotIn("http_accept", values(inspect(b"GET / HTTP/1.1\r\nHost: a.example\r\nAccept: text/html\r\n\r\n")))
        response = inspect(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual((values(response)["http_status"], values(response)["http_content_type"]), ("200", "text"))
        self.assertNotIn("http_method", values(response))

    def test_http_carried_applications(self):
        from protocol_fixtures import IPP_REQUEST, OCSP_RESPONSE, SOAP_REQUEST, WEBDAV_REQUEST
        for data, method, content, app in ((WEBDAV_REQUEST, "PROPFIND", None, "webdav"), (IPP_REQUEST, "POST", "ipp", "ipp"),
                                           (SOAP_REQUEST, "POST", "soap", "soap"), (OCSP_RESPONSE, None, "ocsp", "ocsp")):
            observation = inspect(data)
            fields = values(observation)
            self.assertEqual((fields.get("http_method"), fields.get("http_content_type"), classify(observation).app), (method, content, app), data[:12])
            self.assertEqual(classify(observation).implicitly_uses, ("web-browsing",))
        for method in (b"PROPPATCH", b"MKCOL", b"COPY", b"MOVE", b"LOCK", b"UNLOCK", b"REPORT", b"SEARCH"):
            observation = inspect(method + b" /dav/x HTTP/1.1\r\nHost: a.example\r\n\r\n")
            self.assertEqual((values(observation)["http_method"], classify(observation).app), (method.decode(), "webdav"))
        request = inspect(b"POST /ocsp HTTP/1.1\r\nHost: ocsp.example\r\nContent-Type: application/ocsp-request\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual(classify(request).app, "ocsp")
        self.assertEqual(classify(inspect(b"GET /ws HTTP/1.1\r\nHost: a.example\r\nContent-Type: application/soap+xml\r\n\r\n")).app, "web-browsing")
        self.assertEqual(classify(inspect(b"GET /p HTTP/1.1\r\nHost: a.example\r\nContent-Type: application/ipp\r\n\r\n")).app, "web-browsing")
        response = inspect(b"HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual(classify(response).app, "ipp")
        self.assertEqual(session_verdict(inspect(IPP_REQUEST), response, "tcp", 631).port_usage, "standard")
        self.assertEqual(classify(inspect(WEBDAV_REQUEST), "tcp", 443).port_usage, "standard")

    def test_native_grpc_needs_http2(self):
        # Review round 1: native gRPC exists only over HTTP/2; the same content type on HTTP/1.1 stays web-browsing.
        native = inspect(b"POST /svc HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/grpc\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual((native.application_protocol, values(native)["http_content_type"], classify(native).app), ("http/1.1", "grpc", "web-browsing"))
        web = inspect(b"POST /svc HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/grpc-web+proto\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual((values(web)["http_content_type"], classify(web).app), ("grpc-web", "grpc"))
        from protocol_fixtures import H2_GRPC
        self.assertEqual(classify(inspect(H2_GRPC)).app, "grpc")
        h2_web = h2((b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/svc"), (b"content-type", b"application/grpc-web"))
        self.assertEqual(classify(inspect(h2_web)).app, "grpc")

    def test_dns_over_https(self):
        for data in (DOH_POST, DOH_GET):
            observation = inspect(data)
            self.assertEqual((observation.status, observation.application_protocol, observation.hostname), ("identified", "http/1.1", "doh.example"))
            verdict = classify(observation, "tcp", 443)
            self.assertEqual((verdict.app, verdict.category, verdict.implicitly_uses, verdict.port_usage), ("dns-over-https", "networking", ("web-browsing",), "standard"))
            self.assertNotIn("AAABAAAB", repr(observation))
        post, get = values(inspect(DOH_POST)), values(inspect(DOH_GET))
        self.assertEqual((post["http_method"], post["http_content_type"]), ("POST", "dns"))
        self.assertEqual((get["http_method"], get["http_accept"]), ("GET", "dns"))
        response = inspect(DOH_RESPONSE)
        self.assertEqual((values(response)["http_content_type"], classify(response).app), ("dns", "dns-over-https"))
        self.assertEqual(session_verdict(inspect(DOH_POST), response, "tcp", 443).app, "dns-over-https")
        grpc = h2((b":method", b"POST"), (b":scheme", b"https"), (b":path", b"/dns-query"), (b":authority", b"doh.example"), (b"content-type", b"application/dns-message"))
        self.assertEqual(classify(inspect(grpc)).app, "dns-over-https")
        accept = h2((b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/dns-query?dns=AAAB"), (b":authority", b"doh.example"), (b"accept", b"application/dns-message"))
        observation = inspect(accept)
        self.assertEqual((values(observation)["http2_accept"], classify(observation).app), ("dns", "dns-over-https"))
        plain = h2((b":method", b"GET"), (b":scheme", b"https"), (b":path", b"/"), (b":authority", b"a.example"), (b"accept", b"text/html"))
        self.assertNotIn("http2_accept", values(inspect(plain)))
        self.assertEqual(classify(inspect(plain)).app, "web-browsing")


if __name__ == "__main__":
    unittest.main()

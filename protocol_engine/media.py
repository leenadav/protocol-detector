"""Bounded media-type classes for content-type and accept headers, and the HTTP method vocabulary; values are never emitted."""

STANDARD_METHODS = frozenset((b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"CONNECT", b"OPTIONS", b"TRACE", b"PATCH"))
WEBDAV_METHODS = frozenset((b"PROPFIND", b"PROPPATCH", b"MKCOL", b"COPY", b"MOVE", b"LOCK", b"UNLOCK", b"REPORT", b"SEARCH"))
METHODS = STANDARD_METHODS | WEBDAV_METHODS
WEBDAV_METHOD_NAMES = frozenset(method.decode("ascii") for method in WEBDAV_METHODS)

_CLASSES = (
    (b"application/grpc-web", "grpc-web", True),
    (b"application/grpc", "grpc", False),
    (b"application/grpc+", "grpc", True),
    (b"application/dns-message", "dns", False),
    (b"application/ipp", "ipp", False),
    (b"application/ocsp-request", "ocsp", False),
    (b"application/ocsp-response", "ocsp", False),
    (b"application/soap+xml", "soap", False),
    (b"application/json", "json", False),
    (b"application/xml", "xml", False),
    (b"text/xml", "xml", False),
    (b"application/x-www-form-urlencoded", "form", False),
    (b"multipart/", "multipart", True),
    (b"application/x-protobuf", "protobuf", False),
    (b"application/protobuf", "protobuf", False),
    (b"application/vnd.google.protobuf", "protobuf", False),
    (b"application/octet-stream", "binary", False),
    (b"text/", "text", True),
)


def content_type_class(value):
    """Closed class of one media type (parameters ignored): grpc, grpc-web, dns, ipp, ocsp, soap, json, xml, form, multipart, protobuf, binary, text, other."""
    media = value.split(b";", 1)[0].strip().lower()
    for prefix, label, is_prefix in _CLASSES:
        if (media.startswith(prefix) if is_prefix else media == prefix):
            return label
    if media.endswith(b"+json"):
        return "json"
    if media.endswith(b"+xml"):
        return "xml"
    return "other"


def accept_class(value):
    """Class of the first media type in an accept list."""
    return content_type_class(value.split(b",", 1)[0])

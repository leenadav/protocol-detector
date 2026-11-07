"""D07: optional, budgeted inspection after identification (HTTP/1 and TLS vertical slice).

Off by default (`Config(continuation=0)`): the initial-message fast path is unchanged.
With a byte budget, the parser that identified a stream keeps reading only the
new bytes that arrive after the identification, within that budget and a
message cap, and adds bounded structural evidence about what followed:

* HTTP/1: later messages on the same direction (methods, status classes, a Host
  that differs from the identifying one, a later CONNECT/Upgrade boundary that
  shifts the stream like a first-message one would);
* TLS: record-layer framing after the hello (record counts per content type,
  whether protected application data started, whether an alert was seen).

The identification published before the continuation never changes: evidence is
only added, the hostname stays the one the first message asserted, and any
framing error, budget end or message cap simply ends the continuation with a
`continuation` evidence value naming why. This is not a full-session parser:
bodies are skipped by their declared framing, close-delimited bodies end the
continuation, nothing after an encrypted record is interpreted, and trailers,
interleaved pipelining across directions and HEAD responses are not modelled.
"""
import re

_CHUNK_SIZE = re.compile(rb"[0-9A-Fa-f]{1,16}(?:;[\x21-\x7e \t]*)?")
_RECORD_TYPES = {20: "ccs", 21: "alert", 22: "handshake", 23: "application_data"}
_MAX_METHODS = 8
_MAX_RECORDS = 256


class HttpContinuation:
    """Later HTTP/1 messages on one direction after the identifying one."""

    def __init__(self, config, first, make_parser):
        self.config = config
        self.budget = config.continuation
        self.limit = config.max_transactions
        self._make_parser = make_parser
        self.first_host = first.host
        self.messages = 1
        self.methods = ()
        self.status_classes = ()
        self.host_variation = False
        self.shift = None
        self.scope = None
        self.correlation = None
        self.done = False
        self.ended = None
        self._parser = None
        self._skip = 0            # body bytes still to skip
        self._chunked = False
        self._chunk_line = bytearray()
        self._chunk_state = None  # None | "size" | "data" | "data-crlf" | "trailers"
        self._body_after(first)

    # -- framing of the message that was just completed --

    def _body_after(self, message):
        if message.transfer_encoding:
            self._chunked = True
            self._chunk_state = "size"
            return
        length = message.content_length or 0
        if message.method is None and message.content_length is None and not (
                100 <= (message.status or 0) < 200 or message.status in (204, 304)):
            # A response without declared framing is delimited by connection close.
            self._end("close-delimited")
            return
        if message.method is not None and message.content_length is None:
            length = 0
        self._skip = length

    def _end(self, why):
        self.done = True
        self.ended = why
        self._parser = None

    # -- evidence (bounded; counts and classes only) --

    def evidence(self):
        items = [("http_messages", str(self.messages), "continuation", "structural")]
        if self.methods:
            items.append(("http_methods", ",".join(self.methods), "continuation", "structural"))
        if self.status_classes:
            items.append(("http_status_classes", ",".join(self.status_classes), "continuation", "structural"))
        if self.host_variation:
            items.append(("http_host_variation", "observed", "continuation", "asserted"))
        if self.ended is not None:
            items.append(("continuation", self.ended, "continuation", "context"))
        return tuple(items)

    # -- feeding --

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            if self.budget <= 0:
                self._end("budget")
                break
            if self._skip:
                amount = min(self._skip, len(data) - pos, self.budget)
                self._skip -= amount
                pos += amount
                self.budget -= amount
                continue
            if self._chunked:
                pos = self._feed_chunked(data, pos)
                continue
            if self._parser is None:
                if self.messages >= self.limit:
                    self._end("messages")
                    break
                self._parser = self._make_parser()
            piece = data[pos:pos + self.budget]
            try:
                consumed = self._parser.feed(piece)
            except ValueError:    # ParseError and BudgetError: the identification stands; framing is lost
                self.budget -= len(piece)
                pos += len(piece)
                self._end("framing")
                break
            pos += consumed
            self.budget -= consumed
            if self._parser.done:
                self._record(self._parser)
                if self.done:
                    break
            elif consumed < len(piece):
                break
        return pos

    def _record(self, message):
        self.messages += 1
        if message.method is not None:
            label = message.method.decode("ascii") if message.method in _KNOWN_METHODS else "extension"
            if label not in self.methods and len(self.methods) < _MAX_METHODS:
                self.methods += (label,)
        else:
            label = "%dxx" % (message.status // 100)
            if label not in self.status_classes:
                self.status_classes += (label,)
        if message.host is not None and self.first_host is not None and message.host != self.first_host:
            self.host_variation = True
        if message.shift is not None:
            self.shift = message.shift
            self.scope = getattr(message, "scope", None)
            self.correlation = message.correlation
            self._end("shift")
            return
        self._parser = None
        self._body_after(message)

    def _feed_chunked(self, data, pos):
        while pos < len(data) and self.budget > 0:
            if self._chunk_state == "data":
                amount = min(self._skip, len(data) - pos, self.budget)
                self._skip -= amount
                pos += amount
                self.budget -= amount
                if self._skip == 0:
                    self._chunk_state = "data-crlf"
                continue
            newline = data.find(b"\n", pos)
            end = len(data) if newline < 0 else newline + 1
            piece = data[pos:min(end, pos + self.budget)]
            if len(self._chunk_line) + len(piece) > self.config.max_line:
                self._end("framing")
                return pos + len(piece)
            self._chunk_line.extend(piece)
            pos += len(piece)
            self.budget -= len(piece)
            if newline < 0 or end > pos:
                return pos
            line = bytes(self._chunk_line)
            self._chunk_line.clear()
            if not line.endswith(b"\r\n"):
                self._end("framing")
                return pos
            line = line[:-2]
            if self._chunk_state == "size":
                if not _CHUNK_SIZE.fullmatch(line):
                    self._end("framing")
                    return pos
                size = int(line.split(b";", 1)[0], 16)
                if size == 0:
                    self._chunk_state = "trailers"
                else:
                    self._skip = size
                    self._chunk_state = "data"
            elif self._chunk_state == "data-crlf":
                if line:
                    self._end("framing")
                    return pos
                self._chunk_state = "size"
            else:   # trailers: header lines until an empty line; names are not read
                if not line:
                    self._chunked = False
                    self._chunk_state = None
                    return pos
        return pos


_KNOWN_METHODS = {b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"PATCH", b"TRACE", b"CONNECT",
                  b"PROPFIND", b"PROPPATCH", b"MKCOL", b"COPY", b"MOVE", b"LOCK", b"UNLOCK", b"REPORT",
                  b"RPC_IN_DATA", b"RPC_OUT_DATA", b"RPC_CONNECT"}


class TlsContinuation:
    """Record-layer framing after a TLS hello: counts per content type, nothing decrypted."""

    def __init__(self, config, record_remaining):
        self.budget = config.continuation
        self._remaining = record_remaining   # bytes left in the record that carried the hello
        self._header = bytearray()
        self.counts = {}
        self.records = 0
        self.done = False
        self.ended = None

    def _end(self, why):
        self.done = True
        self.ended = why

    def evidence(self):
        items = []
        if self.records:
            summary = ",".join("%s=%d" % (name, self.counts[name]) for name in ("handshake", "ccs", "alert", "application_data")
                               if name in self.counts)
            items.append(("tls_records", summary, "continuation", "structural"))
            if "application_data" in self.counts:
                items.append(("tls_application_data", "observed", "continuation", "structural"))
            if "alert" in self.counts:
                items.append(("tls_alert", "observed", "continuation", "structural"))
        if self.ended is not None:
            items.append(("continuation", self.ended, "continuation", "context"))
        return tuple(items)

    def feed(self, data):
        pos = 0
        while pos < len(data) and not self.done:
            if self.budget <= 0:
                self._end("budget")
                break
            if self._remaining:
                amount = min(self._remaining, len(data) - pos, self.budget)
                self._remaining -= amount
                pos += amount
                self.budget -= amount
                continue
            needed = 5 - len(self._header)
            amount = min(needed, len(data) - pos, self.budget)
            self._header.extend(data[pos:pos + amount])
            pos += amount
            self.budget -= amount
            if len(self._header) < 5:
                break
            header = bytes(self._header)
            self._header.clear()
            length = int.from_bytes(header[3:5], "big")
            if header[0] not in _RECORD_TYPES or header[1] != 3 or header[2] > 4 or not 1 <= length <= 16384 + 256:
                self._end("framing")
                break
            name = _RECORD_TYPES[header[0]]
            self.counts[name] = self.counts.get(name, 0) + 1
            self.records += 1
            self._remaining = length
            if self.records >= _MAX_RECORDS:
                self._end("records")
        return pos


SUMMARY_FIELDS = ("http_messages", "http_methods", "http_status_classes", "http_host_variation",
                  "tls_records", "tls_application_data", "tls_alert", "continuation")


def continuation_summary(client, server):
    """Per-direction summary of continuation evidence for a session record ({} when none ran)."""
    summary = {}
    for name, observation in (("client", client), ("server", server)):
        if observation is None:
            continue
        fields = {}
        for item in observation.evidence:
            if item.source.rpartition(":")[2] == "continuation" and item.field in SUMMARY_FIELDS:
                key = "ended" if item.field == "continuation" else item.field
                fields[key] = int(item.value) if item.field == "http_messages" else item.value
        if fields:
            summary[name] = fields
    return summary

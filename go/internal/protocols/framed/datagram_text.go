package framed

import (
	"bytes"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/protocols/textroute"
)

func init() {
	DatagramValidators["ssdp"] = ssdpDatagram
	DatagramValidators["sip"] = sipDatagram
}

// ssdpDatagram ports telemetry.ssdp: one complete HTTP header block (LineParser forced to HTTP) plus the
// SSDP-specific headers of the start line's kind.
func ssdpDatagram(data []byte, limits Limits) (*Datagram, error) {
	search := bytes.HasPrefix(data, []byte("M-SEARCH "))
	notify := bytes.HasPrefix(data, []byte("NOTIFY "))
	if !search && !notify && !bytes.HasPrefix(data, []byte("HTTP/1.1 200 OK")) {
		return nil, parsing.Unsupported("Outside SSDP M-SEARCH/NOTIFY/response start lines")
	}
	parser, err := textroute.New(textroute.Options{MaxLine: limits.MaxLine, MaxHeaders: limits.MaxHeaders, MaxBytes: limits.MaxBytes, ForceHTTP: true})
	if err != nil {
		return nil, err
	}
	consumed, err := parser.Feed(data)
	if err != nil {
		return nil, err
	}
	if !parser.Done() || consumed != len(data) {
		return nil, parsing.Malformed("SSDP message must be exactly one complete HTTP header block")
	}
	head := bytes.ToLower(data)
	has := func(s string) bool { return bytes.Contains(head, []byte(s)) }
	kind := "response"
	switch {
	case search:
		if !has("\r\nman: \"ssdp:discover\"\r\n") || !has("\r\nst:") {
			return nil, parsing.Malformed("SSDP M-SEARCH requires MAN ssdp:discover and ST headers")
		}
		kind = "search"
	case notify:
		if !has("\r\nnts: ssdp:") || !has("\r\nnt:") {
			return nil, parsing.Malformed("SSDP NOTIFY requires NTS and NT headers")
		}
		kind = "notify"
	default:
		if !has("\r\nst:") || !has("\r\nusn:") {
			return nil, parsing.Malformed("SSDP response requires ST and USN headers")
		}
	}
	return &Datagram{Protocol: "ssdp", Simple: true,
		Reason: "SSDP " + kind + " header framing validated; device descriptions and locations are not emitted"}, nil
}

// sipDatagram ports datagram.sip: the text route must resolve to SIP and finish, and a Content-Length must equal
// the bytes after the headers.
func sipDatagram(data []byte, limits Limits) (*Datagram, error) {
	parser, err := textroute.New(textroute.Options{MaxLine: limits.MaxLine, MaxHeaders: limits.MaxHeaders, MaxBytes: limits.MaxBytes})
	if err != nil {
		return nil, err
	}
	consumed, err := parser.Feed(data)
	if err != nil {
		return nil, err
	}
	if !parser.Done() || parser.ResolvedFamily() != "sip" {
		return nil, parsing.Malformed("Incomplete or invalid SIP datagram headers")
	}
	if length, ok := parser.ControlField("content-length"); ok {
		n, err := strconv.Atoi(string(bytes.TrimSpace(length)))
		if err != nil || n != len(data)-consumed {
			return nil, parsing.Malformed("SIP datagram body disagrees with Content-Length")
		}
	}
	return &Datagram{Protocol: "sip/2.0", Simple: true,
		Reason: "SIP required header framing and datagram body length validated; body/dialogue semantics unverified"}, nil
}

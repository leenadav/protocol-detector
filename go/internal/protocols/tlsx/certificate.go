package tlsx

import (
	"github.com/leenadav/protocol-detector/go/internal/parsing"
	"github.com/leenadav/protocol-detector/go/internal/protocols/x509x"
)

// certificateWatch ports tls_server.CertificateWatch (Config.certificates): read the records after a TLS 1.2
// ServerHello until the leaf certificate is complete. Only the Certificate handshake message may follow; a
// ChangeCipherSpec, an alert or any other message ends the watch without evidence. The leaf is the first list
// entry; later chain entries are never read. Any error keeps the ServerHello identification (the inspector treats
// an error in a continuation as the end of optional evidence).
type certificateWatch struct {
	budget          int // bytes this watch may consume (the shared max_bytes budget)
	consumed        int
	recordHeader    []byte
	recordRemaining int // bytes left in the record that carried the ServerHello, then in each record
	handshake       []byte
	needed          int
	messageLength   int
	chain           string
	done            bool
	evidence        []parsing.Row
}

func newCertificateWatch(recordRemaining, budget int) *certificateWatch {
	return &certificateWatch{budget: budget, recordRemaining: recordRemaining, needed: 4}
}

func u24(b []byte) int { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }

func (w *certificateWatch) feed(data []byte) (int, error) {
	pos := 0
	defer func() { w.consumed += pos }()
	for pos < len(data) && !w.done {
		if w.consumed+pos >= w.budget {
			return pos, parsing.Budget("Certificate inspection exceeds the configured byte budget")
		}
		if w.recordRemaining == 0 {
			amount := min3(5-len(w.recordHeader), len(data)-pos, w.budget-w.consumed-pos)
			w.recordHeader = append(w.recordHeader, data[pos:pos+amount]...)
			pos += amount
			if len(w.recordHeader) < 5 {
				break
			}
			h := w.recordHeader
			if h[0] != 22 {
				return pos, parsing.Malformed("Certificate message must follow the ServerHello in a handshake record")
			}
			if h[1] != 3 || (h[2] != 1 && h[2] != 2 && h[2] != 3) {
				return pos, parsing.Malformed("Expected plaintext TLS handshake record")
			}
			w.recordRemaining = int(h[3])<<8 | int(h[4])
			w.recordHeader = w.recordHeader[:0]
			if w.recordRemaining < 1 || w.recordRemaining > 16384 {
				return pos, parsing.Malformed("Invalid TLS record length")
			}
		}
		amount := min3(w.needed-len(w.handshake), w.recordRemaining, len(data)-pos)
		if room := w.budget - w.consumed - pos; room < amount {
			amount = room
		}
		w.handshake = append(w.handshake, data[pos:pos+amount]...)
		pos += amount
		w.recordRemaining -= amount
		if len(w.handshake) < w.needed {
			continue
		}
		switch w.needed {
		case 4:
			if w.handshake[0] != 11 {
				return pos, parsing.Malformed("Handshake message after the ServerHello is not Certificate")
			}
			w.messageLength = u24(w.handshake[1:4])
			if w.messageLength < 6 {
				return pos, parsing.Malformed("Certificate message too short for one certificate")
			}
			w.needed = 10
		case 10:
			listLength, leafLength := u24(w.handshake[4:7]), u24(w.handshake[7:10])
			if listLength != w.messageLength-3 || leafLength == 0 || leafLength+3 > listLength {
				return pos, parsing.Malformed("Certificate list lengths disagree with the message")
			}
			limit := w.budget - w.consumed - pos
			if x509x.MaxLeaf < limit {
				limit = x509x.MaxLeaf
			}
			if leafLength > limit {
				return pos, parsing.Budget("Leaf certificate exceeds the inspection budget")
			}
			w.chain = "chain"
			if listLength == leafLength+3 {
				w.chain = "single"
			}
			w.needed = 10 + leafLength
		default:
			profile, err := x509x.LeafProfile(w.handshake[10:])
			if err != nil {
				return pos, err
			}
			w.evidence = []parsing.Row{{Field: "tls_certificate_chain", Value: w.chain, Provenance: "certificate", Strength: "structural"}}
			for _, f := range profile {
				w.evidence = append(w.evidence, parsing.Row{Field: f.Name, Value: f.Value, Provenance: "certificate", Strength: "asserted"})
			}
			w.handshake = nil
			w.done = true
		}
	}
	return pos, nil
}

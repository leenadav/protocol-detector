package framed

import (
	"fmt"
	"github.com/leenadav/protocol-detector/go/internal/parsertest"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// scKerberosReq is an AS-REQ whose req_body carries the given fields (already context-tagged) in order.
func scKerberosReq(bodyFields ...[]byte) []byte {
	body := ber(0x30, cat(bodyFields...))
	return ber(0x6a, ber(0x30, cat(ber(0xa1, ber(2, []byte{5})), ber(0xa2, ber(2, []byte{0x0a})), ber(0xa4, body))))
}

func scEtypes(n int) []byte {
	var list []byte
	for i := 0; i < n; i++ {
		list = append(list, ber(2, []byte{0x12})...)
	}
	return ber(0xa8, ber(0x30, list))
}

// SR-6: an advertised frame size is checked against the byte budget as soon as the header is complete, before
// the frame buffer grows to it: a Diameter header advertising 16 MiB under a 4 KiB budget is refused with a
// budget error after its 20 header bytes, and the parser's buffer never exceeds the header.
func TestAdvertisedFrameSizeIsCheckedBeforeTheBufferGrows(t *testing.T) {
	header := []byte{1, 0xff, 0xff, 0xfc, 0x80, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 2}
	for _, step := range []int{1, 7, 20, 4096} {
		p := NewDiameter(4096, 128)
		data := append(append([]byte{}, header...), make([]byte, 4096)...)
		var err error
		consumed := 0
		for pos := 0; pos < len(data) && err == nil; {
			end := pos + step
			if end > len(data) {
				end = len(data)
			}
			var n int
			n, err = p.Feed(data[pos:end])
			consumed += n
			pos = end
		}
		if err == nil || !strings.Contains(err.Error(), "exceeds byte budget") {
			t.Fatalf("step %d: %v", step, err)
		}
		if consumed > len(header) || cap(p.buffer) > 4096 {
			t.Fatalf("step %d: consumed %d bytes, buffer capacity %d", step, consumed, cap(p.buffer))
		}
	}
}

// scParse feeds data whole to a fresh parser and returns its result or error.
func scParse(p *Parser, data []byte) (string, error) {
	if _, err := p.Feed(data); err != nil {
		return "", err
	}
	if !p.Done() {
		return "", fmt.Errorf("not done")
	}
	return parsertest.Rendered(*p.Result()), nil
}

func scU16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

type scTDSOption struct {
	token          byte
	offset, length int
}

func scTDS(options []scTDSOption, data []byte) []byte {
	var payload []byte
	for _, o := range options {
		payload = append(append(append(payload, o.token), scU16(o.offset)...), scU16(o.length)...)
	}
	payload = append(append(payload, 0xff), data...)
	return append(append([]byte{0x12, 0x01}, scU16(8+len(payload))...), append([]byte{0, 0, 0, 0}, payload...)...)
}

func scTNSConnect(offset, length int, descriptor []byte) []byte {
	body := []byte{0x01, 0x39, 0x01, 0x2c, 0, 0, 0x20, 0, 0x7f, 0xff, 0x4f, 0x98, 0, 0, 0, 1}
	body = append(append(append(body, scU16(length)...), scU16(offset)...), make([]byte, 6)...)
	body = append(body, make([]byte, offset-34)...)
	body = append(body, descriptor...)
	return append(append(scU16(8+len(body)), 0, 0, 1, 0, 0, 0), body...)
}

// SR-39: TDS PRELOGIN and TNS CONNECT/ACCEPT/REFUSE identify only when every option or data region lies inside
// the packet exactly, and emit closed-set labels only: no instance name or connect descriptor.
func TestTDSAndTNSRegionsMustFillThePacketAndNeverLeak(t *testing.T) {
	instance := []byte("SecretInst\x00")
	data := append(append([]byte{15, 0, 0x07, 0xd0, 0, 0}, 0x01), instance...)
	good := []scTDSOption{{0x00, 16, 6}, {0x01, 22, 1}, {0x02, 23, len(instance)}}
	got, err := scParse(NewTDS(65536), scTDS(good, data))
	if err != nil || !strings.Contains(got, "tds_encryption") || strings.Contains(got, "SecretInst") {
		t.Fatalf("TDS PRELOGIN: %s %v", got, err)
	}
	overlap := []scTDSOption{{0x00, 0, 6}, {0x01, 22, 1}, {0x02, 23, len(instance)}}
	unterminated := append(append([]byte{}, data[:len(data)-1]...), 'x')
	for name, packet := range map[string][]byte{
		"datum inside the option table": scTDS(overlap, data),
		"bytes after the last datum":    scTDS(good, append(append([]byte{}, data...), 0)),
		"unterminated INSTOPT":          scTDS(good, unterminated),
		"VERSION of five bytes":         scTDS([]scTDSOption{{0x00, 16, 5}, {0x01, 21, 1}, {0x02, 22, len(instance)}}, data[1:]),
	} {
		if got, err := scParse(NewTDS(65536), packet); err == nil {
			t.Fatalf("TDS %s identified: %s", name, got)
		}
	}

	descriptor := []byte("(DESCRIPTION=(HOST=secrethost)(SERVICE_NAME=secretsvc))")
	got, err = scParse(NewTNS(65536), scTNSConnect(34, len(descriptor), descriptor))
	if err != nil || !strings.Contains(got, "inline") || strings.Contains(got, "secret") {
		t.Fatalf("TNS CONNECT: %s %v", got, err)
	}
	for name, packet := range map[string][]byte{
		"offset inside the fixed fields": scTNSConnect(34, len(descriptor), descriptor)[:0],
		"length one short":               scTNSConnect(34, len(descriptor)-1, descriptor),
		"length one long":                scTNSConnect(34, len(descriptor)+1, descriptor),
		"offset past the header range":   scTNSConnect(76, len(descriptor), descriptor),
		"non-printable descriptor":       scTNSConnect(34, 4, []byte("(\x01\x02)")),
	} {
		if len(packet) == 0 {
			packet = scTNSConnect(34, len(descriptor), descriptor)
			packet[8+19] = 30 // connect data offset 30, inside the fixed fields
		}
		if got, err := scParse(NewTNS(65536), packet); err == nil {
			t.Fatalf("TNS %s identified: %s", name, got)
		}
	}
	accept := func(offset, length int, extra []byte) []byte {
		body := append([]byte{0x01, 0x39, 0, 0, 0x20, 0, 0x7f, 0xff, 0, 1}, append(scU16(length), scU16(offset)...)...)
		body = append(append(body, 0, 0), extra...)
		return append(append(scU16(8+len(body)), 0, 0, 2, 0, 0, 0), body...)
	}
	if got, err := scParse(NewTNS(65536), accept(0, 0, nil)); err != nil || !strings.Contains(got, "accept") {
		t.Fatalf("TNS ACCEPT: %s %v", got, err)
	}
	if got, err := scParse(NewTNS(65536), accept(24, 4, []byte("abc"))); err == nil {
		t.Fatalf("TNS ACCEPT with a data region past the packet identified: %s", got)
	}
	if got, err := scParse(NewTNS(65536), accept(24, 2, []byte("abc"))); err == nil {
		t.Fatalf("TNS ACCEPT with bytes after its data region identified: %s", got)
	}
}

// SR-46: Modbus, GIOP, TACACS+, SMB1 and AMQP server replies are identified only when their fields cover the frame
// exactly, and emit status, code and layout labels only: no register values, server messages, domains or broker
// properties.
func TestTCPServerRepliesMustCoverTheirFramesExactlyAndNeverLeak(t *testing.T) {
	modbus := func(pdu []byte) []byte {
		return append(append([]byte{0, 1, 0, 0}, scU16(2+len(pdu))...), append([]byte{1, 3}, pdu...)...)
	}
	tacacs := func(body []byte) []byte {
		return append([]byte{0xc1, 1, 2, 1, 0, 0, 0, 1, 0, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	}
	reply := func(message, data []byte, extra int) []byte {
		body := append([]byte{1, 0}, append(scU16(len(message)), scU16(len(data))...)...)
		return append(append(append(body, message...), data...), make([]byte, extra)...)
	}
	smb1 := func(words int, byteCount int, bytes []byte) []byte {
		header := append([]byte("\xffSMB\x72"), make([]byte, 27)...)
		header[9] = 0x80
		data := append(append(header, byte(words)), make([]byte, 2*words)...)
		data = append(append(data, byte(byteCount), byte(byteCount>>8)), bytes...)
		return append([]byte{0, 0, byte(len(data) >> 8), byte(len(data))}, data...)
	}
	amqp := func(properties, mechanisms, locales []byte, extra int) []byte {
		payload := []byte{0, 0x0a, 0, 0x0a, 0, 9}
		for _, field := range [][]byte{properties, mechanisms, locales} {
			payload = append(append(payload, 0, 0, byte(len(field)>>8), byte(len(field))), field...)
		}
		payload = append(payload, make([]byte, extra)...)
		return append(append(append([]byte{1, 0, 0}, 0, 0, byte(len(payload)>>8), byte(len(payload))), payload...), 0xce)
	}
	giop := func(status byte, extra int) []byte {
		body := append([]byte{0, 0, 0, 7, 0, 0, 0, status}, make([]byte, extra)...)
		return append(append([]byte("GIOP\x01\x02\x00\x04"), 0, 0, 0, byte(len(body))), body...)
	}
	secrets := []string{"SecretReg", "Welcome secret", "SECRETDOMAIN", "SecretBroker"}
	good := map[string]struct {
		parser func() parsing.Parser
		data   []byte
		label  string
	}{
		"modbus":  {func() parsing.Parser { return NewModbus(65536) }, modbus(append([]byte{10}, "SecretRegs"...)), "modbus"},
		"tacacs":  {func() parsing.Parser { return NewTACACS(65536) }, tacacs(reply([]byte("Welcome secret"), []byte("x"), 0)), "tacacs-plus"},
		"smb1":    {func() parsing.Parser { return NewSMB1(65536, 128) }, smb1(1, 12, []byte("SECRETDOMAIN")), "smb1"},
		"amqp091": {func() parsing.Parser { return NewAMQP() }, amqp([]byte("SecretBroker"), []byte("PLAIN"), []byte("en_US"), 0), "amqp/0-9-1"},
		"giop":    {func() parsing.Parser { return NewGIOP(65536, 8192, 128) }, giop(1, 0), "giop/1.2"},
	}
	for name, c := range good {
		p := c.parser()
		if _, err := p.Feed(c.data); err != nil || !p.Done() || p.Result().ProtocolName != c.label {
			t.Fatalf("%s: %v %+v", name, err, p.Result())
		}
		rendering := parsertest.Rendered(*p.Result())
		for _, s := range secrets {
			if strings.Contains(rendering, s) {
				t.Fatalf("%s: %q emitted: %s", name, s, rendering)
			}
		}
	}
	bad := map[string]struct {
		parser func() parsing.Parser
		data   []byte
	}{
		"modbus count short":      {func() parsing.Parser { return NewModbus(65536) }, modbus(append([]byte{8}, "SecretRegs"...))},
		"modbus count long":       {func() parsing.Parser { return NewModbus(65536) }, modbus(append([]byte{12}, "SecretRegs"...))},
		"tacacs trailing":         {func() parsing.Parser { return NewTACACS(65536) }, tacacs(reply([]byte("Welcome secret"), []byte("x"), 1))},
		"smb1 byte count short":   {func() parsing.Parser { return NewSMB1(65536, 128) }, smb1(1, 11, []byte("SECRETDOMAIN"))},
		"giop trailing":           {func() parsing.Parser { return NewGIOP(65536, 8192, 128) }, giop(1, 4)},
		"amqp trailing":           {func() parsing.Parser { return NewAMQP() }, amqp([]byte("SecretBroker"), []byte("PLAIN"), []byte("en_US"), 1)},
		"amqp properties too big": {func() parsing.Parser { return NewAMQP() }, amqp([]byte("SecretBroker"), []byte("PLAIN"), []byte("en_US"), 0)[:0]},
	}
	for name, c := range bad {
		data := c.data
		if len(data) == 0 { // the server-properties table claims more than the frame holds
			data = amqp([]byte("SecretBroker"), []byte("PLAIN"), []byte("en_US"), 0)
			data[7+9] = 200
		}
		p := c.parser()
		if _, err := p.Feed(data); err == nil && p.Done() {
			t.Fatalf("%s identified: %+v", name, p.Result())
		}
	}
}

// SR-61: Kerberos etype classes come only from a req_body that walks cleanly (strictly increasing context tags,
// required fields present, minimal Int32 etypes, at most 32 offered); any deviation drops every etype label and
// keeps the identification, and no principal, realm or nonce byte is emitted.
func TestKerberosEtypeLabelsDropOnSubstructureFaultsAndStayClosed(t *testing.T) {
	principal := ber(0x30, cat(ber(0xa0, ber(2, []byte{1})), ber(0xa1, ber(0x30, ber(0x1b, []byte("secretuser"))))))
	options := ber(0xa0, ber(3, []byte{0, 0x40, 0x81, 0, 0x10}))
	realm := ber(0xa2, ber(0x1b, []byte("SECRETREALM.ORG")))
	till := ber(0xa5, ber(0x18, []byte("20371231235959Z")))
	nonce := ber(0xa7, ber(2, []byte{0x12, 0x34, 0x56, 0x78}))
	labels := func(name string, data []byte) []string {
		t.Helper()
		m, err := kerberosDatagram(data, Limits{MaxHeaders: 16})
		if err != nil || m == nil || m.Protocol != "kerberos" {
			t.Fatalf("%s: the identification changed: %v %+v", name, err, m)
		}
		rendering := parsertest.Rendered(m)
		for _, secret := range []string{"secretuser", "SECRETREALM", "12345678", "\x12\x34\x56\x78"} {
			if strings.Contains(rendering, secret) {
				t.Fatalf("%s: %q emitted: %s", name, secret, rendering)
			}
		}
		var out []string
		for _, r := range m.Evidence {
			if strings.HasPrefix(r.Field, "kerberos_etype") {
				out = append(out, r.Value)
			}
		}
		return out
	}
	if got := labels("clean", scKerberosReq(options, ber(0xa1, principal), realm, till, nonce, scEtypes(32))); len(got) != 2 || got[0] != "aes-sha1" {
		t.Fatalf("clean request with 32 etypes: %v", got)
	}
	for name, data := range map[string][]byte{
		"33 etypes":        scKerberosReq(options, ber(0xa1, principal), realm, till, nonce, scEtypes(33)),
		"repeated field":   scKerberosReq(options, ber(0xa1, principal), realm, till, nonce, nonce, scEtypes(1)),
		"fields reordered": scKerberosReq(options, realm, ber(0xa1, principal), till, nonce, scEtypes(1)),
		"missing nonce":    scKerberosReq(options, ber(0xa1, principal), realm, till, scEtypes(1)),
		"non-minimal":      scKerberosReq(options, ber(0xa1, principal), realm, till, nonce, ber(0xa8, ber(0x30, ber(2, []byte{0, 0x12})))),
		"five-byte etype":  scKerberosReq(options, ber(0xa1, principal), realm, till, nonce, ber(0xa8, ber(0x30, ber(2, []byte{1, 2, 3, 4, 5})))),
		"empty etype list": scKerberosReq(options, ber(0xa1, principal), realm, till, nonce, ber(0xa8, ber(0x30, nil))),
	} {
		if got := labels(name, data); len(got) != 0 {
			t.Fatalf("%s: etype labels survived a fault: %v", name, got)
		}
	}
}

func scLIFX(word uint16, target []byte, flags byte, kind uint16, payload []byte) []byte {
	d := make([]byte, 36)
	size := 36 + len(payload)
	d[0], d[1] = byte(size), byte(size>>8)
	d[2], d[3] = byte(word), byte(word>>8)
	copy(d[4:8], "SRCE")
	copy(d[8:16], target)
	d[22] = flags
	d[32], d[33] = byte(kind), byte(kind>>8)
	return append(d, payload...)
}

func scTuya(payload []byte, corrupt bool) []byte {
	head := append([]byte{0, 0, 0x55, 0xaa, 0, 0, 0, 1, 0, 0, 0, 0x0a}, 0, 0, 0, byte(len(payload)+8))
	body := append(head, payload...)
	sum := crc32.ChecksumIEEE(body)
	if corrupt {
		sum ^= 1
	}
	return append(append(body, byte(sum>>24), byte(sum>>16), byte(sum>>8), byte(sum)), 0, 0, 0xaa, 0x55)
}

// SR-64: LIFX and Tuya LAN datagrams identify only on their full structural profile (LIFX size, protocol,
// reserved bits, target and per-type payload size; Tuya prefix, length, CRC32 and suffix); every truncation fails
// closed, and no target, source or payload byte is emitted. TP-Link Kasa is covered by TestKasaDatagram and
// TestJSONDocumentGrammar.
func TestSmartHomeDatagramsNeedTheirWholeProfileAndNeverLeak(t *testing.T) {
	untagged := uint16(1024 | 0x1000)
	lifx := scLIFX(untagged, []byte("TARGET\x00\x00"), 0, 2, nil)
	tuya := scTuya([]byte("SECRETPAYLOAD123"), false)
	for name, c := range map[string]struct {
		validate DatagramValidator
		data     []byte
	}{"lifx": {lifxDatagram, lifx}, "tuya": {tuyaDatagram, tuya}} {
		m, err := c.validate(c.data, Limits{MaxBytes: 65536, MaxHeaders: 128})
		if err != nil || m == nil {
			t.Fatalf("%s: %v", name, err)
		}
		rendering := parsertest.Rendered(*m)
		for _, secret := range []string{"TARGET", "SRCE", "SECRETPAYLOAD", "544152474554"} {
			if strings.Contains(rendering, secret) {
				t.Fatalf("%s: %q emitted: %s", name, secret, rendering)
			}
		}
		for i := 0; i < len(c.data); i++ {
			if m, err := c.validate(c.data[:i], Limits{MaxBytes: 65536, MaxHeaders: 128}); err == nil {
				t.Fatalf("%s truncated to %d bytes identified: %+v", name, i, m)
			}
		}
	}
	tagged := uint16(1024 | 0x1000 | 0x2000)
	for name, data := range map[string][]byte{
		"lifx reserved flag bits":   scLIFX(untagged, []byte("TARGET\x00\x00"), 0x04, 2, nil),
		"lifx tagged with a target": scLIFX(tagged, []byte("TARGET\x00\x00"), 0, 2, nil),
		"lifx target tail nonzero":  scLIFX(untagged, []byte("TARGETAB"), 0, 2, nil),
		"lifx type zero":            scLIFX(untagged, nil, 0, 0, nil),
		"lifx payload size":         scLIFX(untagged, nil, 0, 2, []byte{1}),
		"lifx protocol":             scLIFX(1025|0x1000, nil, 0, 2, nil),
		"tuya crc":                  scTuya([]byte("SECRETPAYLOAD123"), true),
		"tuya trailing byte":        append(append([]byte{}, tuya...), 0),
	} {
		validate := lifxDatagram
		if strings.HasPrefix(name, "tuya") {
			validate = tuyaDatagram
		}
		if m, err := validate(data, Limits{MaxBytes: 65536, MaxHeaders: 128}); err == nil {
			t.Fatalf("%s identified: %+v", name, m)
		}
	}
}

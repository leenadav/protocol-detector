package framed

import (
	"strings"
	"testing"
)

func ikeTransform(kind byte, value int, attrs []byte, last bool) []byte {
	body := append([]byte{kind, 0, byte(value >> 8), byte(value)}, attrs...)
	chain := byte(3)
	if last {
		chain = 0
	}
	return append([]byte{chain, 0, 0, byte(4 + len(body))}, body...)
}

func ikeRequest(group int, width int) []byte {
	transforms := cat(ikeTransform(1, 12, []byte{0x80, 0x0e, 0, 128}, false), ikeTransform(2, 5, nil, false),
		ikeTransform(3, 12, nil, false), ikeTransform(4, 14, nil, true))
	proposal := append([]byte{0, 0, 0, byte(8 + len(transforms)), 1, 1, 0, 4}, transforms...)
	sa := append([]byte{34, 0, 0, byte(4 + len(proposal))}, proposal...)
	keBody := append([]byte{byte(group >> 8), byte(group), 0, 0}, make([]byte, width)...)
	ke := append([]byte{40, 0, byte((4 + len(keBody)) >> 8), byte(4 + len(keBody))}, keBody...)
	nonce := append([]byte{0, 0, 0, 36}, make([]byte, 32)...)
	body := cat(sa, ke, nonce)
	header := cat([]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}, make([]byte, 8), []byte{33, 0x20, 34, 0x08, 0, 0, 0, 0})
	size := 28 + len(body)
	return cat(header, []byte{byte(size >> 24), byte(size >> 16), byte(size >> 8), byte(size)}, body)
}

func TestIKEv2InitiatorOfferAndRejections(t *testing.T) {
	limits := Limits{MaxBytes: 65536, MaxHeaders: 128, MaxLine: 8192}
	m, err := ikev2Datagram(ikeRequest(14, 256), limits)
	if err != nil || m.Protocol != "ikev2" || m.Evidence[2].Field != "offered_dh_group" || m.Evidence[2].Value != "14" {
		t.Fatalf("offer: %+v %v", m, err)
	}
	if _, err := ikev2Datagram(cat(make([]byte, 4), ikeRequest(14, 256)), limits); err != nil {
		t.Fatalf("non-ESP marker: %v", err)
	}
	for name, tc := range map[string]struct {
		data   []byte
		limits Limits
		want   string
	}{
		"width":    {ikeRequest(14, 255), limits, "width disagrees"},
		"group":    {ikeRequest(15, 384), limits, "KE/nonce disagrees"},
		"budget":   {ikeRequest(14, 256), Limits{MaxBytes: 65536, MaxHeaders: 4, MaxLine: 8192}, "work budget"},
		"bytes":    {ikeRequest(14, 256), Limits{MaxBytes: 300, MaxHeaders: 128, MaxLine: 8192}, "byte budget"},
		"trailing": {append(ikeRequest(14, 256), 0), limits, "exactly occupy"},
	} {
		if _, err := ikev2Datagram(tc.data, tc.limits); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

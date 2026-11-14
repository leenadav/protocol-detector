package framed

import (
	"strings"
	"testing"
)

func ber(tag byte, content []byte) []byte {
	n := len(content)
	if n < 128 {
		return append([]byte{tag, byte(n)}, content...)
	}
	return append([]byte{tag, 0x82, byte(n >> 8), byte(n)}, content...)
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func asReq(etypes ...[]byte) []byte {
	var list []byte
	for _, e := range etypes {
		list = append(list, ber(2, e)...)
	}
	principal := ber(0x30, cat(ber(0xa0, ber(2, []byte{1})), ber(0xa1, ber(0x30, ber(0x1b, []byte("user"))))))
	body := ber(0x30, cat(ber(0xa0, ber(3, []byte{0, 0x40, 0x81, 0, 0x10})), ber(0xa1, principal), ber(0xa2, ber(0x1b, []byte("EXAMPLE.ORG"))),
		ber(0xa5, ber(0x18, []byte("20371231235959Z"))), ber(0xa7, ber(2, []byte{0x12, 0x34, 0x56, 0x78})), ber(0xa8, ber(0x30, list))))
	return ber(0x6a, ber(0x30, cat(ber(0xa1, ber(2, []byte{5})), ber(0xa2, ber(2, []byte{0x0a})), ber(0xa4, body))))
}

func TestKerberosRequestEtypes(t *testing.T) {
	m, err := kerberosDatagram(asReq([]byte{0x17}, []byte{0x12}, []byte{0x17}, []byte{0x7f}), Limits{MaxHeaders: 16})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range m.Evidence {
		got = append(got, r.Field+"="+r.Value+"@"+r.Provenance)
	}
	want := "application_protocol=kerberos@wire kerberos_message=as-req@wire:message kerberos_etype_preferred=rc4@wire:req_body " +
		"kerberos_etype_offered=rc4@wire:req_body kerberos_etype_offered=aes-sha1@wire:req_body kerberos_etype_offered=other@wire:req_body"
	if strings.Join(got, " ") != want {
		t.Fatalf("evidence\n got %s\nwant %s", strings.Join(got, " "), want)
	}
	// A non-minimal etype drops every etype row without rejecting the message (Python swallows the error).
	m, err = kerberosDatagram(asReq([]byte{0, 0x12}), Limits{MaxHeaders: 16})
	if err != nil || len(m.Evidence) != 2 {
		t.Fatalf("non-minimal etype: %v %+v", err, m)
	}
}

func TestKerberosStreamScopeAndFraming(t *testing.T) {
	msg := asReq([]byte{0x12})
	framed := cat([]byte{0, 0, byte(len(msg) >> 8), byte(len(msg))}, msg)
	p := NewKerberos(4096, 16)
	for i := range framed { // one byte at a time
		if _, err := p.Feed(framed[i : i+1]); err != nil {
			t.Fatal(err)
		}
	}
	if !p.Done() || p.Result().Scope != "initial_message" || p.Result().ProtocolName != "kerberos" {
		t.Fatalf("result %+v", p.Result())
	}
	for frame, want := range map[string]string{
		string(cat([]byte{0x80, 0, 0, 60}, msg)): "extension bit",
		string([]byte{0, 0, 0, 39, 0x6a}):        "too short",
	} {
		if _, err := NewKerberos(4096, 16).Feed([]byte(frame)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("error %v, want %q", err, want)
		}
	}
}

func TestKerberosRejections(t *testing.T) {
	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"unknown tag": {ber(0x6e, ber(0x30, make([]byte, 60))), "covers KDC requests"},
		"trailing":    {append(asReq([]byte{0x12}), 0), "Trailing bytes"},
		"pvno":        {ber(0x6a, ber(0x30, cat(ber(0xa1, ber(2, []byte{4})), ber(0xa2, ber(2, []byte{0x0a})), ber(0xa4, ber(0x30, make([]byte, 40)))))), "pvno outside version 5"},
		"order":       {ber(0x6a, ber(0x30, cat(ber(0xa2, ber(2, []byte{0x0a})), ber(0xa1, ber(2, []byte{5})), ber(0xa4, ber(0x30, make([]byte, 40)))))), "out of order"},
	} {
		if _, _, err := kerberosBody(tc.data, 16); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want %q", name, err, tc.want)
		}
	}
}

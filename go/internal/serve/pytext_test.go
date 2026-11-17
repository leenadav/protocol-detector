package serve

import "testing"

// Vectors from CPython 3.13 (int(), base64.b64decode(validate=True), urllib.parse.urlsplit).
func TestPyIntMatchesPython(t *testing.T) {
	ok := map[string]string{" 5 ": "5", "\xa05": "5", "5\x85": "5", "1_0": "10", "007": "7", "\x0b5": "5", "\x0c5\r\n": "5", "-0": "0", "+3": "3"}
	for in, want := range ok {
		v, msg := pyInt(in)
		if msg != "" || v.String() != want {
			t.Errorf("int(%q) = %v %q, want %s", in, v, msg, want)
		}
	}
	bad := map[string]string{
		"1__0": "invalid literal for int() with base 10: '1__0'", "+_1": "invalid literal for int() with base 10: '+_1'",
		"\x1c5": `invalid literal for int() with base 10: '\x1c5'`, "": "invalid literal for int() with base 10: ''",
		"0x10": "invalid literal for int() with base 10: '0x10'", "\xe9": "invalid literal for int() with base 10: 'é'",
		"a'b": `invalid literal for int() with base 10: "a'b"`, "a'\"b": `invalid literal for int() with base 10: 'a\'"b'`,
		"\t": `invalid literal for int() with base 10: '\t'`, "\xad": `invalid literal for int() with base 10: '\xad'`,
	}
	for in, want := range bad {
		if _, msg := pyInt(in); msg != want {
			t.Errorf("int(%q): %q, want %q", in, msg, want)
		}
	}
	long := make([]byte, 300)
	for i := range long {
		long[i] = 'x'
	}
	if _, msg := pyInt(string(long)); len(msg) != 240 {
		t.Errorf("the repr is not cut at 200 characters: %d", len(msg))
	}
}

func TestB64DecodeStrictMatchesPython(t *testing.T) {
	cases := map[string]string{
		"ab=c": "Discontinuous padding not allowed", "abc": "Incorrect padding", "ab=": "Incorrect padding",
		"a":    "Invalid base64-encoded string: number of data characters (1) cannot be 1 more than a multiple of 4",
		"====": "Leading padding not allowed", "=Zm9v": "Leading padding not allowed", "Zm9v\n": "Only base64 data is allowed",
		"é": "string argument should contain only ASCII characters", "Zm9vYg=": "Incorrect padding", "Zm9vYmE": "Incorrect padding",
		"ab==": "", "Zm9v": "", "": "",
	}
	for in, want := range cases {
		if _, msg := b64decodeStrict(in); msg != want {
			t.Errorf("b64decode(%q): %q, want %q", in, msg, want)
		}
	}
	if out, _ := b64decodeStrict("Zm9vYmFy"); string(out) != "foobar" {
		t.Fatal(string(out))
	}
}

func TestURLSplitPathAndQuery(t *testing.T) {
	cases := []struct{ in, path, query string }{
		{"/api/live/events?cursor=1#x", "/api/live/events", "cursor=1"},
		{"http://127.0.0.1:1/api/health?a", "/api/health", "a"},
		{"\x01/api/server", "/api/server", ""},
		{"/a\tb", "/ab", ""},
		{"x:y", "y", ""},
		{"1x:/p", "1x:/p", ""},
	}
	for _, c := range cases {
		path, query, ok := urlsplit(c.in)
		if !ok || path != c.path || query != c.query {
			t.Errorf("urlsplit(%q) = %q %q %v", c.in, path, query, ok)
		}
	}
	if _, _, ok := urlsplit("http://[x/api"); ok {
		t.Error("an unclosed bracket was accepted")
	}
}

func TestEmailHeaders(t *testing.T) {
	got := emailHeaders("Host: a\r\n b\r\nX:1\rBad Header\r\nY: 2\r\n\r\n")
	if len(got) != 2 || got[0].value != "a\r\n b" || got[1].name != "X" || got[1].value != "1" {
		t.Fatalf("%q", got)
	}
}

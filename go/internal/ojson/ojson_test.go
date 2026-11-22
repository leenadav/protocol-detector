package ojson

import (
	"strings"
	"testing"
)

// Vectors computed with Python 3.13: json.dumps(json.loads(text), allow_nan=False).
func TestDecodeDumpsMatchesPython(t *testing.T) {
	cases := []struct{ in, out string }{
		{`{"a": 1, "b": [1.5, -0, 1e2, 2E-3, 1.0, 12345678901234567890123], "a": 2}`, `{"a": 2, "b": [1.5, 0, 100.0, 0.002, 1.0, 12345678901234567890123]}`},
		{`{"s": "\u00e9\ud83d\ude00\n\"x"}`, `{"s": "\u00e9\ud83d\ude00\n\"x"}`},
		{`  {"x" : null , "y":true,"z":false}  `, `{"x": null, "y": true, "z": false}`},
		{`[0.1, 100000000000000000.0, 1e-7, 123.456e10]`, `[0.1, 1e+17, 1e-07, 1234560000000.0]`},
		{`"\ud800"`, `"\ud800"`},
		{`{"x": "\/"}`, `{"x": "/"}`},
		{`"é"`, `"\u00e9"`},
	}
	for _, c := range cases {
		v, err := Decode([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		got, err := Dumps(v)
		if err != nil || got != c.out {
			t.Errorf("%s: got %s (%v), want %s", c.in, got, err, c.out)
		}
	}
}

func TestDecodeRefusesWhatPythonRefuses(t *testing.T) {
	for _, in := range []string{`{"x": 1,}`, `[1 2]`, `{"x": 01}`, "{\"x\": \"\x01\"}", `{"x"`, ``, `[`, `{"a" 1}`, `nul`, `"\x"`, `"\u12"`, `-`, `1.`, "\xff"} {
		if _, err := Decode([]byte(in)); err == nil {
			t.Errorf("%q decoded", in)
		}
	}
	for _, in := range []string{`[NaN]`, `[-Infinity]`, `{"k": 1e400}`} {
		v, err := Decode([]byte(in))
		if err != nil {
			t.Fatalf("%s: %v (json.loads accepts it)", in, err)
		}
		if _, err := Dumps(v); err == nil || !strings.HasPrefix(err.Error(), "Out of range float values are not JSON compliant: ") {
			t.Errorf("%s: dumps gave %v, want the allow_nan refusal", in, err)
		}
	}
	if _, err := Decode([]byte(strings.Repeat("[", MaxDepth+2))); err == nil {
		t.Error("unbounded nesting decoded")
	}
}

func TestObjectKeepsFirstPositionOfARepeatedKey(t *testing.T) {
	o := NewObject("a", 1, "b", 2)
	o.Set("a", 3)
	if got := MustDumps(o); got != `{"a": 3, "b": 2}` {
		t.Fatal(got)
	}
	c := o.Copy()
	c.Set("c", true)
	if MustDumps(o) == MustDumps(c) {
		t.Fatal("Copy shares keys")
	}
}

// FuzzDecodeIsAFixedPoint: whatever decodes is written as text that decodes to the same text again.
func FuzzDecodeIsAFixedPoint(f *testing.F) {
	for _, seed := range []string{`{"a": [1, 2.5, "x"], "b": {"c": null}}`, `"\ud800"`, `[1e400]`, `{"a":1,"a":2}`, `-0`} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := Decode(data)
		if err != nil {
			return
		}
		text, err := Dumps(v)
		if err != nil {
			return
		}
		again, err := Decode([]byte(text))
		if err != nil {
			t.Fatalf("own output %q does not decode: %v", text, err)
		}
		if second := MustDumps(again); second != text {
			t.Fatalf("not a fixed point: %q then %q", text, second)
		}
	})
}

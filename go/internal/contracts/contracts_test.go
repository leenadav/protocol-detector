package contracts

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/errs"
)

const sample = `{"status":"identified","transport":"tcp","encryption":null,"application_protocol":"http/1.1","application":null,` +
	`"hostname":"a.example","offered_alpn":[],"evidence":[["http_method","GET","client","structural"]],"reason":"HTTP/1.1 request","scope":"initial_message"}`

func TestObservationRoundTripsThePythonShape(t *testing.T) {
	var o Observation
	if err := json.Unmarshal([]byte(sample), &o); err != nil {
		t.Fatal(err)
	}
	if o.Status != Identified || o.Encryption != nil || *o.ApplicationProtocol != "http/1.1" || o.Evidence[0].Strength != StrengthStructural {
		t.Fatalf("decoded %+v", o)
	}
	out, err := json.Marshal(o)
	if err != nil {
		t.Fatal(err)
	}
	var a, b interface{}
	json.Unmarshal([]byte(sample), &a)
	json.Unmarshal(out, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("re-encoded differently:\n%s\n%s", sample, out)
	}
}

func TestNullListsBecomeEmptyListsAndNeverNull(t *testing.T) {
	var o Observation
	if err := json.Unmarshal([]byte(`{"status":"unknown","transport":"udp","offered_alpn":null,"evidence":null,"reason":"x","scope":"initial_message"}`), &o); err != nil {
		t.Fatal(err)
	}
	out, _ := json.Marshal(o)
	if !strings.Contains(string(out), `"offered_alpn":[]`) || !strings.Contains(string(out), `"evidence":[]`) {
		t.Fatalf("null lists leaked: %s", out)
	}
	bad := Observation{Status: Unknown, Transport: "tcp"}
	if _, err := json.Marshal(bad); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatalf("nil lists marshalled: %v", err)
	}
}

func TestClosedVocabularies(t *testing.T) {
	cases := map[string]string{
		"status":    `{"status":"maybe","transport":"tcp","offered_alpn":[],"evidence":[],"reason":"","scope":"initial_message"}`,
		"transport": `{"status":"unknown","transport":"sctp","offered_alpn":[],"evidence":[],"reason":"","scope":"initial_message"}`,
		"evidence":  `{"status":"unknown","transport":"tcp","offered_alpn":[],"evidence":[["a","b"]],"reason":"","scope":"initial_message"}`,
	}
	for name, text := range cases {
		var o Observation
		if err := json.Unmarshal([]byte(text), &o); !errors.Is(err, errs.Invalid.Err()) {
			t.Fatalf("%s accepted: %v", name, err)
		}
	}
	var e Event
	if err := json.Unmarshal([]byte(`{"kind":"guessed","revision":1,"observation":`+sample+`}`), &e); !errors.Is(err, errs.Invalid.Err()) {
		t.Fatalf("unknown kind accepted: %v", err)
	}
	if err := json.Unmarshal([]byte(`{"kind":"refined","revision":2,"observation":`+sample+`}`), &e); err != nil || e.Kind != Refined || e.Revision != 2 {
		t.Fatalf("valid event rejected: %v %+v", err, e)
	}
}

func TestConfigDecodesOverDefaultsAndFailsClosed(t *testing.T) {
	var c Config
	if err := json.Unmarshal([]byte(`{"max_bytes": 64, "continuation": 4096}`), &c); err != nil {
		t.Fatal(err)
	}
	want := DefaultConfig()
	want.MaxBytes, want.Continuation = 64, 4096
	if c != want {
		t.Fatalf("got %+v want %+v", c, want)
	}
	for _, text := range []string{`{"max_bytes": 0}`, `{"max_lines": 3}`, `{"continuation": -1}`} {
		if err := json.Unmarshal([]byte(text), &c); !errors.Is(err, errs.Invalid.Err()) {
			t.Fatalf("%s accepted: %v", text, err)
		}
	}
	if err := json.Unmarshal([]byte(`{}`), &c); err != nil || c != DefaultConfig() {
		t.Fatalf("empty config: %v %+v", err, c)
	}
}

func TestInitialObservationMatchesThePythonDefaults(t *testing.T) {
	out, err := json.Marshal(Initial("tcp"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"status":"detecting","transport":"tcp","encryption":null,"application_protocol":null,"application":null,"hostname":null,` +
		`"offered_alpn":[],"evidence":[],"reason":"Waiting for stream prefix","scope":"initial_message"}`
	if string(out) != want {
		t.Fatalf("initial = %s", out)
	}
}

func FuzzObservationJSONNeverPanics(f *testing.F) {
	f.Add([]byte(sample))
	f.Add([]byte(`{"status":"unknown"}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var o Observation
		if err := json.Unmarshal(data, &o); err != nil {
			return
		}
		out, err := json.Marshal(o)
		if err != nil {
			t.Fatalf("decoded value does not encode: %v", err)
		}
		var again Observation
		if err := json.Unmarshal(out, &again); err != nil || !reflect.DeepEqual(o, again) {
			t.Fatalf("round trip changed the value: %v", err)
		}
	})
}

// Review R4 (2026-11-14): every integer option accepts both ends of its Python range and rejects the values
// just outside; max_crc32c_bytes=0 (checksum work disabled) is valid and max_bytes above 1 MiB is not.
func TestConfigRangesAtTheirBoundaries(t *testing.T) {
	set := func(name string, value int) Config {
		c := DefaultConfig()
		raw, _ := json.Marshal(map[string]int{name: value})
		if err := json.Unmarshal(raw, (*configJSON)(&c)); err != nil {
			t.Fatal(err)
		}
		return c
	}
	if len(ConfigRanges) != 9 {
		t.Fatalf("%d ranges", len(ConfigRanges))
	}
	for _, r := range ConfigRanges {
		if DefaultConfig().integer(r.Name) < r.Low || DefaultConfig().integer(r.Name) > r.High {
			t.Errorf("default %s outside its range", r.Name)
		}
		for _, tc := range []struct {
			value int
			valid bool
		}{{r.Low - 1, false}, {r.Low, true}, {r.Low + 1, true}, {r.High - 1, true}, {r.High, true}, {r.High + 1, false}} {
			c := set(r.Name, tc.value)
			if c.integer(r.Name) != tc.value {
				t.Fatalf("%s not set", r.Name)
			}
			if err := c.Validate(); (err == nil) != tc.valid {
				t.Errorf("%s=%d: valid=%v, got %v", r.Name, tc.value, tc.valid, err)
			}
			var viaJSON Config
			raw, _ := json.Marshal(map[string]int{r.Name: tc.value})
			if err := json.Unmarshal(raw, &viaJSON); (err == nil) != tc.valid {
				t.Errorf("JSON %s=%d: valid=%v, got %v", r.Name, tc.value, tc.valid, err)
			}
		}
	}
	zero := DefaultConfig()
	zero.MaxCRC32CBytes = 0
	if err := zero.Validate(); err != nil {
		t.Errorf("max_crc32c_bytes=0 rejected: %v", err)
	}
	huge := DefaultConfig()
	huge.MaxBytes = 1 << 40
	if huge.Validate() == nil {
		t.Error("max_bytes=1<<40 accepted")
	}
}

// Integration work item #17: Observation.Equal replaces reflect.DeepEqual on the publish path. It must give the
// same answer for every pair, including the cases reflection distinguishes (nil against empty slices, optional
// strings by content).
func TestEqualAgreesWithDeepEqual(t *testing.T) {
	str := func(s string) *string { return &s }
	base := func() Observation {
		o := Initial("tcp")
		o.Status, o.Reason, o.Scope = Identified, "validated", "server_hello"
		o.Encryption, o.ApplicationProtocol, o.Application, o.Hostname = str("tls"), str("http/1.1"), str("app"), str("a.example")
		o.OfferedALPN = []string{"h2", "http/1.1"}
		o.Evidence = []Evidence{{"encryption", "tls", "wire", "structural"}, {"selected_group", "29", "wire:server_hello", "asserted"}}
		return o
	}
	variants := []func(*Observation){
		func(o *Observation) {},
		func(o *Observation) { o.Status = Unknown },
		func(o *Observation) { o.Transport = "udp" },
		func(o *Observation) { o.Reason = "other" },
		func(o *Observation) { o.Scope = "initial_message" },
		func(o *Observation) { o.Encryption = nil },
		func(o *Observation) { o.Encryption = str("tls") }, // same content, another address
		func(o *Observation) { o.Encryption = str("dtls") },
		func(o *Observation) { o.ApplicationProtocol = nil },
		func(o *Observation) { o.ApplicationProtocol = str("h2") },
		func(o *Observation) { o.Application = nil },
		func(o *Observation) { o.Application = str("") },
		func(o *Observation) { o.Hostname = nil },
		func(o *Observation) { o.Hostname = str("b.example") },
		func(o *Observation) { o.OfferedALPN = nil },
		func(o *Observation) { o.OfferedALPN = []string{} },
		func(o *Observation) { o.OfferedALPN = []string{"h2"} },
		func(o *Observation) { o.OfferedALPN = []string{"http/1.1", "h2"} },
		func(o *Observation) { o.Evidence = nil },
		func(o *Observation) { o.Evidence = []Evidence{} },
		func(o *Observation) { o.Evidence = o.Evidence[:1] },
		func(o *Observation) { o.Evidence[1].Value = "23" },
		func(o *Observation) { o.Evidence[0].Strength = "asserted" },
		func(o *Observation) { o.Evidence = append(o.Evidence, Evidence{"x", "y", "z", "w"}) },
	}
	for i, a := range variants {
		for j, b := range variants {
			x, y := base(), base()
			a(&x)
			b(&y)
			if got, want := x.Equal(y), reflect.DeepEqual(x, y); got != want {
				t.Errorf("variants %d and %d: Equal %v, DeepEqual %v", i, j, got, want)
			}
		}
	}
	// A new field must be added to Equal: this fails when the struct grows.
	if n := reflect.TypeOf(Observation{}).NumField(); n != 10 {
		t.Fatalf("Observation has %d fields; update Equal and this test", n)
	}
	if allocs := testing.AllocsPerRun(100, func() { x, y := base(), base(); _ = x.Equal(y) }); allocs > float64(testing.AllocsPerRun(100, func() { _, _ = base(), base() })) {
		t.Errorf("Equal allocates: %v", allocs)
	}
}

func BenchmarkObservationEqual(b *testing.B) {
	o := Initial("tcp")
	o.Evidence = []Evidence{{"encryption", "tls", "wire", "structural"}, {"selected_group", "29", "wire:server_hello", "asserted"}}
	p := o
	b.Run("Equal", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = o.Equal(p)
		}
	})
	b.Run("DeepEqual", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = reflect.DeepEqual(o, p)
		}
	})
}

package pyjson

import (
	"math"
	"testing"
)

// Expected texts are Python's json.dumps / repr / round for the same values.
func TestDumpsMatchesPythonText(t *testing.T) {
	orders := func(path string) []string {
		if path == "row" {
			return []string{"type", "start", "names"}
		}
		return nil
	}
	var none *string
	value := map[string]interface{}{"names": []string{"a", "café", "€\U0001f600", "q\"\\\n\x7f"}, "start": 1700000000.25, "type": "session",
		"zeta": none, "alpha": map[string]int{"b": 2, "a": 1}, "empty": []string(nil), "flag": true, "port": uint16(443)}
	want := `{"type": "session", "start": 1700000000.25, "names": ["a", "caf` + "\\u00e9" + `", "` + "\\u20ac\\ud83d\\ude00" + `", "q\"\\\n\u007f"], ` +
		`"alpha": {"a": 1, "b": 2}, "empty": [], "flag": true, "port": 443, "zeta": null}`
	if got := Dumps(value, "row", orders); got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

func TestFloatAndRound(t *testing.T) {
	for value, want := range map[float64]string{1700000000.0: "1700000000.0", 0.001: "0.001", 1e-05: "1e-05", 1e16: "1e+16", 123456789012345680.0: "1.2345678901234568e+17",
		0.30000000000000004: "0.30000000000000004", 5e-324: "5e-324", 1.5: "1.5", -2.0: "-2.0", 9999999999999998.0: "9999999999999998.0"} {
		if got := Float(value); got != want {
			t.Errorf("Float(%v) = %s, want %s", value, got, want)
		}
	}
	if Float(math.Inf(1)) != "Infinity" || Float(math.NaN()) != "NaN" || Float(math.Copysign(0, -1)) != "-0.0" {
		t.Error("special values")
	}
	// round(2.675, 2) is 2.67 in Python (the binary value is below the tie); round(0.0000005, 6) is 0.0.
	for _, c := range []struct {
		x      float64
		digits int
		want   float64
	}{{2.675, 2, 2.67}, {0.0000005, 6, 0.0}, {0.0000015, 6, 2e-06}, {1.0000005, 6, 1.000001}, {61.000999999, 6, 61.001}} {
		if got := Round(c.x, c.digits); got != c.want {
			t.Errorf("Round(%v, %d) = %v, want %v", c.x, c.digits, got, c.want)
		}
	}
}

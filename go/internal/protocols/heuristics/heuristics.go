// Package heuristics ports protocol_engine/heuristics.py: bounded payload heuristics for traffic no profile matched.
// They never identify an application; they describe the shape of an unknown payload prefix (entropy, printable
// ratio, zero ratio) over at most Config.heuristic_bytes bytes with one pass and a 256-entry histogram. No payload
// byte is emitted. Evidence strength is "heuristic".
package heuristics

import (
	"math"
	"strconv"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// Profile is heuristics.PayloadProfile.
type Profile struct {
	Size       int
	Entropy    float64 // Shannon entropy in bits per byte, rounded to 2 places
	Printable  float64 // fraction of bytes in 0x09, 0x0a, 0x0d, 0x20..0x7e, rounded to 3 places
	Zeros      float64 // fraction of 0x00 bytes, rounded to 3 places
	LongestRun int
}

// round is Python's round(x, places): the nearest float to the correctly rounded (half-even) decimal.
func round(x float64, places int) float64 {
	v, _ := strconv.ParseFloat(strconv.FormatFloat(x, 'f', places, 64), 64)
	return v
}

func printable(b byte) bool { return (b >= 0x20 && b < 0x7f) || b == 0x09 || b == 0x0a || b == 0x0d }

// PayloadProfile profiles the first limit bytes.
func PayloadProfile(data []byte, limit int) Profile {
	if len(data) > limit {
		data = data[:limit]
	}
	size := len(data)
	if size == 0 {
		return Profile{}
	}
	var counts [256]int
	printables, run, longest := 0, 0, 0
	for _, b := range data {
		counts[b]++
		if printable(b) {
			printables++
			run++
			if run > longest {
				longest = run
			}
		} else {
			run = 0
		}
	}
	entropy := 0.0
	for _, count := range counts {
		if count > 0 {
			p := float64(count) / float64(size)
			entropy -= p * math.Log2(p)
		}
	}
	return Profile{Size: size, Entropy: round(math.Abs(entropy), 2), Printable: round(float64(printables)/float64(size), 3),
		Zeros: round(float64(counts[0])/float64(size), 3), LongestRun: longest}
}

// Class is heuristics.payload_class (thresholds in RISKS.md).
func Class(p Profile) string {
	switch {
	case p.Size < 8:
		return "insufficient"
	case p.Printable >= 0.95:
		return "text"
	case p.Size >= 64 && p.Entropy >= 0.90*math.Log2(math.Min(float64(p.Size), 256)):
		return "high-entropy"
	case p.Zeros >= 0.30:
		return "sparse-binary"
	}
	return "binary"
}

// Evidence is heuristics.heuristic_evidence: four rows for a non-empty prefix, none for empty data.
func Evidence(data []byte, source string, limit int) []contracts.Evidence {
	p := PayloadProfile(data, limit)
	if p.Size == 0 {
		return nil
	}
	provenance := source + ":heuristic"
	return []contracts.Evidence{{Field: "payload_class", Value: Class(p), Source: provenance, Strength: "heuristic"},
		{Field: "payload_entropy", Value: strconv.FormatFloat(p.Entropy, 'f', 2, 64), Source: provenance, Strength: "heuristic"},
		{Field: "payload_printable", Value: strconv.FormatFloat(p.Printable, 'f', 3, 64), Source: provenance, Strength: "heuristic"},
		{Field: "payload_bytes_profiled", Value: strconv.Itoa(p.Size), Source: provenance, Strength: "heuristic"}}
}

// LabelEntropy is heuristics.label_entropy, summing in first-appearance order as the Python dict does.
func LabelEntropy(label []byte) float64 {
	if len(label) == 0 {
		return 0
	}
	counts := map[byte]int{}
	var order []byte
	for _, b := range label {
		if counts[b] == 0 {
			order = append(order, b)
		}
		counts[b]++
	}
	size := float64(len(label))
	sum := 0.0
	for _, b := range order {
		p := float64(counts[b]) / size
		sum += p * math.Log2(p)
	}
	return round(math.Abs(sum), 2)
}

func lower(b []byte) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		out[i] = c
	}
	return out
}

// DNSNameShape is datagram.dns_name_shape: the shape of a query name; the name itself is never emitted. Suspicious:
// a label of 40+ bytes, a name of 150+ bytes, or a label of 16+ bytes whose byte entropy reaches 4.0 bits.
func DNSNameShape(qname []byte) []contracts.Evidence {
	trimmed := qname
	for len(trimmed) > 0 && trimmed[len(trimmed)-1] == '.' {
		trimmed = trimmed[:len(trimmed)-1]
	}
	var labels [][]byte
	start := 0
	for i := 0; i <= len(trimmed); i++ {
		if i == len(trimmed) || trimmed[i] == '.' {
			if i > start {
				labels = append(labels, trimmed[start:i])
			}
			start = i + 1
		}
	}
	longest, entropy := 0, 0.0
	for _, l := range labels {
		if len(l) > longest {
			longest = len(l)
		}
		if len(l) >= 16 {
			if e := LabelEntropy(lower(l)); e > entropy {
				entropy = e
			}
		}
	}
	shape := "ordinary"
	if longest >= 40 || len(qname) >= 150 || entropy >= 4.0 {
		shape = "suspicious"
	}
	row := func(field, value string) contracts.Evidence {
		return contracts.Evidence{Field: field, Value: value, Source: "wire:heuristic", Strength: "heuristic"}
	}
	return []contracts.Evidence{row("dns_query_shape", shape), row("dns_query_labels", strconv.Itoa(len(labels))),
		row("dns_query_longest_label", strconv.Itoa(longest)), row("dns_label_entropy", strconv.FormatFloat(entropy, 'f', 2, 64))}
}

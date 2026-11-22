package textroute

import (
	"reflect"
	"strings"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// oraclePosture is the map-based kexinitPosture as it stood before the allocation work (2026-11-16): the
// scans that replaced it must give the same rows, in the same order, for every name-list.
func oraclePosture(lists [][]byte) []parsing.Row {
	nameSet := func(value []byte) map[string]bool {
		out := map[string]bool{}
		if len(value) == 0 {
			return out
		}
		for _, n := range strings.Split(string(value), ",") {
			out[n] = true
		}
		return out
	}
	union := func(a, b map[string]bool) map[string]bool {
		out := map[string]bool{}
		for k := range a {
			out[k] = true
		}
		for k := range b {
			out[k] = true
		}
		return out
	}
	intersects := func(a, b map[string]bool) bool {
		for k := range a {
			if b[k] {
				return true
			}
		}
		return false
	}
	cbcWithETM := func(ciphers, macs map[string]bool) bool {
		if !intersects(ciphers, cbcOr64) {
			return false
		}
		for m := range macs {
			if strings.HasSuffix(m, "-etm@openssh.com") {
				return true
			}
		}
		return false
	}
	kex, hostkeys := nameSet(lists[0]), nameSet(lists[1])
	c2sCiphers, s2cCiphers := nameSet(lists[2]), nameSet(lists[3])
	c2sMacs, s2cMacs := nameSet(lists[4]), nameSet(lists[5])
	ciphers, macs := union(c2sCiphers, s2cCiphers), union(c2sMacs, s2cMacs)
	byList := map[int]map[string]bool{0: kex, 1: hostkeys, 2: ciphers, 4: macs}
	families := map[string]bool{}
	for n := range kex {
		if f, ok := kexFamily[n]; ok {
			families[f] = true
		}
	}
	class := "other"
	for _, f := range kexRank {
		if families[f] {
			class = f
			break
		}
	}
	rows := []parsing.Row{{Field: "ssh_kex_class", Value: class, Provenance: "kexinit", Strength: "asserted"}}
	for _, w := range weakClasses {
		if intersects(byList[w.index], w.names) {
			rows = append(rows, parsing.Row{Field: "ssh_weak_algorithm", Value: w.label, Provenance: "kexinit", Strength: "asserted"})
		}
	}
	terrapin := "not-applicable"
	if kex["kex-strict-c-v00@openssh.com"] || kex["kex-strict-s-v00@openssh.com"] {
		terrapin = "strict"
	} else if ciphers["chacha20-poly1305@openssh.com"] || cbcWithETM(c2sCiphers, c2sMacs) || cbcWithETM(s2cCiphers, s2cMacs) {
		terrapin = "exposed"
	}
	return append(rows, parsing.Row{Field: "ssh_terrapin", Value: terrapin, Provenance: "kexinit", Strength: "asserted"})
}

// vocabulary is every name the posture tables know, plus a few they do not.
func vocabulary() []string {
	seen := map[string]bool{"unknown-algo": true, "ssh-ed25519": true, "aes128-gcm@openssh.com": true, "hmac-sha2-256": true,
		"chacha20-poly1305@openssh.com": true, "kex-strict-c-v00@openssh.com": true, "kex-strict-s-v00@openssh.com": true,
		"hmac-sha2-256-etm@openssh.com": true, "umac-64-etm@openssh.com": true}
	for n := range kexFamily {
		seen[n] = true
	}
	for _, w := range weakClasses {
		for n := range w.names {
			seen[n] = true
		}
	}
	out := make([]string, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	return out
}

func listsFrom(data []byte, names []string) [][]byte {
	lists := make([][]byte, 10)
	for i := range lists {
		var picked []string
		for j := 0; j < 6 && len(data) > 0; j++ {
			b := data[0]
			data = data[1:]
			if b%7 == 0 {
				break
			}
			picked = append(picked, names[int(b)%len(names)])
		}
		lists[i] = []byte(strings.Join(picked, ","))
	}
	return lists
}

func TestKexinitPostureMatchesTheOracle(t *testing.T) {
	names := vocabulary()
	for seed := 0; seed < 20000; seed++ {
		data := make([]byte, 64)
		x := uint32(seed)*2654435761 + 1
		for i := range data {
			x ^= x << 13
			x ^= x >> 17
			x ^= x << 5
			data[i] = byte(x)
		}
		lists := listsFrom(data, names)
		if got, want := kexinitPosture(lists), oraclePosture(lists); !reflect.DeepEqual(got, want) {
			t.Fatalf("lists %q:\n got %v\nwant %v", lists, got, want)
		}
	}
	empty := make([][]byte, 10)
	if got, want := kexinitPosture(empty), oraclePosture(empty); !reflect.DeepEqual(got, want) {
		t.Fatalf("empty lists: %v, want %v", got, want)
	}
}

func FuzzKexinitPostureMatchesTheOracle(f *testing.F) {
	f.Add([]byte{1, 2, 3, 0, 4, 5, 6, 7, 8, 9, 10})
	names := vocabulary()
	f.Fuzz(func(t *testing.T, data []byte) {
		lists := listsFrom(data, names)
		if got, want := kexinitPosture(lists), oraclePosture(lists); !reflect.DeepEqual(got, want) {
			t.Fatalf("lists %q:\n got %v\nwant %v", lists, got, want)
		}
	})
}

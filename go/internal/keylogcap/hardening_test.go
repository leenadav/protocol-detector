package keylogcap

import (
	"encoding/binary"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/decrypt"
)

// SEC-KEY-1 (PRO-119): Analyze releases its key provider on every return, so the indexed secrets are overwritten
// whether the capture is reported or refused (before, nothing called Release and the secrets stayed in the heap
// until the collector reused it). The report is unchanged: it never carried a secret.
func TestAnalyzeReleasesItsKeyProviderOnEveryReturn(t *testing.T) {
	var providers []*decrypt.KeyProvider
	original := newKeyProvider
	newKeyProvider = func() *decrypt.KeyProvider {
		p := original()
		providers = append(providers, p)
		return p
	}
	t.Cleanup(func() { newKeyProvider = original })
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	client, server, keylog := exchange()
	capture := pcap(conversation(client, server)...)
	truncated := append([]byte{}, capture...)
	binary.LittleEndian.PutUint32(truncated[24+12:], 9999)
	for _, tc := range []struct {
		name, keylog string
		data         []byte
		refused      bool
	}{
		{"reported", keylog, capture, false},
		{"key-log refusal", keylog + "two fields\n", capture, true},
		{"capture refusal after indexing", keylog, truncated, true},
	} {
		providers = nil
		text, err := Analyze(tc.data, tc.keylog, pack)
		if (err != nil) != tc.refused || (!tc.refused && text == "") {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(providers) != 1 {
			t.Fatalf("%s: %d providers", tc.name, len(providers))
		}
		if p := providers[0]; !p.Released() || p.Len() != 0 {
			t.Fatalf("%s: provider not released (%s)", tc.name, p)
		}
	}
	// The reported capture still decrypts: Release runs after the report is built.
	out, _ := analyzeFrames(t, keylog, conversation(client, server)...)
	if out.Decrypted != 1 {
		t.Fatalf("decrypted %d", out.Decrypted)
	}
}

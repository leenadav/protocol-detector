package content

import (
	"os"
	"testing"
)

// FuzzParseNeverPanics feeds arbitrary bytes to the pack loader, which also takes host-supplied packs
// (Culvert item #16): it must refuse or accept, never crash, and an accepted pack must carry verified digests.
func FuzzParseNeverPanics(f *testing.F) {
	data, err := os.ReadFile(packPath)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(data[:4096])
	f.Add([]byte(`{"schema": 1, "release": {"version": "x", "digest": "y", "components": {}}, "applications": []}`))
	f.Add([]byte(`{"schema": 1}`))
	f.Add([]byte(`[]`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > 1<<16 {
			return
		}
		pack, err := Parse(input)
		if err != nil {
			return
		}
		if len(pack.Digests.Pack) != 64 || pack.Digests.Release != pack.Release.Digest {
			t.Fatalf("accepted pack without verified digests: %+v", pack.Digests)
		}
	})
}

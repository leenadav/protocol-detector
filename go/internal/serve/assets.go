package serve

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/leenadav/protocol-detector/go/internal/ojson"
)

// The two fixed assets of the demo page, exported once from the reference (assets/README.md):
//
//   - demo.pcap: the synthetic demo capture (presentation/server.py demo_bytes(): locally built fixtures, never
//     real traffic). The reference built a new one per request around a fresh OpenSSL ClientHello; this
//     service answers the same capture every time.
//   - catalog.json: the "protocols", "applications" and "outcomes" tables of catalog_data(), in their order.
//     The "source" and "limits" fields are added here, from SOURCE.json and this service's limits.
var (
	//go:embed assets/demo.pcap
	demoCapture []byte
	//go:embed assets/catalog.json
	catalogTables []byte
)

// DemoCapture is the synthetic demo capture (GET /api/sample and the "demo" job).
func DemoCapture() []byte { return append([]byte(nil), demoCapture...) }

// sourceKeys are the SOURCE.json fields catalog_data() publishes, in its order (a missing one is null).
var sourceKeys = []string{"version", "branch", "commit", "repository", "build_digest", "components"}

// catalogData is catalog_data(): the build identity of root/SOURCE.json, the embedded tables and the limits.
func catalogData(root string) (*ojson.Object, error) {
	data, err := os.ReadFile(filepath.Join(root, "SOURCE.json"))
	if err != nil {
		return nil, err
	}
	v, err := ojson.Decode(data)
	if err != nil {
		return nil, err
	}
	source, ok := v.(*ojson.Object)
	if !ok {
		return nil, fmt.Errorf("SOURCE.json is not an object")
	}
	t, err := ojson.Decode(catalogTables)
	if err != nil {
		return nil, err
	}
	tables, ok := t.(*ojson.Object)
	if !ok {
		return nil, fmt.Errorf("the embedded catalog is not an object")
	}
	published := ojson.NewObject()
	for _, key := range sourceKeys {
		value, _ := source.Get(key)
		published.Set(key, value)
	}
	out := ojson.NewObject("source", published)
	for _, key := range []string{"protocols", "applications", "outcomes"} {
		value, ok := tables.Get(key)
		if !ok {
			return nil, fmt.Errorf("the embedded catalog has no %q", key)
		}
		out.Set(key, value)
	}
	out.Set("limits", ojson.NewObject("upload_mb", ojson.FromInt(8), "frames", ojson.FromInt(MaxFrames),
		"sessions", ojson.FromInt(MaxSessions), "worker_seconds", ojson.FromInt(WorkerSeconds)))
	return out, nil
}

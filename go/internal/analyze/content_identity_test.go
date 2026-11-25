package analyze

// PRO-428: a test of the content release the binary embeds, whatever it is, through the whole engine (capture
// decoding, reassembly, the TLS profile, application identification and the session record). The frozen answers of
// cases.json and the golden files pin release 2026.11.9 (migration/fixtures/content-2026.11.9), so they say nothing
// about a release added later; this test does. tools/content_pack.py --self-test --e2e runs it on a tree with the
// example batch added.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// helloWithSNI is a TLS 1.2 ClientHello record whose one extension is server_name(host).
func helloWithSNI(host string) []byte {
	name := append([]byte{0, byte(len(host) >> 8), byte(len(host))}, host...)
	list := append([]byte{byte(len(name) >> 8), byte(len(name))}, name...)
	ext := append([]byte{0, 0, byte(len(list) >> 8), byte(len(list))}, list...)
	body := append([]byte{3, 3}, make([]byte, 32)...)
	body = append(body, 0, 0, 2, 0x13, 0x01, 1, 0, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hs := append([]byte{1, 0, byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

// tlsSessions is a capture with one complete TCP session to port 443 per name, each carrying a ClientHello with
// that server name, closed by FIN from both sides; session i uses client port 20000+i.
func tlsSessions(names []string) []byte {
	const client, server = "192.0.2.10", "198.51.100.20"
	var frames [][]byte
	for i, name := range names {
		port := uint16(20000 + i)
		hello := helloWithSNI(name)
		end := 1000 + uint32(len(hello))
		frames = append(frames,
			testframes.TCP(client, port, server, 443, 999, 0, 0x02, nil),
			testframes.TCP(server, 443, client, port, 8999, 1000, 0x12, nil),
			testframes.TCP(client, port, server, 443, 1000, 9000, 0x10, nil),
			testframes.TCP(client, port, server, 443, 1000, 9000, 0x18, hello),
			testframes.TCP(client, port, server, 443, end, 9000, 0x11, nil),
			testframes.TCP(server, 443, client, port, 9000, end+1, 0x11, nil))
	}
	return classicCapture(frames...)
}

type sessionRecord struct {
	Type        string            `json:"type"`
	Client      []json.RawMessage `json:"client"`
	App         string            `json:"app"`
	Category    string            `json:"category"`
	Subcategory string            `json:"subcategory"`
	Technology  string            `json:"technology"`
	Risk        int               `json:"risk"`
	Attribution *struct {
		Provider string `json:"provider"`
		Kind     string `json:"kind"`
	} `json:"attribution"`
	Content struct {
		Version string `json:"version"`
		Digest  string `json:"digest"`
	} `json:"content"`
}

// analyzeSessions runs `analyze --json --sessions` on the capture and returns the session records by client port.
func analyzeSessions(t *testing.T, pack *content.Pack, capture []byte) map[int]sessionRecord {
	t.Helper()
	path := filepath.Join(t.TempDir(), "names.pcap")
	if err := os.WriteFile(path, capture, 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if _, err := Run(path, pack, Options{JSON: true, Sessions: true}, &out); err != nil {
		t.Fatal(err)
	}
	records := map[int]sessionRecord{}
	scanner := bufio.NewScanner(&out)
	scanner.Buffer(make([]byte, 1<<20), 1<<24)
	for scanner.Scan() {
		var record sessionRecord
		if json.Unmarshal(scanner.Bytes(), &record) != nil || record.Type != "session" {
			continue
		}
		var port int
		if len(record.Client) != 2 || json.Unmarshal(record.Client[1], &port) != nil {
			t.Fatalf("session record without a client port: %s", scanner.Text())
		}
		records[port] = record
	}
	return records
}

// Every server-name record of the embedded release names its application through the engine: each domain, and a
// name under it, is identified as the entry's application with the entry's own fields, attributed to it as a
// service; each web front (an exact name, which wins over a domain of the same entry, such as an apex both list) is
// attributed to its provider as provider-web and never names the service. The records
// carry the release the binary embeds.
func TestEveryServerNameRecordIsIdentifiedThroughTheEngine(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(pack.HostEntryOrder) == 0 {
		t.Fatal("the embedded pack has no server-name entries")
	}
	type probe struct{ name, entry, kind string }
	var probes []probe
	fronts := pack.WebFronts()
	for _, entry := range pack.HostEntryOrder {
		for _, domain := range pack.AppDomains[entry] {
			if fronts[domain] == "" { // an exact web front wins over a domain of the same entry (tested below)
				probes = append(probes, probe{domain, entry, "service"})
			}
			probes = append(probes, probe{"pro-428-probe." + domain, entry, "service"})
		}
	}
	frontNames := make([]string, 0, len(fronts))
	for name := range fronts {
		frontNames = append(frontNames, name)
	}
	sort.Strings(frontNames)
	for _, name := range frontNames {
		probes = append(probes, probe{name, fronts[name], "provider-web"})
	}
	names := make([]string, len(probes))
	for i, p := range probes {
		names[i] = p.name
	}
	records := analyzeSessions(t, pack, tlsSessions(names))
	if len(records) != len(probes) {
		t.Fatalf("%d session records for %d sessions", len(records), len(probes))
	}
	failures := 0
	for i, p := range probes {
		record := records[20000+i]
		problem := ""
		switch {
		case record.Content.Version != pack.Release.Version || record.Content.Digest != pack.Release.Digest:
			problem = fmt.Sprintf("content %s/%s, the embedded release is %s/%s", record.Content.Version, record.Content.Digest,
				pack.Release.Version, pack.Release.Digest)
		case record.Attribution == nil || record.Attribution.Provider != p.entry || record.Attribution.Kind != p.kind:
			problem = fmt.Sprintf("attribution %+v, want provider %s kind %s", record.Attribution, p.entry, p.kind)
		case p.kind == "service":
			app := pack.Applications[p.entry]
			if record.App != app.Name || record.Category != app.Category || record.Subcategory != app.Subcategory ||
				record.Technology != app.Technology || record.Risk != app.Risk {
				problem = fmt.Sprintf("identified as %s (%s/%s, %s, risk %d), the entry is %s (%s/%s, %s, risk %d)", record.App,
					record.Category, record.Subcategory, record.Technology, record.Risk, app.Name, app.Category, app.Subcategory,
					app.Technology, app.Risk)
			}
		case record.App != "ssl":
			problem = "a web front named application " + record.App + "; it must stay ssl"
		}
		if problem != "" {
			failures++
			if failures <= 25 {
				t.Errorf("%s (entry %s): %s", p.name, p.entry, problem)
			}
		}
	}
	if failures > 0 {
		t.Fatalf("%d of %d server names failed", failures, len(probes))
	}
	t.Logf("release %s: %d server-name entries, %d names identified through the engine", pack.Release.Version,
		len(pack.HostEntryOrder), len(probes))
}

// The probe itself must be able to fail: a name in no entry is not identified as a service.
func TestAServerNameOutsideTheCatalogIsNotIdentified(t *testing.T) {
	pack, err := content.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	records := analyzeSessions(t, pack, tlsSessions([]string{"pro-428-unlisted.invalid"}))
	if record, ok := records[20000]; !ok || record.App != "ssl" || record.Attribution != nil {
		t.Fatalf("an unlisted name gave %+v", records[20000])
	}
}

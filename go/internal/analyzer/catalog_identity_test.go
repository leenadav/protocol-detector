package analyzer

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// currentPackFile is the current content pack, the one the product binary embeds (PRO-428).
const currentPackFile = "../content/pack.json"

func u16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func vector(width int, body []byte) []byte {
	if width == 1 {
		return append([]byte{byte(len(body))}, body...)
	}
	return append(u16(len(body)), body...)
}

// tlsClientHello is one TLS record carrying a TLS 1.3 ClientHello that offers host as its server name.
func tlsClientHello(host string) []byte {
	ext := func(kind int, body []byte) []byte { return append(append(u16(kind), u16(len(body))...), body...) }
	name := append([]byte{0}, vector(2, []byte(host))...)
	var extensions []byte
	for _, e := range [][]byte{
		ext(0, vector(2, name)),
		ext(43, vector(1, append(u16(0x0304), u16(0x0303)...))),
		ext(10, vector(2, append(u16(0x001d), u16(0x0017)...))),
		ext(13, vector(2, append(u16(0x0403), u16(0x0804)...))),
		ext(51, vector(2, append(append(u16(0x001d), u16(32)...), make([]byte, 32)...))),
	} {
		extensions = append(extensions, e...)
	}
	body := append(append([]byte{3, 3}, make([]byte, 32)...), 0)
	body = append(append(body, vector(2, append(u16(0x1301), u16(0x1302)...))...), 1, 0)
	body = append(body, vector(2, extensions)...)
	hello := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 3, 1, byte(len(hello) >> 8), byte(len(hello))}, hello...)
}

// flowRecord runs one client opening (an HTTP request or a TLS ClientHello) on a fresh TCP connection through the
// analyzer with the given pack and returns its record.
func flowRecord(t *testing.T, pack *content.Pack, port uint16, payload []byte) map[string]interface{} {
	t.Helper()
	a, err := New(pack, Options{IncludeHostnames: true, Session: session.Options{MaxConnections: 8, ByteLimit: 65536, IdleTimeout: 60, MaxUDPFlows: -1}})
	if err != nil {
		t.Fatal(err)
	}
	c, s := transport.Endpoint{Addr: "192.0.2.10", Port: 52000}, transport.Endpoint{Addr: "198.51.100.20", Port: port}
	a.Process(0, seg(c, s, 999, 0, transport.SYN, nil))
	a.Process(0, seg(s, c, 8999, 1000, transport.SYN|transport.ACK, nil))
	a.Process(0, seg(c, s, 1000, 9000, transport.ACK, nil))
	a.Process(0, seg(c, s, 1000, 9000, transport.ACK|8, payload))
	if err := a.Finish("eof"); err != nil {
		t.Fatal(err)
	}
	if len(a.Records) != 1 {
		t.Fatalf("%d records", len(a.Records))
	}
	return a.Records[0]
}

// Every server-name record of the current content pack is identified as its application by the engine (PRO-428):
// for each entry, each of its domains and a name under it, offered as an HTTP Host and as a TLS server name, gives
// a record whose application is the entry, and each of its web fronts (a name that is exactly the provider's
// website, which may also be one of its domains) is attributed to the entry as its provider ("provider-web").
// A record added by a batch is covered the moment the batch is applied, with no test edit.
func TestEveryServerNameRecordIsIdentifiedByTheEngine(t *testing.T) {
	data, err := os.ReadFile(currentPackFile)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := content.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		HostCatalog struct {
			Entries []struct {
				Name      string   `json:"name"`
				Domains   []string `json:"domains"`
				WebFronts []string `json:"web_fronts"`
			} `json:"entries"`
		} `json:"host_catalog"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, entry := range doc.HostCatalog.Entries {
		fronts := map[string]bool{}
		for _, front := range entry.WebFronts {
			fronts[front] = true
		}
		for _, domain := range entry.Domains {
			for _, host := range []string{domain, "probe." + domain} {
				if fronts[host] {
					continue // an exact web front is the provider's website, checked below
				}
				openings := map[string]struct {
					port    uint16
					payload []byte
				}{
					"http": {80, []byte(fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\n\r\n", host))},
					"tls":  {443, tlsClientHello(host)},
				}
				for kind, o := range openings {
					record := flowRecord(t, pack, o.port, o.payload)
					if record["app"] != entry.Name {
						t.Errorf("%s %s (entry %s): record app %v, attribution %v", kind, host, entry.Name, record["app"], record["attribution"])
					}
					checked++
				}
			}
		}
		for _, front := range entry.WebFronts {
			record := flowRecord(t, pack, 443, tlsClientHello(front))
			attribution, _ := record["attribution"].(map[string]interface{})
			if attribution == nil || attribution["provider"] != entry.Name || attribution["kind"] != "provider-web" {
				t.Errorf("web front %s (entry %s): record app %v, attribution %v", front, entry.Name, record["app"], record["attribution"])
			}
			checked++
		}
	}
	if len(doc.HostCatalog.Entries) != len(pack.AppDomains) || checked < 4*len(doc.HostCatalog.Entries) {
		t.Fatalf("%d entries (%d in the pack), %d openings checked", len(doc.HostCatalog.Entries), len(pack.AppDomains), checked)
	}
	t.Logf("release %s: %d server-name entries, %d openings identified", pack.Release.Version, len(doc.HostCatalog.Entries), checked)
}

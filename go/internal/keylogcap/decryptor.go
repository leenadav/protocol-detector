package keylogcap

import (
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/appid"
	"github.com/leenadav/protocol-detector/go/internal/content"
	"github.com/leenadav/protocol-detector/go/internal/contracts"
	"github.com/leenadav/protocol-detector/go/internal/decrypt"
	"github.com/leenadav/protocol-detector/go/internal/engine"
	"github.com/leenadav/protocol-detector/go/internal/session"
	"github.com/leenadav/protocol-detector/go/internal/transport"
)

// Note and Profile are the decryptor's fixed statements (decryptor.py NOTE and PROFILE).
const (
	Note    = "Record AEAD verified with supplied secrets; peer identity and certificate trust are not validated."
	Profile = "TLS 1.2 ECDHE-RSA AES-GCM / TLS 1.3 AEAD key-log POC; no CBC, QUIC, 0-RTT, HRR or renegotiation."
)

// safeEvidence are the evidence fields a row may carry: labels only, never a name, URL or credential.
var safeEvidence = map[string]bool{"application_protocol": true, "encryption": true, "http_method": true, "http_status": true,
	"http_content_type": true, "http_content_type_class": true, "grpc": true, "webdav": true, "rpc_method": true}

// row is a dict in insertion order.
type row struct {
	keys   []string
	values map[string]interface{}
}

func (r *row) set(key string, value interface{}) {
	if _, seen := r.values[key]; !seen {
		r.keys = append(r.keys, key)
	}
	r.values[key] = value
}

func (r *row) remove(key string) {
	if _, seen := r.values[key]; !seen {
		return
	}
	delete(r.values, key)
	for i, k := range r.keys {
		if k == key {
			r.keys = append(r.keys[:i], r.keys[i+1:]...)
			return
		}
	}
}

var metadataKeys = []string{"version", "cipher_suite", "authenticated_records", "client_plaintext_bytes", "server_plaintext_bytes", "state", "reason_code"}

func (r *row) update(metadata map[string]interface{}) {
	for _, key := range metadataKeys {
		if value, ok := metadata[key]; ok {
			r.set(key, value)
		}
	}
}

type connection struct {
	client, server transport.Endpoint
	sid            string
	generation     int
	tls            *decrypt.Connection
	outer          [2]*engine.Inspector
	inner          [2]*engine.Inspector // nil: no plaintext view on that side
	looksTLS       bool
	err            string
	failed         bool
	closed         bool
	row            *row
	dirty          bool
}

func newConnection(e event, keys decrypt.Keys) (*connection, error) {
	c := &connection{client: e.client, server: e.server, sid: e.sid, generation: e.generation, dirty: true,
		tls: decrypt.NewConnection(keys, e.client.String(), e.server.String())}
	for i := range c.outer {
		in, err := engine.New(contracts.DefaultConfig(), "")
		if err != nil {
			return nil, err
		}
		c.outer[i] = in
	}
	if e.client == e.server {
		c.outer[0] = c.outer[1] // one dict entry in the reference: the later inspector
	}
	return c, nil
}

func (c *connection) side(endpoint transport.Endpoint) int {
	if endpoint == c.client {
		return 0
	}
	return 1
}

func (c *connection) raw(endpoint transport.Endpoint, data []byte) {
	if c.closed {
		return // bytes after both FINs: the owner validates overlaps
	}
	c.outer[c.side(endpoint)].Feed(data)
	if len(data) > 0 && !c.looksTLS && data[0] == 0x16 {
		c.looksTLS = true
	}
	c.tls.Feed(endpoint.String(), data)
	c.dirty = true
}

func (c *connection) plaintext(delta decrypt.PlaintextDelta) error {
	side := 1
	if delta.Endpoint == c.client.String() {
		side = 0
	}
	inspector := c.outer[side]
	if c.inner[side] == nil {
		o := inspector.Observation
		if o.Encryption != nil && *o.Encryption == "tls" && o.Status != contracts.Invalidated {
			c.inner[side] = inspector // merged view through FeedDecrypted
		} else {
			// Decryption validated this envelope even if its hello is outside the passive detector's
			// narrower profile: classify the plaintext with a decrypted-source inspector.
			in, err := engine.NewDecrypted(contracts.DefaultConfig())
			if err != nil {
				return err
			}
			c.inner[side] = in
		}
		if c.client == c.server {
			c.inner[1-side] = c.inner[side]
		}
	}
	target := c.inner[side]
	c.dirty = true
	if target == inspector {
		_, err := target.FeedDecrypted(delta.Data)
		return err
	}
	target.Feed(delta.Data)
	return nil
}

// observation is the direction's view for the layered reducer: the plaintext view when there is one.
func (c *connection) observation(side int) *contracts.Observation {
	target := c.inner[side]
	if target == nil {
		o := c.outer[side].Observation
		return &o
	}
	o := target.Observation
	if target != c.outer[side] {
		tls := "tls"
		o.Encryption = &tls
	}
	return &o
}

func endpointList(e transport.Endpoint) []interface{} { return []interface{}{e.Addr, int(e.Port)} }

// build settles the cached row.
func (c *connection) build(pack *content.Pack) *row {
	c.dirty = false
	r := &row{values: map[string]interface{}{}}
	r.set("client", endpointList(c.client))
	r.set("server", endpointList(c.server))
	r.set("session_id", c.sid)
	r.set("generation", c.generation)
	c.row = r
	if c.failed {
		code := "unsupported_profile"
		if strings.Contains(c.err, "missing") || strings.Contains(c.err, "Conflicting") {
			code = "gap"
		}
		r.set("status", "unavailable")
		r.set("reason", c.err)
		r.set("reason_code", code)
		return r
	}
	r.set("outer_protocol", "tls")
	quality := "provisional"
	if c.closed {
		quality = "intact"
	}
	port := int(c.server.Port)
	metadata := c.tls.Metadata()
	if c.tls.State == decrypt.StateFailed {
		r.update(metadata)
		r.set("status", "unavailable")
		r.set("reason", c.tls.Reason)
		r.set("reason_code", c.tls.ReasonCode)
		client, server := c.outer[0].Observation, c.outer[1].Observation
		view, _ := appid.LayeredViewWith(pack, "tcp", &client, &server, nil, port, true, appid.Bytes{}, appid.Bytes{}, metadata, quality)
		r.set("layers", view)
		c.inner = [2]*engine.Inspector{} // dependent inner evidence does not survive a failed decryption
		return r
	}
	r.update(metadata)
	r.remove("state")
	switch c.tls.State {
	case decrypt.StateComplete:
		r.set("status", "decrypted")
	case decrypt.StateDecrypting:
		r.set("status", "decrypting")
		r.set("reason_code", "awaiting_bytes")
	default:
		r.set("status", c.tls.State)
		r.set("reason_code", c.tls.State)
	}
	view, effective := appid.LayeredViewWith(pack, "tcp", c.observation(0), c.observation(1), nil, port, true,
		appid.Bytes{N: c.tls.Plaintext[0], Known: true}, appid.Bytes{N: c.tls.Plaintext[1], Known: true}, metadata, quality)
	r.set("layers", view)
	if c.inner[0] != nil || c.inner[1] != nil {
		// No raw payload, key material, hostname, URL or credentials leave this adapter.
		evidence := []interface{}{}
		for side := 0; side < 2; side++ {
			if target := c.inner[side]; target != nil {
				for _, e := range target.Observation.Evidence {
					if safeEvidence[e.Field] {
						evidence = append(evidence, map[string]interface{}{"field": e.Field, "value": e.Value, "source": e.Source, "strength": e.Strength})
					}
				}
			}
		}
		var innerProtocol interface{}
		if inner, ok := view["inner"].(map[string]interface{}); ok {
			innerProtocol = inner["protocol"]
		}
		reasons := effective.Reasons
		if reasons == nil {
			reasons = []string{}
		}
		r.set("application", effective.App)
		r.set("inner_protocol", innerProtocol)
		r.set("category", effective.Category)
		r.set("app_status", effective.Status)
		r.set("reasons", reasons)
		r.set("evidence", evidence)
		r.set("note", Note)
	}
	return r
}

// decryptor is the one consumer of the coordinator's retained tier.
type decryptor struct {
	pack        *content.Pack
	owner       *Tier
	keys        decrypt.Keys
	connections map[session.Key]*connection
	order       []session.Key // insertion order of connections
	finished    []*connection // closed connections, in close order

	opened, closedCount, recordsAuthenticated, plaintextBytes, workCalls, reportCalls, retracted int
}

func newDecryptor(pack *content.Pack, owner *Tier, keys decrypt.Keys) *decryptor {
	return &decryptor{pack: pack, owner: owner, keys: keys, connections: map[session.Key]*connection{}}
}

func (d *decryptor) forget(key session.Key) {
	delete(d.connections, key)
	for i, k := range d.order {
		if k == key {
			d.order = append(d.order[:i], d.order[i+1:]...)
			return
		}
	}
}

// pump consumes every queued owner event; cheap, no cryptography.
func (d *decryptor) pump() error {
	for _, e := range d.owner.drain() {
		c := d.connections[e.key]
		switch e.kind {
		case "open":
			created, err := newConnection(e, d.keys)
			if err != nil {
				return err
			}
			if c == nil {
				d.order = append(d.order, e.key)
			}
			d.connections[e.key] = created
			d.opened++
		case "data":
			if c != nil && !c.failed {
				c.raw(e.endpoint, e.data)
			}
		case "error":
			if c != nil && !c.failed {
				// A conflicting overlap or an exhausted budget retracts the plaintext view, even after the
				// FIN event settled the row: nothing authenticated survives a contradicted reassembly.
				c.failed, c.err = true, e.reason
				c.inner = [2]*engine.Inspector{}
				c.dirty = true
				d.retracted++
			}
		case "fin":
			if c != nil && !c.closed {
				if err := d.finalize(c, e.progress, false); err != nil {
					return err
				}
			}
		case "close":
			if c != nil {
				d.forget(e.key)
				if err := d.finalize(c, e.progress, true); err != nil {
					return err
				}
				d.closedCount++
				// Nothing changes a closed connection any more (it left d.connections and d.order): settle
				// its row now and drop the inspectors, so the up to 4096 connections kept for reports hold
				// rows, not parser state (the TLS decoder released its own at its terminal state). The row
				// is the one a later report would have built (Go-only; Codex PRO-13 P2).
				c.build(d.pack)
				c.outer, c.inner = [2]*engine.Inspector{}, [2]*engine.Inspector{}
				d.finished = append(d.finished, c)
				if len(d.finished) > 4096 {
					d.finished = d.finished[1:]
				}
			}
		}
	}
	return nil
}

// finalize settles a connection whose directions both ended (fin) or which the owner released (close). A
// connection still waiting for its secrets is not failed at the FIN; the close event is the deadline.
func (d *decryptor) finalize(c *connection, progress []progress, final bool) error {
	if !c.failed && !c.closed {
		if len(progress) < 2 {
			c.failed, c.err = true, "Both TCP directions and SYNs are required."
		} else {
			for _, p := range progress {
				if p.stored != p.contiguous {
					c.failed, c.err = true, "TCP capture has missing bytes."
					break
				}
				if p.hasFin && p.fin != p.contiguous {
					c.failed, c.err = true, "TCP bytes are missing before FIN."
					break
				}
			}
		}
	}
	c.closed = true
	if !c.failed {
		if _, err := d.workOne(c, 1<<20); err != nil {
			return err
		}
		if final || c.tls.State != decrypt.StateAwaitingKeys {
			c.tls.Finish()
		}
	}
	c.dirty = true
	return nil
}

func (d *decryptor) workOne(c *connection, quantum int) (bool, error) {
	before := c.tls.RecordsAuthenticated
	wasFailed := c.tls.State == decrypt.StateFailed
	telemetry := d.owner.Telemetry
	var done func()
	if telemetry != nil {
		done = telemetry.Stage("decrypt")
	}
	deltas := c.tls.Advance(quantum)
	if done != nil {
		done()
	}
	for _, delta := range deltas {
		if err := c.plaintext(delta); err != nil {
			return false, err
		}
		d.plaintextBytes += len(delta.Data)
		if telemetry != nil {
			telemetry.Add("bytes.decrypted", len(delta.Data))
		}
	}
	d.recordsAuthenticated += c.tls.RecordsAuthenticated - before
	if telemetry != nil && !wasFailed && c.tls.State == decrypt.StateFailed && c.tls.ReasonCode == decrypt.AuthenticationFailed {
		telemetry.Add("decryption.auth_failures", 1)
	}
	return len(deltas) > 0 || c.tls.RecordsAuthenticated != before, nil
}

// work authenticates at most quantum records per connection per round, round-robin, for at most rounds.
func (d *decryptor) work(quantum, rounds int) error {
	d.workCalls++
	for round := 0; round < rounds; round++ {
		progressed := false
		for _, key := range append([]session.Key{}, d.order...) {
			c := d.connections[key]
			if !c.failed && c.tls.HasWork() {
				did, err := d.workOne(c, quantum)
				if err != nil {
					return err
				}
				progressed = progressed || did
				if c.closed && !c.tls.HasWork() && c.tls.State != decrypt.StateAwaitingKeys {
					c.tls.Finish() // ended earlier while waiting for keys; the keys came
				}
			}
		}
		if !progressed {
			break
		}
	}
	if d.owner.Telemetry != nil {
		d.owner.Telemetry.Set("keys.pending", d.awaitingKeys())
	}
	return nil
}

func (d *decryptor) awaitingKeys() int {
	n := 0
	for _, c := range d.connections {
		if c.tls.State == decrypt.StateAwaitingKeys {
			n++
		}
	}
	return n
}

// rows are the cached rows of the connections that looked like TLS or failed, closed ones first.
func (d *decryptor) rows() []*row {
	out := []*row{}
	all := append([]*connection{}, d.finished...)
	for _, key := range d.order {
		all = append(all, d.connections[key])
	}
	for _, c := range all {
		if c.dirty {
			c.build(d.pack)
		}
		if c.looksTLS || c.failed {
			out = append(out, c.row)
		}
	}
	return out
}

// Decryptor is the exported consumer of a retained tier (the live decryption worker's view of it).
type Decryptor struct{ d *decryptor }

// NewDecryptor attaches a decryptor to a tier.
func NewDecryptor(pack *content.Pack, tier *Tier, keys decrypt.Keys) *Decryptor {
	return &Decryptor{newDecryptor(pack, tier, keys)}
}

// Pump consumes the tier's queued events; Work does one bounded slice of record authentication.
func (x *Decryptor) Pump() error                    { return x.d.pump() }
func (x *Decryptor) Work(quantum, rounds int) error { return x.d.work(quantum, rounds) }

// Report is Decryptor.report(frames, skipped) as JSON text; profile replaces the fixed profile sentence when
// it is not empty (the live snapshot's wording).
func (x *Decryptor) Report(frames, skipped int, profile string) string {
	return x.d.report(frames, skipped, profile)
}

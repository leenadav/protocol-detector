package oracle

import (
	"bytes"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// tsharkFields are the dissector fields read, in column order after the flow address columns.
var tsharkFields = []string{
	"tls.handshake.extensions_server_name",
	"tls.handshake.extensions_alpn_str",
	"tls.handshake.version",
	"tls.handshake.extensions.supported_version",
	"http.host",
	"quic.version",
}

// Tshark dissects path with tshark (an external process; never linked) and returns the fields of each flow's
// client-to-server packets, keyed like ReadFlows. decodeAs maps "tcp.port==N" or "udp.port==N" to a dissector,
// because the relay listens on ephemeral ports tshark would not otherwise dissect as TLS, HTTP or QUIC. Only
// tshark is told the protocol; the engine gets no hint.
func Tshark(binary, path string, decodeAs map[string]string, clients map[string]bool) (map[string]Fields, error) {
	args := []string{"-n", "-r", path, "-o", "tcp.reassemble_out_of_order:TRUE", "-T", "fields",
		"-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,",
		"-Y", "tls.handshake.type == 1 || http.request || quic.long.packet_type == 0",
		"-e", "ip.src", "-e", "tcp.srcport", "-e", "udp.srcport", "-e", "ip.dst", "-e", "tcp.dstport", "-e", "udp.dstport"}
	for selector, dissector := range decodeAs {
		args = append(args, "-d", selector+","+dissector)
	}
	for _, f := range tsharkFields {
		args = append(args, "-e", f)
	}
	cmd := exec.Command(binary, args...) // fixed binary and arguments built here
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("tshark: %v: %s", err, stderr.String())
	}
	out := map[string]Fields{}
	for _, line := range strings.Split(strings.TrimRight(stdout.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		col := strings.Split(line, "\t")
		if len(col) != 6+len(tsharkFields) {
			return nil, fmt.Errorf("tshark: %d columns in %q", len(col), line)
		}
		proto, sp, dp := "tcp", col[1], col[4]
		if col[1] == "" {
			proto, sp, dp = "udp", col[2], col[5]
		}
		k := key(proto, col[0], sp, col[3], dp)
		if !clients[k] {
			continue // a server packet (QUIC server Initials match the filter too)
		}
		f := out[k]
		// A flow's first non-empty value wins: a ClientHello spread over packets yields its fields once.
		set := func(dst *string, v string) {
			if *dst == "" {
				*dst = v
			}
		}
		set(&f.SNI, strings.ToLower(col[6]))
		set(&f.ALPN, col[7])
		set(&f.TLSVersion, maxTLSVersion(col[8], col[9]))
		set(&f.HTTPHost, hostOnly(col[10]))
		set(&f.QUICVersion, quicVersion(col[11]))
		out[k] = f
	}
	return out, nil
}

var tlsNames = map[uint64]string{0x0300: "SSL 3.0", 0x0301: "1.0", 0x0302: "1.1", 0x0303: "1.2", 0x0304: "1.3"}

// maxTLSVersion is the highest known version in supported_versions, else the legacy ClientHello version, the
// rule the engine documents for tls_offered_max_version (GREASE values are not known versions).
func maxTLSVersion(legacy, supported string) string {
	best := uint64(0)
	for _, v := range strings.Split(supported, ",") {
		if n, err := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 32); err == nil && tlsNames[n] != "" && n > best {
			best = n
		}
	}
	if best == 0 {
		// The legacy field repeats for every handshake message in the frame; the ClientHello's comes first.
		first := strings.Split(legacy, ",")[0]
		if n, err := strconv.ParseUint(strings.TrimPrefix(first, "0x"), 16, 32); err == nil {
			best = n
		}
	}
	return tlsNames[best]
}

// quicVersion maps the first Initial's version to the engine's names.
func quicVersion(v string) string {
	first := strings.Split(v, ",")[0]
	n, err := strconv.ParseUint(strings.TrimPrefix(first, "0x"), 16, 32)
	if err != nil {
		return ""
	}
	switch n {
	case 0x00000001:
		return "1"
	case 0x6b3343cf:
		return "2"
	}
	return fmt.Sprintf("0x%08x", n)
}

// hostOnly lower-cases an HTTP Host and drops its port (the engine reports the host name alone).
func hostOnly(h string) string {
	h = strings.ToLower(strings.Split(h, ",")[0])
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[i:], "]") {
		h = h[:i]
	}
	return h
}

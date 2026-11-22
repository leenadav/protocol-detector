// Package fingerprint ports protocol_engine/fingerprints.py: derived handshake fingerprints (JA3/JA4 for a TLS client,
// JA3S/JA4S for a TLS server, HASSH over SSH KEXINIT name-lists, the HTTP/2 SETTINGS string). A fingerprint is a
// deterministic digest of structural handshake fields: at best an implementation family, never a user, a product
// version or an authenticated identity. No key material, random bytes or session identifiers enter a digest.
package fingerprint

import (
	"crypto/md5" // JA3, JA3S and HASSH are defined over MD5: a fingerprint digest, not a security control
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ClientHello is parsers.ClientHelloInfo: the structural fields a fingerprint reads.
type ClientHello struct {
	Version             int
	Ciphers             []int
	Extensions          []int // wire order
	ALPN                []string
	Groups              []int
	SignatureAlgorithms []int
	PointFormats        []int
	SupportedVersions   []int
}

// IsGREASE reports draft-ietf-tls-grease values 0x0a0a, 0x1a1a, ..., 0xfafa.
func IsGREASE(v int) bool { return v&0x0f0f == 0x0a0a && v>>8 == v&0xff }

var versions = map[int]string{0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3", 0x0002: "s2",
	0xfeff: "d1", 0xfefd: "d2", 0xfefc: "d3"}

func sha12(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])[:12]
}

func alnum(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

// alpnCode is the JA4 two-character code of the first offered or selected ALPN value.
func alpnCode(alpn []string) string {
	if len(alpn) == 0 {
		return "00"
	}
	value := alpn[0]
	var raw []byte
	if strings.HasPrefix(value, "hex:") {
		raw, _ = hex.DecodeString(value[4:])
	} else {
		for _, r := range value { // latin-1 with replacement: offers are printable ASCII or hex: already
			if r > 0xff {
				raw = append(raw, '?')
			} else {
				raw = append(raw, byte(r))
			}
		}
	}
	if len(raw) == 0 {
		return "00"
	}
	first, last := raw[0], raw[len(raw)-1]
	if alnum(first) && alnum(last) {
		return string([]byte{first, last})
	}
	text := hex.EncodeToString(raw)
	return text[:1] + text[len(text)-1:]
}

func versionCode(version int, supported []int) string {
	chosen, any := 0, false
	for _, v := range supported {
		if !IsGREASE(v) && (!any || v > chosen) {
			chosen, any = v, true
		}
	}
	if !any {
		chosen = version
	}
	if code, ok := versions[chosen]; ok {
		return code
	}
	return "00"
}

func withoutGREASE(values []int) []int {
	out := []int{}
	for _, v := range values {
		if !IsGREASE(v) {
			out = append(out, v)
		}
	}
	return out
}

func hex4(values []int) string {
	parts := make([]string, len(values))
	for i, v := range values {
		parts[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(parts, ",")
}

func min99(n int) int {
	if n > 99 {
		return 99
	}
	return n
}

// JA4 is the FoxIO JA4 client fingerprint; protocol is t (TCP), q (QUIC) or d (DTLS).
func JA4(info *ClientHello, protocol string) string {
	ciphers, extensions := withoutGREASE(info.Ciphers), withoutGREASE(info.Extensions)
	sni := "i"
	for _, e := range info.Extensions {
		if e == 0 {
			sni = "d"
		}
	}
	partA := fmt.Sprintf("%s%s%s%02d%02d%s", protocol, versionCode(info.Version, info.SupportedVersions), sni, min99(len(ciphers)),
		min99(len(extensions)), alpnCode(info.ALPN))
	partB := "000000000000"
	if len(ciphers) > 0 {
		sorted := append([]int{}, ciphers...)
		sort.Ints(sorted)
		partB = sha12(hex4(sorted))
	}
	var filtered []int
	for _, e := range extensions {
		if e != 0 && e != 16 {
			filtered = append(filtered, e)
		}
	}
	sort.Ints(filtered)
	algorithms := withoutGREASE(info.SignatureAlgorithms)
	text := hex4(filtered)
	if len(algorithms) > 0 {
		text += "_" + hex4(algorithms)
	}
	partC := "000000000000"
	if len(filtered) > 0 || len(algorithms) > 0 {
		partC = sha12(text)
	}
	return partA + "_" + partB + "_" + partC
}

func dashed(values []int, dropGREASE bool) string {
	var parts []string
	for _, v := range values {
		if !dropGREASE || !IsGREASE(v) {
			parts = append(parts, strconv.Itoa(v))
		}
	}
	return strings.Join(parts, "-")
}

func md5Hex(text string) string {
	sum := md5.Sum([]byte(text)) // the fingerprint definitions name MD5; nothing is authenticated with it
	return hex.EncodeToString(sum[:])
}

// JA3 is the Salesforce JA3 (MD5) over version, ciphers, extensions, groups and point formats, GREASE removed.
func JA3(info *ClientHello) string {
	return md5Hex(strings.Join([]string{strconv.Itoa(info.Version), dashed(info.Ciphers, true), dashed(info.Extensions, true),
		dashed(info.Groups, true), dashed(info.PointFormats, false)}, ","))
}

// JA3S is the server's JA3S (MD5) over version, selected cipher and extension order.
func JA3S(version, cipher int, extensions []int) string {
	return md5Hex(fmt.Sprintf("%d,%d,%s", version, cipher, dashed(extensions, false)))
}

// JA4S is the server fingerprint: protocol, version, extension count, ALPN code, cipher, extension hash.
func JA4S(version, cipher int, extensions []int, alpn []string, protocol string) string {
	code, ok := versions[version]
	if !ok {
		code = "00"
	}
	partA := fmt.Sprintf("%s%s%02d%s", protocol, code, min99(len(extensions)), alpnCode(alpn))
	partC := "000000000000"
	if len(extensions) > 0 {
		partC = sha12(hex4(extensions))
	}
	return partA + "_" + fmt.Sprintf("%04x", cipher) + "_" + partC
}

func asciiReplace(b []byte) string {
	out := make([]byte, len(b))
	for i, c := range b {
		if c >= 128 {
			c = '?'
		}
		out[i] = c
	}
	return string(out)
}

// HASSH is the Salesforce HASSH (MD5) over the client's KEXINIT kex, encryption, MAC and compression name-lists.
func HASSH(kex, encryption, mac, compression []byte) string {
	return md5Hex(strings.Join([]string{asciiReplace(kex), asciiReplace(encryption), asciiReplace(mac), asciiReplace(compression)}, ";"))
}

// Setting is one HTTP/2 SETTINGS entry.
type Setting struct{ ID, Value uint32 }

// H2Settings is the Akamai-style SETTINGS portion: "id:value;id:value" in frame order.
func H2Settings(settings []Setting) string {
	parts := make([]string, len(settings))
	for i, s := range settings {
		parts[i] = fmt.Sprintf("%d:%d", s.ID, s.Value)
	}
	return strings.Join(parts, ";")
}

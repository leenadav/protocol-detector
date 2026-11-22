package textroute

import (
	"bytes"
	"encoding/binary"
	"regexp"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// SSH identification line and the one KEXINIT that follows it (parsers.py LineParser "ssh", KexInit,
// ssh_posture.py). Only closed posture classes leave; names, the cookie and the lists never do.

var sshBanner = regexp.MustCompile(`^SSH-(?:2\.0|1\.99)-[\x21-\x2c\x2e-\x7e]+(?: [\x20-\x7e]*)?$`)

const (
	sshReason    = "SSH identification validated; key exchange offers classified, nothing negotiated or verified"
	kexMaxPacket = 35000
)

type kexInit struct {
	maxBytes int
	buffer   []byte
	needed   int
	length   int
	hasLen   bool
	done     bool
	lists    [][]byte
}

func newKexInit(maxBytes int) *kexInit { return &kexInit{maxBytes: maxBytes, needed: 4} }

func (k *kexInit) feed(data []byte) (int, error) {
	pos := 0
	for pos < len(data) && !k.done {
		amount := k.needed - len(k.buffer)
		if amount > len(data)-pos {
			amount = len(data) - pos
		}
		k.buffer = append(k.buffer, data[pos:pos+amount]...)
		pos += amount
		if len(k.buffer) < k.needed {
			break
		}
		if !k.hasLen {
			k.length = int(binary.BigEndian.Uint32(k.buffer[:4]))
			k.hasLen = true
			limit := kexMaxPacket
			if k.maxBytes-4 < limit {
				limit = k.maxBytes - 4
			}
			if k.length < 17 || k.length > limit {
				return pos, parsing.Malformed("SSH packet length outside KEXINIT profile")
			}
			k.needed = 4 + k.length
			k.buffer = append(make([]byte, 0, k.needed), k.buffer...) // one allocation for the whole packet
			continue
		}
		if err := k.validate(k.buffer[4:]); err != nil {
			return pos, err
		}
		k.done = true
		k.buffer = nil
	}
	return pos, nil
}

func (k *kexInit) validate(packet []byte) error {
	padding := int(packet[0])
	if packet[1] != 20 {
		return parsing.Malformed("First SSH packet is not KEXINIT")
	}
	if padding < 4 || 1+padding+1+16 > len(packet) {
		return parsing.Malformed("Invalid SSH KEXINIT padding or cookie framing")
	}
	pos := 18
	payloadEnd := len(packet) - padding
	lists := make([][]byte, 0, 10)
	for i := 0; i < 10; i++ {
		if pos+4 > payloadEnd {
			return parsing.Malformed("Truncated SSH KEXINIT name-list")
		}
		// Capped at the profile limit as uint32 before it becomes an int: on a 32-bit platform 0xffffffff would be -1.
		raw := binary.BigEndian.Uint32(packet[pos:])
		pos += 4
		if raw > 4096 {
			return parsing.Malformed("SSH KEXINIT name-list exceeds packet or profile")
		}
		size := int(raw)
		if size > payloadEnd-pos {
			return parsing.Malformed("SSH KEXINIT name-list exceeds packet or profile")
		}
		value := packet[pos : pos+size]
		for _, b := range value {
			if b < 0x21 || b > 0x7e {
				return parsing.Malformed("SSH KEXINIT name-list must be printable ASCII")
			}
		}
		if len(value) > 0 {
			for rest := value; ; {
				name, tail, more := bytes.Cut(rest, comma)
				if len(name) < 1 || len(name) > 64 {
					return parsing.Malformed("SSH KEXINIT name-list has an empty or over-long name")
				}
				if !more {
					break
				}
				rest = tail
			}
		}
		// The lists point into the packet buffer this parser owns (it is never written again), so no copy is
		// needed; they keep it alive exactly as long as copies of them would have.
		lists = append(lists, value[:len(value):len(value)])
		pos += size
	}
	if pos+5 > payloadEnd || packet[pos] > 1 || packet[pos+1] != 0 || packet[pos+2] != 0 || packet[pos+3] != 0 || packet[pos+4] != 0 {
		return parsing.Malformed("Invalid SSH KEXINIT trailer")
	}
	if pos+5 != payloadEnd {
		return parsing.Malformed("Unexpected bytes after SSH KEXINIT")
	}
	k.lists = lists
	return nil
}

// --- posture (ssh_posture.py) ------------------------------------------------------------------

var kexFamily = map[string]string{}

func init() {
	for _, n := range []string{"sntrup761x25519-sha512@openssh.com", "sntrup761x25519-sha512", "mlkem768x25519-sha256", "mlkem768nistp256-sha256", "mlkem1024nistp384-sha384"} {
		kexFamily[n] = "pq-hybrid"
	}
	for _, n := range []string{"curve25519-sha256", "curve25519-sha256@libssh.org", "curve448-sha512", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521"} {
		kexFamily[n] = "ecdh"
	}
	for _, n := range []string{"diffie-hellman-group14-sha256", "diffie-hellman-group15-sha512", "diffie-hellman-group16-sha512", "diffie-hellman-group17-sha512", "diffie-hellman-group18-sha512", "diffie-hellman-group-exchange-sha256"} {
		kexFamily[n] = "dh-sha2"
	}
	for _, n := range []string{"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"} {
		kexFamily[n] = "dh-sha1"
	}
}

var kexRank = []string{"pq-hybrid", "ecdh", "dh-sha2", "dh-sha1"}

type weakClass struct {
	label string
	index int
	names map[string]bool
}

var weakClasses = []weakClass{
	{"kex-sha1", 0, set("diffie-hellman-group1-sha1 diffie-hellman-group14-sha1 diffie-hellman-group-exchange-sha1")},
	{"hostkey-dss", 1, set("ssh-dss ssh-dss-cert-v01@openssh.com")},
	{"hostkey-rsa-sha1", 1, set("ssh-rsa ssh-rsa-cert-v01@openssh.com")},
	{"cipher-none", 2, set("none")},
	{"cipher-rc4", 2, set("arcfour arcfour128 arcfour256")},
	{"cipher-3des-or-64-bit-block", 2, set("3des-cbc 3des-ctr blowfish-cbc blowfish-ctr cast128-cbc cast128-ctr idea-cbc des-cbc des-cbc@ssh.com")},
	{"cipher-cbc", 2, set("aes128-cbc aes192-cbc aes256-cbc rijndael-cbc@lysator.liu.se twofish-cbc twofish128-cbc twofish192-cbc twofish256-cbc serpent128-cbc serpent192-cbc serpent256-cbc")},
	{"mac-none", 4, set("none")},
	{"mac-md5", 4, set("hmac-md5 hmac-md5-96 hmac-md5-etm@openssh.com hmac-md5-96-etm@openssh.com")},
	{"mac-truncated", 4, set("hmac-sha1-96 hmac-sha1-96-etm@openssh.com umac-32@openssh.com")},
}

var cbcOr64 = func() map[string]bool {
	out := map[string]bool{}
	for _, w := range weakClasses {
		if w.label == "cipher-cbc" || w.label == "cipher-3des-or-64-bit-block" {
			for n := range w.names {
				out[n] = true
			}
		}
	}
	return out
}()

var comma = []byte{','}

// hasName reports whether a validated name-list (comma-separated, no empty names) contains name.
func hasName(list []byte, name string) bool {
	for rest := list; len(rest) > 0; {
		item, tail, _ := bytes.Cut(rest, comma)
		if string(item) == name {
			return true
		}
		rest = tail
	}
	return false
}

// anyIn reports whether a validated name-list has a name in the set (a map lookup with a converted key does
// not allocate).
func anyIn(list []byte, names map[string]bool) bool {
	for rest := list; len(rest) > 0; {
		item, tail, _ := bytes.Cut(rest, comma)
		if names[string(item)] {
			return true
		}
		rest = tail
	}
	return false
}

func anySuffix(list []byte, suffix string) bool {
	for rest := list; len(rest) > 0; {
		item, tail, _ := bytes.Cut(rest, comma)
		if bytes.HasSuffix(item, []byte(suffix)) {
			return true
		}
		rest = tail
	}
	return false
}

// cbcWithETM is a CBC or 64-bit-block cipher offered with an encrypt-then-MAC mode in one direction.
func cbcWithETM(ciphers, macs []byte) bool {
	return anyIn(ciphers, cbcOr64) && anySuffix(macs, "-etm@openssh.com")
}

// kexinitPosture ports ssh_posture.kexinit_posture: rows (field, value) from closed sets only. Membership is
// tested on the name-lists directly; the result depends on no iteration order (classes and ranks are ordered
// tables), so it is the reference's.
func kexinitPosture(lists [][]byte) []parsing.Row {
	kex, hostkeys := lists[0], lists[1]
	c2sCiphers, s2cCiphers := lists[2], lists[3]
	c2sMacs, s2cMacs := lists[4], lists[5]
	var families [4]bool // indexed like kexRank
	for rest := kex; len(rest) > 0; {
		item, tail, _ := bytes.Cut(rest, comma)
		if f, ok := kexFamily[string(item)]; ok {
			for i, ranked := range kexRank {
				if ranked == f {
					families[i] = true
				}
			}
		}
		rest = tail
	}
	class := "other"
	for i, f := range kexRank {
		if families[i] {
			class = f
			break
		}
	}
	rows := make([]parsing.Row, 0, 2+len(weakClasses))
	rows = append(rows, parsing.Row{Field: "ssh_kex_class", Value: class, Provenance: "kexinit", Strength: "asserted"})
	for _, w := range weakClasses {
		var hit bool
		switch w.index {
		case 0:
			hit = anyIn(kex, w.names)
		case 1:
			hit = anyIn(hostkeys, w.names)
		case 2: // the union of both directions' ciphers
			hit = anyIn(c2sCiphers, w.names) || anyIn(s2cCiphers, w.names)
		case 4: // the union of both directions' MACs
			hit = anyIn(c2sMacs, w.names) || anyIn(s2cMacs, w.names)
		}
		if hit {
			rows = append(rows, parsing.Row{Field: "ssh_weak_algorithm", Value: w.label, Provenance: "kexinit", Strength: "asserted"})
		}
	}
	terrapin := "not-applicable"
	if hasName(kex, "kex-strict-c-v00@openssh.com") || hasName(kex, "kex-strict-s-v00@openssh.com") {
		terrapin = "strict"
	} else if hasName(c2sCiphers, "chacha20-poly1305@openssh.com") || hasName(s2cCiphers, "chacha20-poly1305@openssh.com") ||
		cbcWithETM(c2sCiphers, c2sMacs) || cbcWithETM(s2cCiphers, s2cMacs) {
		terrapin = "exposed"
	}
	return append(rows, parsing.Row{Field: "ssh_terrapin", Value: terrapin, Provenance: "kexinit", Strength: "asserted"})
}

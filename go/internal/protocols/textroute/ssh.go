package textroute

import (
	"encoding/binary"
	"regexp"
	"strings"

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
	var lists [][]byte
	for i := 0; i < 10; i++ {
		if pos+4 > payloadEnd {
			return parsing.Malformed("Truncated SSH KEXINIT name-list")
		}
		size := int(binary.BigEndian.Uint32(packet[pos:]))
		pos += 4
		if pos+size > payloadEnd || size > 4096 {
			return parsing.Malformed("SSH KEXINIT name-list exceeds packet or profile")
		}
		value := packet[pos : pos+size]
		for _, b := range value {
			if b < 0x21 || b > 0x7e {
				return parsing.Malformed("SSH KEXINIT name-list must be printable ASCII")
			}
		}
		if len(value) > 0 {
			for _, name := range strings.Split(string(value), ",") {
				if len(name) < 1 || len(name) > 64 {
					return parsing.Malformed("SSH KEXINIT name-list has an empty or over-long name")
				}
			}
		}
		lists = append(lists, append([]byte{}, value...))
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

func nameSet(value []byte) map[string]bool {
	out := map[string]bool{}
	if len(value) == 0 {
		return out
	}
	for _, n := range strings.Split(string(value), ",") {
		out[n] = true
	}
	return out
}

func union(a, b map[string]bool) map[string]bool {
	out := map[string]bool{}
	for k := range a {
		out[k] = true
	}
	for k := range b {
		out[k] = true
	}
	return out
}

func intersects(a, b map[string]bool) bool {
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

func cbcWithETM(ciphers, macs map[string]bool) bool {
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

// kexinitPosture ports ssh_posture.kexinit_posture: rows (field, value) from closed sets only.
func kexinitPosture(lists [][]byte) []parsing.Row {
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

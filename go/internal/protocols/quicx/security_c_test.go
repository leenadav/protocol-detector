package quicx

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/testframes"
)

// scSealV1 seals a QUIC v1 client Initial like testframes.QUICInitial, but with the given unprotected first byte,
// so the reserved bits can be set under a valid AEAD tag (public inputs only: the v1 salt and the DCID).
func scSealV1(first byte, dcid, frames []byte, padTo int) []byte {
	salt, _ := hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	expand := func(secret []byte, label string, n int) []byte {
		full := "tls13 " + label
		info := append([]byte{byte(n >> 8), byte(n), byte(len(full))}, full...)
		out, _ := hkdf.Expand(sha256.New, secret, string(append(info, 0)), n)
		return out
	}
	prk, _ := hkdf.Extract(sha256.New, dcid, salt)
	secret := expand(prk, "client in", 32)
	key, iv, hp := expand(secret, "quic key", 16), expand(secret, "quic iv", 12), expand(secret, "quic hp", 16)
	payload := append([]byte{}, frames...)
	if pad := padTo - (7 + len(dcid) + 1 + 2 + 4 + len(frames) + 16); pad > 0 {
		payload = append(payload, make([]byte, pad)...)
	}
	header := append([]byte{first, 0, 0, 0, 1, byte(len(dcid))}, dcid...)
	header = append(header, 0, 0) // no SCID, no token
	length := 4 + len(payload) + 16
	header = append(header, 0x40|byte(length>>8), byte(length), 0, 0, 0, 2)
	nonce := append([]byte{}, iv...)
	nonce[11] ^= 2
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	sealed := gcm.Seal(nil, nonce, payload, header)
	hpBlock, _ := aes.NewCipher(hp)
	mask := make([]byte, 16)
	hpBlock.Encrypt(mask, sealed[:16])
	out := append(append([]byte{}, header...), sealed...)
	out[0] ^= mask[0] & 0x0f
	for i := 0; i < 4; i++ {
		out[len(header)-4+i] ^= mask[1+i]
	}
	return out
}

// SR-23: Initial protection removal uses only public inputs, and an opened packet whose reserved header bits are
// set, a failed tag or a frame outside the Initial profile keeps the structural QUIC identification with
// initial_protection "unverified" and carries no CRYPTO-derived evidence (no server name).
func TestReservedBitsTagAndFrameFailuresKeepTheIdentificationUnverified(t *testing.T) {
	ping := []byte{1}
	clean := scSealV1(0xc3, dcid, ping, 1200)
	if m, err := Validate(clean, defaults, nil, "", nil); err != nil || fieldsOf(m)["initial_protection"] == "unverified" {
		t.Fatalf("control packet: %+v %v", m, err)
	}
	if !equalBytes(clean, testframes.QUICInitial(V1, dcid, nil, ping, 2, nil, 1200)) {
		t.Fatal("the local sealer disagrees with testframes.QUICInitial")
	}
	reserved := scSealV1(0xcf, dcid, ping, 1200) // reserved bits 0x0c set under a valid tag
	tagged := append([]byte{}, clean...)
	tagged[len(tagged)-1] ^= 1
	stream := scSealV1(0xc3, dcid, []byte{0x08, 0}, 1200)
	for name, packet := range map[string][]byte{"reserved bits": reserved, "failed tag": tagged, "STREAM frame": stream} {
		m, err := Validate(packet, defaults, nil, "", nil)
		if err != nil || m == nil {
			t.Fatalf("%s: the structural identification was lost: %v", name, err)
		}
		f := fieldsOf(m)
		if f["encryption"] != "quic" || f["packet_type"] != "initial" || f["initial_protection"] != "unverified" || m.HasHost {
			t.Fatalf("%s: %+v", name, m)
		}
	}
}

func equalBytes(a, b []byte) bool { return string(a) == string(b) }

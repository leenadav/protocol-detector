// Package x509x ports protocol_engine/x509.py: a bounded structural walk of the leaf X.509 certificate of a TLS 1.2
// Certificate message. It reports what the structure says about itself (version, whether the issuer equals the
// subject, public key family and size, signature algorithm family, lifetime, the CA flag, the extended key usage
// class, whether alternative names are present, the validity window in calendar days) and nothing that names or
// identifies the server: issuer, subject, serial, alternative names, key and signature bytes are read for their
// framing only. Nothing is verified (no signature check, chain building, name matching or revocation). Every DER
// length is checked against its container before it is read and element counts are bounded, so a hostile
// certificate costs at most one linear pass over at most MaxLeaf bytes. Go's crypto/x509 is deliberately not used:
// it verifies and accepts a different profile, and the contract here is the Python reference's exact acceptance.
package x509x

import (
	"bytes"
	"fmt"
	"math/bits"
	"strconv"
	"strings"
	"time"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// Budgets of x509.py.
const (
	MaxLeaf             = 16384
	maxNameParts        = 32
	maxExtensions       = 64
	maxSerial           = 32
	maxEKU              = 16
	maxGeneralNames     = 256
	maxPathLengthOctets = 4
	MinRSABits          = 2048
	MinECBits           = 256
	minCaptureTime      = 946684800    // 2000-01-01T00:00:00Z: earlier capture clocks are treated as unset
	maxCaptureTime      = 253402300800 // 10000-01-01T00:00:00Z
)

func oid(hexText string) string {
	b := make([]byte, len(hexText)/2)
	fmt.Sscanf(hexText, "%x", &b)
	return string(b)
}

var (
	oidRSA     = oid("2a864886f70d010101")
	oidEC      = oid("2a8648ce3d0201")
	oidEd25519 = oid("2b6570")
	oidEd448   = oid("2b6571")
	curves     = map[string]int{oid("2a8648ce3d030107"): 256, oid("2b81040022"): 384, oid("2b81040023"): 521}
	signatures = map[string]string{oid("2a864886f70d010104"): "md5-rsa", oid("2a864886f70d010105"): "sha1-rsa",
		oid("2a864886f70d01010b"): "sha256-rsa", oid("2a864886f70d01010c"): "sha384-rsa", oid("2a864886f70d01010d"): "sha512-rsa",
		oid("2a864886f70d01010a"): "rsa-pss", oid("2a8648ce3d0401"): "ecdsa-sha1", oid("2a8648ce3d040302"): "ecdsa-sha256",
		oid("2a8648ce3d040303"): "ecdsa-sha384", oid("2a8648ce3d040304"): "ecdsa-sha512", oidEd25519: "ed25519", oidEd448: "ed448"}
	basicConstraints = oid("551d13")
	subjectAltName   = oid("551d11")
	extendedKeyUsage = oid("551d25")
	serverAuth       = oid("2b06010505070301")
	anyKeyUsage      = oid("551d2500")
	// WeakSignatures are x509.WEAK_SIGNATURES.
	WeakSignatures = map[string]bool{"md5-rsa": true, "sha1-rsa": true, "ecdsa-sha1": true}
)

const (
	tagSequence, tagSet, tagInteger, tagBitString, tagOctetString, tagOID, tagBoolean = 0x30, 0x31, 0x02, 0x03, 0x04, 0x06, 0x01
	tagUTCTime, tagGeneralizedTime                                                    = 0x17, 0x18
)

var generalNameTags = map[byte]bool{0xa0: true, 0x81: true, 0x82: true, 0xa3: true, 0xa4: true, 0xa5: true, 0x86: true, 0x87: true, 0x88: true}

func fail(text string) error { return parsing.Malformed(text) }

// element is x509._element: (tag, content start, content end) of the DER element at pos, bounded by limit.
func element(data []byte, pos, limit int) (byte, int, int, error) {
	if pos+2 > limit {
		return 0, 0, 0, fail("DER element truncated")
	}
	tag := data[pos]
	if tag&0x1f == 0x1f {
		return 0, 0, 0, fail("Multi-byte DER tag outside the certificate profile")
	}
	first := data[pos+1]
	pos += 2
	// A long-form length saturates once it exceeds the container, so no shift or sum can overflow int on 32-bit
	// Go (SEC-X509-1); the error order (minimal encoding, then container) is the reference's.
	var length int
	over := false
	switch {
	case first < 0x80:
		length = int(first)
	case first == 0x80:
		return 0, 0, 0, fail("Indefinite DER length is not valid in a certificate")
	default:
		count := int(first & 0x7f)
		if count > 4 || pos+count > limit {
			return 0, 0, 0, fail("DER length encoding invalid")
		}
		for _, b := range data[pos : pos+count] {
			if length > limit>>8 {
				over = true
				continue
			}
			length = length<<8 | int(b)
		}
		if (!over && length < 0x80) || data[pos] == 0 {
			return 0, 0, 0, fail("DER length is not minimally encoded")
		}
		pos += count
	}
	if over || length > limit-pos {
		return 0, 0, 0, fail("DER element exceeds its container")
	}
	return tag, pos, pos + length, nil
}

func expect(data []byte, pos, limit int, tag byte, what string) (int, int, error) {
	found, start, end, err := element(data, pos, limit)
	if err != nil {
		return 0, 0, err
	}
	if found != tag {
		return 0, 0, fail(what + " has an unexpected DER tag")
	}
	return start, end, nil
}

func oidContents(data []byte, start, end int, what string) error {
	if start == end || end-start > 32 || data[end-1]&0x80 != 0 {
		return fail(what + " object identifier is malformed")
	}
	for p := start; p < end; p++ {
		if data[p] == 0x80 && (p == start || data[p-1]&0x80 == 0) {
			return fail(what + " object identifier arc is not minimally encoded")
		}
	}
	return nil
}

func readOID(data []byte, pos, limit int, what string) (string, int, error) {
	start, end, err := expect(data, pos, limit, tagOID, what)
	if err != nil {
		return "", 0, err
	}
	if err := oidContents(data, start, end, what); err != nil {
		return "", 0, err
	}
	return string(data[start:end]), end, nil
}

func single(data []byte, start, end int, what string) error {
	if start == end {
		return fail(what + " is empty")
	}
	_, _, innerEnd, err := element(data, start, end)
	if err != nil {
		return err
	}
	if innerEnd != end {
		return fail(what + " must hold exactly one element")
	}
	return nil
}

// algorithm returns (oid, parameters or nil, end).
func algorithm(data []byte, pos, limit int, what string) (string, []byte, int, error) {
	start, end, err := expect(data, pos, limit, tagSequence, what)
	if err != nil {
		return "", nil, 0, err
	}
	o, cursor, err := readOID(data, start, end, what)
	if err != nil {
		return "", nil, 0, err
	}
	var params []byte
	if cursor < end {
		_, _, after, err := element(data, cursor, end)
		if err != nil {
			return "", nil, 0, err
		}
		params = data[cursor:after]
		if after != end {
			return "", nil, 0, fail(what + " algorithm identifier has trailing bytes")
		}
	}
	return o, params, end, nil
}

func name(data []byte, pos, limit int, what string) ([]byte, int, error) {
	start, end, err := expect(data, pos, limit, tagSequence, what)
	if err != nil {
		return nil, 0, err
	}
	cursor, parts := start, 0
	for cursor < end {
		parts++
		if parts > maxNameParts {
			return nil, 0, fail(what + " exceeds the name component budget")
		}
		rdnStart, rdnEnd, err := expect(data, cursor, end, tagSet, what)
		if err != nil {
			return nil, 0, err
		}
		if rdnStart == rdnEnd {
			return nil, 0, fail(what + " contains an empty relative distinguished name")
		}
		inner, attributes := rdnStart, 0
		for inner < rdnEnd {
			attributes++
			if attributes > maxNameParts {
				return nil, 0, fail(what + " exceeds the name component budget")
			}
			attrStart, attrEnd, err := expect(data, inner, rdnEnd, tagSequence, what)
			if err != nil {
				return nil, 0, err
			}
			_, valuePos, err := readOID(data, attrStart, attrEnd, what)
			if err != nil {
				return nil, 0, err
			}
			_, _, valueEnd, err := element(data, valuePos, attrEnd)
			if err != nil {
				return nil, 0, err
			}
			if valueEnd != attrEnd {
				return nil, 0, fail(what + " attribute has trailing bytes")
			}
			inner = valueEnd
		}
		cursor = rdnEnd
	}
	return data[start:end], end, nil
}

// moment is a validated calendar date and time (Python datetime semantics: year 1..9999).
type moment struct{ year, month, day, hour, minute, second int }

func (m moment) unix() int64 {
	return time.Date(m.year, time.Month(m.month), m.day, m.hour, m.minute, m.second, 0, time.UTC).Unix()
}

func dayText(year, month, day int) string { return fmt.Sprintf("%04d-%02d-%02d", year, month, day) }

func daysIn(year, month int) int {
	switch month {
	case 2:
		if year%4 == 0 && (year%100 != 0 || year%400 == 0) {
			return 29
		}
		return 28
	case 4, 6, 9, 11:
		return 30
	}
	return 31
}

func number(b []byte) int {
	n := 0
	for _, c := range b {
		n = n*10 + int(c-'0')
	}
	return n
}

func readTime(data []byte, pos, limit int) (moment, int, error) {
	tag, start, end, err := element(data, pos, limit)
	if err != nil {
		return moment{}, 0, err
	}
	text := data[start:end]
	var digits []byte
	switch {
	case tag == tagUTCTime && len(text) == 13:
		digits = text[:12]
	case tag == tagGeneralizedTime && len(text) == 15:
		digits = text[:14]
	default:
		return moment{}, 0, fail("Certificate validity time is not a UTCTime or GeneralizedTime with seconds in UTC")
	}
	if text[len(text)-1] != 'Z' || len(digits) == 0 {
		return moment{}, 0, fail("Certificate validity time is not in UTC")
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return moment{}, 0, fail("Certificate validity time is not in UTC")
		}
	}
	var m moment
	var rest []byte
	if tag == tagUTCTime {
		two := number(digits[:2])
		m.year = 2000 + two
		if two >= 50 {
			m.year = 1900 + two
		}
		rest = digits[2:]
	} else {
		m.year, rest = number(digits[:4]), digits[4:]
	}
	m.month, m.day, m.hour, m.minute, m.second = number(rest[0:2]), number(rest[2:4]), number(rest[4:6]), number(rest[6:8]), number(rest[8:10])
	if m.year < 1 || m.month < 1 || m.month > 12 || m.day < 1 || m.day > daysIn(m.year, m.month) || m.hour > 23 || m.minute > 59 || m.second > 59 {
		return moment{}, 0, fail("Certificate validity time is not a calendar date")
	}
	return m, end, nil
}

func bitString(data []byte, pos, limit int, what string) (int, int, error) {
	start, end, err := expect(data, pos, limit, tagBitString, what)
	if err != nil {
		return 0, 0, err
	}
	if start == end || data[start] != 0 {
		return 0, 0, fail(what + " bit string must be non-empty with no unused bits")
	}
	return start + 1, end, nil
}

func publicKey(data []byte, pos, limit int) (string, int, error) {
	start, end, err := expect(data, pos, limit, tagSequence, "Subject public key info")
	if err != nil {
		return "", 0, err
	}
	o, params, cursor, err := algorithm(data, start, end, "Public key")
	if err != nil {
		return "", 0, err
	}
	keyStart, keyEnd, err := bitString(data, cursor, end, "Subject public key")
	if err != nil {
		return "", 0, err
	}
	if keyEnd != end {
		return "", 0, fail("Subject public key info has trailing bytes")
	}
	size := keyEnd - keyStart
	switch o {
	case oidRSA:
		if !bytes.Equal(params, []byte{5, 0}) {
			return "", 0, fail("RSA public key parameters must be NULL")
		}
		seqStart, seqEnd, err := expect(data, keyStart, keyEnd, tagSequence, "RSA public key")
		if err != nil {
			return "", 0, err
		}
		modStart, modEnd, err := expect(data, seqStart, seqEnd, tagInteger, "RSA modulus")
		if err != nil {
			return "", 0, err
		}
		expStart, expEnd, err := expect(data, modEnd, seqEnd, tagInteger, "RSA exponent")
		if err != nil {
			return "", 0, err
		}
		if expEnd != seqEnd || expEnd-expStart > 8 || modStart == modEnd {
			return "", 0, fail("RSA public key encoding invalid")
		}
		// x509.py reads data[exp_start] even for an empty exponent, i.e. the byte after it; mirrored exactly (past the
		// end of the certificate Python raises IndexError, reported here as malformed).
		if expStart >= len(data) {
			return "", 0, fail("RSA public key encoding invalid")
		}
		if data[modStart]&0x80 != 0 || data[expStart]&0x80 != 0 || (data[expStart] == 0 && expEnd-expStart > 1) {
			return "", 0, fail("RSA public key integers must be positive and minimally encoded")
		}
		if data[modStart] == 0 {
			if modEnd-modStart == 1 || data[modStart+1]&0x80 == 0 {
				return "", 0, fail("RSA modulus is not minimally encoded")
			}
			modStart++
		}
		n := (modEnd-modStart-1)*8 + bits.Len8(data[modStart])
		return "rsa-" + strconv.Itoa(n), end, nil
	case oidEC:
		if params == nil || params[0] != tagOID {
			return "ec-other", end, nil
		}
		named, after, err := readOID(params, 0, len(params), "EC named curve")
		if err != nil {
			return "", 0, err
		}
		if after != len(params) {
			return "", 0, fail("EC named curve parameters have trailing bytes")
		}
		curve, ok := curves[named]
		if !ok {
			return "ec-other", end, nil
		}
		coordinate := (curve + 7) / 8
		if keyStart >= len(data) { // Python indexes data[key_start] here; past the end it raises
			return "", 0, fail("EC public key point encoding does not match the named curve")
		}
		form := data[keyStart]
		if !((form == 4 && size == 1+2*coordinate) || ((form == 2 || form == 3) && size == 1+coordinate)) {
			return "", 0, fail("EC public key point encoding does not match the named curve")
		}
		return "ec-" + strconv.Itoa(curve), end, nil
	case oidEd25519, oidEd448:
		want := 57
		if o == oidEd25519 {
			want = 32
		}
		if params != nil || size != want {
			return "", 0, fail("Edwards public key encoding invalid")
		}
		if o == oidEd25519 {
			return "ed25519", end, nil
		}
		return "ed448", end, nil
	}
	return "other", end, nil
}

func basicConstraintsValue(data []byte, start, end int) (string, error) {
	seqStart, seqEnd, err := expect(data, start, end, tagSequence, "Basic constraints")
	if err != nil {
		return "", err
	}
	if seqEnd != end {
		return "", fail("Basic constraints has trailing bytes")
	}
	ca, cursor := false, seqStart
	if cursor < seqEnd && data[cursor] == tagBoolean {
		flagStart, flagEnd, err := expect(data, cursor, seqEnd, tagBoolean, "Basic constraints cA")
		if err != nil {
			return "", err
		}
		if flagEnd-flagStart != 1 || data[flagStart] != 0xff {
			return "", fail("Basic constraints cA must be absent or a DER TRUE")
		}
		ca, cursor = true, flagEnd
	}
	if cursor < seqEnd && data[cursor] == tagInteger {
		if !ca {
			return "", fail("Path length constraint requires cA TRUE")
		}
		valueStart, valueEnd, err := expect(data, cursor, seqEnd, tagInteger, "Path length constraint")
		if err != nil {
			return "", err
		}
		size := valueEnd - valueStart
		if size < 1 || size > maxPathLengthOctets || data[valueStart]&0x80 != 0 ||
			(data[valueStart] == 0 && size > 1 && data[valueStart+1]&0x80 == 0) {
			return "", fail("Path length constraint must be a small non-negative minimally encoded INTEGER")
		}
		cursor = valueEnd
	}
	if cursor != seqEnd {
		return "", fail("Basic constraints has unexpected fields")
	}
	if ca {
		return "yes", nil
	}
	return "no", nil
}

func keyUsagePurposes(data []byte, start, end int) (string, error) {
	seqStart, seqEnd, err := expect(data, start, end, tagSequence, "Extended key usage")
	if err != nil {
		return "", err
	}
	if seqEnd != end || seqStart == seqEnd {
		return "", fail("Extended key usage must be one non-empty sequence")
	}
	cursor, count := seqStart, 0
	hasServer, hasAny := false, false
	for cursor < seqEnd {
		count++
		if count > maxEKU {
			return "", fail("Extended key usage exceeds the purpose budget")
		}
		var purpose string
		if purpose, cursor, err = readOID(data, cursor, seqEnd, "Key purpose"); err != nil {
			return "", err
		}
		hasServer = hasServer || purpose == serverAuth
		hasAny = hasAny || purpose == anyKeyUsage
	}
	switch {
	case hasServer:
		return "server-auth", nil
	case hasAny:
		return "any", nil
	}
	return "other", nil
}

func generalNames(data []byte, start, end int) error {
	seqStart, seqEnd, err := expect(data, start, end, tagSequence, "Subject alternative name")
	if err != nil {
		return err
	}
	if seqEnd != end || seqStart == seqEnd {
		return fail("Subject alternative name must be one non-empty sequence")
	}
	cursor, count := seqStart, 0
	for cursor < seqEnd {
		count++
		if count > maxGeneralNames {
			return fail("Subject alternative name exceeds the entry budget")
		}
		tag, valueStart, valueEnd, err := element(data, cursor, seqEnd)
		if err != nil {
			return err
		}
		if !generalNameTags[tag] {
			return fail("Subject alternative name entry is not a GeneralName choice in its DER form")
		}
		size := valueEnd - valueStart
		switch tag {
		case 0x81, 0x82, 0x86:
			high := false
			for _, b := range data[valueStart:valueEnd] {
				high = high || b&0x80 != 0
			}
			if size == 0 || high {
				return fail("Subject alternative name text entry must be a non-empty IA5String")
			}
		case 0x87:
			if size != 4 && size != 16 {
				return fail("Subject alternative name iPAddress must be 4 or 16 octets")
			}
		case 0x88:
			if err := oidContents(data, valueStart, valueEnd, "Subject alternative name registeredID"); err != nil {
				return err
			}
		case 0xa0:
			_, after, err := readOID(data, valueStart, valueEnd, "Subject alternative name otherName")
			if err != nil {
				return err
			}
			var tagValue byte
			var innerStart, innerEnd int
			if after < valueEnd {
				if tagValue, innerStart, innerEnd, err = element(data, after, valueEnd); err != nil {
					return err
				}
			}
			if after >= valueEnd || tagValue != 0xa0 || innerEnd != valueEnd {
				return fail("Subject alternative name otherName needs exactly its [0] value")
			}
			if err := single(data, innerStart, innerEnd, "Subject alternative name otherName value"); err != nil {
				return err
			}
		case 0xa3:
			inner, parts := valueStart, 0
			for inner < valueEnd {
				parts++
				if parts > maxNameParts {
					return fail("Subject alternative name x400Address exceeds the component budget")
				}
				if _, _, inner, err = element(data, inner, valueEnd); err != nil {
					return err
				}
			}
			if parts == 0 {
				return fail("Subject alternative name x400Address is empty")
			}
		case 0xa4:
			_, nameEnd, err := name(data, valueStart, valueEnd, "Subject alternative name directoryName")
			if err != nil {
				return err
			}
			if nameEnd != valueEnd {
				return fail("Subject alternative name directoryName has trailing bytes")
			}
		default: // ediPartyName
			inner := valueStart
			if inner < valueEnd && data[inner] == 0xa0 {
				var assignerStart int
				if _, assignerStart, inner, err = element(data, inner, valueEnd); err != nil {
					return err
				}
				if err := single(data, assignerStart, inner, "Subject alternative name ediPartyName nameAssigner"); err != nil {
					return err
				}
			}
			if inner >= valueEnd || data[inner] != 0xa1 {
				return fail("Subject alternative name ediPartyName needs its partyName")
			}
			_, partyStart, partyEnd, err := element(data, inner, valueEnd)
			if err != nil {
				return err
			}
			if partyEnd != valueEnd {
				return fail("Subject alternative name ediPartyName has trailing bytes")
			}
			if err := single(data, partyStart, partyEnd, "Subject alternative name ediPartyName partyName"); err != nil {
				return err
			}
		}
		cursor = valueEnd
	}
	return nil
}

func extensions(data []byte, pos, limit int) (int, [3]string, error) {
	posture := [3]string{"no", "absent", "absent"}
	start, end, err := expect(data, pos, limit, tagSequence, "Extensions")
	if err != nil {
		return 0, posture, err
	}
	if start == end {
		return 0, posture, fail("Extensions sequence must not be empty")
	}
	cursor, seen := start, map[string]bool{}
	for cursor < end {
		if len(seen) >= maxExtensions {
			return 0, posture, fail("Certificate exceeds the extension count budget")
		}
		extStart, extEnd, err := expect(data, cursor, end, tagSequence, "Extension")
		if err != nil {
			return 0, posture, err
		}
		o, inner, err := readOID(data, extStart, extEnd, "Extension")
		if err != nil {
			return 0, posture, err
		}
		if seen[o] {
			return 0, posture, fail("Certificate repeats an extension")
		}
		seen[o] = true
		tag, flagStart, flagEnd, err := element(data, inner, extEnd)
		if err != nil {
			return 0, posture, err
		}
		if tag == tagBoolean {
			if flagEnd-flagStart != 1 || data[flagStart] != 0xff {
				return 0, posture, fail("Extension critical flag must be absent or a DER TRUE")
			}
			inner = flagEnd
		}
		valueStart, valueEnd, err := expect(data, inner, extEnd, tagOctetString, "Extension value")
		if err != nil {
			return 0, posture, err
		}
		if valueEnd != extEnd {
			return 0, posture, fail("Extension has trailing bytes")
		}
		switch o {
		case basicConstraints:
			if posture[0], err = basicConstraintsValue(data, valueStart, valueEnd); err != nil {
				return 0, posture, err
			}
		case extendedKeyUsage:
			if posture[1], err = keyUsagePurposes(data, valueStart, valueEnd); err != nil {
				return 0, posture, err
			}
		case subjectAltName:
			if err := generalNames(data, valueStart, valueEnd); err != nil {
				return 0, posture, err
			}
			posture[2] = "present"
		}
		cursor = extEnd
	}
	return end, posture, nil
}

// Field is one (field, value) pair of the leaf profile.
type Field struct{ Name, Value string }

// LeafProfile is x509.leaf_profile: structural evidence of one DER certificate, or a malformed error for anything
// that disagrees with RFC 5280 section 4.1 framing. Values come from closed sets or are small integers.
func LeafProfile(der []byte) ([]Field, error) {
	limit := len(der)
	if limit > MaxLeaf {
		return nil, fail("Leaf certificate exceeds the inspection budget")
	}
	outerStart, outerEnd, err := expect(der, 0, limit, tagSequence, "Certificate")
	if err != nil {
		return nil, err
	}
	if outerEnd != limit {
		return nil, fail("Certificate has trailing bytes")
	}
	tbsStart, tbsEnd, err := expect(der, outerStart, outerEnd, tagSequence, "TBSCertificate")
	if err != nil {
		return nil, err
	}
	cursor, version := tbsStart, 1
	tag, start, end, err := element(der, cursor, tbsEnd)
	if err != nil {
		return nil, err
	}
	if tag == 0xa0 {
		valueStart, valueEnd, err := expect(der, start, end, tagInteger, "Version")
		if err != nil {
			return nil, err
		}
		if valueEnd != end || valueEnd-valueStart != 1 || (der[valueStart] != 1 && der[valueStart] != 2) {
			return nil, fail("Certificate version must be an explicit v2 or v3")
		}
		version, cursor = int(der[valueStart])+1, end
	}
	serialStart, serialEnd, err := expect(der, cursor, tbsEnd, tagInteger, "Serial number")
	if err != nil {
		return nil, err
	}
	if serialEnd-serialStart < 1 || serialEnd-serialStart > maxSerial {
		return nil, fail("Serial number length outside the profile")
	}
	signatureOID, _, cursor, err := algorithm(der, serialEnd, tbsEnd, "Certificate signature")
	if err != nil {
		return nil, err
	}
	innerAlgorithm := der[serialEnd:cursor]
	issuer, cursor, err := name(der, cursor, tbsEnd, "Issuer")
	if err != nil {
		return nil, err
	}
	validityStart, validityEnd, err := expect(der, cursor, tbsEnd, tagSequence, "Validity")
	if err != nil {
		return nil, err
	}
	notBefore, cursor, err := readTime(der, validityStart, validityEnd)
	if err != nil {
		return nil, err
	}
	notAfter, cursor, err := readTime(der, cursor, validityEnd)
	if err != nil {
		return nil, err
	}
	if cursor != validityEnd {
		return nil, fail("Validity has trailing bytes")
	}
	if notAfter.unix() < notBefore.unix() {
		return nil, fail("Certificate validity ends before it starts")
	}
	subject, cursor, err := name(der, validityEnd, tbsEnd, "Subject")
	if err != nil {
		return nil, err
	}
	key, cursor, err := publicKey(der, cursor, tbsEnd)
	if err != nil {
		return nil, err
	}
	posture := [3]string{"no", "absent", "absent"}
	for cursor < tbsEnd {
		tag, start, end, err := element(der, cursor, tbsEnd)
		if err != nil {
			return nil, err
		}
		switch tag {
		case 0x81, 0x82:
			if version < 2 || start == end {
				return nil, fail("Unique identifiers require a v2 or v3 certificate")
			}
		case 0xa3:
			if version != 3 {
				return nil, fail("Extensions require a v3 certificate")
			}
			walked, p, err := extensions(der, start, end)
			if err != nil {
				return nil, err
			}
			posture = p
			if walked != end || end != tbsEnd {
				return nil, fail("Extensions must be the last TBSCertificate field")
			}
		default:
			return nil, fail("Unexpected field after the subject public key")
		}
		cursor = end
	}
	_, _, cursor, err = algorithm(der, tbsEnd, outerEnd, "Outer signature")
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(der[tbsEnd:cursor], innerAlgorithm) {
		return nil, fail("Certificate signature algorithms disagree")
	}
	_, signatureEnd, err := bitString(der, cursor, outerEnd, "Signature value")
	if err != nil {
		return nil, err
	}
	if signatureEnd != outerEnd {
		return nil, fail("Certificate has bytes after the signature")
	}
	selfIssued := "no"
	if bytes.Equal(issuer, subject) {
		selfIssued = "yes"
	}
	signature, ok := signatures[signatureOID]
	if !ok {
		signature = "other"
	}
	lifetime := (notAfter.unix() - notBefore.unix()) / 86400 // timedelta.days, never negative here
	fields := []Field{{"tls_certificate_version", strconv.Itoa(version)}, {"tls_certificate_self_issued", selfIssued},
		{"tls_certificate_key", key}, {"tls_certificate_signature", signature},
		{"tls_certificate_lifetime_days", strconv.FormatInt(lifetime, 10)},
		{"tls_certificate_not_before", dayText(notBefore.year, notBefore.month, notBefore.day)},
		{"tls_certificate_not_after", dayText(notAfter.year, notAfter.month, notAfter.day)}}
	if version == 3 {
		fields = append(fields, Field{"tls_certificate_ca", posture[0]}, Field{"tls_certificate_eku", posture[1]}, Field{"tls_certificate_san", posture[2]})
	}
	return fields, nil
}

// Validity is x509.validity: current, expired or not-yet-valid at capture time at (POSIX seconds) from the
// day-granular window, or "" when a date is missing or the capture clock is unset (outside 2000..9999).
func Validity(notBefore, notAfter string, at *float64) string {
	if notBefore == "" || notAfter == "" || at == nil || *at < minCaptureTime || *at >= maxCaptureTime {
		return ""
	}
	t := time.Unix(int64(*at), 0).UTC()
	day := dayText(t.Year(), int(t.Month()), t.Day())
	switch {
	case day < notBefore:
		return "not-yet-valid"
	case day > notAfter:
		return "expired"
	}
	return "current"
}

// WeakKey is x509.weak_key: RSA below 2048 bits or a named curve below 256 bits.
func WeakKey(label string) bool {
	family, size, ok := strings.Cut(label, "-")
	if !ok || size == "" {
		return false
	}
	for _, c := range size {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(size)
	if err != nil {
		return false
	}
	return (family == "rsa" && n < MinRSABits) || (family == "ec" && n < MinECBits)
}

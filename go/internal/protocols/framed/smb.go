package framed

import (
	"bytes"

	"github.com/leenadav/protocol-detector/go/internal/parsing"
)

// SMB1 (windows.SMB1Parser) and SMB2/3 (network.SMB2Parser) over direct TCP / NetBIOS framing: the NEGOTIATE
// message in either direction identifies the family, then exactly one more frame is watched, a SESSION_SETUP
// whose security buffer names the authentication mechanism through classifyToken. Only closed labels are emitted;
// names, challenges, tokens and signatures are not. Reason sentences are the Python ones.

// le reads n little-endian bytes at at the way int.from_bytes(data[at:at+n], "little") does: bytes past the end
// are simply absent (a short slice reads as its available bytes, an empty one as 0), which the Python profiles
// rely on for frames shorter than a field they read.
func le(data []byte, at, n int) int {
	v := 0
	for i := n - 1; i >= 0; i-- {
		if at+i < len(data) && at+i >= 0 {
			v = v<<8 | int(data[at+i])
		} else {
			v <<= 8
		}
	}
	return v
}

func anyNonZero(data []byte, from, to int) bool {
	for i := from; i < to && i < len(data); i++ {
		if data[i] != 0 {
			return true
		}
	}
	return false
}

// smbParser is the shared shape: a framed NEGOTIATE, then a watch of one more frame of the same family.
type smbParser struct {
	base      *Parser
	maxBytes  int
	magic     []byte // "\xffSMB" or "\xfeSMB"
	minSize   int    // smallest SESSION_SETUP frame (after the 4-byte length)
	budgetMsg string
	shortMsg  string
	setup     func(data []byte) ([]parsing.Row, string, error)
	result    *parsing.Result
	refined   bool
	frame     []byte
	needed    int
}

func (p *smbParser) Done() bool              { return p.base.Done() }
func (p *smbParser) Result() *parsing.Result { return p.result }
func (p *smbParser) Refined() bool           { return p.refined }

func (p *smbParser) Feed(data []byte) (int, error) {
	if !p.base.Done() {
		n, err := p.base.Feed(data)
		if err != nil {
			return n, err
		}
		if p.base.Done() {
			r := *p.base.Result()
			r.Continues = true // watch exactly one more frame: SESSION_SETUP names the mechanism
			p.result = &r
		}
		return n, nil
	}
	return p.nextFrame(data)
}

func (p *smbParser) nextFrame(data []byte) (int, error) {
	pos := 0
	for pos < len(data) && p.result.Continues {
		start := pos
		amount := p.needed - len(p.frame)
		if amount > len(data)-pos {
			amount = len(data) - pos
		}
		p.frame = append(p.frame, data[pos:pos+amount]...)
		pos += amount
		if len(p.frame) < p.needed {
			break
		}
		if p.needed == 8 {
			if p.frame[0] != 0 || !bytes.Equal(p.frame[4:8], p.magic) {
				p.result.Continues = false // not a frame of this family: the identification stands, these bytes are not inspected
				return start, nil
			}
			size := be(p.frame[1:4])
			if size < p.minSize {
				return pos, parsing.Malformed(p.shortMsg)
			}
			if 4+size > p.maxBytes {
				return pos, parsing.Budget(p.budgetMsg)
			}
			p.needed = 4 + size
			if len(p.frame) < p.needed {
				continue
			}
		}
		rows, suffix, err := p.setup(append([]byte(nil), p.frame[4:]...))
		if err != nil {
			return pos, err
		}
		p.result.Extra = append(append([]parsing.Row{}, p.result.Extra...), rows...)
		p.result.Reason += suffix
		p.refined = true
		p.result.Continues = false
	}
	return pos, nil
}

func tokenRows(blob []byte) ([]parsing.Row, error) {
	token, err := classifyToken(blob)
	if err != nil {
		return nil, err
	}
	rows := []parsing.Row{row("gss_mechanism", token.Mechanism, "session_setup", "asserted")}
	if token.NTLMMessage != "" {
		rows = append(rows, row("ntlm_message", token.NTLMMessage, "session_setup", "asserted"))
	}
	return rows, nil
}

// --- SMB1 -------------------------------------------------------------------------------------------------

// NewSMB1 ports SMB1Parser: NetBIOS session header plus SMB_COM_NEGOTIATE, then one SESSION_SETUP_ANDX frame.
func NewSMB1(maxBytes, maxHeaders int) parsing.Parser {
	p := &smbParser{maxBytes: maxBytes, magic: []byte("\xffSMB"), minSize: 35, needed: 8,
		budgetMsg: "SMB1 SESSION_SETUP frame exceeds byte budget", shortMsg: "SMB1 frame shorter than a header with word and byte counts",
		setup: smb1SessionSetup}
	p.base = newParser(maxBytes, spec{header: 8,
		size: func(h []byte) (int, error) {
			if h[0] != 0 || !bytes.Equal(h[4:8], []byte("\xffSMB")) {
				return 0, parsing.Malformed("Invalid NetBIOS/SMB1 header")
			}
			size := be(h[1:4])
			if size < 35 {
				return 0, parsing.Malformed("SMB1 negotiate frame too short")
			}
			return 4 + size, nil
		},
		validate: func(framed []byte) (*parsing.Result, error) { return smb1Negotiate(framed[4:], maxHeaders) }})
	return p
}

func smb1Negotiate(data []byte, maxHeaders int) (*parsing.Result, error) {
	if data[4] != 0x72 {
		return nil, parsing.Unsupported("Only SMB1 NEGOTIATE requests and responses are supported")
	}
	if data[9]&0x80 != 0 {
		return smb1NegotiateResponse(data)
	}
	if anyNonZero(data, 5, 9) {
		return nil, parsing.Malformed("SMB1 negotiate request must carry zero status and the request direction flag")
	}
	if data[32] != 0 {
		return nil, parsing.Malformed("SMB1 negotiate word count must be zero")
	}
	count := le(data, 33, 2)
	body := data[35:]
	if len(body) != count || len(body) == 0 {
		return nil, parsing.Malformed("SMB1 byte count disagrees with frame")
	}
	limit := maxHeaders
	if limit > 32 {
		limit = 32
	}
	pos, dialects := 0, 0
	for pos < len(body) {
		if body[pos] != 2 {
			return nil, parsing.Malformed("SMB1 dialect must use the string buffer format")
		}
		end := bytes.IndexByte(body[pos+1:], 0)
		if end < 0 || end == 0 {
			return nil, parsing.Malformed("SMB1 dialect string unterminated or empty")
		}
		end += pos + 1
		for _, c := range body[pos+1 : end] {
			if c < 32 || c > 126 {
				return nil, parsing.Malformed("SMB1 dialect outside printable ASCII")
			}
		}
		if dialects++; dialects > limit {
			return nil, parsing.Budget("SMB1 dialect count exceeds budget")
		}
		pos = end + 1
	}
	return &parsing.Result{ProtocolName: "smb1", Scope: "negotiation_request",
		Reason: "SMB1 negotiate request framing and dialect strings validated; dialect selection and session unverified",
		Extra:  []parsing.Row{row("smb1_message", "negotiate-request", "header", "structural")}}, nil
}

// smb1NegotiateResponse: NT LM 0.12 (17 words), LAN Manager (13) or core (1) layouts.
func smb1NegotiateResponse(data []byte) (*parsing.Result, error) {
	if anyNonZero(data, 5, 9) {
		return nil, parsing.Unsupported("SMB1 negotiate response profile covers STATUS_SUCCESS")
	}
	words := int(data[32])
	if words != 1 && words != 13 && words != 17 {
		return nil, parsing.Unsupported("SMB1 negotiate response word count outside the known dialect layouts")
	}
	if len(data) < 33+2*words+2 {
		return nil, parsing.Malformed("SMB1 negotiate response shorter than its parameter words")
	}
	if index := le(data, 33, 2); index > 32 && index != 0xffff {
		return nil, parsing.Malformed("SMB1 dialect index outside the request's possible range")
	}
	byteCount := le(data, 33+2*words, 2)
	if len(data)-(35+2*words) != byteCount {
		return nil, parsing.Malformed("SMB1 byte count disagrees with frame")
	}
	label := "core"
	switch words {
	case 17:
		if data[35]&^0x0f != 0 {
			return nil, parsing.Malformed("SMB1 security mode reserved bits set")
		}
		if challenge := int(data[66]); challenge > byteCount || (challenge != 0 && challenge != 8) {
			return nil, parsing.Malformed("SMB1 encryption key length must be 0 or 8 within the byte count")
		}
		label = "nt-lm-0.12"
	case 13:
		label = "lan-manager"
	}
	return &parsing.Result{ProtocolName: "smb1", Scope: "negotiation_response",
		Reason: "SMB1 negotiate response framing validated; challenge and domain not emitted, dialect selection unverified",
		Extra: []parsing.Row{row("smb1_message", "negotiate-response", "header", "structural"),
			row("smb1_dialect_layout", label, "header", "asserted")}}, nil
}

const smbSetupSuffix = "; SESSION_SETUP_ANDX read for the authentication mechanism, names and responses not emitted"

// smb1SessionSetup ports _session_setup: SMB_COM_SESSION_SETUP_ANDX (0x73) with an extended security blob,
// LM/NTLM response lengths, or the response action.
func smb1SessionSetup(data []byte) ([]parsing.Row, string, error) {
	if data[4] != 0x73 {
		return nil, "", parsing.Unsupported("Only SESSION_SETUP_ANDX is read after NEGOTIATE")
	}
	words := int(data[32])
	if len(data) < 35+2*words || 35+2*words+le(data, 33+2*words, 2) != len(data) {
		return nil, "", parsing.Malformed("SMB1 SESSION_SETUP_ANDX word or byte count disagrees with the frame")
	}
	count := le(data, 33+2*words, 2)
	body := data[35+2*words:]
	var rows []parsing.Row
	if data[9]&0x80 != 0 {
		status := le(data, 5, 4)
		if status != 0 && status != 0xC0000016 {
			return nil, "", parsing.Unsupported("SESSION_SETUP_ANDX response status outside success and more-processing")
		}
		if words != 3 && words != 4 {
			return nil, "", parsing.Malformed("SESSION_SETUP_ANDX response word count must be 3 or 4")
		}
		action := le(data, 37, 2)
		if action&^3 != 0 {
			return nil, "", parsing.Malformed("SESSION_SETUP_ANDX response action outside the defined bits")
		}
		rows = append(rows, row("smb1_message", "session-setup-response", "header", "structural"))
		session := "authenticated"
		if status != 0 {
			session = "continuing"
		} else if action&1 != 0 {
			session = "guest"
		}
		rows = append(rows, row("smb_session", session, "session_setup", "asserted"))
		if words == 4 {
			length := le(data, 39, 2)
			if length > count {
				return nil, "", parsing.Malformed("SESSION_SETUP_ANDX response security blob exceeds the byte count")
			}
			if length > 0 {
				token, err := tokenRows(body[:length])
				if err != nil {
					return nil, "", err
				}
				rows = append(rows, token...)
			}
		}
		return rows, smbSetupSuffix, nil
	}
	if anyNonZero(data, 5, 9) {
		return nil, "", parsing.Malformed("SESSION_SETUP_ANDX request must carry zero status")
	}
	rows = append(rows, row("smb1_message", "session-setup-request", "header", "structural"))
	switch words {
	case 12:
		length := le(data, 47, 2)
		if length == 0 || length > count {
			return nil, "", parsing.Malformed("SESSION_SETUP_ANDX extended security blob outside the byte count")
		}
		token, err := tokenRows(body[:length])
		if err != nil {
			return nil, "", err
		}
		rows = append(rows, token...)
	case 13:
		insensitive, sensitive := le(data, 47, 2), le(data, 49, 2)
		if insensitive+sensitive > count || insensitive > 24 || sensitive > 1024 {
			return nil, "", parsing.Malformed("SESSION_SETUP_ANDX password response lengths outside the byte count or NTLM sizes")
		}
		label := "none"
		if insensitive > 0 || sensitive > 0 {
			label = "ntlm-response"
		}
		rows = append(rows, row("gss_mechanism", label, "session_setup", "asserted"))
	case 10:
		length := le(data, 47, 2)
		if length > count || length > 24 {
			return nil, "", parsing.Malformed("SESSION_SETUP_ANDX LAN Manager password length outside the byte count")
		}
		label := "none"
		if length > 0 {
			label = "lm-response"
		}
		rows = append(rows, row("gss_mechanism", label, "session_setup", "asserted"))
	default:
		return nil, "", parsing.Unsupported("SESSION_SETUP_ANDX word count outside the 10/12/13 layouts")
	}
	return rows, smbSetupSuffix, nil
}

// --- SMB2/3 -----------------------------------------------------------------------------------------------

var (
	smbDialects      = map[int]string{0x202: "2.0.2", 0x210: "2.1", 0x2ff: "wildcard", 0x300: "3.0", 0x302: "3.0.2", 0x311: "3.1.1"}
	smb2SessionFlags = [3]struct {
		bit   int
		label string
	}{{1, "guest"}, {2, "anonymous"}, {4, "encrypted"}}
	smbCiphers         = map[int]string{0: "none", 1: "aes-128-ccm", 2: "aes-128-gcm", 3: "aes-256-ccm", 4: "aes-256-gcm"}
	smbSigningAlgos    = map[int]string{0: "hmac-sha256", 1: "aes-cmac", 2: "aes-gmac"}
	smbSupportedOffers = map[int]bool{0x202: true, 0x210: true, 0x300: true, 0x302: true, 0x311: true}
)

const (
	smb2CapEncryption       = 0x40
	statusMoreProcessing    = 0xC0000016
	smb2FlagServerToRedir   = 0x01
	smb2FlagRelatedOps      = 0x04
	smb2FlagSigned          = 0x08
	smb2SessionSetupSuffix  = "; SESSION_SETUP read for the authentication mechanism, credentials and tokens not emitted"
	smb2NegotiateRespReason = "SMB2/3 NEGOTIATE response validated; selected dialect and signing mode unauthenticated, security token not emitted"
)

func lookup(table map[int]string, key int) string {
	if v, ok := table[key]; ok {
		return v
	}
	return "other"
}

// NewSMB2 ports SMB2Parser: SMB2/3 NEGOTIATE in either direction, then one SESSION_SETUP frame.
func NewSMB2(maxBytes int) parsing.Parser {
	p := &smbParser{maxBytes: maxBytes, magic: []byte("\xfeSMB"), minSize: 64 + 9, needed: 8,
		budgetMsg: "SMB2 SESSION_SETUP frame exceeds byte budget", shortMsg: "SMB2 frame shorter than a SESSION_SETUP body",
		setup: smb2SessionSetup}
	p.base = newParser(maxBytes, spec{header: 8,
		size: func(h []byte) (int, error) {
			if h[0] != 0 || !bytes.Equal(h[4:8], []byte("\xfeSMB")) {
				return 0, parsing.Malformed("Invalid direct TCP SMB2 header")
			}
			size := be(h[1:4])
			if size < 102 {
				return 0, parsing.Malformed("SMB2 NEGOTIATE frame too short")
			}
			return 4 + size, nil
		},
		validate: func(framed []byte) (*parsing.Result, error) { return smb2Negotiate(framed[4:]) }})
	return p
}

func smb2Negotiate(data []byte) (*parsing.Result, error) {
	u16 := func(at int) int { return le(data, at, 2) }
	u32 := func(at int) int { return le(data, at, 4) }
	if u16(4) != 64 || u16(12) != 0 {
		return nil, parsing.Unsupported("Only SMB2 NEGOTIATE requests and responses supported")
	}
	flags := u32(16)
	if flags == 1 {
		return smb2NegotiateResponse(data)
	}
	if flags != 0 || u32(20) != 0 || anyNonZero(data, 8, 12) || anyNonZero(data, 36, 64) {
		return nil, parsing.Malformed("Invalid initial SMB2 request flags, IDs or signature")
	}
	if mode := u16(68); u16(64) != 36 || mode < 1 || mode > 3 || u16(70) != 0 {
		return nil, parsing.Malformed("Invalid SMB2 negotiate fixed fields")
	}
	count := u16(66)
	if count == 0 {
		return nil, parsing.Malformed("SMB2 requires at least one dialect")
	}
	if count > 128 {
		return nil, parsing.Budget("SMB2 dialect count exceeds limit")
	}
	end := 100 + count*2
	if end > len(data) {
		return nil, parsing.Malformed("Truncated SMB2 dialect array")
	}
	offered, supported, has311 := map[int]bool{}, false, false
	for at := 100; at < end; at += 2 {
		d := u16(at)
		offered[d] = true
		supported = supported || smbSupportedOffers[d]
		has311 = has311 || d == 0x311
	}
	if !supported {
		return nil, parsing.Unsupported("No supported SMB2 dialect offered")
	}
	if !has311 {
		if anyNonZero(data, 92, 100) || len(data) != end {
			return nil, parsing.Malformed("Unexpected SMB2 negotiate extension")
		}
	} else if _, err := smb2Contexts(data, u32(92), u16(96), end, u16(98), false); err != nil {
		return nil, err
	}
	signing := "enabled"
	if u16(68)&2 != 0 {
		signing = "required"
	}
	return &parsing.Result{ProtocolName: "smb2", Scope: "negotiation_request",
		Reason: "SMB2/3 direct TCP NEGOTIATE request validated; dialects are offers, signing/encryption unverified",
		Extra:  []parsing.Row{row("smb_signing", signing, "negotiate_request", "asserted")}}, nil
}

type smbPosture struct {
	cipher, signing       string
	hasCipher, hasSigning bool
}

// smb2Contexts ports _contexts: SMB 3.1.1 negotiate contexts, 8-byte aligned, unique kinds, preauth (kind 1) required.
func smb2Contexts(data []byte, pos, contexts, end, reserved int, response bool) (smbPosture, error) {
	u16 := func(at int) int { return le(data, at, 2) }
	u32 := func(at int) int { return le(data, at, 4) }
	var posture smbPosture
	if contexts == 0 || contexts > 128 {
		return posture, parsing.Budget("SMB3 negotiate context count outside inspection limit")
	}
	if reserved != 0 || pos < end || pos%8 != 0 || pos > len(data) {
		return posture, parsing.Malformed("Invalid SMB3 context offset")
	}
	seen := map[int]bool{}
	for index := 0; index < contexts; index++ {
		if pos+8 > len(data) {
			return posture, parsing.Malformed("Truncated SMB3 context header")
		}
		kind, size := u16(pos), u16(pos+2)
		if seen[kind] || u32(pos+4) != 0 {
			return posture, parsing.Malformed("Duplicate SMB3 context or nonzero reserved field")
		}
		seen[kind] = true
		start, stop := pos+8, pos+8+size
		if stop > len(data) {
			return posture, parsing.Malformed("SMB3 context exceeds frame")
		}
		switch kind {
		case 1:
			if size < 6 {
				return posture, parsing.Malformed("Truncated SMB3 preauthentication context")
			}
			hashes, salt := u16(start), u16(start+2)
			if hashes == 0 || 4+2*hashes+salt != size || (response && hashes != 1) {
				return posture, parsing.Malformed("Invalid SMB3 preauthentication lengths")
			}
			sha512 := false
			for at := start + 4; at < start+4+2*hashes; at += 2 {
				sha512 = sha512 || u16(at) == 1
			}
			if !sha512 {
				return posture, parsing.Unsupported("SMB3 preauthentication lacks supported SHA-512 offer")
			}
		case 2:
			if n := u16(start); size < 4 || n == 0 || 2+2*n != size || (response && n != 1) {
				return posture, parsing.Malformed("Invalid SMB3 encryption capability lengths")
			}
			if response {
				posture.cipher, posture.hasCipher = lookup(smbCiphers, u16(start+2)), true
			}
		case 8:
			if n := u16(start); size < 4 || n == 0 || 2+2*n != size || (response && n != 1) {
				return posture, parsing.Malformed("Invalid SMB3 signing capability lengths")
			}
			if response {
				posture.signing, posture.hasSigning = lookup(smbSigningAlgos, u16(start+2)), true
			}
		}
		if index+1 < contexts {
			pos = (stop + 7) &^ 7
		} else {
			pos = stop
		}
	}
	if !seen[1] || pos != len(data) {
		return posture, parsing.Malformed("Missing SMB3 preauthentication context or trailing data")
	}
	return posture, nil
}

// smb2NegotiateResponse ports _response: MS-SMB2 2.2.4, fixed 64-byte body, security buffer, 3.1.1 contexts.
func smb2NegotiateResponse(data []byte) (*parsing.Result, error) {
	u16 := func(at int) int { return le(data, at, 2) }
	u32 := func(at int) int { return le(data, at, 4) }
	if u32(8) != 0 || u32(20) != 0 {
		return nil, parsing.Unsupported("SMB2 NEGOTIATE response profile covers STATUS_SUCCESS without next-command chaining")
	}
	if len(data) < 128 || u16(64) != 65 {
		return nil, parsing.Malformed("SMB2 NEGOTIATE response body shorter than its fixed fields")
	}
	securityMode, dialect, contexts := u16(66), u16(68), u16(70)
	if securityMode < 1 || securityMode > 3 {
		return nil, parsing.Malformed("SMB2 response security mode must enable signing")
	}
	name, ok := smbDialects[dialect]
	if !ok {
		return nil, parsing.Unsupported("SMB2 response dialect outside the profile")
	}
	if u32(92) == 0 || u32(96) == 0 || u32(100) == 0 {
		return nil, parsing.Malformed("SMB2 response transfer sizes must be nonzero")
	}
	offset, length := u16(120), u16(122)
	if length != 0 && (offset != 128 || offset+length > len(data)) {
		return nil, parsing.Malformed("SMB2 response security buffer outside the frame")
	}
	end := 128 + length
	var posture smbPosture
	if dialect == 0x311 {
		var err error
		if posture, err = smb2Contexts(data, u32(124), contexts, end, 0, true); err != nil {
			return nil, err
		}
	} else if contexts != 0 || u32(124) != 0 || len(data) != end {
		return nil, parsing.Malformed("Negotiate contexts require dialect 3.1.1")
	}
	signing := "enabled"
	if securityMode&2 != 0 {
		signing = "required"
	}
	rows := []parsing.Row{row("smb_dialect", name, "negotiate_response", "asserted"), row("smb_signing", signing, "negotiate_response", "asserted")}
	encryption := ""
	switch dialect {
	case 0x202, 0x210:
		encryption = "unavailable"
	case 0x300, 0x302:
		encryption = "not-supported"
		if u32(88)&smb2CapEncryption != 0 {
			encryption = "supported"
		}
	case 0x311:
		encryption = "not-supported"
		if posture.hasCipher && posture.cipher != "none" {
			encryption = "supported"
		}
	}
	if encryption != "" {
		rows = append(rows, row("smb_encryption", encryption, "negotiate_response", "asserted"))
	}
	if posture.hasCipher {
		rows = append(rows, row("smb_encryption_cipher", posture.cipher, "negotiate_response", "asserted"))
	}
	if posture.hasSigning {
		rows = append(rows, row("smb_signing_algorithm", posture.signing, "negotiate_response", "asserted"))
	}
	return &parsing.Result{ProtocolName: "smb2", Scope: "negotiation_response", Reason: smb2NegotiateRespReason, Extra: rows}, nil
}

// smb2SessionSetup ports _session_setup: MS-SMB2 2.2.5/2.2.6; the security buffer names the mechanism.
func smb2SessionSetup(data []byte) ([]parsing.Row, string, error) {
	u16 := func(at int) int { return le(data, at, 2) }
	u32 := func(at int) int { return le(data, at, 4) }
	if u16(4) != 64 || u16(12) != 1 {
		return nil, "", parsing.Unsupported("Only a SESSION_SETUP frame is read after NEGOTIATE")
	}
	flags := u32(16)
	response := flags&smb2FlagServerToRedir != 0
	if u32(20) != 0 || flags&smb2FlagRelatedOps != 0 {
		return nil, "", parsing.Unsupported("Compounded SESSION_SETUP is outside the profile")
	}
	status := u32(8)
	if flags&^(smb2FlagServerToRedir|smb2FlagSigned) != 0 || (!response && flags != 0) {
		return nil, "", parsing.Malformed("SESSION_SETUP header flags outside the profile")
	}
	if flags&smb2FlagSigned != 0 {
		if status != 0 {
			return nil, "", parsing.Malformed("Signed SESSION_SETUP outside the final successful response")
		}
	} else if anyNonZero(data, 48, 64) {
		return nil, "", parsing.Malformed("Unsigned SESSION_SETUP carries a signature")
	}
	var rows []parsing.Row
	var start, length int
	if response {
		if status != 0 && status != statusMoreProcessing {
			return nil, "", parsing.Unsupported("SESSION_SETUP response status outside success and more-processing")
		}
		if u16(64) != 9 {
			return nil, "", parsing.Malformed("SESSION_SETUP response structure size must be 9")
		}
		offset := u16(68)
		length = u16(70)
		if offset != 72 && length != 0 {
			return nil, "", parsing.Malformed("SESSION_SETUP response security buffer must follow the fixed fields")
		}
		rows = append(rows, row("smb_message", "session-setup-response", "session_setup", "structural"))
		sessionFlags := u16(66)
		if sessionFlags&^7 != 0 {
			return nil, "", parsing.Malformed("SESSION_SETUP response session flags outside MS-SMB2")
		}
		session := "authenticated"
		if status == statusMoreProcessing {
			session = "continuing"
		} else {
			for _, f := range smb2SessionFlags {
				if sessionFlags&f.bit != 0 {
					session = f.label
					break
				}
			}
		}
		rows = append(rows, row("smb_session", session, "session_setup", "asserted"))
		start = 72
	} else {
		if status != 0 {
			return nil, "", parsing.Malformed("SESSION_SETUP request must carry STATUS_SUCCESS")
		}
		if u16(64) != 25 {
			return nil, "", parsing.Malformed("SESSION_SETUP request structure size must be 25")
		}
		if data[66]&^1 != 0 || data[67] < 1 || data[67] > 3 {
			return nil, "", parsing.Malformed("SESSION_SETUP request flags or security mode outside MS-SMB2")
		}
		offset := u16(76)
		length = u16(78)
		if offset != 88 {
			return nil, "", parsing.Malformed("SESSION_SETUP request security buffer must follow the fixed fields")
		}
		rows = append(rows, row("smb_message", "session-setup-request", "session_setup", "structural"))
		start = 88
	}
	if start+length != len(data) {
		return nil, "", parsing.Malformed("SESSION_SETUP security buffer disagrees with the frame")
	}
	if length > 0 {
		token, err := tokenRows(data[start : start+length])
		if err != nil {
			return nil, "", err
		}
		rows = append(rows, token...)
	} else if !response {
		return nil, "", parsing.Malformed("SESSION_SETUP request without a security buffer")
	}
	return rows, smb2SessionSetupSuffix, nil
}

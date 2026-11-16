package content

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/leenadav/protocol-detector/go/internal/pyjson"
)

// The content digest contract (migration/CONTENT-DIGEST.md). Two digests are defined over a schema-1 pack:
//
//   - the release digest, the 16 hexadecimal digits every record pins as content.digest. It is the value the
//     reference computes (protocol_engine/content.py); this file states it over the pack alone and verifies it.
//   - the pack digest, a full SHA-256 over the canonical encoding of the whole pack document. It covers every
//     field of the pack and is what an embedding host pins.
//
// Both use one canonical encoding, CJ1, of JSON values restricted to objects, arrays, strings, integers, booleans
// and null.

// PackDigestPrefix separates pack digests from every other use of SHA-256 over the same bytes.
const PackDigestPrefix = "protodetect-content-pack-v1\n"

// maxDigestDepth bounds the nesting of a pack document (schema 1 nests five levels).
const maxDigestDepth = 16

// ApplicationFields is the order in which an application's fields enter the application_catalog component.
var ApplicationFields = []string{"name", "category", "subcategory", "technology", "risk", "description", "characteristics",
	"standard_ports", "secure_ports", "implicitly_uses", "depends_on", "container", "aliases"}

// ComponentNames are the components of a release digest.
var ComponentNames = []string{"application_catalog", "families", "host_catalog", "risks"}

var integerText = regexp.MustCompile(`^(0|-?[1-9][0-9]{0,15})$`)
var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// integer is a JSON integer kept as its canonical decimal text.
type integer string

// parseStrict reads one JSON document into the restricted value set: map[string]interface{}, []interface{},
// string, integer, bool and nil. It refuses what CJ1 cannot encode unambiguously: a repeated object key, a number
// that is not a plain integer of at most 16 digits, U+FFFD in a string (an undecodable sequence), nesting beyond
// the bound, and anything after the document.
func parseStrict(data []byte) (interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := readValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, invalid("content pack has data after its document")
	}
	return value, nil
}

func checkString(s string) error {
	if !utf8.ValidString(s) || strings.ContainsRune(s, utf8.RuneError) {
		return invalid("content pack string is not valid Unicode")
	}
	return nil
}

func readValue(decoder *json.Decoder, depth int) (interface{}, error) {
	if depth > maxDigestDepth {
		return nil, invalid("content pack is nested too deeply")
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, invalid("content pack is not the expected JSON shape")
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			object := map[string]interface{}{}
			for decoder.More() {
				keyToken, err := decoder.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok {
					return nil, invalid("content pack is not the expected JSON shape")
				}
				if err := checkString(key); err != nil {
					return nil, err
				}
				if _, repeated := object[key]; repeated {
					return nil, invalid("content pack repeats an object key")
				}
				if object[key], err = readValue(decoder, depth+1); err != nil {
					return nil, err
				}
			}
			if _, err := decoder.Token(); err != nil {
				return nil, invalid("content pack is not the expected JSON shape")
			}
			return object, nil
		case '[':
			array := []interface{}{}
			for decoder.More() {
				item, err := readValue(decoder, depth+1)
				if err != nil {
					return nil, err
				}
				array = append(array, item)
			}
			if _, err := decoder.Token(); err != nil {
				return nil, invalid("content pack is not the expected JSON shape")
			}
			return array, nil
		}
		return nil, invalid("content pack is not the expected JSON shape")
	case string:
		if err := checkString(t); err != nil {
			return nil, err
		}
		return t, nil
	case json.Number:
		if !integerText.MatchString(string(t)) {
			return nil, invalid("content pack number is not a plain integer")
		}
		return integer(t), nil
	case bool, nil:
		return t, nil
	}
	return nil, invalid("content pack is not the expected JSON shape")
}

// writeCanonical appends the CJ1 encoding of a restricted value: object keys in ascending order of their UTF-8
// bytes, ", " between members and items, ": " after a key, strings in ASCII with every character outside
// U+0020..U+007E escaped, integers in decimal, true, false and null.
func writeCanonical(b *strings.Builder, value interface{}) {
	switch v := value.(type) {
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		b.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				b.WriteString(", ")
			}
			pyjson.String(b, key)
			b.WriteString(": ")
			writeCanonical(b, v[key])
		}
		b.WriteByte('}')
	case []interface{}:
		b.WriteByte('[')
		for i, item := range v {
			if i > 0 {
				b.WriteString(", ")
			}
			writeCanonical(b, item)
		}
		b.WriteByte(']')
	case string:
		pyjson.String(b, v)
	case integer:
		b.WriteString(string(v))
	case bool:
		if v {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	default:
		b.WriteString("null")
	}
}

// Canonical is the CJ1 encoding of a JSON document, or an error when the document is outside the restricted set.
func Canonical(data []byte) ([]byte, error) {
	value, err := parseStrict(data)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	writeCanonical(&b, value)
	return []byte(b.String()), nil
}

// chain is the component hash: SHA-256 over each part's CJ1 encoding followed by one zero byte, in hexadecimal.
func chain(parts []interface{}) string {
	hasher := sha256.New()
	for _, part := range parts {
		var b strings.Builder
		writeCanonical(&b, part)
		hasher.Write([]byte(b.String()))
		hasher.Write([]byte{0})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

// Digests are the digests of one pack.
type Digests struct {
	// Pack is the pack digest: 64 hexadecimal digits over the whole document.
	Pack string
	// Release is the release digest recomputed from the components: 16 hexadecimal digits.
	Release string
	// Components are the component hashes that enter the release digest. Recomputed lists the ones derived from
	// the pack's own tables; families is carried as stated, because schema 1 holds no family inventory.
	Components map[string]string
	Recomputed []string
}

func object(value interface{}, what string) (map[string]interface{}, error) {
	out, ok := value.(map[string]interface{})
	if !ok {
		return nil, invalid("content pack " + what + " is not an object")
	}
	return out, nil
}

func exactKeys(o map[string]interface{}, keys []string, what string) error {
	if len(o) != len(keys) {
		return invalid("content pack " + what + " has fields outside the digest contract")
	}
	for _, key := range keys {
		if _, ok := o[key]; !ok {
			return invalid("content pack " + what + " has fields outside the digest contract")
		}
	}
	return nil
}

// ComputeDigests computes both digests of a pack and verifies what the pack states about itself: the three
// components that its tables determine and the release digest. A pack that states anything else is refused.
func ComputeDigests(data []byte) (*Digests, error) {
	value, err := parseStrict(data)
	if err != nil {
		return nil, err
	}
	document, err := object(value, "document")
	if err != nil {
		return nil, err
	}
	release, err := object(document["release"], "release")
	if err != nil {
		return nil, err
	}
	stated, err := object(release["components"], "release components")
	if err != nil {
		return nil, err
	}
	if err := exactKeys(stated, ComponentNames, "release components"); err != nil {
		return nil, err
	}
	components := map[string]string{}
	for _, name := range ComponentNames {
		text, ok := stated[name].(string)
		if !ok || !hex64.MatchString(text) {
			return nil, invalid("content pack component " + name + " is not a SHA-256 value")
		}
		components[name] = text
	}

	hostCatalog, err := object(document["host_catalog"], "host catalog")
	if err != nil {
		return nil, err
	}
	entries, ok := hostCatalog["entries"].([]interface{})
	if !ok {
		return nil, invalid("content pack host catalog has no entries")
	}
	recomputed := map[string]string{"host_catalog": chain(entries)}

	list, ok := document["applications"].([]interface{})
	if !ok {
		return nil, invalid("content pack has no applications")
	}
	type named struct {
		name string
		part interface{}
	}
	applications := make([]named, 0, len(list))
	for _, item := range list {
		application, err := object(item, "application")
		if err != nil {
			return nil, err
		}
		if err := exactKeys(application, ApplicationFields, "application"); err != nil {
			return nil, err
		}
		name, ok := application["name"].(string)
		if !ok {
			return nil, invalid("application entry without a name")
		}
		fields := make([]interface{}, 0, len(ApplicationFields))
		for _, field := range ApplicationFields {
			fields = append(fields, application[field])
		}
		applications = append(applications, named{name, []interface{}{name, fields}})
	}
	sort.SliceStable(applications, func(i, j int) bool { return applications[i].name < applications[j].name })
	parts := make([]interface{}, 0, len(applications))
	for _, application := range applications {
		parts = append(parts, application.part)
	}
	recomputed["application_catalog"] = chain(parts)

	risks, err := object(document["risks"], "risks")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(risks))
	for name := range risks {
		names = append(names, name)
	}
	sort.Strings(names)
	parts = parts[:0]
	for _, name := range names {
		risk, err := object(risks[name], "risk")
		if err != nil {
			return nil, err
		}
		if err := exactKeys(risk, []string{"severity", "description"}, "risk"); err != nil {
			return nil, err
		}
		parts = append(parts, []interface{}{name, []interface{}{risk["severity"], risk["description"]}})
	}
	recomputed["risks"] = chain(parts)

	out := &Digests{Components: components}
	for _, name := range ComponentNames {
		if computed, derived := recomputed[name]; derived {
			if computed != components[name] {
				return nil, invalid("content pack digest mismatch: component " + name)
			}
			out.Recomputed = append(out.Recomputed, name)
		}
	}
	parts = parts[:0]
	for _, name := range ComponentNames { // already in ascending order
		parts = append(parts, components[name])
	}
	out.Release = chain(parts)[:16]
	if statedDigest, _ := release["digest"].(string); statedDigest != out.Release {
		return nil, invalid("content pack digest mismatch: release digest")
	}
	var b strings.Builder
	writeCanonical(&b, document)
	sum := sha256.Sum256([]byte(PackDigestPrefix + b.String()))
	out.Pack = hex.EncodeToString(sum[:])
	return out, nil
}

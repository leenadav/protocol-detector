package detector

import "unicode/utf8"

// MaxEvidenceValue bounds every evidence value and Detail string copied out of the engine, in bytes.
const MaxEvidenceValue = 255

// MaxEvidence bounds the evidence items of one direction's snapshot.
const MaxEvidence = 32

// Evidence is one detached evidence item. Value is "" when Class is ClassWithheld.
type Evidence struct {
	Field    string
	Value    string
	Source   string
	Strength string
	Class    EvidenceClass
}

// evidenceClasses classifies the evidence fields the engine emits. A field missing from this table is
// withheld. The table is closed on purpose: adding a family to a profile means classifying its fields
// (TestProfileEvidenceFieldsAreClassified fails otherwise).
var evidenceClasses = map[string]EvidenceClass{
	// Engine fields.
	"application_protocol": ClassCategorical,
	"encryption":           ClassCategorical,
	"ambiguous_candidates": ClassCategorical,
	"shift":                ClassCategorical,
	"shift_from":           ClassCategorical,
	"shifted_payload":      ClassCategorical,
	"candidate_hint":       ClassCategorical,
	"hostname":             ClassHostname,
	"offered_alpn":         ClassAsserted,
	// TLS.
	"tls_handshake":           ClassCategorical,
	"tls_ech":                 ClassCategorical,
	"tls_offered_max_version": ClassCategorical,
	"tls_weak_cipher_offered": ClassCategorical,
	"selected_tls_version":    ClassCategorical,
	"selected_cipher":         ClassCategorical,
	"selected_cipher_mode":    ClassCategorical,
	"selected_group":          ClassCategorical,
	"selected_key_exchange":   ClassCategorical,
	"requested_group":         ClassCategorical,
	"selected_alpn":           ClassAsserted,
	// HTTP.
	"http_method":         ClassAsserted,
	"http_status":         ClassCategorical,
	"http_content_type":   ClassCategorical,
	"http_accept":         ClassCategorical,
	"http_upgrade":        ClassAsserted,
	"http_auth_scheme":    ClassAsserted,
	"http_auth_challenge": ClassAsserted,
	// SSH.
	"ssh_version":        ClassAsserted,
	"ssh_kex_class":      ClassCategorical,
	"ssh_weak_algorithm": ClassCategorical,
	"ssh_terrapin":       ClassCategorical,
	// SMTP.
	"smtp_client_identity": ClassHostname,
}

// classify returns the class of a field, ClassWithheld when unclassified.
func classify(field string) EvidenceClass {
	if c, ok := evidenceClasses[field]; ok {
		return c
	}
	return ClassWithheld
}

// bounded copies s and cuts it to at most MaxEvidenceValue bytes on a rune boundary. string(...) of a
// []byte conversion is not needed: Go strings are immutable, but the copy keeps the result independent
// of any larger string the engine may hold.
func bounded(s string) string {
	if len(s) > MaxEvidenceValue {
		cut := MaxEvidenceValue
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut]
	}
	return string(append([]byte(nil), s...))
}

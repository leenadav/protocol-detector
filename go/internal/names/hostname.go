// Package names holds the exact DNS hostname normalization shared by HTTP Host and TLS SNI handling
// (protocol_engine/model.py normalize_hostname): lowercase ASCII labels, no IP literals.
package names

import (
	"errors"
	"net"
	"regexp"
	"strings"
)

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ErrInvalid is returned for anything that is not an exact ASCII DNS host.
var ErrInvalid = errors.New("invalid hostname")

// Normalize lowercases, strips one trailing dot and validates every label; IP literals are rejected.
func Normalize(value string) (string, error) {
	value = strings.ToLower(value)
	value = strings.TrimSuffix(value, ".")
	if value == "" || len(value) > 253 {
		return "", ErrInvalid
	}
	if net.ParseIP(value) != nil {
		return "", ErrInvalid
	}
	for _, part := range strings.Split(value, ".") {
		if !label.MatchString(part) {
			return "", ErrInvalid
		}
	}
	return value, nil
}

// IsIPv4 reports a strict dotted quad (ipaddress.IPv4Address): four decimal octets, no leading zeros.
func IsIPv4(value string) bool {
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 || (len(p) > 1 && p[0] == '0') {
			return false
		}
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
			n = n*10 + int(c-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}

// IsIPv6 reports an IPv6 literal (ipaddress.IPv6Address accepts the same textual forms as net.ParseIP
// for the cases the parsers see; zone identifiers are not accepted by either here).
func IsIPv6(value string) bool {
	if strings.Contains(value, "%") || !strings.Contains(value, ":") {
		return false
	}
	return net.ParseIP(value) != nil
}

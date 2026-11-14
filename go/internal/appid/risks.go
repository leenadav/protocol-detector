package appid

import (
	"sort"
	"strings"

	"github.com/leenadav/protocol-detector/go/internal/contracts"
)

// Flow risks (protocol_engine/risks.py) for the evidence fields the ported families emit plus every
// field a later family may add that needs no helper the Go backend lacks. Certificate validity and key
// classification (x509 helpers) are not ported: those fields only appear with the certificates option,
// which the Go inspector refuses, so their branches are unreachable here.

var sharing = map[string]bool{"rdp": true, "vnc": true, "smb": true, "ftp": true, "bittorrent": true, "rsync": true, "tftp": true}
var legacyTLS = map[string]bool{"1.0": true, "1.1": true, "SSL 3.0": true}
var obsoleteProtocols = map[string]bool{"smb1": true, "telnet": true}
var protectedVersions = map[string]bool{"snmp/3": true}
var prohibitedCiphers = map[string]bool{"null": true, "export": true, "anon": true, "rc4": true, "des": true}
var noForwardSecrecy = map[string]bool{"static-rsa": true, "static-ecdh": true, "psk": true}
var weakEtypes = map[string]bool{"des": true, "des3": true, "rc4": true}
var sshRiskExempt = map[string]bool{"hostkey-rsa-sha1": true, "cipher-none": true}

var riskFields = map[string]bool{}

func init() {
	for _, f := range strings.Fields(`ssh_version selected_tls_version rdp_security_flags rdp_selected_protocol tls_offered_max_version
		dns_query_shape payload_class tls_certificate_self_issued tls_certificate_key tls_certificate_signature tls_certificate_lifetime_days
		tls_ech dns_rcode kerberos_error radius_code modbus_pdu zmtp_mechanism rip_authentication gss_mechanism ldap_bind smb_session
		http_auth_scheme http_auth_challenge http2_auth_scheme http2_auth_challenge selected_key_exchange tls_certificate_ca
		tls_certificate_eku tls_certificate_san tls_certificate_not_before tls_certificate_not_after ssh_weak_algorithm ssh_terrapin
		smb_signing smb_encryption rdp_selected_security mysql_tls_supported mysql_client_ssl mysql_auth_plugin tds_session_encryption
		postgresql_message snmp_security_level snmp_usm_discovery snmp_pdu kerberos_etype_offered kerberos_reply_etype
		kerberos_ticket_etype tls_weak_cipher_offered`) {
		riskFields[f] = true
	}
}

func applicationRisks(v *Verdict) []string {
	var out []string
	if v.App == "incomplete" || v.App == "insufficient-data" || v.App == "not-applicable" {
		return out
	}
	if v.Encryption == nil && containsString(v.Characteristics, "cleartext-credentials") {
		out = append(out, "cleartext-credential-protocol")
	}
	if sharing[v.App] {
		out = append(out, "desktop-or-file-sharing-session")
	}
	if v.App == "http-proxy" {
		out = append(out, "http-proxy-tunnel")
	}
	return out
}

func remove(list []string, v string) []string {
	for i, x := range list {
		if x == v {
			return append(list[:i], list[i+1:]...)
		}
	}
	return list
}

// FlowRisks ports risks.flow_risks (sorted, deduplicated). Certificate-validity evaluation is absent (see above).
func FlowRisks(v *Verdict, client, server *contracts.Observation) []string {
	found := applicationRisks(v)
	if v.PortUsage == "nonstandard" {
		found = append(found, "nonstandard-port")
	}
	if v.ShiftedFrom != nil && *v.ShiftedFrom == "http-proxy" && !containsString(found, "http-proxy-tunnel") {
		found = append(found, "http-proxy-tunnel")
	}
	for _, o := range []*contracts.Observation{client, server} {
		if o == nil {
			continue
		}
		status := o.Status
		if status == contracts.Malformed {
			found = append(found, "malformed-protocol")
			continue
		}
		if status == contracts.Identified {
			proto := deref(o.ApplicationProtocol)
			if obsoleteProtocols[proto] {
				found = append(found, "obsolete-protocol")
			} else if protectedVersions[proto] && containsString(found, "cleartext-credential-protocol") {
				found = remove(found, "cleartext-credential-protocol")
			}
		} else if status != contracts.Unknown {
			continue
		}
		window := map[string]string{}
		for _, e := range o.Evidence {
			field, value := e.Field, e.Value
			if !riskFields[field] {
				continue
			}
			switch field {
			case "tls_offered_max_version":
				if legacyTLS[value] {
					found = append(found, "tls-legacy-version-offer")
				}
				if o.Hostname == nil {
					found = append(found, "tls-missing-sni")
				}
			case "payload_class":
				if value == "high-entropy" && status == contracts.Unknown {
					found = append(found, "unknown-high-entropy-payload")
				}
			case "dns_query_shape":
				if value == "suspicious" {
					found = append(found, "dns-suspicious-query-name")
				}
			case "tls_certificate_self_issued":
				if value == "yes" {
					found = append(found, "tls-self-issued-certificate")
				}
			case "modbus_pdu":
				if value == "exception" {
					found = append(found, "modbus-exception-response")
				}
			case "radius_code":
				if value == "access-reject" {
					found = append(found, "radius-access-reject")
				}
			case "kerberos_error":
				if value != "25" {
					found = append(found, "kerberos-error-response")
				}
			case "dns_rcode":
				if value == "servfail" || value == "nxdomain" || value == "refused" {
					found = append(found, "dns-error-response")
				}
			case "tls_ech":
				if value == "outer" {
					found = append(found, "tls-encrypted-client-hello")
				}
			case "rip_authentication":
				if value != "simple-password" && containsString(found, "cleartext-credential-protocol") {
					found = remove(found, "cleartext-credential-protocol")
				}
			case "gss_mechanism":
				if (value == "ntlm" || value == "ntlm-response" || value == "lm-response") && !containsString(found, "ntlm-authentication") {
					found = append(found, "ntlm-authentication")
				}
			case "http_auth_scheme", "http_auth_challenge", "http2_auth_scheme", "http2_auth_challenge":
				if value == "ntlm" && !containsString(found, "ntlm-authentication") {
					found = append(found, "ntlm-authentication")
				}
				if value == "basic" && strings.HasSuffix(field, "scheme") && v.Encryption == nil && !containsString(found, "http-basic-authentication") {
					found = append(found, "http-basic-authentication")
				}
			case "ldap_bind":
				if value != "simple" && value != "sasl-plain" && value != "sasl-other" && containsString(found, "cleartext-credential-protocol") {
					found = remove(found, "cleartext-credential-protocol")
				}
			case "smb_session":
				if (value == "guest" || value == "anonymous") && !containsString(found, "smb-guest-or-anonymous-session") {
					found = append(found, "smb-guest-or-anonymous-session")
				}
			case "zmtp_mechanism":
				if value != "plain" && containsString(found, "cleartext-credential-protocol") {
					found = remove(found, "cleartext-credential-protocol")
				}
			case "smb_signing":
				if value == "enabled" && strings.HasSuffix(e.Source, "negotiate_response") {
					found = append(found, "smb-signing-not-required")
				}
			case "smb_encryption":
				if value == "unavailable" || value == "not-supported" {
					found = append(found, "smb-encryption-unavailable")
				}
			case "ssh_weak_algorithm":
				if value == "cipher-none" {
					found = append(found, "ssh-none-cipher-offered")
				}
				if !sshRiskExempt[value] {
					found = append(found, "ssh-weak-algorithm-offered")
				}
			case "ssh_terrapin":
				if value == "exposed" {
					found = append(found, "ssh-terrapin-exposed")
				}
			case "rdp_selected_security":
				if value == "standard-rdp" || value == "tls" {
					found = append(found, "rdp-nla-not-negotiated")
				}
			case "mysql_tls_supported":
				if value == "false" {
					found = append(found, "database-encryption-unavailable")
				}
			case "mysql_client_ssl":
				if value == "not-requested" && strings.HasPrefix(e.Source, "wire") {
					found = append(found, "database-session-unencrypted")
				}
			case "mysql_auth_plugin":
				if value == "cleartext" && strings.HasPrefix(e.Source, "wire") && !containsString(found, "cleartext-credential-protocol") {
					found = append(found, "cleartext-credential-protocol")
				}
			case "tds_session_encryption":
				if value == "none" {
					found = append(found, "database-encryption-unavailable")
				}
				if value == "none" || value == "login-only" {
					found = append(found, "database-session-unencrypted")
				}
			case "postgresql_message":
				if value == "startup" && strings.HasPrefix(e.Source, "wire") {
					found = append(found, "database-session-unencrypted")
				}
			case "kerberos_etype_offered":
				if weakEtypes[value] {
					found = append(found, "kerberos-weak-etype-offered")
				}
			case "kerberos_reply_etype", "kerberos_ticket_etype":
				if weakEtypes[value] {
					found = append(found, "kerberos-weak-etype-selected")
				}
			case "tls_weak_cipher_offered":
				if prohibitedCiphers[value] {
					found = append(found, "tls-prohibited-cipher-offered")
				} else {
					found = append(found, "tls-64-bit-block-cipher-offered")
				}
			case "selected_key_exchange":
				if noForwardSecrecy[value] {
					found = append(found, "tls-no-forward-secrecy")
				}
			case "tls_certificate_ca":
				if value == "yes" {
					found = append(found, "tls-ca-certificate-as-leaf")
				}
			case "tls_certificate_eku":
				if value == "other" {
					found = append(found, "tls-certificate-not-for-server-auth")
				}
			case "tls_certificate_san":
				if value == "absent" {
					found = append(found, "tls-certificate-without-san")
				}
			case "snmp_security_level", "snmp_usm_discovery", "snmp_pdu":
				window[field] = value
			case "tls_certificate_lifetime_days":
				if n, ok := atoi(value); ok && n > 398 {
					found = append(found, "tls-certificate-lifetime-excessive")
				}
			case "ssh_version", "selected_tls_version", "rdp_security_flags", "rdp_selected_protocol":
				if (field == "ssh_version" && value == "1.99") || (field == "selected_tls_version" && legacyTLS[value]) ||
					((field == "rdp_security_flags" || field == "rdp_selected_protocol") && value == "0") {
					if !containsString(found, "obsolete-protocol") {
						found = append(found, "obsolete-protocol")
					}
				}
			}
		}
		if level, ok := window["snmp_security_level"]; ok {
			if _, discovery := window["snmp_usm_discovery"]; window["snmp_pdu"] != "report" && !discovery {
				if level == "no-auth-no-priv" {
					found = append(found, "snmpv3-unauthenticated")
				} else if level == "auth-no-priv" {
					found = append(found, "snmpv3-no-privacy")
				}
			}
		}
	}
	if len(found) == 0 {
		return []string{}
	}
	uniq := map[string]bool{}
	var out []string
	for _, r := range found {
		if !uniq[r] {
			uniq[r] = true
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

func atoi(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}

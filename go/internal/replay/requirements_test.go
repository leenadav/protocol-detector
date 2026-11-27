package replay

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/leenadav/protocol-detector/go/internal/parity"
)

// The protocol-profile security requirements (SECURITY-REQUIREMENTS.md) were verified by the Python reference's
// tests until PRO-403 removed them (their last state is the tag python-final). Their inputs live on in two frozen
// files with the exact answers the reference gave, evidence and metrics included:
//
//   - migration/fixtures/requirements.json.gz: every stream and datagram inspector input the requirements' own
//     Python tests made (truncations, wrong lengths and counts, reserved values, hints, neighbours, seeded
//     mutations), recorded per test by migration/parity/requirement_cases.py and labelled `module::function`;
//   - migration/fixtures/cases.json: the parity cases of the families each requirement names.
//
// Each TestSR* replays both and fails on any difference: a guard that stops refusing a malformed message changes the
// status, and a value that starts to be emitted changes the evidence. Every named Python test must have left cases
// and every named family must keep both accepted and refused cases, so no requirement is verified by an empty
// selection. Bounds no recorded input sits on have their own tests (internal/engine requirement_bounds_test.go).

var frozen struct {
	once    sync.Once
	doc     *parity.Document
	results map[string]json.RawMessage
	err     error
}

func frozenResults(t *testing.T) (*parity.Document, map[string]json.RawMessage) {
	t.Helper()
	frozen.once.Do(func() {
		frozen.doc, frozen.err = parity.Load(context.Background(), "../../../migration/fixtures/cases.json")
		if frozen.err != nil {
			return
		}
		var results *parity.Results
		if results, frozen.err = Run(context.Background(), frozen.doc); frozen.err == nil {
			frozen.results = results.Results
		}
	})
	if frozen.err != nil {
		t.Fatal(frozen.err)
	}
	return frozen.doc, frozen.results
}

// statuses lists the engine statuses an expected answer reports: the final observation of a stream case, the
// observation of a datagram case, or every record of a session case.
func statuses(expected interface{}) []string {
	m, _ := expected.(map[string]interface{})
	for _, key := range []string{"final", "observation"} {
		if o, ok := m[key].(map[string]interface{}); ok {
			if s, ok := o["status"].(string); ok {
				return []string{s}
			}
		}
	}
	var found []string
	records, _ := m["records"].([]interface{})
	for _, r := range records {
		rec, _ := r.(map[string]interface{})
		for _, key := range []string{"engine_status", "status"} {
			if s, ok := rec[key].(string); ok {
				found = append(found, s)
				break
			}
		}
	}
	return found
}

// selection names the cases of a requirement: every case of the listed families, plus cases whose identifier
// contains one of the listed fragments.
type selection struct {
	families  []string
	fragments []string
}

// groups names the selected family of a case (or "") and the fragments its identifier contains.
func (s selection) groups(c *parity.Case) (string, []string) {
	name := ""
	for _, f := range s.families {
		if family(c.Label) == f {
			name = f
		}
	}
	var fragments []string
	for _, f := range s.fragments {
		if strings.Contains(c.ID, f) {
			fragments = append(fragments, "~"+f)
		}
	}
	return name, fragments
}

// requireFrozenCases replays the selected cases and fails unless every Go answer equals the reference's (deltas.json
// pins apply, an unsupported answer never verifies), every selected family has at least one case the reference
// identified and one it refused (any other status), and every fragment selects at least one case.
func requireFrozenCases(t *testing.T, s selection) {
	t.Helper()
	doc, results := frozenResults(t)
	pinned := loadPinned(t)
	accepted, refused, selected := map[string]int{}, map[string]int{}, map[string]int{}
	var failures []string
	for i := range doc.Cases {
		c := &doc.Cases[i]
		group, fragments := s.groups(c)
		if group == "" && len(fragments) == 0 {
			continue
		}
		raw, ok := results[c.ID]
		if !ok {
			failures = append(failures, c.ID+": no result")
			continue
		}
		var marker Unsupported
		if json.Unmarshal(raw, &marker) == nil && marker.Unsupported != "" {
			failures = append(failures, c.ID+": unsupported: "+marker.Unsupported)
			continue
		}
		var want, got interface{}
		if err := json.Unmarshal(c.Expected, &want); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatal(err)
		}
		if items, ok := pinned[c.ID]; ok {
			var err error
			if want, err = expectPinned(want, items); err != nil {
				failures = append(failures, c.ID+": "+err.Error())
				continue
			}
		}
		if c.Kind == "session" {
			canonicalizeRecords(got)
		}
		if d := diff("$", want, got); d != "" {
			failures = append(failures, c.ID+": "+d)
			continue
		}
		for _, f := range fragments {
			selected[f]++
		}
		if group == "" {
			continue
		}
		for _, status := range statuses(want) {
			if status == "identified" {
				accepted[group]++
			} else {
				refused[group]++
			}
		}
	}
	for _, f := range s.families {
		if accepted[f] == 0 || refused[f] == 0 {
			failures = append(failures, fmt.Sprintf("%s: %d identified and %d refused cases; a requirement needs both", f, accepted[f], refused[f]))
		}
		t.Logf("%-20s identified %4d  refused %4d", f, accepted[f], refused[f])
	}
	for _, f := range s.fragments {
		if selected["~"+f] == 0 {
			failures = append(failures, fmt.Sprintf("fragment %q selects no case", f))
		}
		t.Logf("%-20s cases %4d", "~"+f, selected["~"+f])
	}
	if len(failures) > 0 {
		limit := len(failures)
		if limit > 25 {
			limit = 25
		}
		t.Fatalf("%d failures, first %d:\n%s", len(failures), limit, strings.Join(failures[:limit], "\n"))
	}
}

// requireRequirement replays what a requirement names in requirementCases: the recorded inputs of its Python tests
// and the frozen cases of its families and fragments. A requirement with neither fails.
func requireRequirement(t *testing.T, name string) {
	t.Helper()
	spec, ok := requirementCases[name]
	if !ok || (len(spec.tests) == 0 && len(spec.sel.families) == 0 && len(spec.sel.fragments) == 0) {
		t.Fatalf("%s names no case", name)
	}
	if len(spec.tests) > 0 {
		requireRecordedTests(t, spec.tests...)
	}
	if len(spec.sel.families) > 0 || len(spec.sel.fragments) > 0 {
		requireFrozenCases(t, spec.sel)
	}
}

// requirementCases names, per requirement, the Python tests (python-final) whose recorded inputs it replays and the
// families or case-id fragments of migration/fixtures/cases.json it replays (generated from the python-final rows).
var requirementCases = map[string]struct {
	tests []string
	sel   selection
}{
	"TestSR1BudgetsEndInBudgetExhausted": {
		tests: []string{"test_engine::test_budgets_are_not_protocol_mismatch", "test_engine::test_line_header_and_tls_bounds", "test_gateway::test_fastcgi_header_budget_preflight_and_exact_byte_boundary"},
		sel:   selection{families: []string{"fastcgi"}, fragments: []string{}},
	},
	"TestSR2HintsSelectButNeverIdentify": {
		tests: []string{"test_expansion::test_candidate_hints_are_not_classification", "test_gateway::test_hint_is_not_proof_and_no_confusion_with_existing_protocols"},
		sel:   selection{families: []string{}, fragments: []string{"hint-"}},
	},
	"TestSR3AmbiguousInputIsNeverArbitrarilyIdentified": {
		tests: []string{"test_expansion::test_ambiguous_dns_coap_is_not_arbitrarily_identified", "test_ikev2::test_real_coap_and_dhcp_ambiguities_are_unknown"},
		sel:   selection{families: []string{"dns", "coap", "dhcp"}, fragments: []string{"ambiguous"}},
	},
	"TestSR6AdvertisedSizesAndCountsAreChecked": {
		tests: []string{"test_expansion::test_memcached_command_shapes_and_limits", "test_expansion::test_postgresql_startup_and_negotiation_are_distinct", "test_ikev2::test_aggregate_work_and_byte_budgets"},
		sel:   selection{families: []string{"memcached", "postgresql", "ikev2"}, fragments: []string{}},
	},
	"TestSR8NoCredentialsInObservations": {
		tests: []string{"test_expansion::test_ldap_bind_ber_and_no_credentials_in_observation", "test_expansion::test_mqtt5_connect_and_will_properties", "test_gateway::test_fastcgi_all_roles_ids_flags_and_arbitrary_padding"},
		sel:   selection{families: []string{"ldap", "mqtt", "fastcgi"}, fragments: []string{}},
	},
	"TestSR14TerminalInspectionReleasesBuffers": {
		tests: []string{"test_expansion::test_completed_text_parser_is_released_without_cyclic_gc", "test_gateway::test_terminal_state_releases_buffers_without_cyclic_gc"},
		sel:   selection{families: []string{}, fragments: []string{}},
	},
	"TestSR16RandomAndMutatedInputsStayBounded": {
		tests: []string{"test_engine::test_seeded_random_data_and_mutations_are_bounded", "test_expansion::test_seeded_datagram_mutations_and_random_noise_never_crash", "test_ikev2::test_seeded_mutations_and_parser_call_ceiling"},
		sel:   selection{families: []string{}, fragments: []string{"/mutated"}},
	},
	"TestSR21SSHContinuationNeverDowngrades": {
		tests: []string{"test_fingerprints::test_ssh_continuation_never_downgrades_identification", "test_fingerprints::test_ssh_identification_then_hassh_refinement"},
		sel:   selection{families: []string{"ssh"}, fragments: []string{"kexinit"}},
	},
	"TestSR22FingerprintsOnlyWhenConfigured": {
		tests: []string{"test_fingerprints::test_client_hello_fingerprints_only_when_enabled"},
		sel:   selection{families: []string{"tls", "quic"}, fragments: []string{"fingerprints"}},
	},
	"TestSR23QUICProtectionFailuresKeepTheStructure": {
		tests: []string{"test_quic::test_protection_failures_are_reported_not_guessed", "test_quic::test_frames_allowed_in_initial"},
		sel:   selection{families: []string{"quic"}, fragments: []string{}},
	},
	"TestSR24QUICCryptoAssemblyIsBoundedAndScoped": {
		tests: []string{"test_quic::test_cross_datagram_assembly_requires_an_assembler", "test_quic::test_rfc9001_client_initial_opens_to_the_published_client_hello", "test_quic::test_mutations_and_noise_stay_within_documented_statuses_and_time"},
		sel:   selection{families: []string{"quic"}, fragments: []string{}},
	},
	"TestSR25SharedTextLinesAreContextNotIdentity": {
		tests: []string{"test_decoders_v027::test_shared_lines_report_candidates_as_context_not_identity"},
		sel:   selection{families: []string{"smtp", "ftp", "pop3", "imap", "irc"}, fragments: []string{"ambiguous"}},
	},
	"TestSR26StructuralDecodersRejectWhatDisagrees": {
		tests: []string{"test_decoders_v027::test_truncations_and_mutations_never_raise_and_stay_bounded", "test_decoders_v027::test_identified_observations_carry_structural_evidence_only", "test_decoders_v027::test_kerberos_asn1_framing_on_tcp_and_udp", "test_decoders_v027::test_flow_export_framing"},
		sel:   selection{families: []string{"kerberos", "netflow", "ipfix", "sflow", "bacnet", "dnp3", "iec-104", "ethernet-ip"}, fragments: []string{}},
	},
	"TestSR27ShiftsKeepTheCarrier": {
		tests: []string{"test_shift::test_failed_or_missing_shifted_phase_keeps_the_carrier", "test_shift::test_budgets_cover_both_phases", "test_shift::test_all_split_points_and_fragments_agree"},
		sel:   selection{families: []string{"websocket", "http"}, fragments: []string{"starttls", "shift"}},
	},
	"TestSR28ShiftBoundariesAreStructural": {
		tests: []string{"test_shift::test_connect_requires_authority_form_and_marks_http_proxy", "test_shift::test_websocket_upgrade_rules_and_frame_profile", "test_shift::test_smtp_watches_for_starttls_within_bounds", "test_shift::test_database_and_rdp_negotiations"},
		sel:   selection{families: []string{"websocket", "smtp", "imap", "pop3", "postgresql", "rdp"}, fragments: []string{"starttls"}},
	},
	"TestSR29HeuristicsNeverIdentify": {
		tests: []string{"test_risks::test_unknown_stream_is_profiled_only_when_enabled_and_bounded", "test_risks::test_datagrams_and_dns_name_shape", "test_risks::test_identified_streams_are_never_profiled"},
		sel:   selection{families: []string{}, fragments: []string{}},
	},
	"TestSR34S7commNeedsAValidatedCarrier": {
		tests: []string{"test_s7comm::test_connection_request_and_confirm_shift_to_s7", "test_s7comm::test_s7_profile_rejections_keep_the_carrier", "test_s7comm::test_tpkt_route_distinguishes_rdp_and_cotp_confirms"},
		sel:   selection{families: []string{"s7comm", "iso-tsap", "rdp"}, fragments: []string{}},
	},
	"TestSR35HostOpenedShiftsNeedBothDirections": {
		tests: []string{},
		sel:   selection{families: []string{}, fragments: []string{"session/correlation"}},
	},
	"TestSR37SNMPv3FramingWithoutSecrets": {
		tests: []string{"test_snmpv3::test_discovery_and_encrypted_messages_identify_without_secrets", "test_snmpv3::test_rejections"},
		sel:   selection{families: []string{"snmp"}, fragments: []string{}},
	},
	"TestSR38TLSCertificateWatchEmitsLabelsOnly": {
		tests: []string{"test_certificates::test_evidence_only_when_enabled_and_no_names", "test_certificates::test_rejections_keep_the_identification", "test_certificates::test_tls13_retry_and_client_hello_never_continue"},
		sel:   selection{families: []string{"tls"}, fragments: []string{}},
	},
	"TestSR39TDSAndTNSNegotiations": {
		tests: []string{"test_enterprise_db::test_tds_rejections", "test_enterprise_db::test_tns_rejections", "test_enterprise_db::test_mutations_never_raise_and_never_leak", "test_enterprise_db::test_dispatch_neighbours_are_unchanged"},
		sel:   selection{families: []string{"tds", "tns"}, fragments: []string{}},
	},
	"TestSR40OPCUAAndSOCKS5ServerReplies": {
		tests: []string{"test_opcua_socks::test_opcua_rejections_and_text_neighbours", "test_opcua_socks::test_socks5_server_rejections_and_dcerpc_neighbour", "test_opcua_socks::test_mutations_never_raise_or_leak"},
		sel:   selection{families: []string{"opcua", "socks5", "dcerpc"}, fragments: []string{}},
	},
	"TestSR41EncryptedClientHello": {
		tests: []string{"test_ech::test_outer_ech_is_reported_and_the_public_name_kept", "test_ech::test_malformed_ech_makes_the_hello_malformed", "test_ech::test_quic_initial_reports_ech"},
		sel:   selection{families: []string{"tls", "quic"}, fragments: []string{}},
	},
	"TestSR42SNMPAndDNSResponses": {
		tests: []string{"test_responses::test_snmp_pdu_kinds_and_values_never_emitted", "test_responses::test_snmp_rejections", "test_responses::test_dns_message_kind_rcode_and_risk", "test_responses::test_mutations_never_raise_or_leak"},
		sel:   selection{families: []string{"snmp", "dns"}, fragments: []string{}},
	},
	"TestSR43SMB2KerberosAndDCERPCReplies": {
		tests: []string{"test_server_replies::test_smb2_negotiate_response", "test_server_replies::test_kerberos_replies_and_errors", "test_server_replies::test_dcerpc_bind_ack_and_nak", "test_server_replies::test_mutations_never_raise_or_leak"},
		sel:   selection{families: []string{"smb2", "kerberos", "dcerpc"}, fragments: []string{}},
	},
	"TestSR44DatabaseAndDirectoryReplies": {
		tests: []string{"test_db_replies::test_postgresql_server_messages", "test_db_replies::test_ldap_bind_response", "test_db_replies::test_cql_responses", "test_db_replies::test_mysql_handshake_response", "test_db_replies::test_mutations_never_raise_or_leak"},
		sel:   selection{families: []string{"postgresql", "ldap", "cql", "mysql"}, fragments: []string{}},
	},
	"TestSR45UDPServerReplies": {
		tests: []string{"test_udp_replies::test_dtls_server_flight", "test_udp_replies::test_radius_responses_require_the_hint_and_match_their_code", "test_udp_replies::test_openvpn_server_reset", "test_udp_replies::test_ikev2_responder", "test_udp_replies::test_mutations_never_raise_or_leak"},
		sel:   selection{families: []string{"dtls", "radius", "openvpn", "ikev2"}, fragments: []string{}},
	},
	"TestSR46TCPServerReplies": {
		tests: []string{"test_tcp_replies::test_modbus_responses_and_exceptions", "test_tcp_replies::test_giop_replies", "test_tcp_replies::test_tacacs_reply", "test_tcp_replies::test_smb1_negotiate_response", "test_tcp_replies::test_amqp_connection_start", "test_tcp_replies::test_mutations_never_raise_or_leak"},
		sel:   selection{families: []string{"modbus", "giop", "tacacs-plus", "smb1", "amqp"}, fragments: []string{}},
	},
	"TestSR47MoreServerReplies": {
		tests: []string{"test_more_replies::test_tftp_server_packets", "test_more_replies::test_l2tp_and_pptp_replies", "test_more_replies::test_memcached_responses_and_netbios_neighbour", "test_more_replies::test_git_server_lines", "test_more_replies::test_fastcgi_application_records", "test_more_replies::test_mutations_never_raise_or_leak"},
		sel:   selection{families: []string{"tftp", "l2tp", "pptp", "memcached", "git", "fastcgi", "dhcp", "ntp", "mongodb", "wireguard"}, fragments: []string{}},
	},
	"TestSR48HTTP2HeaderBlocks": {
		tests: []string{"test_http2_headers::test_budgets_bound_the_continuation", "test_http2_headers::test_preamble_frames_before_headers", "test_http2_headers::test_continuation_padding_and_priority", "test_http2_headers::test_header_list_validation", "test_http2_headers::test_seeded_mutations_are_bounded_and_never_leak_header_values", "test_http2_headers::test_response_status_and_no_value_leakage"},
		sel:   selection{families: []string{"http2", "http2-server"}, fragments: []string{}},
	},
	"TestSR49RPCDiameterZMTPAndBolt": {
		tests: []string{"test_onc_rpc::test_authentication_structures", "test_onc_rpc::test_reply_rules", "test_onc_rpc::test_record_marking", "test_onc_rpc::test_memcached_neighbour_and_datagram_isolation", "test_onc_rpc::test_seeded_mutations_are_bounded", "test_diameter::test_avp_rules", "test_diameter::test_header_rules", "test_diameter::test_isolation_from_neighbours_and_mutations", "test_greetings::test_greeting_rules_and_boundaries", "test_greetings::test_handshake_rules", "test_greetings::test_isolation_and_mutations", "test_content_classes::test_http1_method_and_header_classes"},
		sel:   selection{families: []string{"onc-rpc", "diameter", "zmtp", "bolt"}, fragments: []string{}},
	},
	"TestSR50XMPPSyslogAndHTTPCarried": {
		tests: []string{"test_xmpp_syslog::test_header_rules", "test_xmpp_syslog::test_header_variants", "test_xmpp_syslog::test_seeded_mutations", "test_xmpp_syslog::test_framing_rules", "test_xmpp_syslog::test_both_framings", "test_content_classes::test_http_carried_applications"},
		sel:   selection{families: []string{"xmpp", "syslog", "http"}, fragments: []string{}},
	},
	"TestSR51DesktopStorageAndRoutingProfiles": {
		tests: []string{"test_desktop_storage::test_setup_rules", "test_desktop_storage::test_link_rules", "test_desktop_storage::test_dsi_rules", "test_desktop_storage::test_rules", "test_desktop_storage::test_rules_and_isolation", "test_desktop_storage::test_hinted_compound_packets", "test_desktop_storage::test_streams_and_datagrams_bounded", "test_desktop_storage::test_versions_commands_and_authentication"},
		sel:   selection{families: []string{"x11", "x11-server", "spice", "afp", "fins", "rip", "rtcp"}, fragments: []string{}},
	},
	"TestSR52LDAPIRCTURNAndNetBIOS": {
		tests: []string{"test_v054::test_request_alone_never_shifts_and_keeps_the_cleartext_risk", "test_v054::test_named_success_response_shifts_the_server_direction", "test_v054::test_unnamed_refused_and_other_extended_operations_do_not_shift", "test_v054::test_extended_operation_rules", "test_v054::test_replay_preconditions", "test_v054::test_registration_and_server_lines_identify_with_closed_labels", "test_v054::test_four_parameter_user_is_ambiguous_with_ftp_until_the_server_decides", "test_v054::test_grammar_rules", "test_v054::test_split_points_and_mutations_are_bounded", "test_v054::test_turn_methods_identify_with_method_and_class", "test_v054::test_turn_attribute_and_class_rules", "test_v054::test_netbios_name_service_is_told_from_dns_by_label_and_type", "test_v054::test_rpc_methods_name_the_application"},
		sel:   selection{families: []string{"ldap", "irc", "stun", "netbios-ns"}, fragments: []string{"starttls"}},
	},
	"TestSR53MDNSNetBIOSAndLLMNR": {
		tests: []string{"test_v055::test_profiles_identify_with_closed_labels", "test_v055::test_marker_and_section_rules", "test_v055::test_mutations_and_contexts_are_bounded", "test_v055::test_opcodes_identify_the_family", "test_v055::test_section_and_name_rules", "test_v055::test_mutations_stay_bounded_and_isolated", "test_v055::test_hint_only_profile"},
		sel:   selection{families: []string{"mdns", "netbios-ns", "llmnr"}, fragments: []string{}},
	},
	"TestSR54AuthenticationMechanismLabels": {
		tests: []string{"test_v056::test_smb2_mechanisms_after_negotiate", "test_v056::test_smb2_session_setup_rules", "test_v056::test_smb1_session_setup", "test_v056::test_bind_mechanism_labels_and_risk", "test_v056::test_http1_schemes_and_risks", "test_v056::test_http2_schemes", "test_v056::test_kerberos_tokens_share_one_validator", "test_v056::test_smb2_session_setup_header_flags", "test_v056::test_repeated_and_listed_http_authentication", "test_v056::test_kerberos_message_envelopes", "test_v056::test_dialect_dependent_flags_end_the_watch", "test_v056::test_kerberos_error_microseconds_range"},
		sel:   selection{families: []string{"smb2", "smb1", "kerberos", "ldap", "http", "http2"}, fragments: []string{}},
	},
	"TestSR55TLSPostureLabels": {
		tests: []string{"test_v057::test_tls12_suites_by_key_exchange_and_record_protection", "test_v057::test_tls13_key_share_psk_and_retry", "test_v057::test_dtls12_server_hello_carries_the_same_labels", "test_v057::test_basic_constraints_eku_and_san_labels", "test_v057::test_extension_rules_reject_without_losing_the_identification", "test_v057::test_no_names_and_mutations_keep_the_identification", "test_v057::test_risk_needs_a_capture_clock", "test_v057::test_general_name_budget_and_forms", "test_v057::test_explicit_critical_false_is_not_der", "test_v057::test_general_name_inner_values", "test_v057::test_ec_named_curve_oid_is_der"},
		sel:   selection{families: []string{"tls", "dtls"}, fragments: []string{}},
	},
	"TestSR56SSHAlgorithmPosture": {
		tests: []string{"test_v058::test_default_read_events_and_risks", "test_v058::test_split_points_and_a_banner_alone", "test_v058::test_rejections_keep_the_identification", "test_fingerprints::test_ssh_continuation_never_downgrades_identification"},
		sel:   selection{families: []string{"ssh"}, fragments: []string{"kexinit"}},
	},
	"TestSR57SMBTransportProtection": {
		tests: []string{"test_v059::test_encryption_by_dialect_and_capability", "test_v059::test_311_cipher_and_signing_contexts", "test_v059::test_risks", "test_v059::test_split_points"},
		sel:   selection{families: []string{"smb2"}, fragments: []string{"cipher", "encryption"}},
	},
	"TestSR58RDPSecurityPosture": {
		tests: []string{"test_v060::test_offered_security_and_credential_modes", "test_v060::test_selected_security_and_server_flags", "test_v060::test_failure_codes", "test_v060::test_nla_risk_follows_the_server_selection", "test_v060::test_split_points_and_mutations"},
		sel:   selection{families: []string{"rdp", "iso-tsap"}, fragments: []string{}},
	},
	"TestSR59DatabaseTransportProtection": {
		tests: []string{"test_v061::test_tds_session_encryption_follows_the_response", "test_v061::test_mysql_greeting_and_handshake_response", "test_v061::test_postgresql_startup_in_the_clear", "test_v061::test_split_points"},
		sel:   selection{families: []string{"tds", "postgresql", "mysql"}, fragments: []string{}},
	},
	"TestSR60SNMPv3SecurityLevel": {
		tests: []string{"test_v062::test_levels_follow_msg_flags", "test_v062::test_discovery_and_reports_are_exempt", "test_v062::test_mutations_stay_in_closed_labels"},
		sel:   selection{families: []string{"snmp"}, fragments: []string{}},
	},
	"TestSR61KerberosEncryptionTypes": {
		tests: []string{"test_v063::test_offered_classes_in_preference_order", "test_v063::test_selected_classes_in_replies", "test_v063::test_substructure_faults_drop_labels_but_keep_the_identification", "test_v063::test_mutations_stay_in_closed_labels"},
		sel:   selection{families: []string{"kerberos"}, fragments: []string{"etype"}},
	},
	"TestSR62WeakCipherSuiteClasses": {
		tests: []string{"test_v064::test_offer_rows_and_risks", "test_v064::test_split_points"},
		sel:   selection{families: []string{"tls"}, fragments: []string{"weak"}},
	},
	"TestSR63ServerNameCatalog": {
		tests: []string{},
		sel:   selection{families: []string{}, fragments: []string{"host-catalog", "sni"}},
	},
	"TestSR64SmartHomeLANDatagrams": {
		tests: []string{"test_v066::test_every_truncation_fails_closed", "test_v066::test_mutations_never_crash", "test_v066::test_kasa_rules_and_budget", "test_v066::test_evidence_is_fixed_vocabulary", "test_v066::test_hint_never_establishes_identity"},
		sel:   selection{families: []string{"lifx-lan", "tuya-lan", "tplink-smarthome"}, fragments: []string{}},
	},
	"TestSR65ContinuationOnlyAddsBoundedEvidence": {
		tests: []string{"test_continuation::test_default_configuration_stops_at_the_first_message", "test_continuation::test_later_requests_add_counts_without_changing_identity", "test_continuation::test_budget_ends_the_continuation_and_charges_nothing_beyond_it", "test_continuation::test_large_declared_body_consumes_budget_then_ends", "test_continuation::test_framing_error_keeps_the_identification", "test_continuation::test_header_budget_inside_a_later_message_ends_the_continuation", "test_continuation::test_bad_record_header_ends_with_framing", "test_continuation::test_budget_bounds_record_framing", "test_continuation::test_304_metadata_never_consumes_the_next_response_as_a_body", "test_continuation::test_no_body_statuses_take_precedence_over_framing_metadata"},
		sel:   selection{families: []string{}, fragments: []string{"options"}},
	},
	"TestSR68SessionSequencesMatchTheReference": {
		tests: []string{},
		sel:   selection{families: []string{}, fragments: []string{"session/"}},
	},
}

// SR-1 (SECURITY-REQUIREMENTS.md).
func TestSR1BudgetsEndInBudgetExhausted(t *testing.T) {
	requireRequirement(t, "TestSR1BudgetsEndInBudgetExhausted")
}

// SR-2 (SECURITY-REQUIREMENTS.md).
func TestSR2HintsSelectButNeverIdentify(t *testing.T) {
	requireRequirement(t, "TestSR2HintsSelectButNeverIdentify")
}

// SR-3 (SECURITY-REQUIREMENTS.md).
func TestSR3AmbiguousInputIsNeverArbitrarilyIdentified(t *testing.T) {
	requireRequirement(t, "TestSR3AmbiguousInputIsNeverArbitrarilyIdentified")
}

// SR-6 (SECURITY-REQUIREMENTS.md).
func TestSR6AdvertisedSizesAndCountsAreChecked(t *testing.T) {
	requireRequirement(t, "TestSR6AdvertisedSizesAndCountsAreChecked")
}

// SR-8 (SECURITY-REQUIREMENTS.md).
func TestSR8NoCredentialsInObservations(t *testing.T) {
	requireRequirement(t, "TestSR8NoCredentialsInObservations")
}

// SR-14 (SECURITY-REQUIREMENTS.md).
func TestSR14TerminalInspectionReleasesBuffers(t *testing.T) {
	requireRequirement(t, "TestSR14TerminalInspectionReleasesBuffers")
}

// SR-16 (SECURITY-REQUIREMENTS.md).
func TestSR16RandomAndMutatedInputsStayBounded(t *testing.T) {
	requireRequirement(t, "TestSR16RandomAndMutatedInputsStayBounded")
}

// SR-21 (SECURITY-REQUIREMENTS.md).
func TestSR21SSHContinuationNeverDowngrades(t *testing.T) {
	requireRequirement(t, "TestSR21SSHContinuationNeverDowngrades")
}

// SR-22 (SECURITY-REQUIREMENTS.md).
func TestSR22FingerprintsOnlyWhenConfigured(t *testing.T) {
	requireRequirement(t, "TestSR22FingerprintsOnlyWhenConfigured")
}

// SR-23 (SECURITY-REQUIREMENTS.md).
func TestSR23QUICProtectionFailuresKeepTheStructure(t *testing.T) {
	requireRequirement(t, "TestSR23QUICProtectionFailuresKeepTheStructure")
}

// SR-24 (SECURITY-REQUIREMENTS.md).
func TestSR24QUICCryptoAssemblyIsBoundedAndScoped(t *testing.T) {
	requireRequirement(t, "TestSR24QUICCryptoAssemblyIsBoundedAndScoped")
}

// SR-25 (SECURITY-REQUIREMENTS.md).
func TestSR25SharedTextLinesAreContextNotIdentity(t *testing.T) {
	requireRequirement(t, "TestSR25SharedTextLinesAreContextNotIdentity")
}

// SR-26 (SECURITY-REQUIREMENTS.md).
func TestSR26StructuralDecodersRejectWhatDisagrees(t *testing.T) {
	requireRequirement(t, "TestSR26StructuralDecodersRejectWhatDisagrees")
}

// SR-27 (SECURITY-REQUIREMENTS.md).
func TestSR27ShiftsKeepTheCarrier(t *testing.T) {
	requireRequirement(t, "TestSR27ShiftsKeepTheCarrier")
}

// SR-28 (SECURITY-REQUIREMENTS.md).
func TestSR28ShiftBoundariesAreStructural(t *testing.T) {
	requireRequirement(t, "TestSR28ShiftBoundariesAreStructural")
}

// SR-29 (SECURITY-REQUIREMENTS.md).
func TestSR29HeuristicsNeverIdentify(t *testing.T) {
	requireRequirement(t, "TestSR29HeuristicsNeverIdentify")
}

// SR-34 (SECURITY-REQUIREMENTS.md).
func TestSR34S7commNeedsAValidatedCarrier(t *testing.T) {
	requireRequirement(t, "TestSR34S7commNeedsAValidatedCarrier")
}

// SR-35 (SECURITY-REQUIREMENTS.md).
func TestSR35HostOpenedShiftsNeedBothDirections(t *testing.T) {
	requireRequirement(t, "TestSR35HostOpenedShiftsNeedBothDirections")
}

// SR-37 (SECURITY-REQUIREMENTS.md).
func TestSR37SNMPv3FramingWithoutSecrets(t *testing.T) {
	requireRequirement(t, "TestSR37SNMPv3FramingWithoutSecrets")
}

// SR-38 (SECURITY-REQUIREMENTS.md).
func TestSR38TLSCertificateWatchEmitsLabelsOnly(t *testing.T) {
	requireRequirement(t, "TestSR38TLSCertificateWatchEmitsLabelsOnly")
}

// SR-39 (SECURITY-REQUIREMENTS.md).
func TestSR39TDSAndTNSNegotiations(t *testing.T) {
	requireRequirement(t, "TestSR39TDSAndTNSNegotiations")
}

// SR-40 (SECURITY-REQUIREMENTS.md).
func TestSR40OPCUAAndSOCKS5ServerReplies(t *testing.T) {
	requireRequirement(t, "TestSR40OPCUAAndSOCKS5ServerReplies")
}

// SR-41 (SECURITY-REQUIREMENTS.md).
func TestSR41EncryptedClientHello(t *testing.T) {
	requireRequirement(t, "TestSR41EncryptedClientHello")
}

// SR-42 (SECURITY-REQUIREMENTS.md).
func TestSR42SNMPAndDNSResponses(t *testing.T) { requireRequirement(t, "TestSR42SNMPAndDNSResponses") }

// SR-43 (SECURITY-REQUIREMENTS.md).
func TestSR43SMB2KerberosAndDCERPCReplies(t *testing.T) {
	requireRequirement(t, "TestSR43SMB2KerberosAndDCERPCReplies")
}

// SR-44 (SECURITY-REQUIREMENTS.md).
func TestSR44DatabaseAndDirectoryReplies(t *testing.T) {
	requireRequirement(t, "TestSR44DatabaseAndDirectoryReplies")
}

// SR-45 (SECURITY-REQUIREMENTS.md).
func TestSR45UDPServerReplies(t *testing.T) { requireRequirement(t, "TestSR45UDPServerReplies") }

// SR-46 (SECURITY-REQUIREMENTS.md).
func TestSR46TCPServerReplies(t *testing.T) { requireRequirement(t, "TestSR46TCPServerReplies") }

// SR-47 (SECURITY-REQUIREMENTS.md).
func TestSR47MoreServerReplies(t *testing.T) { requireRequirement(t, "TestSR47MoreServerReplies") }

// SR-48 (SECURITY-REQUIREMENTS.md).
func TestSR48HTTP2HeaderBlocks(t *testing.T) { requireRequirement(t, "TestSR48HTTP2HeaderBlocks") }

// SR-49 (SECURITY-REQUIREMENTS.md).
func TestSR49RPCDiameterZMTPAndBolt(t *testing.T) {
	requireRequirement(t, "TestSR49RPCDiameterZMTPAndBolt")
}

// SR-50 (SECURITY-REQUIREMENTS.md).
func TestSR50XMPPSyslogAndHTTPCarried(t *testing.T) {
	requireRequirement(t, "TestSR50XMPPSyslogAndHTTPCarried")
}

// SR-51 (SECURITY-REQUIREMENTS.md).
func TestSR51DesktopStorageAndRoutingProfiles(t *testing.T) {
	requireRequirement(t, "TestSR51DesktopStorageAndRoutingProfiles")
}

// SR-52 (SECURITY-REQUIREMENTS.md).
func TestSR52LDAPIRCTURNAndNetBIOS(t *testing.T) {
	requireRequirement(t, "TestSR52LDAPIRCTURNAndNetBIOS")
}

// SR-53 (SECURITY-REQUIREMENTS.md).
func TestSR53MDNSNetBIOSAndLLMNR(t *testing.T) { requireRequirement(t, "TestSR53MDNSNetBIOSAndLLMNR") }

// SR-54 (SECURITY-REQUIREMENTS.md).
func TestSR54AuthenticationMechanismLabels(t *testing.T) {
	requireRequirement(t, "TestSR54AuthenticationMechanismLabels")
}

// SR-55 (SECURITY-REQUIREMENTS.md).
func TestSR55TLSPostureLabels(t *testing.T) { requireRequirement(t, "TestSR55TLSPostureLabels") }

// SR-56 (SECURITY-REQUIREMENTS.md).
func TestSR56SSHAlgorithmPosture(t *testing.T) { requireRequirement(t, "TestSR56SSHAlgorithmPosture") }

// SR-57 (SECURITY-REQUIREMENTS.md).
func TestSR57SMBTransportProtection(t *testing.T) {
	requireRequirement(t, "TestSR57SMBTransportProtection")
}

// SR-58 (SECURITY-REQUIREMENTS.md).
func TestSR58RDPSecurityPosture(t *testing.T) { requireRequirement(t, "TestSR58RDPSecurityPosture") }

// SR-59 (SECURITY-REQUIREMENTS.md).
func TestSR59DatabaseTransportProtection(t *testing.T) {
	requireRequirement(t, "TestSR59DatabaseTransportProtection")
}

// SR-60 (SECURITY-REQUIREMENTS.md).
func TestSR60SNMPv3SecurityLevel(t *testing.T) { requireRequirement(t, "TestSR60SNMPv3SecurityLevel") }

// SR-61 (SECURITY-REQUIREMENTS.md).
func TestSR61KerberosEncryptionTypes(t *testing.T) {
	requireRequirement(t, "TestSR61KerberosEncryptionTypes")
}

// SR-62 (SECURITY-REQUIREMENTS.md).
func TestSR62WeakCipherSuiteClasses(t *testing.T) {
	requireRequirement(t, "TestSR62WeakCipherSuiteClasses")
}

// SR-63 (SECURITY-REQUIREMENTS.md).
func TestSR63ServerNameCatalog(t *testing.T) { requireRequirement(t, "TestSR63ServerNameCatalog") }

// SR-64 (SECURITY-REQUIREMENTS.md).
func TestSR64SmartHomeLANDatagrams(t *testing.T) {
	requireRequirement(t, "TestSR64SmartHomeLANDatagrams")
}

// SR-65 (SECURITY-REQUIREMENTS.md).
func TestSR65ContinuationOnlyAddsBoundedEvidence(t *testing.T) {
	requireRequirement(t, "TestSR65ContinuationOnlyAddsBoundedEvidence")
}

// SR-68 (SECURITY-REQUIREMENTS.md).
func TestSR68SessionSequencesMatchTheReference(t *testing.T) {
	requireRequirement(t, "TestSR68SessionSequencesMatchTheReference")
}

// recorded holds migration/fixtures/requirements.json.gz: the inspector inputs that the requirements' Python tests
// made at python-final, with the reference's answers (migration/parity/requirement_cases.py), labelled
// `<module>::<function>` after the test that made them.
var recorded struct {
	once    sync.Once
	doc     *parity.Document
	results map[string]json.RawMessage
	err     error
}

// maxRecordedBytes bounds the decompressed requirement cases (about 67 MB today).
const maxRecordedBytes = 160 << 20

func recordedResults(t *testing.T) (*parity.Document, map[string]json.RawMessage) {
	t.Helper()
	recorded.once.Do(func() {
		file, err := os.Open("../../../migration/fixtures/requirements.json.gz")
		if err != nil {
			recorded.err = err
			return
		}
		defer func() { _ = file.Close() }()
		reader, err := gzip.NewReader(file)
		if err != nil {
			recorded.err = err
			return
		}
		data, err := io.ReadAll(io.LimitReader(reader, maxRecordedBytes+1))
		if err != nil || len(data) > maxRecordedBytes {
			recorded.err = fmt.Errorf("requirement cases unreadable or over %d bytes: %v", maxRecordedBytes, err)
			return
		}
		if recorded.doc, recorded.err = parity.Decode(context.Background(), data, "../../../migration/fixtures"); recorded.err != nil {
			return
		}
		var results *parity.Results
		if results, recorded.err = Run(context.Background(), recorded.doc); recorded.err == nil {
			recorded.results = results.Results
		}
	})
	if recorded.err != nil {
		t.Fatal(recorded.err)
	}
	return recorded.doc, recorded.results
}

// requireRecordedTests replays every input the named Python tests (`module::function`) made and fails unless each
// Go answer equals the reference's; each named test must have left at least one case.
func requireRecordedTests(t *testing.T, tests ...string) {
	t.Helper()
	doc, results := recordedResults(t)
	pinned := loadRecordedPins(t)
	want := map[string]int{}
	for _, name := range tests {
		want[name] = 0
	}
	var failures []string
	for i := range doc.Cases {
		c := &doc.Cases[i]
		if _, ok := want[c.Label]; !ok {
			continue
		}
		want[c.Label]++
		if d := compareCase(t, c, results[c.ID], pinned); d != "" {
			failures = append(failures, c.ID+": "+d)
		}
	}
	for _, name := range tests {
		if want[name] == 0 {
			failures = append(failures, name+": no recorded case")
		}
		t.Logf("%-90s %5d cases", name, want[name])
	}
	if len(failures) > 0 {
		limit := len(failures)
		if limit > 25 {
			limit = 25
		}
		t.Fatalf("%d failures, first %d:\n%s", len(failures), limit, strings.Join(failures[:limit], "\n"))
	}
}

// compareCase returns "" when the Go answer equals the expectation (after an approved pin), else the difference.
func compareCase(t *testing.T, c *parity.Case, raw json.RawMessage, pinned map[string][]pinnedDelta) string {
	t.Helper()
	if raw == nil {
		return "no result"
	}
	var marker Unsupported
	if json.Unmarshal(raw, &marker) == nil && marker.Unsupported != "" {
		return "unsupported: " + marker.Unsupported
	}
	var want, got interface{}
	if err := json.Unmarshal(c.Expected, &want); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if items, ok := pinned[c.ID]; ok {
		var err error
		if want, err = expectPinned(want, items); err != nil {
			return err.Error()
		}
	}
	return diff("$", want, got)
}

// TestRecordedRequirementCasesAllMatch replays every recorded case once, whatever requirement names it.
func TestRecordedRequirementCasesAllMatch(t *testing.T) {
	doc, results := recordedResults(t)
	pinned := loadRecordedPins(t)
	var failures []string
	labels := map[string]bool{}
	for i := range doc.Cases {
		c := &doc.Cases[i]
		labels[c.Label] = true
		if d := compareCase(t, c, results[c.ID], pinned); d != "" {
			failures = append(failures, c.ID+": "+d)
		}
	}
	t.Logf("%d recorded cases from %d tests", len(doc.Cases), len(labels))
	if len(doc.Cases) < 40000 || len(labels) < 250 {
		t.Fatalf("only %d cases from %d tests", len(doc.Cases), len(labels))
	}
	if len(failures) > 0 {
		limit := len(failures)
		if limit > 40 {
			limit = 40
		}
		t.Fatalf("%d failures, first %d:\n%s", len(failures), limit, strings.Join(failures[:limit], "\n"))
	}
}

// loadRecordedPins reads migration/parity/requirement-deltas.json: the approved Go-only divergences (deltas.json form)
// that apply to recorded cases. Every entry needs a justification, a Go value and a recorded case it applies to.
func loadRecordedPins(t *testing.T) map[string][]pinnedDelta {
	t.Helper()
	raw, err := os.ReadFile("../../../migration/parity/requirement-deltas.json")
	if err != nil {
		t.Fatal(err)
	}
	var all map[string][]pinnedDelta
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatalf("requirement-deltas.json: %v", err)
	}
	doc, _ := recordedResults(t)
	ids := make(map[string]bool, len(doc.Cases))
	for i := range doc.Cases {
		ids[doc.Cases[i].ID] = true
	}
	for id, items := range all {
		if !ids[id] {
			t.Fatalf("requirement-deltas.json %s: no recorded case has this id", id)
		}
		for _, item := range items {
			if item.Go == nil || item.Justification == "" {
				t.Fatalf("requirement-deltas.json %s %s: a pinned delta needs a Go value and a justification", id, item.Path)
			}
		}
	}
	return all
}

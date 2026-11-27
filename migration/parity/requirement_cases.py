"""PRO-403: freeze the inspector inputs of the security requirements' Python tests as Go-replayable cases.

    python3 -B migration/parity/requirement_cases.py --reference DIR [--out migration/fixtures/requirements.json.gz]

The Python reference engine and its tests were removed by PRO-403; the tag python-final keeps them. DIR is an
extract of that tag (`git archive python-final | tar -x -C DIR`). For every test module SECURITY-REQUIREMENTS.md
named before the removal (REFERENCES below, the rows' former `module::function` references), this tool runs the
named test functions under the reference, records every stream Inspector and DatagramInspector input they made
(bytes in feed order, hint, configuration, end reason), and writes them as cases in the migration/fixtures/cases.json
schema, labelled `<module>::<function>`, with the answer the reference gives when the input is replayed alone
(migration/parity/cases.py run_stream / run_datagram). Inputs the case schema cannot express (signatures, rules,
decrypted provenance, an explicit scope, clock or QUIC assembler, a hint outside the parser registry, a call that
raised) are left out and counted. Nothing in this repository is imported for behaviour; the reference runs from DIR.

The Go tests in go/internal/replay/requirements_test.go replay the file and compare every answer.
"""
import argparse
import gzip
import importlib
import json
import sys
import unittest
from pathlib import Path

# The former references of SECURITY-REQUIREMENTS.md (python-final) whose tests feed the stream or datagram inspector.
REFERENCES = {
    "test_engine": ["test_budgets_are_not_protocol_mismatch", "test_line_header_and_tls_bounds", "test_seeded_random_data_and_mutations_are_bounded",
                    "test_no_plaintext_api_without_tls", "test_decrypted_refinement_retains_tls"],
    "test_gateway": ["test_fastcgi_header_budget_preflight_and_exact_byte_boundary", "test_hint_is_not_proof_and_no_confusion_with_existing_protocols",
                     "test_fastcgi_all_roles_ids_flags_and_arbitrary_padding", "test_terminal_state_releases_buffers_without_cyclic_gc"],
    "test_expansion": ["test_candidate_hints_are_not_classification", "test_ambiguous_dns_coap_is_not_arbitrarily_identified",
                       "test_memcached_command_shapes_and_limits", "test_postgresql_startup_and_negotiation_are_distinct",
                       "test_ldap_bind_ber_and_no_credentials_in_observation", "test_mqtt5_connect_and_will_properties",
                       "test_completed_text_parser_is_released_without_cyclic_gc", "test_seeded_datagram_mutations_and_random_noise_never_crash"],
    "test_ikev2": ["test_real_coap_and_dhcp_ambiguities_are_unknown", "test_aggregate_work_and_byte_budgets", "test_seeded_mutations_and_parser_call_ceiling"],
    "test_fingerprints": ["test_ssh_continuation_never_downgrades_identification", "test_ssh_identification_then_hassh_refinement",
                          "test_client_hello_fingerprints_only_when_enabled", "test_ja4_matches_independent_computation_and_grease_rules"],
    "test_quic": ["test_protection_failures_are_reported_not_guessed", "test_frames_allowed_in_initial", "test_cross_datagram_assembly_requires_an_assembler",
                  "test_rfc9001_client_initial_opens_to_the_published_client_hello", "test_mutations_and_noise_stay_within_documented_statuses_and_time"],
    "test_decoders_v027": ["test_shared_lines_report_candidates_as_context_not_identity", "test_truncations_and_mutations_never_raise_and_stay_bounded",
                           "test_identified_observations_carry_structural_evidence_only", "test_kerberos_asn1_framing_on_tcp_and_udp", "test_flow_export_framing"],
    "test_shift": ["test_failed_or_missing_shifted_phase_keeps_the_carrier", "test_budgets_cover_both_phases", "test_all_split_points_and_fragments_agree",
                   "test_connect_requires_authority_form_and_marks_http_proxy", "test_websocket_upgrade_rules_and_frame_profile",
                   "test_smtp_watches_for_starttls_within_bounds", "test_database_and_rdp_negotiations"],
    "test_risks": ["test_unknown_stream_is_profiled_only_when_enabled_and_bounded", "test_datagrams_and_dns_name_shape", "test_identified_streams_are_never_profiled"],
    "test_s7comm": ["test_connection_request_and_confirm_shift_to_s7", "test_s7_profile_rejections_keep_the_carrier", "test_tpkt_route_distinguishes_rdp_and_cotp_confirms"],
    "test_snmpv3": ["test_discovery_and_encrypted_messages_identify_without_secrets", "test_rejections"],
    "test_certificates": ["test_evidence_only_when_enabled_and_no_names", "test_rejections_keep_the_identification", "test_tls13_retry_and_client_hello_never_continue"],
    "test_enterprise_db": ["test_tds_rejections", "test_tns_rejections", "test_mutations_never_raise_and_never_leak", "test_dispatch_neighbours_are_unchanged"],
    "test_opcua_socks": ["test_opcua_rejections_and_text_neighbours", "test_socks5_server_rejections_and_dcerpc_neighbour", "test_mutations_never_raise_or_leak"],
    "test_ech": ["test_outer_ech_is_reported_and_the_public_name_kept", "test_malformed_ech_makes_the_hello_malformed", "test_quic_initial_reports_ech"],
    "test_responses": ["test_snmp_pdu_kinds_and_values_never_emitted", "test_snmp_rejections", "test_dns_message_kind_rcode_and_risk", "test_mutations_never_raise_or_leak"],
    "test_server_replies": ["test_smb2_negotiate_response", "test_kerberos_replies_and_errors", "test_dcerpc_bind_ack_and_nak", "test_mutations_never_raise_or_leak"],
    "test_db_replies": ["test_postgresql_server_messages", "test_ldap_bind_response", "test_cql_responses", "test_mysql_handshake_response", "test_mutations_never_raise_or_leak"],
    "test_udp_replies": ["test_dtls_server_flight", "test_radius_responses_require_the_hint_and_match_their_code", "test_openvpn_server_reset", "test_ikev2_responder",
                         "test_mutations_never_raise_or_leak"],
    "test_tcp_replies": ["test_modbus_responses_and_exceptions", "test_giop_replies", "test_tacacs_reply", "test_smb1_negotiate_response", "test_amqp_connection_start",
                         "test_mutations_never_raise_or_leak"],
    "test_more_replies": ["test_tftp_server_packets", "test_l2tp_and_pptp_replies", "test_memcached_responses_and_netbios_neighbour", "test_git_server_lines",
                          "test_fastcgi_application_records", "test_mutations_never_raise_or_leak"],
    "test_http2_headers": None,
    "test_onc_rpc": None, "test_diameter": None, "test_greetings": None, "test_content_classes": None, "test_xmpp_syslog": None,
    "test_desktop_storage": None, "test_v054": None, "test_v055": None, "test_v056": None, "test_v057": None, "test_v058": None,
    "test_v059": None, "test_v060": None, "test_v061": None, "test_v062": None, "test_v063": None, "test_v064": None, "test_v066": None,
    "test_continuation": None,
}
MAX_CHUNKINGS = 3  # distinct splits kept per input; the full split sweeps are the Go split-invariance tests' job
MAX_PER_TEST = 2000  # the first inputs of a seeded mutation loop, in the loop's order; the Go fuzz tests go further


class Recorder:
    def __init__(self, engine, cases_module):
        self.engine, self.cases = engine, cases_module
        self.current, self.calls, self.skipped = None, [], {}

    def skip(self, why):
        self.skipped[why] = self.skipped.get(why, 0) + 1

    def install(self):
        recorder, engine = self, self.engine
        base_stream, base_datagram = engine.Inspector, engine.DatagramInspector

        class Stream(base_stream):
            def __init__(self, config=None, rules=None, source="wire", protocol_hint=None, signatures=None):
                super().__init__(config, rules, source, protocol_hint, signatures)
                self._record = {"label": recorder.current, "kind": "stream", "hint": protocol_hint, "chunks": [], "end": None,
                                "config": recorder.config(self.config), "ok": source == "wire" and rules is None and not signatures}
                recorder.calls.append(self._record)

            def feed(self, data):
                self._record["chunks"].append(bytes(data).hex())
                return super().feed(data)

            def end(self, *args, **kwargs):
                if self._record["end"] is not None:
                    self._record["ok"] = False
                self._record["end"] = args[0] if args else kwargs.get("reason", "EOF before identification completed")
                return super().end(*args, **kwargs)

            def invalidate(self, reason):
                self._record["ok"] = False
                return super().invalidate(reason)

            def feed_decrypted(self, data):
                self._record["ok"] = False
                return super().feed_decrypted(data)

        class Datagram(base_datagram):
            def __init__(self, config=None, signatures=None, quic_assembler=None):
                super().__init__(config, signatures, quic_assembler)
                self._plain = not signatures and quic_assembler is None

            def inspect(self, data, protocol_hint=None, scope=None, now=None):
                recorder.calls.append({"label": recorder.current, "kind": "datagram", "hint": protocol_hint, "payload": bytes(data).hex(),
                                       "config": recorder.config(self.config), "ok": self._plain and scope is None and now is None})
                return super().inspect(data, protocol_hint, scope, now)

        for module in (engine, sys.modules["protocol_engine.engine"]):
            module.Inspector = Stream
        for module in (engine, sys.modules["protocol_engine.datagram"]):
            module.DatagramInspector = Datagram
        self.base = base_stream, base_datagram

    def config(self, config):
        data = self.cases.config_dict(config)
        return data if self.cases.config_from(data) == config else None

    def run(self, module_name, functions):
        module = importlib.import_module(module_name)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(module)
        recorder = self

        class Result(unittest.TestResult):
            def startTest(self, test):
                name = test.id().rsplit(".", 1)[-1]
                recorder.current = "{}::{}".format(module_name, name)
                super().startTest(test)

        def flatten(s):
            for item in s:
                if isinstance(item, unittest.TestSuite):
                    yield from flatten(item)
                else:
                    yield item
        selected = [t for t in flatten(suite) if functions is None or t.id().rsplit(".", 1)[-1] in functions]
        found = {t.id().rsplit(".", 1)[-1] for t in selected}
        missing = sorted(set(functions or ()) - found)
        result = Result()
        unittest.TestSuite(selected).run(result)
        problems = [str(t) for t, _ in result.errors + result.failures]
        return missing, problems


def build(reference):
    sys.path.insert(0, str(reference))
    sys.path.insert(0, str(reference / "migration" / "parity"))
    import protocol_engine
    cases_module = importlib.import_module("cases")
    recorder = Recorder(protocol_engine, cases_module)
    recorder.install()
    report = {}
    for module, functions in REFERENCES.items():
        missing, problems = recorder.run(module, functions)
        if missing or problems:
            raise SystemExit("{}: missing tests {} / failing {}".format(module, missing, problems[:3]))
        report[module] = len(functions) if functions else "all"
    # Replay each recorded input alone on the reference classes and keep the answers.
    protocol_engine.engine.Inspector, protocol_engine.datagram.DatagramInspector = recorder.base
    cases_module.Inspector, cases_module.DatagramInspector = recorder.base
    parsers = cases_module.PARSERS
    out, seen, chunkings, per_test = [], set(), {}, {}
    for call in recorder.calls:
        if not call["ok"] or call["config"] is None:
            recorder.skip("not expressible")
            continue
        if call["kind"] == "stream" and not call["chunks"]:
            recorder.skip("no bytes fed")
            continue
        if call["hint"] is not None and (call["kind"] == "stream" and call["hint"] not in parsers):
            recorder.skip("hint outside the parser registry")
            continue
        if per_test.get(call["label"], 0) >= MAX_PER_TEST:
            recorder.skip("beyond the per-test cap")
            continue
        case = {"kind": call["kind"], "label": call["label"], "hint": call["hint"], "config": call["config"]}
        if call["kind"] == "stream":
            case.update(chunks=call["chunks"], end=call["end"])
            whole = (call["label"], call["hint"], json.dumps(call["config"], sort_keys=True), "".join(call["chunks"]), call["end"])
            key = whole + (tuple(call["chunks"]),)
            if key in seen:
                continue
            if chunkings.get(whole, 0) >= MAX_CHUNKINGS:
                recorder.skip("further chunkings of one input")
                continue
            chunkings[whole] = chunkings.get(whole, 0) + 1
        else:
            case.update(payload=call["payload"])
            key = (call["label"], call["hint"], json.dumps(call["config"], sort_keys=True), call["payload"])
            if key in seen:
                continue
        seen.add(key)
        try:
            case["expected"] = cases_module.run_case(case)
        except Exception as error:  # the original call raised too: not a case
            recorder.skip("raised " + type(error).__name__)
            continue
        per_test[call["label"]] = per_test.get(call["label"], 0) + 1
        out.append(case)
    counters = {}
    for case in out:
        counters[case["label"]] = counters.get(case["label"], 0) + 1
        case["id"] = "{}/{}/{}".format(case["kind"], case["label"], counters[case["label"]])
    return out, recorder.skipped, report


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", required=True, type=Path, help="an extract of the python-final tag")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[1] / "fixtures" / "requirements.json.gz")
    args = parser.parse_args(argv)
    cases, skipped, report = build(args.reference.resolve())
    document = {"schema": 1, "reference": "python-final", "generator": "migration/parity/requirement_cases.py",
                "canonicalization": "as migration/fixtures/cases.json", "cases": cases}
    data = (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    with gzip.GzipFile(args.out, "wb", compresslevel=9, mtime=0) as handle:  # mtime 0: the same input writes the same bytes
        handle.write(data)
    labels = sorted({c["label"] for c in cases})
    print("requirement cases: {} cases from {} test functions in {} modules; skipped {}".format(len(cases), len(labels), len(report), skipped))
    return 0


if __name__ == "__main__":
    sys.exit(main())

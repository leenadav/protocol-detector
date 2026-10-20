# Security requirements

Each requirement names the test(s) that verify it. `tools/check_security_requirements.py`
fails CI when a referenced module or test no longer exists. Format of the last
column: `test_module::test_function[, ...]`.

| ID | Requirement | Verified by |
|---|---|---|
| SR-1 | Byte, update, line and header budgets terminate inspection with `budget_exhausted`, never with an exception or unbounded allocation | `test_engine::test_budgets_are_not_protocol_mismatch, test_engine::test_line_header_and_tls_bounds, test_gateway::test_fastcgi_header_budget_preflight_and_exact_byte_boundary` |
| SR-2 | A candidate hint restricts validation and never produces an identification by itself | `test_expansion::test_candidate_hints_are_not_classification, test_gateway::test_hint_is_not_proof_and_no_confusion_with_existing_protocols` |
| SR-3 | Input valid under two supported profiles is reported unknown; a competing budget failure blocks identification | `test_expansion::test_ambiguous_dns_coap_is_not_arbitrarily_identified, test_ikev2::test_real_coap_and_dhcp_ambiguities_are_unknown` |
| SR-4 | Conflicting overlapping TCP bytes invalidate the classification atomically before any new byte is admitted | `test_reassembly::test_conflicts_are_atomic_even_after_new_bytes_and_before_gap_fill, test_reassembly::test_late_conflict_invalidates_real_identification` |
| SR-5 | Rejected TCP control state publishes a directional retraction visible to event consumers | `test_control_retractions::test_analyzer_rejects_with_directional_event_and_releases_state` |
| SR-6 | Advertised frame sizes and element counts are checked before buffers grow | `test_expansion::test_memcached_command_shapes_and_limits, test_expansion::test_postgresql_startup_and_negotiation_are_distinct, test_ikev2::test_aggregate_work_and_byte_budgets` |
| SR-7 | Capture truncation or reported drops retract active observations and never fabricate a clean EOF | `test_live::test_truncation_discards_active_state_and_reports_gap, test_lifecycle::test_capture_gap_retracts_instead_of_fabricating_eof, test_live::test_pipe_eof_and_process_cleanup_and_loss_exit_code` |
| SR-8 | Observations and reasons never contain credentials, payload values or secrets | `test_expansion::test_ldap_bind_ber_and_no_credentials_in_observation, test_expansion::test_mqtt5_connect_and_will_properties, test_gateway::test_fastcgi_all_roles_ids_flags_and_arbitrary_padding` |
| SR-9 | Live output and session records omit hostnames unless explicitly enabled | `test_live::test_monitor_complete_pipeline_no_payload_output, test_appid::test_hostnames_are_opt_in, test_appid::test_live_monitor_emits_sessions_apps_and_summary` |
| SR-10 | PCAP framing with invalid lengths, snapshot sizes or timestamps fails closed and bounds buffered input | `test_live::test_pcap_malformed_length_eof_closed_and_buffer_bound, test_live::test_pcap_bytewise_multiple_records_and_truncation_metadata` |
| SR-11 | IPv6, fragments and unsupported link types are rejected on every supported wrapper | `test_live::test_ipv6_is_rejected_on_every_supported_link_wrapper, test_live::test_packet_fuzz_no_unhandled_exceptions` |
| SR-12 | Operator-supplied interface names and BPF filters never reach a shell | `test_live::test_command_arguments_are_not_shell_code` |
| SR-13 | Plaintext refinement requires a previously identified TLS envelope and keeps provenance | `test_engine::test_no_plaintext_api_without_tls, test_engine::test_decrypted_refinement_retains_tls` |
| SR-14 | Terminal inspection releases parser buffers without relying on cyclic garbage collection | `test_expansion::test_completed_text_parser_is_released_without_cyclic_gc, test_gateway::test_terminal_state_releases_buffers_without_cyclic_gc, test_lifecycle::test_monitor_has_no_owner_callback_reference_cycle` |
| SR-15 | Session verdicts never upgrade evidence: outcomes follow engine status precedence and configured mappings keep their carrier | `test_appid::test_session_merge_prefers_identification_and_records_disagreement, test_appid::test_configured_mapping_becomes_custom_application_over_its_container, test_appid::test_outcomes_for_unknown_malformed_budget_incomplete_invalidated` |
| SR-16 | Random and mutated inputs never raise, select more than one candidate or inspect more bytes than supplied | `test_engine::test_seeded_random_data_and_mutations_are_bounded, test_expansion::test_seeded_datagram_mutations_and_random_noise_never_crash, test_ikev2::test_seeded_mutations_and_parser_call_ceiling` |
| SR-17 | Reassembly memory is bounded by the configured window and released on expiry | `test_reassembly::test_large_operations_have_window_bounded_temporary_memory, test_live::test_reassembly_memory_bound_and_release` |
| SR-18 | Custom signature patterns are rejected unless they carry a literal anchor and avoid nested quantifiers, backreferences, lookaround and large repeat counts; evaluation is prefiltered and bounded | `test_signatures::test_anchor_requirements_and_unsafe_constructs, test_signatures::test_signature_evaluation_is_bounded_and_prefiltered` |
| SR-19 | Parser contexts are retained only when configured and never appear in observations, events or adapter output | `test_signatures::test_contexts_are_only_retained_when_configured, test_signatures::test_analyzer_and_cli_accept_signature_files, test_signatures::test_header_block_is_bounded` |
| SR-20 | Candidate hints never open unknown-payload signature evaluation | `test_signatures::test_unknown_payload_signatures_stream, test_signatures::test_unknown_payload_signatures_datagram` |

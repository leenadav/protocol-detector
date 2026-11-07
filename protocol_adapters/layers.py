"""Layered App-ID view (stage 5: A05, A13).

One session carries several layers of knowledge: the transport, the outer protocol seen on the wire, the
encryption envelope, the inner protocol seen in authenticated plaintext, and the application named from
them. Before this module, the decryption adapter rewrote observations with replace() to squeeze an inner
verdict out of session_verdict, and the frontend merged decryption rows and classifications on its own.

layered_view() is the one reducer: it splits each direction's observation into its wire part and its
decrypted part (by evidence provenance, never by erasing it), asks session_verdict for each layer, and
derives an effective verdict plus an explicit identity basis:

    authenticated_plaintext  the application was identified in plaintext authenticated with supplied secrets
                             (record authentication, not peer or product identity verification)
    structural               identified from the structural profile of the wire protocol
    configured_rule          named by a configured mapping or custom signature (operator intent)
    client_assertion         named by a client-asserted server name (SNI, Host) through the built-in catalog
    none                     no identification

Offered ALPN, asserted names and derived fingerprints are listed as claims (field, source, strength), never
as identity and never with their values. Nothing here reads payload; the view carries labels only.
"""
from dataclasses import replace

from protocol_engine.appid import _HOST_REASON, session_verdict, verdict_fields

VERSION = 1
BASES = ("authenticated_plaintext", "structural", "configured_rule", "client_assertion", "none")
CLAIM_STRENGTHS = ("asserted", "offered", "derived")
DECRYPTION_NOTE = "Plaintext was authenticated with supplied secrets (record AEAD); this is not peer identity or product verification."


def split_observation(observation):
    """(outer, inner) views of one direction: wire evidence vs decrypted evidence; inner is None without any."""
    if observation is None:
        return None, None
    inner_evidence = tuple(e for e in observation.evidence if e.source.startswith("decrypted"))
    if not inner_evidence:
        return observation, None
    outer_evidence = tuple(e for e in observation.evidence if not e.source.startswith("decrypted"))
    inner_host = any(e.field == "hostname" for e in inner_evidence)
    outer_host = next((e.value for e in outer_evidence if e.field == "hostname"), None)
    inner = replace(observation, encryption=None, offered_alpn=(), evidence=inner_evidence,
                    hostname=observation.hostname if inner_host else None,
                    application=observation.application if any(e.field == "application" for e in inner_evidence) else None)
    outer = replace(observation, application_protocol=None, evidence=outer_evidence, hostname=outer_host,
                    application=observation.application if any(e.field == "application" for e in outer_evidence) else None,
                    reason="TLS envelope (plaintext classified separately)")
    return outer, inner


def identity_basis(verdict, inner_identified, observations):
    if inner_identified:
        return "authenticated_plaintext"
    if verdict is None or not verdict.identified:
        return "none"
    if _HOST_REASON in verdict.reasons:
        return "client_assertion"           # built-in server-name catalog: a client-asserted name, never authenticated
    if verdict.base_app is not None or any(e.strength in ("configured_mapping", "configured_signature")
                                           for obs in observations if obs is not None for e in obs.evidence):
        return "configured_rule"
    return "structural"


def claims(observations):
    seen, out = set(), []
    for obs in observations:
        if obs is None:
            continue
        for e in obs.evidence:
            if e.strength in CLAIM_STRENGTHS and (e.field, e.source, e.strength) not in seen:
                seen.add((e.field, e.source, e.strength))
                out.append({"field": e.field, "source": e.source, "strength": e.strength})
    return out


def _protocol(verdict):
    return verdict.client_protocol or verdict.server_protocol if verdict is not None else None


def layered_view(transport, client, server, verdict=None, server_port=None, client_bytes=None, server_bytes=None,
                 decryption=None, capture_quality="intact", handshake_complete=True, signatures=None, at=None):
    """The layered view of one session from its two directional observations (merged or wire-only).

    `verdict` is the session verdict already computed for the wire layer when the caller has one (the
    Analyzer); otherwise it is computed here. `decryption` is the decoder's metadata dict (state,
    reason_code, authenticated_records, version, cipher_suite) when a decoder ran on this session.
    """
    outer_client, inner_client = split_observation(client)
    outer_server, inner_server = split_observation(server)
    if verdict is None or inner_client is not None or inner_server is not None:
        outer = session_verdict(outer_client, outer_server, transport, server_port, client_bytes, server_bytes,
                                handshake_complete=handshake_complete, signatures=signatures, at=at)
    else:
        outer = verdict
    inner = None
    if inner_client is not None or inner_server is not None:
        inner = session_verdict(inner_client, inner_server, transport, server_port, client_bytes, server_bytes,
                                handshake_complete=True, signatures=signatures, at=at)
    decryption_ok = decryption is None or decryption.get("state") in ("decrypting", "complete")
    inner_identified = inner is not None and inner.identified and decryption_ok
    effective = inner if inner_identified else outer
    encryption = next((obs.encryption for obs in (outer_client, outer_server) if obs is not None and obs.encryption), None)
    outer_protocol = _protocol(outer)
    inner_protocol = _protocol(inner) if inner_identified else None
    chain = []
    for label in (encryption, outer_protocol if outer_protocol != encryption else None, inner_protocol, effective.app if effective.identified else None):
        if label and label not in chain:
            chain.append(label)
    view = {
        "version": VERSION,
        "transport": transport,
        "outer": {"protocol": outer_protocol or encryption, "app": outer.app, "status": outer.status},
        "encryption": None if encryption is None else {
            "protocol": encryption,
            "offered_alpn": sorted({alpn for obs in (outer_client, outer_server) if obs is not None for alpn in obs.offered_alpn}),
            "server_name_asserted": any(e.field == "hostname" for obs in (outer_client, outer_server) if obs is not None for e in obs.evidence),
            "version": decryption.get("version") if decryption else None,
        },
        "inner": None if inner is None else {"protocol": _protocol(inner), "app": inner.app, "status": inner.status,
                                             "source": "decrypted", "authenticated": bool(decryption_ok)},
        "application": {"name": effective.app, "category": effective.category, "status": effective.status,
                        "basis": identity_basis(effective, inner_identified, (outer_client, outer_server)),
                        # D03: affiliation, family and activity stay separate fields; none of them is identity.
                        "provider": effective.attribution["provider"] if effective.attribution else None,
                        "affiliation": effective.attribution["kind"] if effective.attribution else None,
                        "activity": effective.attribution["activity"] if effective.attribution else None},
        "decryption": None if decryption is None else {key: decryption.get(key) for key in ("state", "reason_code", "authenticated_records")},
        "capture_quality": capture_quality,
        "chain": chain,
        "claims": claims((outer_client, outer_server)),
    }
    if decryption is not None:
        view["note"] = DECRYPTION_NOTE
    return view, effective


def effective_fields(view_effective):
    """verdict_fields() for the effective verdict a layered view chose (same keys as a session record)."""
    return verdict_fields(view_effective)

"""D12: structured reasons for everything that is not an identification.

A non-identified outcome used to be a status and a free-text reason. `explain()` adds a closed code
and the stage that produced it, derived from the observation (and the inspector's selected
candidate when the caller has it), without changing the observation itself:

| code                 | stage      | meaning                                                                 |
|----------------------|------------|-------------------------------------------------------------------------|
| no-dispatch          | dispatch   | the prefix routed to no supported family                                 |
| ambiguous            | dispatch   | structurally valid for several families; candidates listed              |
| profile-unsupported  | profile    | a family was selected, the message is outside its documented profile    |
| malformed            | profile    | a family was selected and the bytes violate its structure                |
| budget               | budget     | a byte, line, header, count or depth budget ended inspection            |
| no-payload           | lifecycle  | the direction carried no bytes before tracking ended                     |
| incomplete           | lifecycle  | bytes arrived but the initial message did not complete before the end   |
| no-handshake         | lifecycle  | no TCP handshake was observed for the connection                         |
| midstream            | lifecycle  | the connection was observed midstream (D05), start unobserved            |
| invalidated          | integrity  | reassembly or assembly contradiction withdrew the observation            |

`family` names the candidate whose parser spoke (None when dispatch never selected one), `detail`
keeps the engine's sentence. Codes are a reporting vocabulary: they never influence a verdict.
"""
from types import MappingProxyType

CODES = ("no-dispatch", "ambiguous", "profile-unsupported", "malformed", "budget", "no-payload", "incomplete",
         "no-handshake", "midstream", "invalidated")
STAGES = MappingProxyType({"no-dispatch": "dispatch", "ambiguous": "dispatch", "profile-unsupported": "profile", "malformed": "profile",
                           "budget": "budget", "no-payload": "lifecycle", "incomplete": "lifecycle", "no-handshake": "lifecycle",
                           "midstream": "lifecycle", "invalidated": "integrity"})
_NO_DISPATCH = ("Prefix outside supported protocol families", "No supported datagram structure selected")


def _code(observation, candidate, bytes_received):
    status = observation.status
    reason = observation.reason or ""
    if status == "invalidated":
        return "invalidated"
    if status == "budget_exhausted":
        return "budget"
    if status == "malformed":
        return "malformed"
    if status == "unknown":
        if any(item.field == "ambiguous_candidates" for item in observation.evidence) or reason.startswith("Ambiguous"):
            return "ambiguous"
        if reason in _NO_DISPATCH:
            return "no-dispatch"
        return "profile-unsupported"
    # detecting / incomplete: the stream ended (or has not ended) before a profile completed
    if bytes_received == 0:
        return "no-payload"
    return "incomplete"


def explain(observation, candidate=None, inspector=None):
    """Structured reason for a non-identified observation; None for an identification."""
    if observation is None:
        return None
    if observation.status == "identified":
        return None
    if inspector is not None:
        candidate = inspector.resolved_family if candidate is None else candidate
        bytes_received = inspector.metrics.bytes_received
    else:
        bytes_received = None if observation.status == "detecting" and observation.reason == "Waiting for stream prefix" else 1
        if bytes_received is None:
            bytes_received = 0
    code = _code(observation, candidate, bytes_received)
    out = {"code": code, "stage": STAGES[code], "family": None, "detail": observation.reason}
    if code in ("profile-unsupported", "malformed", "budget") and candidate not in (None, "unknown", "text", "git_text", "tpkt"):
        out["family"] = candidate
    if code == "ambiguous":
        for item in observation.evidence:
            if item.field == "ambiguous_candidates":
                out["candidates"] = item.value.split(",")
    hint = [item.value for item in observation.evidence if item.field == "candidate_hint"]
    if hint and out["family"] is None and code in ("profile-unsupported", "malformed", "budget"):
        out["family"] = hint[0]
    return out


def session_unknown(verdict, client, server, client_inspector=None, server_inspector=None, mode="handshake", handshake=True):
    """Per-direction structured reasons for a session record whose verdict is not an identification."""
    if verdict.status in ("identified", "correlated"):
        return None
    out = {}
    if not handshake and mode == "handshake":
        out["session"] = {"code": "no-handshake", "stage": "lifecycle", "family": None, "detail": verdict.reasons[0] if verdict.reasons else None}
    elif mode == "midstream" and verdict.status == "midstream":
        out["session"] = {"code": "midstream", "stage": "lifecycle", "family": None, "detail": verdict.reasons[0] if verdict.reasons else None}
    for name, observation, inspector in (("client", client, client_inspector), ("server", server, server_inspector)):
        item = explain(observation, inspector=inspector) if observation is not None else None
        if item is not None:
            out[name] = item
    return out or None

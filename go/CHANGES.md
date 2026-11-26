# Changes to the Go module

Release notes for `github.com/leenadav/protocol-detector/go`, per `docs/governance/VERSIONING.md`. No version
has been tagged yet; these notes become the first tag's.

## Unreleased

### Breaking

- `detector.DefaultConfig()` now admits SMTP as well as HTTP/1, TLS and SSH: the first visibility profile
  (working plan decision 4, approved 2026-11-18). An SMTP stream that was `outside_profile` under the default is
  now `identified`. A host that sets `Config.Families` itself is unaffected.

### Added

- `detector.Stats.RefusedFlowLimit` counts the `NewFlow` refusals caused by `Config.MaxFlows` (included in
  `Refused`, beside `RefusedMemory`): flows the host relays uninspected because the table was full. It is this
  API's form of the offline `analyze` counters `udp_flow_limit` and `tcp_connection_limit` (PRO-448).

# PRO-119 held patch: a closing alert ends its sender's direction

`close-alert-ends-direction.patch` (on top of `c01942f`) is the fix for the second A2 run's SEC-DEC-1 (PRO-47, 21:16):
after an authenticated close_notify or fatal alert, the Go decryptor keeps decoding that sender's records
(`go/internal/decrypt/connection.go`, the TLS 1.3 and TLS 1.2 alert paths). With the patch the direction is marked
closed and its later records are dropped unread (TLS 1.3: every alert except user_canceled; TLS 1.2: close_notify
or a fatal level), with `TestRecordsAfterAClosingAlertAreNotDecoded`.

It is held because it moves the parity target. The Python reference (`presentation/poc_decryption/engine.py`)
decodes records after an alert, and the random decrypt differential reaches the difference: `decrypt_diff.py`
seed 2 (2,000 captures), case 236, a mutated capture with a record after the client's close_notify. Python
fails it (`authentication_failed`, 14 records authenticated); with the patch Go ignores the client's later
records and reports the connection `decrypted` (17 records, 404 plaintext bytes, application webdav).

To land it Lee approves the Go-only divergence, as for SEC-QUIC-3 (PRO-124). Then: `git apply` the patch, add an
approved-divergence class to `migration/parity/decrypt_diff.py` (and `live_decrypt_diff.py` if it reaches it)
limited to captures where a record follows an authenticated closing alert in the same direction, with self-test
rejections, and record the divergence in `migration/STATUS.md`.

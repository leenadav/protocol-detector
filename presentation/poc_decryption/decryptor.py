"""Decryptor: the one consumer of the coordinator's retained reassembly tier (stage 4: A02, A03, A07, A09).

It owns no flow table and decodes no packets. The SessionCoordinator reassembles each TCP direction once
(protocol_adapters.sessions.Stream) and hands out StreamDeltas through drain(); this class feeds them to one
TlsConnection per connection, releases authenticated plaintext into the engine's Inspectors, and keeps a
cached row per connection. report() only assembles those rows: a status read performs no parsing and no
cryptography (A02). work(quantum) is the only place records are authenticated, in bounded round-robin
slices so one connection cannot monopolize the capture loop (A07).
"""
from dataclasses import asdict, replace

from protocol_engine import Inspector
from protocol_engine.appid import session_verdict

from . import DecryptionError, KeyProvider
from .engine import TlsConnection

SAFE_EVIDENCE = {'application_protocol', 'encryption', 'http_method', 'http_status', 'http_content_type',
                 'http_content_type_class', 'grpc', 'webdav', 'rpc_method'}
NOTE = 'Record AEAD verified with supplied secrets; peer identity and certificate trust are not validated.'
PROFILE = 'TLS 1.2 ECDHE-RSA AES-GCM / TLS 1.3 AEAD key-log POC; no CBC, QUIC, 0-RTT, HRR or renegotiation.'


class _Connection:
    def __init__(self, key, client, server, sid, generation, keys):
        self.key, self.client, self.server = key, client, server
        self.sid, self.generation = sid, generation
        self.tls = TlsConnection(keys, client, server)
        self.outer = {client: Inspector(), server: Inspector()}
        self.inner = {}                 # endpoint -> Inspector(source='decrypted') when the outer envelope was not TLS
        self.looks_tls = False
        self.error = None
        self.closed = False
        self.row = None
        self.dirty = True

    # ----- bytes ------------------------------------------------------------------
    def raw(self, endpoint, data):
        if self.closed:
            return                                    # bytes after both FINs: the owner validates overlaps
        self.outer[endpoint].feed(data)
        if data and not self.looks_tls and data[:1] == b'\x16':
            self.looks_tls = True
        self.tls.feed(endpoint, data)
        self.dirty = True

    def plaintext(self, delta):
        inspector = self.outer[delta.endpoint]
        if delta.endpoint not in self.inner:
            if inspector.observation.encryption == 'tls' and inspector.observation.status != 'invalidated':
                self.inner[delta.endpoint] = inspector            # merged view through feed_decrypted
            else:
                # Decryption validated this envelope even if its hello is outside the passive detector's
                # narrower profile: classify the plaintext with a decrypted-source inspector.
                self.inner[delta.endpoint] = Inspector(source='decrypted')
        target = self.inner[delta.endpoint]
        if target is inspector:
            target.feed_decrypted(delta.data)
        else:
            target.feed(delta.data)
        self.dirty = True

    def observation(self, endpoint):
        target = self.inner.get(endpoint)
        if target is None:
            return None
        observation = target.observation
        if target is not self.outer[endpoint]:
            observation = replace(observation, encryption='tls')
        return observation

    # ----- the cached row --------------------------------------------------------------
    def build(self):
        self.dirty = False
        row = {'client': list(self.client), 'server': list(self.server), 'session_id': self.sid, 'generation': self.generation}
        if self.error is not None:
            row.update(status='unavailable', reason=self.error, reason_code='gap' if 'missing' in self.error or 'Conflicting' in self.error else 'unsupported_profile')
            self.row = row
            return row
        row['outer_protocol'] = 'tls'
        tls = self.tls
        if tls.state == 'failed':
            row.update(tls.metadata(), status='unavailable', reason=tls.reason, reason_code=tls.reason_code)
            self.row = row
            return row
        row.update(tls.metadata())
        if tls.state == 'complete':
            row['status'] = 'decrypted'
        elif tls.state == 'decrypting':
            row['status'] = 'decrypting'
            row['reason_code'] = 'awaiting_bytes'
        else:
            row['status'] = tls.state
            row['reason_code'] = tls.state
        if self.inner:
            observations = [self.observation(e) for e in (self.client, self.server)]
            stripped = [replace(o, encryption=None, application=None,
                                evidence=tuple(e for e in o.evidence if e.source.startswith('decrypted')))
                        if o is not None else None for o in observations]
            if all(o is not None for o in stripped):
                verdict = session_verdict(stripped[0], stripped[1], 'tcp', self.server[1],
                                          tls.plaintext[self.client], tls.plaintext[self.server])
            else:
                present = next(o for o in stripped if o is not None)
                other = replace(present, status='unknown', application_protocol=None, evidence=())
                pair = (present, other) if stripped[0] is not None else (other, present)
                verdict = session_verdict(pair[0], pair[1], 'tcp', self.server[1],
                                          tls.plaintext[self.client], tls.plaintext[self.server])
            # No raw payload, key material, hostname, URL or credentials leave this adapter.
            evidence = []
            for endpoint in (self.client, self.server):
                target = self.inner.get(endpoint)
                if target is not None:
                    evidence.extend(asdict(e) for e in target.observation.evidence if e.field in SAFE_EVIDENCE)
            row.update(application=verdict.app, inner_protocol=verdict.client_protocol or verdict.server_protocol,
                       category=verdict.category, app_status=verdict.status, reasons=list(verdict.reasons),
                       evidence=evidence, note=NOTE)
        self.row = row
        return row


class Decryptor:
    def __init__(self, coordinator, keys=None):
        self.coordinator = coordinator
        self.keys = keys if keys is not None else KeyProvider()
        self.connections = {}
        self.finished = []            # closed connections' rows, in close order
        self.counts = {'opened': 0, 'closed': 0, 'records_authenticated': 0, 'plaintext_bytes': 0,
                       'work_calls': 0, 'report_calls': 0, 'retracted': 0}
        self._report = None

    # ----- the coordinator's events -------------------------------------------------
    def pump(self):
        """Consume every queued coordinator event; cheap, no cryptography."""
        for item in self.coordinator.drain():
            kind, key = item[0], item[1]
            if kind == 'open':
                _, _, client, server, sid, generation = item
                self.connections[key] = _Connection(key, client, server, sid, generation, self.keys)
                self.counts['opened'] += 1
            elif kind == 'data':
                connection = self.connections.get(key)
                if connection is not None and connection.error is None:
                    connection.raw(item[2], item[3].data)
            elif kind == 'error':
                connection = self.connections.get(key)
                if connection is not None and connection.error is None:
                    # A conflicting overlap or an exhausted budget retracts the plaintext view, even after the
                    # FIN event settled the row: nothing authenticated survives a contradicted reassembly.
                    connection.error = item[2]
                    connection.inner.clear()
                    connection.dirty = True
                    self.counts['retracted'] += 1
            elif kind == 'fin':
                connection = self.connections.get(key)
                if connection is not None and not connection.closed:
                    self._finalize(connection, item[2], final=False)
            elif kind == 'close':
                connection = self.connections.pop(key, None)
                if connection is not None:
                    self._finalize(connection, item[3], final=True)
                    self.counts['closed'] += 1
                    self.finished.append(connection)
                    if len(self.finished) > 4096:
                        self.finished.pop(0)
        self._report = None

    def _finalize(self, connection, progress, final):
        """Both directions ended (fin) or the owner released the connection (close): settle the row.

        A connection that ended while still waiting for its secrets is not failed at the FIN: late key-log
        lines may still arrive while the owner retains it (bounded by its idle timeout and the aggregate
        budget); the close event is the deadline.
        """
        if connection.error is None and not connection.closed:
            if len(progress) < 2:
                connection.error = 'Both TCP directions and SYNs are required.'
            else:
                for endpoint, state in progress.items():
                    if state['stored'] != state['contiguous']:
                        connection.error = 'TCP capture has missing bytes.'
                        break
                    if state['fin'] is not None and state['fin'] != state['contiguous']:
                        connection.error = 'TCP bytes are missing before FIN.'
                        break
        connection.closed = True
        if connection.error is None:
            self._work_one(connection, None)
            if final or connection.tls.state != 'awaiting_keys':
                connection.tls.finish()
        connection.dirty = True

    # ----- bounded work -------------------------------------------------------------
    def _work_one(self, connection, quantum):
        before = connection.tls.records_authenticated
        deltas = connection.tls.advance(quantum if quantum is not None else 1 << 20)
        for delta in deltas:
            connection.plaintext(delta)
            self.counts['plaintext_bytes'] += len(delta.data)
        self.counts['records_authenticated'] += connection.tls.records_authenticated - before
        return bool(deltas) or connection.tls.records_authenticated != before

    def work(self, quantum=64, rounds=16):
        """Authenticate at most quantum records per connection per round, round-robin, for at most `rounds`."""
        self.counts['work_calls'] += 1
        did = False
        for _ in range(rounds):
            progressed = False
            for connection in list(self.connections.values()):
                if connection.error is None and connection.tls.has_work():
                    progressed |= self._work_one(connection, quantum)
                    if connection.closed and not connection.tls.has_work() and connection.tls.state not in ('awaiting_keys',):
                        connection.tls.finish()          # ended earlier while waiting for keys; the keys came
            did |= progressed
            if not progressed:
                break
        if did:
            self._report = None
        return did

    def pending(self):
        return sum(1 for c in self.connections.values() if c.error is None and c.tls.has_work())

    def awaiting_keys(self):
        return sum(1 for c in self.connections.values() if c.tls.state == 'awaiting_keys')

    # ----- status (no parsing, no cryptography) -----------------------------------------------
    def rows(self):
        out = []
        for connection in self.finished + list(self.connections.values()):
            if connection.dirty:
                connection.build()
            if connection.looks_tls or connection.error is not None:
                out.append(connection.row)
        return out

    def report(self, frames=0, skipped=0):
        self.counts['report_calls'] += 1
        if self._report is None or self._report.get('frames') != frames:
            rows = self.rows()
            self._report = {'connections': rows, 'frames': frames, 'skipped': skipped,
                            'decrypted': sum(r['status'] == 'decrypted' for r in rows), 'profile': PROFILE,
                            'counts': dict(self.counts, awaiting_keys=self.awaiting_keys(), active=len(self.connections)),
                            'budget': {'retained_bytes': self.coordinator.retained_bytes(),
                                       'retained_limit': self.coordinator.retain.aggregate if self.coordinator.retain else 0,
                                       'rejected_connections': self.coordinator.counts['retained_rejected_connections'],
                                       'rejected_bytes': self.coordinator.counts['retained_rejected_bytes']}}
        return self._report


__all__ = ['Decryptor', 'DecryptionError', 'PROFILE']

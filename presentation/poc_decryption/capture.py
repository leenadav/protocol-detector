"""Capture adapter: strict bounded TCP reconstruction, then authenticated TLS decoding."""
from dataclasses import asdict, replace
from . import MAX_STREAM, DecryptionError, decrypt_streams, read_keys


def analyze_capture(data, keylog):
    from protocol_adapters.capture_stream import PcapStreamDecoder
    from protocol_adapters.link_packets import decode_frame
    from protocol_adapters.packets import TCPPacket, PacketError
    from protocol_adapters.sessions import Stream, StreamError
    from protocol_engine import Inspector
    from protocol_engine.appid import session_verdict
    if len(data) > 8 * 1024 * 1024:
        raise DecryptionError('Capture exceeds 8 MiB.')
    keys = read_keys(keylog)
    decoder, flows, frames, skipped = PcapStreamDecoder(), {}, 0, 0
    for offset in range(0, len(data), 65536):
        for record in decoder.feed(data[offset:offset + 65536]):
            frames += 1
            if frames > 20000 or record.truncated:
                raise DecryptionError('Capture is truncated or exceeds 20,000 frames.')
            try:
                packet = decode_frame(record.data, record.linktype)
            except PacketError:
                skipped += 1
                continue
            if not isinstance(packet, TCPPacket):
                continue
            key = tuple(sorted((packet.source, packet.destination)))
            if key not in flows:
                if len(flows) >= 64:
                    raise DecryptionError('Capture exceeds 64 TCP connections.')
                flows[key] = {'streams': {}, 'client': None, 'server': None, 'error': None, 'fin': {}}
            flow = flows[key]
            if packet.flags & 2:
                first = (packet.sequence + 1) % (2 ** 32)
                previous = flow['streams'].get(packet.source)
                if previous is not None and previous.first_sequence != first:
                    flow['error'] = 'Connection tuple reuse is outside the POC profile.'
                if previous is None:
                    flow['streams'][packet.source] = Stream(first, MAX_STREAM, compatibility=False)
                if not packet.flags & 16:
                    flow['client'], flow['server'] = packet.source, packet.destination
            if packet.payload:
                stream = flow['streams'].get(packet.source)
                if stream is None:
                    flow['error'] = 'TCP SYN is missing; stream origin cannot be established.'
                else:
                    try:
                        stream.feed((packet.sequence + bool(packet.flags & 2)) % (2 ** 32), packet.payload)
                    except StreamError as error:
                        flow['error'] = str(error)
            if packet.flags & 1:
                flow['fin'][packet.source] = (packet.sequence + len(packet.payload)) % (2 ** 32)
    decoder.end()
    output = []
    for endpoints, flow in flows.items():
        client, server = flow['client'], flow['server']
        streams = flow['streams']
        if not any(s.contiguous and s.buffer[0] == 22 for s in streams.values()):
            if flow['error']:
                output.append({'client': client or endpoints[0], 'server': server or endpoints[1],
                               'status': 'unavailable', 'reason': flow['error']})
            continue
        result = {'client': client or endpoints[0], 'server': server or endpoints[1], 'outer_protocol': 'tls'}
        try:
            if flow['error']:
                raise DecryptionError(flow['error'])
            if client not in streams or server not in streams:
                raise DecryptionError('Both TCP directions and SYNs are required.')
            for endpoint, stream in streams.items():
                if stream.stored != stream.contiguous:
                    raise DecryptionError('TCP capture has missing bytes.')
                if endpoint in flow['fin'] and (flow['fin'][endpoint] - stream.first_sequence) % (2 ** 32) != stream.contiguous:
                    raise DecryptionError('TCP bytes are missing before FIN.')
            wire = [bytes(streams[e].buffer[:streams[e].contiguous]) for e in (client, server)]
            cp, sp, metadata = decrypt_streams(wire[0], wire[1], keys)
            inspectors, observations = [], []
            for raw, plain, endpoint in zip(wire, (cp, sp), (client, server)):
                inspector = Inspector()
                inspector.feed(raw)
                if inspector.observation.encryption == 'tls':
                    if plain:
                        inspector.feed_decrypted(plain)
                    observation = inspector.observation
                else:
                    # Decryption validated this envelope, even if its key-share group
                    # is outside the passive detector's narrower hello profile.
                    inspector = Inspector(source='decrypted')
                    inspector.feed(plain)
                    observation = replace(inspector.observation, encryption='tls')
                inspectors.append(inspector)
                observations.append(observation)
            inner = [replace(o, encryption=None, application=None,
                             evidence=tuple(e for e in o.evidence if e.source.startswith('decrypted')))
                     for o in observations]
            verdict = session_verdict(inner[0], inner[1],
                                      'tcp', server[1], len(cp), len(sp))
            # No raw payload, key material, hostname, URL or credentials leave this adapter.
            safe_evidence = []
            allowed = {'application_protocol', 'encryption', 'http_method', 'http_status', 'http_content_type',
                       'http_content_type_class', 'grpc', 'webdav', 'rpc_method'}
            for inspector in inspectors:
                safe_evidence.extend(asdict(e) for e in inspector.observation.evidence if e.field in allowed)
            result.update(metadata, status='decrypted', application=verdict.app,
                          inner_protocol=verdict.client_protocol or verdict.server_protocol,
                          category=verdict.category, app_status=verdict.status,
                          reasons=list(verdict.reasons), evidence=safe_evidence,
                          note='Record AEAD verified with supplied secrets; peer identity and certificate trust are not validated.')
        except (DecryptionError, ValueError) as error:
            result.update(status='unavailable', reason=str(error))
        output.append(result)
    return {'connections': output, 'frames': frames, 'skipped': skipped,
            'decrypted': sum(row['status'] == 'decrypted' for row in output),
            'profile': 'TLS 1.2 ECDHE-RSA AES-GCM / TLS 1.3 AEAD key-log POC; no CBC, QUIC, 0-RTT, HRR or renegotiation.'}

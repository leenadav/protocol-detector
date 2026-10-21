"""Regression tests for the v0.27 decoder expansion.

Every family added in v0.27 must satisfy its documented structural profile:
identification only after the complete initial message, rejection of malformed
lengths and reserved values, no payload/credential emission, and ambiguity
resolved by bidirectional correlation rather than by hints.
"""
import random
import unittest

from protocol_engine import Config, DatagramInspector, Inspector
from protocol_engine.appid import classify, session_verdict
from protocol_engine.dispatch import select
from protocol_fixtures import (BACNET, CQL, DNP3, ENIP, ENIP_UDP, FTP, IEC104, IMAP_CLIENT, IPFIX, ISO_TSAP, KAFKA, KERBEROS,
                               KERBEROS_TCP, L2TP, MODBUS, NETBIOS_SS, NETFLOW5, NETFLOW9, OPENVPN, OPENVPN_TCP, POP3_CLIENT,
                               POP3_SERVER, PPTP, RDP, RTP, SFLOW, SMB1, SSDP, TACACS, TELNET, WIREGUARD)


def stream(data, **kwargs):
    inspector = Inspector(**kwargs)
    inspector.feed(data)
    return inspector.observation


def datagram(data, hint=None, **kwargs):
    return DatagramInspector(**kwargs).inspect(data, hint)


class TextAmbiguityTests(unittest.TestCase):
    """220 greetings and USER/PASS/QUIT commands are shared; the other direction decides."""

    def test_shared_lines_report_candidates_as_context_not_identity(self):
        for data, candidates in ((b'220 mail.example.org ESMTP\r\n', 'smtp,ftp'), (b'USER alice\r\n', 'ftp,pop3'),
                                 (b'PASS secret\r\n', 'ftp,pop3,irc'), (b'QUIT\r\n', 'ftp,pop3'), (b'* OK ready\r\n', 'imap')):
            result = stream(data)
            self.assertEqual(result.status, 'unknown', result)
            self.assertIsNone(result.application_protocol)
            self.assertEqual([(e.field, e.value, e.strength) for e in result.evidence], [('ambiguous_candidates', candidates, 'context')])
            self.assertNotIn('secret', repr(result))
            self.assertNotIn('alice', repr(result))

    def test_exclusive_commands_identify_without_a_greeting(self):
        for data, protocol in ((FTP, 'ftp'), (b'STOR somefile.bin\r\n', 'ftp'), (b'PASV\r\n', 'ftp'), (b'TYPE I\r\n', 'ftp'), (b'CWD /pub\r\n', 'ftp'),
                               (POP3_CLIENT, 'pop3'), (b'RSET\r\n', 'pop3'), (b'UIDL 3\r\n', 'pop3'), (POP3_SERVER, 'pop3'),
                               (b'-ERR no\r\n', 'pop3'), (IMAP_CLIENT, 'imap'), (b'tag1 LOGIN user pass\r\n', 'imap')):
            result = stream(data)
            self.assertEqual((result.status, result.application_protocol), ('identified', protocol), (data, result))
        for data in (b'RETR\r\n', b'TYPE Q\r\n', b'PORT 1,2,3\r\n', b'TOP x\r\n', b'STOR\r\n', b'STAT 1\r\n', b'+OK\xff\r\n', b'+ OK\r\n', b'A001\r\n', b'A001 CAPABILIT\r\n', b'A001 CAPABILITY x\x00\r\n',
                     b'* LOGIN x\r\n', b'tag LOGIN ' + b'x' * 9000 + b'\r\n'):
            self.assertNotEqual(stream(data).status, 'identified', data)
        self.assertNotIn('pass', repr(stream(b'tag1 LOGIN user pass\r\n')).lower().replace('password', ''))

    def test_bidirectional_correlation_resolves_shared_lines(self):
        client, server = stream(b'USER alice\r\n'), stream(b'220 ftp.example.org ready\r\n')
        verdict = session_verdict(client, server, 'tcp', 21, 12, 25, True, None)
        self.assertEqual((verdict.app, verdict.status, verdict.port_usage), ('ftp', 'correlated', 'standard'))
        verdict = session_verdict(stream(b'USER alice\r\n'), stream(POP3_SERVER), 'tcp', 110, 12, 24, True, None)
        self.assertEqual((verdict.app, verdict.status), ('pop3', 'identified'))
        verdict = session_verdict(stream(b'EHLO host\r\n'), stream(b'220 mail ready\r\n'), 'tcp', 25, 11, 16, True, None)
        self.assertEqual((verdict.app, verdict.status), ('smtp', 'identified'))
        # Disjoint candidate sets or a lone ambiguous direction never become an identity.
        verdict = session_verdict(stream(b'* OK ready\r\n'), stream(b'220 ready\r\n'), 'tcp', 143, 12, 11, True, None)
        self.assertEqual((verdict.app, verdict.status), ('unknown-tcp', 'unknown'))
        verdict = session_verdict(stream(b'USER alice\r\n'), None, 'tcp', 21, 12, 0, True, None)
        self.assertEqual((verdict.app, verdict.status), ('unknown-tcp', 'unknown'))
        self.assertEqual(classify(stream(b'USER alice\r\n'), 'tcp', 21).app, 'unknown-tcp')


class TerminalAndWindowsTests(unittest.TestCase):
    def test_telnet_requires_two_complete_negotiation_commands(self):
        self.assertEqual(stream(TELNET).application_protocol, 'telnet')
        self.assertEqual(stream(TELNET[:3]).status, 'detecting')
        self.assertEqual(stream(TELNET[:5]).status, 'detecting')
        for data in (b'\xff\xfd\x18\xff\xf0\x01', b'\xff\xfd\x18A', b'\xff\xfa\x18\x01\xff\xf0', b'\xff\xff\xff\xff\xff\xff'):
            self.assertNotEqual(stream(data).status, 'identified', data)
        self.assertEqual(select(b'\xff\xff'), 'bgp')
        self.assertEqual(select(b'\xff\xfd'), 'telnet')

    def test_smb1_negotiate_dialect_strings_and_netbios_session_request(self):
        self.assertEqual(stream(SMB1).application_protocol, 'smb1')
        self.assertNotIn('NT LM', repr(stream(SMB1)))
        for data in (SMB1.replace(b'\x02PC', b'\x03PC'), SMB1.replace(b'\xffSMB\x72', b'\xffSMB\x73'),
                     SMB1[:4] + SMB1[4:8] + b'\x01' + SMB1[9:], SMB1[:-3]):
            self.assertNotEqual(stream(data).status, 'identified', data)
        self.assertEqual(stream(NETBIOS_SS).application_protocol, 'netbios-ss')
        for data in (NETBIOS_SS[:3] + b'\x43' + NETBIOS_SS[4:], NETBIOS_SS.replace(b'\x20E', b'\x20Z', 1), NETBIOS_SS[:-1] + b'\x01'):
            self.assertEqual(stream(data).status, 'malformed', data)
        self.assertNotIn('FILESERVER', repr(stream(NETBIOS_SS)))

    def test_kerberos_asn1_framing_on_tcp_and_udp(self):
        self.assertEqual(stream(KERBEROS_TCP).application_protocol, 'kerberos')
        self.assertEqual(datagram(KERBEROS).application_protocol, 'kerberos')
        self.assertNotIn('EXAMPLE.ORG', repr(stream(KERBEROS_TCP)) + repr(datagram(KERBEROS)))
        wrong_pvno = KERBEROS.replace(b'\xa1\x03\x02\x01\x05', b'\xa1\x03\x02\x01\x04')
        wrong_type = KERBEROS.replace(b'\xa2\x03\x02\x01\x0a', b'\xa2\x03\x02\x01\x07')
        for data in (wrong_pvno, wrong_type, KERBEROS + b'\x00', KERBEROS[:-1], b'\x6a\x80' + bytes(16), b'\x6a\x84\xff\xff\xff\xff' + bytes(8)):
            self.assertNotEqual(datagram(data).status, 'identified', data)
            self.assertNotEqual(stream(len(data).to_bytes(4, 'big') + data).status, 'identified', data)
        self.assertNotEqual(stream((len(KERBEROS) + 1).to_bytes(4, 'big') + KERBEROS).status, 'identified')

    def test_tacacs_plus_header_profile(self):
        self.assertEqual(stream(TACACS).application_protocol, 'tacacs-plus')
        self.assertNotIn('user', repr(stream(TACACS)))
        for data in (TACACS[:1] + b'\x04' + TACACS[2:], TACACS[:8] + b'\x7f\xff\xff\xff' + TACACS[12:], TACACS[:1] + b'\x01\x00\x01' + TACACS[4:8] + b'\x00\x00\x00\x00'):
            self.assertNotEqual(stream(data).status, 'identified', data)
        self.assertEqual(stream(TACACS[:8] + (len(TACACS) - 11).to_bytes(4, 'big') + TACACS[12:]).status, 'detecting')


class VPNTests(unittest.TestCase):
    def test_wireguard_message_sizes_and_reserved_bytes(self):
        result = datagram(WIREGUARD)
        self.assertEqual((result.status, result.encryption, result.application_protocol), ('identified', 'wireguard', None))
        self.assertEqual(datagram(b'\x02\x00\x00\x00' + bytes(88)).encryption, 'wireguard')
        self.assertEqual(datagram(b'\x03\x00\x00\x00' + bytes(60)).encryption, 'wireguard')
        for data in (WIREGUARD[:-1], WIREGUARD + b'\x00', b'\x01\x00\x00\x01' + WIREGUARD[4:], b'\x02\x00\x00\x00' + bytes(92),
                     b'\x04\x00\x00\x00' + bytes(144)):
            self.assertNotEqual(datagram(data).encryption, 'wireguard', data)
        verdict = classify(result, 'udp', 51820)
        self.assertEqual((verdict.app, verdict.encryption, verdict.port_usage), ('wireguard', 'wireguard', 'standard'))

    def test_openvpn_control_framing_on_udp_and_tcp(self):
        self.assertEqual(datagram(OPENVPN).encryption, 'openvpn')
        self.assertEqual(stream(OPENVPN_TCP).application_protocol, 'openvpn')
        for data in (b'\x38' + bytes(8) + b'\x00' + bytes(4), b'\x38' + OPENVPN[1:9] + b'\x09' + bytes(4), OPENVPN[:-1], b'\x08' + OPENVPN[1:]):
            self.assertNotEqual(datagram(data).status, 'identified', data)
        self.assertEqual(stream((len(OPENVPN) + 1).to_bytes(2, 'big') + OPENVPN).status, 'detecting')
        self.assertEqual(stream(b'\x00\x05' + OPENVPN).status, 'unknown')
        # tls-auth adds an HMAC, packet id and timestamp before the ack array.
        tls_auth = b'\x38' + OPENVPN[1:9] + bytes(20) + (1).to_bytes(4, 'big') + (1700000000).to_bytes(4, 'big') + b'\x00' + bytes(4)
        self.assertEqual(datagram(tls_auth).encryption, 'openvpn')

    def test_pptp_and_l2tp_control_connection_requests(self):
        self.assertEqual(stream(PPTP).application_protocol, 'pptp')
        self.assertNotIn('client-host', repr(stream(PPTP)))
        for data in (PPTP[:1] + b'\x9d' + PPTP[2:], PPTP[:4] + b'\x1a\x2b\x3c\x4e' + PPTP[8:], PPTP[:8] + b'\x00\x00' + PPTP[10:],
                     PPTP[:2] + b'\x00\x02' + PPTP[4:]):
            self.assertNotEqual(stream(data).status, 'identified', data)
        self.assertEqual(datagram(L2TP).application_protocol, 'l2tp/2')
        for data in (L2TP[:12] + L2TP[20:], L2TP[:2] + b'\x00\x10' + L2TP[4:], b'\xc8\x03' + L2TP[2:], L2TP[:-1], L2TP[:20] + b'\x80\x08\x00\x00\x00\x02\x00\x01' + L2TP[28:]):
            self.assertNotEqual(datagram(data).status, 'identified', data)


class TelemetryTests(unittest.TestCase):
    def test_ssdp_requires_the_discovery_headers(self):
        self.assertEqual(datagram(SSDP).application_protocol, 'ssdp')
        notify = b'NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNT: upnp:rootdevice\r\nNTS: ssdp:alive\r\nUSN: uuid:x\r\n\r\n'
        self.assertEqual(datagram(notify).application_protocol, 'ssdp')
        self.assertNotIn('uuid:x', repr(datagram(notify)))
        for data in (SSDP.replace(b'MAN: "ssdp:discover"\r\n', b''), SSDP.replace(b'ST: ssdp:all\r\n', b''), SSDP[:-2], SSDP.replace(b'HTTP/1.1', b'HTTP/2.0'),
                     notify.replace(b'NTS: ssdp:alive\r\n', b''), b'M-SEARCH * HTTP/1.1\r\n' + b'X: y\r\n' * 200 + b'\r\n'):
            self.assertNotEqual(datagram(data).status, 'identified', data)

    def test_flow_export_framing(self):
        self.assertEqual(datagram(NETFLOW5).application_protocol, 'netflow/5')
        self.assertEqual(datagram(NETFLOW9).application_protocol, 'netflow/9')
        self.assertEqual(datagram(IPFIX).application_protocol, 'ipfix')
        self.assertEqual(datagram(SFLOW).application_protocol, 'sflow/5')
        rejected = (NETFLOW5[:2] + b'\x00\x03' + NETFLOW5[4:], NETFLOW5[:2] + b'\x00\x00' + NETFLOW5[4:24], NETFLOW5 + b'\x00',
                    NETFLOW9[:20] + b'\x00\x05' + NETFLOW9[22:], NETFLOW9[:22] + b'\x00\x13' + NETFLOW9[24:], NETFLOW9[:20],
                    IPFIX[:2] + b'\x00\x21' + IPFIX[4:], IPFIX[:16] + b'\x00\x01' + IPFIX[18:], IPFIX[:16] + b'\x00\x02\x00\x02' + IPFIX[20:],
                    b'\x00\x00\x00\x04' + SFLOW[4:], SFLOW[:4] + b'\x00\x00\x00\x03' + SFLOW[8:], SFLOW[:24] + b'\x00\x00\x00\x02' + SFLOW[28:], SFLOW + b'\x00')
        for data in rejected:
            self.assertNotEqual(datagram(data).status, 'identified', data)
        many = NETFLOW9[:16] + b'\x01\x00\x00\x04' * 64
        self.assertEqual(datagram(many, config=Config(max_headers=8)).status, 'budget_exhausted')
        self.assertEqual(datagram(many).application_protocol, 'netflow/9')


class ICSTests(unittest.TestCase):
    def test_modbus_request_pdu_lengths_follow_the_function_code(self):
        self.assertEqual(stream(MODBUS).application_protocol, 'modbus')
        for data in (MODBUS[:2] + b'\x00\x01' + MODBUS[4:], MODBUS[:4] + b'\x00\x05' + MODBUS[6:], MODBUS[:7] + b'\x00' + MODBUS[8:],
                     MODBUS[:7] + b'\x83' + MODBUS[8:], MODBUS[:10] + b'\x00\x7e', MODBUS[:10] + b'\x00\x00'):
            self.assertNotEqual(stream(data).status, 'identified', data)
        self.assertEqual(stream(MODBUS[:-1]).status, 'detecting')

    def test_dnp3_crc_blocks(self):
        self.assertEqual(stream(DNP3).application_protocol, 'dnp3')
        self.assertEqual(select(b'\x05\x64'), 'dnp3')
        for data in (DNP3[:8] + bytes([DNP3[8] ^ 1]) + DNP3[9:], DNP3[:-1] + bytes([DNP3[-1] ^ 1]), DNP3[:2] + b'\x04' + DNP3[3:], DNP3[:3] + b'\x00' + DNP3[4:]):
            self.assertEqual(stream(data).status, 'malformed', data)
        self.assertEqual(stream(DNP3[:-1]).status, 'detecting')

    def test_bacnet_bvlc_and_npdu(self):
        self.assertEqual(datagram(BACNET).application_protocol, 'bacnet')
        self.assertEqual(datagram(b'\x81\x0a\x00\x08\x01\x00\x10\x08').application_protocol, 'bacnet')
        for data in (BACNET[:2] + b'\x00\x0d' + BACNET[4:], BACNET[:4] + b'\x02' + BACNET[5:], BACNET[:-2] + b'\x80\x08', BACNET[:5] + b'\x60' + BACNET[6:],
                     b'\x81\x0d' + BACNET[2:], b'\x81\x0a\x00\x08\x01\x20\xff\xff', b'\x81\x0a\x00\x06\x01\x00'):
            self.assertNotEqual(datagram(data).status, 'identified', data)

    def test_tpkt_routes_rdp_and_iso_tsap(self):
        self.assertEqual(stream(ISO_TSAP).application_protocol, 'iso-tsap')
        self.assertEqual(stream(RDP).application_protocol, 'rdp')
        for data in (ISO_TSAP[:4] + b'\x12' + ISO_TSAP[5:], ISO_TSAP[:5] + b'\xf0' + ISO_TSAP[6:], ISO_TSAP[:12] + b'\x30' + ISO_TSAP[13:], ISO_TSAP[:-2]):
            self.assertNotEqual(stream(data).status, 'identified', data)

    def test_ethernet_ip_and_iec_104(self):
        self.assertEqual(stream(ENIP).application_protocol, 'ethernet-ip')
        self.assertEqual(datagram(ENIP_UDP).application_protocol, 'ethernet-ip')
        for data in (ENIP[:2] + b'\x05\x00' + ENIP[4:], ENIP[:8] + b'\x01\x00\x00\x00' + ENIP[12:], ENIP[:-1]):
            self.assertNotEqual(stream(data).status, 'identified', data)
        self.assertNotEqual(datagram(ENIP_UDP[:2] + b'\x04\x00' + ENIP_UDP[4:]).status, 'identified')
        self.assertEqual(stream(IEC104).application_protocol, 'iec-104')
        for data in (b'\x68\x04\x47\x00\x00\x00', b'\x68\x04\x07\x01\x00\x00', b'\x68\x05\x07\x00\x00\x00\x00'):
            self.assertNotEqual(stream(data).status, 'identified', data)


class DataInfrastructureTests(unittest.TestCase):
    def test_kafka_request_header(self):
        self.assertEqual(stream(KAFKA).application_protocol, 'kafka')
        self.assertNotIn('tester', repr(stream(KAFKA)))
        null_client = (len(KAFKA) - 4 - 6).to_bytes(4, 'big') + KAFKA[4:12] + b'\xff\xff' + KAFKA[20:]
        self.assertEqual(stream(null_client).application_protocol, 'kafka')
        for data in (KAFKA[:4] + b'\x00\x63' + KAFKA[6:], KAFKA[:6] + b'\x00\x63' + KAFKA[8:], KAFKA[:12] + b'\x7f\xff' + KAFKA[14:],
                     KAFKA.replace(b'client', b'cl\x00ent'), b'\x80' + KAFKA[1:]):
            self.assertNotEqual(stream(data).status, 'identified', data)
        # Selection happens at eight bytes so three-byte fragments and whole feeds agree.
        self.assertEqual(select(KAFKA[:8]), 'kafka')
        self.assertIsNone(select(KAFKA[:7]))

    def test_cql_startup_and_options(self):
        self.assertEqual(stream(CQL).application_protocol, 'cql/4')
        self.assertEqual(stream(b'\x04\x00\x00\x01\x05\x00\x00\x00\x00').application_protocol, 'cql/4')
        self.assertNotIn('3.0.0', repr(stream(CQL)))
        for data in (b'\x84' + CQL[1:], CQL[:4] + b'\x11' + CQL[5:], CQL[:5] + b'\x00\x00\x00\x05' + CQL[9:], CQL.replace(b'CQL_VERSION', b'XQL_VERSION'),
                     b'\x04\x00\x00\x01\x05\x00\x00\x00\x01\x00', CQL[:1] + b'\x10' + CQL[2:]):
            self.assertNotEqual(stream(data).status, 'identified', data)

    def test_rtp_requires_a_hint_and_structural_header(self):
        self.assertEqual(datagram(RTP).status, 'unknown')
        self.assertEqual(datagram(RTP, 'rtp').application_protocol, 'rtp')
        self.assertEqual(datagram(b'\x81' + RTP[1:12] + bytes(4), 'rtp').application_protocol, 'rtp')
        for data in (b'\x40' + RTP[1:], RTP[:1] + b'\x48' + RTP[2:], RTP[:11], b'\x81' + RTP[1:12]):
            self.assertNotEqual(datagram(data, 'rtp').status, 'identified', data)
        # A hint selects the candidate; it never turns a non-RTP datagram into RTP.
        for data in (WIREGUARD, KERBEROS, SSDP):
            self.assertEqual(datagram(data, 'rtp').status, 'unknown', data)


class RobustnessTests(unittest.TestCase):
    STREAMS = (FTP, POP3_SERVER, POP3_CLIENT, IMAP_CLIENT, TELNET, SMB1, NETBIOS_SS, KERBEROS_TCP, TACACS, OPENVPN_TCP, PPTP, MODBUS,
               DNP3, ISO_TSAP, ENIP, IEC104, KAFKA, CQL)
    DATAGRAMS = (WIREGUARD, OPENVPN, L2TP, SSDP, NETFLOW5, NETFLOW9, IPFIX, SFLOW, BACNET, KERBEROS, ENIP_UDP, RTP)

    def test_truncations_and_mutations_never_raise_and_stay_bounded(self):
        rng = random.Random(2027)
        statuses = {'identified', 'unknown', 'malformed', 'incomplete', 'detecting', 'budget_exhausted'}
        for base in self.STREAMS:
            for cut in range(len(base)):
                self.assertIn(stream(base[:cut]).status, statuses)
            for _ in range(200):
                changed = bytearray(base)
                changed[rng.randrange(len(changed))] = rng.randrange(256)
                inspector = Inspector()
                inspector.feed(bytes(changed))
                inspector.end()
                self.assertIn(inspector.observation.status, statuses)
                self.assertLessEqual(inspector.metrics.bytes_inspected, len(changed))
        for base in self.DATAGRAMS:
            for cut in range(len(base)):
                self.assertIn(datagram(base[:cut], 'rtp' if base is RTP else None).status, statuses)
            for _ in range(200):
                changed = bytearray(base)
                changed[rng.randrange(len(changed))] = rng.randrange(256)
                self.assertIn(datagram(bytes(changed), 'rtp' if base is RTP else None).status, statuses)

    def test_identified_observations_carry_structural_evidence_only(self):
        for base in self.STREAMS:
            result = stream(base)
            self.assertEqual(result.status, 'identified', result)
            self.assertTrue(all(e.strength == 'structural' for e in result.evidence), result)
        for base in self.DATAGRAMS:
            result = datagram(base, 'rtp' if base is RTP else None)
            self.assertEqual(result.status, 'identified', result)
            verdict = classify(result, 'udp', None)
            self.assertNotEqual(verdict.app, 'unknown-udp', (base, verdict))


if __name__ == '__main__':
    unittest.main()

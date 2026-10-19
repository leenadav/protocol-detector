"""Bounded IKEv2 IKE_SA_INIT initiator profile (RFC7296/5282/4868).

Validates plaintext negotiation framing, not crypto, peer identity or IPsec data.
"""
from types import MappingProxyType
from .datagram_result import DatagramMatch
from .extended import UnsupportedPrefix
from .model import Evidence
from .parsers import BudgetError, ParseError

_GROUP_BYTES = MappingProxyType({14:256, 15:384, 16:512, 17:768, 18:1024})
_PRF_NONCE_MIN = MappingProxyType({2:16, 5:16, 6:24, 7:32})
_START_TYPES = (33, 34, 40, 41, 43)


def _header_at(data, start):
    return (len(data) >= start+28 and data[start+17] == 32 and data[start+18] == 34 and data[start+19] == 8
            and data[start+16] in _START_TYPES and data[start+8:start+16] == bytes(8)
            and data[start+20:start+24] == bytes(4))


def ike_probe(data):
    """Two fixed header positions only; never search opaque payload contents."""
    # Minimum supported message:28 header +40 SA(AEAD) +264 KE +20 nonce.
    return len(data) >= 352 and (_header_at(data, 0) or (data[:4] == b'\0\0\0\0' and _header_at(data, 4)))


class _Budget:
    def __init__(self, config):
        self.remaining = min(config.max_headers, 128)

    def spend(self, count=1):
        self.remaining -= count
        if self.remaining < 0:
            raise BudgetError('IKE payload/proposal/transform work budget exceeded')


def _u16(data, offset):
    return int.from_bytes(data[offset:offset+2], 'big')


def _sa(data, budget):
    pos, number, groups, nonce_min = 0, 0, set(), 16
    while pos < len(data):
        budget.spend()
        number += 1
        if len(data)-pos < 8:
            raise ParseError('Truncated IKE proposal header')
        size = _u16(data,pos+2)
        end = pos + size
        if size < 8 or end > len(data):
            raise ParseError('IKE proposal length outside SA payload')
        if data[pos] != (2 if end < len(data) else 0) or data[pos+1] != 0:
            raise ParseError('Invalid IKE proposal chaining or reserved byte')
        if data[pos+4] != number:
            raise ParseError('IKE proposal numbers must begin at one and increase')
        if data[pos+5] != 1 or data[pos+6] != 0:
            raise UnsupportedPrefix('IKE initial proposal requires IKE protocol and no inner SPI')
        count = data[pos+7]
        if not count:
            raise ParseError('Empty IKE transform list')
        budget.spend(count)
        pos += 8
        types, encryption = set(), set()
        for index in range(count):
            if end-pos < 8:
                raise ParseError('Truncated IKE transform header')
            size = _u16(data,pos+2)
            stop = pos+size
            if size < 8 or stop > end:
                raise ParseError('IKE transform length outside proposal')
            if data[pos] != (3 if index+1<count else 0) or data[pos+1] or data[pos+5]:
                raise ParseError('Invalid IKE transform chaining or reserved bytes')
            kind, value = data[pos+4], _u16(data,pos+6)
            attributes = data[pos+8:stop]
            if kind == 1:
                if value not in (12,18,19,20):
                    raise UnsupportedPrefix('IKE encryption offer outside AES-CBC/GCM profile')
                if len(attributes) != 4 or attributes[:2] != b'\x80\x0e' or _u16(attributes,2) not in (128,192,256):
                    raise ParseError('IKE AES requires one TV key-length attribute (128/192/256)')
                encryption.add('cbc' if value==12 else 'aead')
            else:
                if attributes:
                    raise UnsupportedPrefix('IKE profile excludes attributes on non-encryption transforms')
                if kind == 2:
                    if value not in _PRF_NONCE_MIN:
                        raise UnsupportedPrefix('IKE PRF offer outside HMAC-SHA profile')
                    nonce_min = max(nonce_min, _PRF_NONCE_MIN[value])
                elif kind == 3:
                    if value not in (2,12,13,14):
                        raise UnsupportedPrefix('IKE integrity offer outside HMAC-SHA profile')
                elif kind == 4:
                    if value not in _GROUP_BYTES:
                        raise UnsupportedPrefix('IKE DH offer outside MODP groups14..18')
                    groups.add(value)
                else:
                    raise UnsupportedPrefix('IKE transform type outside supported initial profile')
            types.add(kind)
            pos = stop
        if pos != end:
            raise ParseError('Trailing bytes or wrong transform count in IKE proposal')
        if not {1,2,4} <= types:
            raise ParseError('IKE proposal missing encryption, PRF or DH offers')
        if len(encryption) != 1:
            raise UnsupportedPrefix('Mixed CBC/AEAD in one IKE proposal is outside this profile')
        if (encryption == {'cbc'}) != (3 in types):
            raise ParseError('IKE CBC needs integrity; AEAD-only proposals must omit it')
    if not number:
        raise ParseError('Empty IKE SA proposal list')
    return groups, nonce_min


def ikev2(data, config):
    if _header_at(data,0):
        start=0
    elif data[:4]==bytes(4) and _header_at(data,4):
        start=4
    else:
        raise UnsupportedPrefix('Outside IKEv2 initial initiator header profile')
    if not any(data[start:start+8]):
        raise ParseError('IKE initiator SPI must be nonzero')
    size=int.from_bytes(data[start+24:start+28],'big')
    if size+start > config.max_bytes:
        raise BudgetError('Declared IKE message exceeds byte budget')
    if size < 28 or size != len(data)-start:
        raise ParseError('IKE message length must exactly occupy datagram after optional marker')
    budget=_Budget(config)
    kind,pos=data[start+16],start+28
    seen=set()
    groups,nonce_min,group,nonce_size=None,16,None,None
    payload_number=0
    while kind:
        budget.spend()
        payload_number+=1
        if len(data)-pos < 4:
            raise ParseError('Truncated IKE generic payload header')
        next_kind,flags,size=data[pos],data[pos+1],_u16(data,pos+2)
        end=pos+size
        if size < 4 or end > len(data):
            raise ParseError('IKE payload length exceeds message')
        if flags & 0x7f:
            raise ParseError('IKE profile requires zero reserved payload bits')
        body=data[pos+4:end]
        if kind in (33,34,40):
            if kind in seen:
                raise ParseError('Duplicate required IKE payload')
            seen.add(kind)
        if kind == 33:
            groups,nonce_min=_sa(body,budget)
        elif kind == 34:
            if len(body)<4 or body[2:4]!=b'\0\0':
                raise ParseError('Invalid IKE key-exchange header')
            group=_u16(body,0)
            if group not in _GROUP_BYTES:
                raise UnsupportedPrefix('IKE KE group outside supported MODP profile')
            if len(body)-4 != _GROUP_BYTES[group]:
                raise ParseError('IKE public value width disagrees with MODP group')
        elif kind == 40:
            nonce_size=len(body)
            if not 16 <= nonce_size <= 256:
                raise ParseError('IKE nonce must contain16..256 bytes')
        elif kind == 41:
            if len(body)<4 or body[:2]!=b'\0\0':
                raise ParseError('IKE initial notify requires zero protocol and SPI size')
            notification=_u16(body,2)
            if notification in (16388,16389):
                if len(body)!=24:
                    raise ParseError('IKE NAT-detection hash must contain20 bytes')
            elif notification==16390:
                if payload_number!=1 or not 1 <= len(body)-4 <= 64:
                    raise ParseError('IKE cookie must be first and contain1..64 bytes')
            else:
                raise UnsupportedPrefix('IKE notification outside NAT-detection/cookie profile')
        elif kind == 43:
            if not body:
                raise ParseError('Empty IKE Vendor ID')
            if len(body)>config.max_line:
                raise BudgetError('IKE Vendor ID exceeds opaque field budget')
        else:
            raise UnsupportedPrefix('IKE payload type outside SA_INIT request profile')
        kind,pos=next_kind,end
    if pos!=len(data):
        raise ParseError('Bytes remain after IKE payload chain terminates')
    if seen!={33,34,40}:
        raise ParseError('IKE initial request requires SA, KE and nonce')
    if group not in groups or nonce_size<nonce_min:
        raise ParseError('IKE KE/nonce disagrees with algorithm proposals')
    return DatagramMatch(application_protocol='ikev2',
                         evidence=(Evidence('application_protocol','ikev2','wire','structural'),
                                   Evidence('exchange','ike_sa_init_request','wire','structural'),
                                   Evidence('offered_dh_group',str(group),'ike_initiator','asserted')),
                         reason='IKEv2 initial proposal/KE/nonce structure validated; offers unauthenticated, no established IPsec or encrypted payload claim')

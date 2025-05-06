from typing import List, Tuple
from config import CACHE_TTL

QTYPE_MAP = {'A': 1, 'NS': 2, 'AAAA': 28, 'PTR': 12}
REVERSE_QTYPE = {v: k for k, v in QTYPE_MAP.items()}

class DNSProtocol:
    @staticmethod
    def build_query(domain: str, qtype: str) -> bytes:
        query_id = b'\xab\xcd'
        flags = b'\x01\x00'
        qdcount = b'\x00\x01'
        question = b''

        for part in domain.encode('ascii').split(b'.'):
            question += bytes([len(part)]) + part
        question += b'\x00'

        question += QTYPE_MAP.get(qtype, 1).to_bytes(2, 'big')
        question += (1).to_bytes(2, 'big')  # CLASS IN

        return query_id + flags + qdcount + (0).to_bytes(6, 'big') + question

    @staticmethod
    def parse_response(response: bytes, qtype: str) -> Tuple[List[dict], int]:
        records = []
        ttl_min = CACHE_TTL
        ptr = 12
        while response[ptr] != 0:
            ptr += 1 + response[ptr]
        ptr += 5
        ancount = int.from_bytes(response[6:8], 'big')

        for _ in range(ancount):
            if response[ptr] & 0xC0 == 0xC0:
                ptr += 2
            else:
                while response[ptr] != 0:
                    ptr += 1 + response[ptr]
                ptr += 1

            rtype = int.from_bytes(response[ptr:ptr+2], 'big')
            ptr += 2
            ptr += 2  # class
            ttl = int.from_bytes(response[ptr:ptr+4], 'big')
            ptr += 4
            rdlength = int.from_bytes(response[ptr:ptr+2], 'big')
            ptr += 2

            if rtype == 1 and qtype == 'A':
                ip = '.'.join(str(b) for b in response[ptr:ptr+4])
                records.append({'type': 'A', 'value': ip, 'ttl': ttl})
            elif rtype == 28 and qtype == 'AAAA':
                ipv6 = ':'.join(f"{response[ptr+i]<<8 | response[ptr+i+1]:x}" for i in range(0, 16, 2))
                records.append({'type': 'AAAA', 'value': ipv6, 'ttl': ttl})
            elif rtype == 2 and qtype == 'NS':
                name = DNSProtocol.parse_name(response, ptr)
                records.append({'type': 'NS', 'value': name, 'ttl': ttl})
            elif rtype == 12 and qtype == 'PTR':
                ptr_name = DNSProtocol.parse_name(response, ptr)
                records.append({'type': 'PTR', 'value': ptr_name, 'ttl': ttl})

            ptr += rdlength
            ttl_min = min(ttl_min, ttl)

        return records, ttl_min

    @staticmethod
    def parse_name(response: bytes, offset: int) -> str:
        name = []
        jumped = False
        original_offset = offset
        while True:
            length = response[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0 == 0xC0:
                pointer = int.from_bytes(response[offset:offset+2], 'big') & 0x3FFF
                if not jumped:
                    original_offset = offset + 2
                offset = pointer
                jumped = True
            else:
                name.append(response[offset+1:offset+1+length].decode())
                offset += 1 + length
        if not jumped:
            return '.'.join(name)
        return '.'.join(name)

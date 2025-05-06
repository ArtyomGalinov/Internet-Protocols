import datetime
import socket
from typing import List, Tuple
from cache_manager import DNSCache
from protocol import DNSProtocol, QTYPE_MAP, REVERSE_QTYPE
from config import GOOGLE_DNS, CACHE_TTL

class DNSServer:
    def __init__(self):
        self.cache = DNSCache()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1', 53))

    def query_google_dns(self, domain: str, qtype: str):
        query = DNSProtocol.build_query(domain, qtype)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(2)
            try:
                s.sendto(query, GOOGLE_DNS)
                response, _ = s.recvfrom(512)
                return DNSProtocol.parse_response(response, qtype)
            except Exception as e:
                print(f"[!] DNS query failed: {e}")
                return [], CACHE_TTL

    def get_records(self, domain: str, qtype: str) -> List[dict]:
        cached = self.cache.get(domain, qtype)
        if cached:
            print(f"Using cached records for {domain} {qtype}")
            raw_records = cached["data"]["null"]
            return [{"type": qtype, "value": r["value"], "ttl": r["ttl"]} for r in raw_records]

        print(f"Querying Google DNS for {domain} {qtype}")
        records, ttl = self.query_google_dns(domain, qtype)

        if records:
            cache_entry = {
                "origin": f"{domain}.",
                "time": datetime.datetime.now().isoformat(sep=" "),
                "data": {
                    "null": [{"ttl": r["ttl"], "value": r["value"]} for r in records]
                },
                "ttl": ttl
            }
            self.cache.set(domain, qtype, cache_entry)

        return records

    def build_response(self, query: bytes, records: List[dict], qtype: str) -> bytes:
        response = query[:2] + b'\x81\x80' + query[4:6] + len(records).to_bytes(2, 'big') + b'\x00\x00\x00\x00'
        ptr = 12
        while query[ptr] != 0:
            ptr += 1 + query[ptr]
        response += query[12:ptr+5]

        for record in records:
            response += b'\xc0\x0c'
            rtype = QTYPE_MAP.get(record['type'], 1)
            response += rtype.to_bytes(2, 'big')  # TYPE
            response += (1).to_bytes(2, 'big')  # CLASS
            response += record['ttl'].to_bytes(4, 'big')  # TTL

            if record['type'] == 'A':
                rdata = bytes(map(int, record['value'].split('.')))
            elif record['type'] == 'AAAA':
                rdata = b''.join(int(part, 16).to_bytes(2, 'big') for part in record['value'].split(':') if part)
            elif record['type'] in ('NS', 'PTR'):
                rdata = b''
                for part in record['value'].split('.'):
                    rdata += bytes([len(part)]) + part.encode()
                rdata += b'\x00'
            else:
                continue

            response += len(rdata).to_bytes(2, 'big') + rdata
        return response

    def handle_query(self, data: bytes, addr: Tuple[str, int]):
        try:
            ptr = 12
            domain_parts = []
            while data[ptr] != 0:
                length = data[ptr]
                domain_parts.append(data[ptr+1:ptr+1+length].decode())
                ptr += 1 + length
            domain = '.'.join(domain_parts)
            qtype_val = int.from_bytes(data[ptr+1:ptr+3], 'big')
            qtype_str = REVERSE_QTYPE.get(qtype_val)

            if not qtype_str:
                print(f"[!] Unsupported query type: {qtype_val}")
                return

            print(f"[>] {qtype_str} query for {domain} from {addr}")
            records = self.get_records(domain, qtype_str)
            if records:
                response = self.build_response(data, records, qtype_str)
                self.socket.sendto(response, addr)
        except Exception as e:
            print(f"[!] Error handling query: {e}")

    def run(self):
        print("[*] DNS server running on 127.0.0.1:53")
        try:
            while True:
                data, addr = self.socket.recvfrom(512)
                self.handle_query(data, addr)
        except KeyboardInterrupt:
            print("\n[!] Server shutting down")
        finally:
            self.socket.close()


if __name__ == '__main__':
    server = DNSServer()
    server.run()

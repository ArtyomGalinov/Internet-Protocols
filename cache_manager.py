import os
import json
import datetime
from typing import Optional

CACHE_DIR = 'cache'


class DNSCache:
    def __init__(self):
        os.makedirs(CACHE_DIR, exist_ok=True)

    def _get_cache_file_path(self, domain: str, qtype: str) -> str:
        sanitized_domain = domain.replace('/', '_').replace('\\', '_')
        return os.path.join(CACHE_DIR, f"{sanitized_domain}_{qtype}.cfg")

    def get(self, domain: str, qtype: str) -> Optional[dict]:
        filename = os.path.join(CACHE_DIR, f"{domain}_{qtype}.json")
        if not os.path.exists(filename):
            return None

        with open(filename, 'r') as f:
            try:
                data = json.load(f)
                cache_time = datetime.datetime.fromisoformat(data['time'])
                if (datetime.datetime.now() - cache_time).total_seconds() > data['ttl']:
                    return None
                return data
            except Exception as e:
                print(f"Failed to load cache for {domain} {qtype}: {e}")
                return None

    def set(self, domain: str, qtype: str, data: dict):
        filename = os.path.join(CACHE_DIR, f"{domain}_{qtype}.json")
        print(f"[>] Saving cache for {domain} {qtype}")
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2)

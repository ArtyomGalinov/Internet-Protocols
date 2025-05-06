import os

GOOGLE_DNS = ('8.8.8.8', 53)
CACHE_DIR = 'cache'
CACHE_TTL = 300

os.makedirs(CACHE_DIR, exist_ok=True)

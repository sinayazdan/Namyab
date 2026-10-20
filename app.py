#!/usr/bin/env python3
"""NumberBox lookup - built from scratch (stdlib HTTP server, no Flask needed).
Reverse-engineered protocol of the NumberBox Android app (v7.9.3).
"""
import base64
import json
import os
import re
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests

# --- Crypto constants (extracted from the Android APK) ---
K128 = bytes.fromhex('b2c0d351067184fe')
IV128 = bytes.fromhex('7ae8be8095cbf86f22376ca61b516a5f')
K256 = bytes.fromhex('8f434346648f6a94df89dda901c5176b10a6d83960dd3b1ac88b59b2dc327aa4')
IV256 = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
FILE_SIZE = '52256768'
BASE = os.path.dirname(os.path.abspath(__file__))

with open(os.path.join(BASE, 'cert_b64.txt')) as f:
    CERT_DER_B64 = f.read().strip()
CERT_HEX = base64.b64decode(CERT_DER_B64).hex()


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    pad_len = 16 - (len(plaintext) % 16)
    plaintext += bytes([pad_len] * pad_len)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(plaintext) + enc.finalize()


def _stamp(prefix: str) -> str:
    return f"{prefix}|{uuid.uuid4()}|{int(time.time() * 1000)}"


def encrypt_one(text: str) -> str:
    inner = _stamp(CERT_HEX).encode('utf-8')
    cert_b64 = base64.b64encode(_aes_cbc_encrypt(K256, IV256, inner)).decode()
    outer = f"{_stamp(f'{text}|{cert_b64}')}|{FILE_SIZE}".encode('utf-8')
    rand8 = os.urandom(8)
    ct = _aes_cbc_encrypt(K128 + rand8, IV128, outer)
    return base64.b64encode(ct + rand8).decode()


def parse_phone(raw: str):
    raw = raw.strip()
    if not raw.startswith('+'):
        return None
    digits = re.sub(r'\D', '', raw)
    if len(digits) < 8 or len(digits) > 15:
        return None
    for cclen in (1, 2, 3):
        cc = digits[:cclen]
        national = digits[cclen:]
        if cc in ('1', '98', '44', '49', '33', '39', '34', '7', '90', '971', '966',
                  '91', '86', '81', '82', '61', '55', '52', '31', '46', '47', '48'):
            if len(national) >= 7:
                return cc, national
    return digits[:2], digits[2:]


def lookup(phone: str):
    parsed = parse_phone(phone)
    if not parsed:
        return {'error': 'Invalid phone number'}, 400
    cc, national = parsed
    payload = {
        'ccode': encrypt_one(f'%2B{cc}'),
        'number': encrypt_one(national),
        'version': '7.9.3',
    }
    try:
        r = requests.post(
            'https://api.numberbox.app/search',
            json=payload,
            headers={
                'User-Agent': 'okhttp/4.12.0',
                'Content-Type': 'application/json; charset=UTF-8',
                'Device': 'android',
            },
            timeout=30,
        )
        data = r.json()
        return data, r.status_code
    except Exception as e:
        return {'error': f'Network error: {e}'}, 502


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype='application/json'):
        if isinstance(body, str):
            body = body.encode('utf-8')
        self.send_response(code)
        self.send_header('Content-Type', ctype + '; charset=utf-8')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if urlparse(self.path).path in ('/', '/index.html'):
            with open(os.path.join(BASE, 'index.html'), 'rb') as f:
                self._send(200, f.read(), 'text/html')
        else:
            self._send(404, '{"error":"not found"}')

    def do_POST(self):
        if urlparse(self.path).path == '/api/search':
            length = int(self.headers.get('Content-Length', 0))
            try:
                body = json.loads(self.rfile.read(length) or b'{}')
            except Exception:
                body = {}
            phone = str(body.get('phone', '')).strip()
            data, status = lookup(phone)
            self._send(status, json.dumps(data, ensure_ascii=False))
        else:
            self._send(404, '{"error":"not found"}')


if __name__ == '__main__':
    srv = HTTPServer(('127.0.0.1', 8901), Handler)
    print('NumberBox listening on 127.0.0.1:8901', flush=True)
    srv.serve_forever()

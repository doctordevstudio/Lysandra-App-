"""Wire protocol (mirrors android Crypto.kt + native lib).

init    : client signs body with HMAC(APP_SECRET); server answers with a signed token.
session : sk = HMAC(APP_SECRET, "sk" || client_nonce || server_nonce)
requests: X-D device id, X-T unix ts, X-N nonce,
          X-S = HMAC(sk, METHOD|PATH|T|N|sha256(body))
bodies / responses: AES-256-GCM with sk, urlsafe-b64(iv12 || ct || tag)
"""
import hmac, hashlib, base64, os, json, time
from cachetools import TTLCache
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from . import settings

_nonces = TTLCache(maxsize=500_000, ttl=180)  # replay protection


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def hmac_hex(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha256).hexdigest()


def session_key(cn: bytes, sn: bytes) -> bytes:
    return hmac.new(settings.APP_SECRET, b"sk" + cn + sn, hashlib.sha256).digest()


def make_token(payload: dict) -> str:
    raw = b64e(json.dumps(payload, separators=(",", ":")).encode())
    return f"{raw}.{hmac_hex(settings.APP_SECRET, b'tok' + raw.encode())[:40]}"


def read_token(tok: str):
    try:
        raw, sig = tok.split(".", 1)
        good = hmac_hex(settings.APP_SECRET, b"tok" + raw.encode())[:40]
        if not hmac.compare_digest(sig, good):
            return None
        p = json.loads(b64d(raw))
        return p if p.get("exp", 0) > time.time() else None
    except Exception:
        return None


def encrypt(sk: bytes, obj) -> str:
    iv = os.urandom(12)
    data = json.dumps(obj, separators=(",", ":")).encode()
    return b64e(iv + AESGCM(sk).encrypt(iv, data, None))


def decrypt(sk: bytes, blob: str):
    raw = b64d(blob)
    return json.loads(AESGCM(sk).decrypt(raw[:12], raw[12:], None))


def check_nonce(device: str, nonce: str, ts: int) -> bool:
    if abs(time.time() - ts) > 60:
        return False
    k = f"{device}:{nonce}"
    if k in _nonces:
        return False
    _nonces[k] = 1
    return True


def sign_request(sk: bytes, method: str, path: str, ts: str, nonce: str, body: bytes) -> str:
    msg = f"{method}|{path}|{ts}|{nonce}|{hashlib.sha256(body).hexdigest()}".encode()
    return hmac_hex(sk, msg)

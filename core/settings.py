import os, json

def env(k, d=""):
    return os.environ.get(k, d)

FIREBASE_DB_URL = env("FIREBASE_DB_URL").rstrip("/")
APP_SECRET = bytes.fromhex(env("APP_SECRET_HEX", "00" * 32))
ALLOWED_CERTS = {c.strip().lower() for c in env("ALLOWED_CERT_SHA256").split(",") if c.strip()}
ADMIN_USER = env("ADMIN_USER", "admin")
ADMIN_PASS = env("ADMIN_PASS")
SESSION_SECRET = env("SESSION_SECRET", "change-me").encode()
ORIGIN_SECRET = env("ORIGIN_SECRET")
YT_PROXY = env("YT_PROXY")
MAX_PARALLEL = int(env("MAX_PARALLEL_EXTRACT", "6"))
SESSION_IDLE_SECONDS = 15 * 60
ADMIN_LOCK_SECONDS = 24 * 3600
ADMIN_MAX_FAILS = 3
PLAY_INTEGRITY = env("PLAY_INTEGRITY_ENABLED") == "1"
PI_PACKAGE = env("PLAY_INTEGRITY_PACKAGE", "com.drdev.hamza")

def _j(k):
    try:
        return json.loads(env(k) or "null")
    except Exception:
        return None

FIREBASE_SA = _j("FIREBASE_SA_JSON")
GCP_SA = _j("GCP_SA_JSON")

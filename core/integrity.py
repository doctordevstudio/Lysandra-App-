"""Optional Play Integrity verification (PLAY_INTEGRITY_ENABLED=1)."""
import asyncio, httpx
from . import settings


async def verify(token: str, nonce_b64: str) -> bool:
    if not settings.PLAY_INTEGRITY:
        return True
    if not token or not settings.GCP_SA:
        return False
    from google.oauth2 import service_account
    from google.auth.transport.requests import Request
    creds = service_account.Credentials.from_service_account_info(
        settings.GCP_SA, scopes=["https://www.googleapis.com/auth/playintegrity"])
    await asyncio.to_thread(creds.refresh, Request())
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.post(f"https://playintegrity.googleapis.com/v1/{settings.PI_PACKAGE}:decodeIntegrityToken",
                         headers={"Authorization": f"Bearer {creds.token}"}, json={"integrity_token": token})
    if r.status_code != 200:
        return False
    p = r.json().get("tokenPayloadExternal", {})
    if p.get("requestDetails", {}).get("nonce") != nonce_b64:
        return False
    if p.get("requestDetails", {}).get("requestPackageName") != settings.PI_PACKAGE:
        return False
    return "MEETS_DEVICE_INTEGRITY" in p.get("deviceIntegrity", {}).get("deviceRecognitionVerdict", [])

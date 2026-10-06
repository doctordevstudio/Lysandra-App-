"""Firebase Realtime Database over REST (/path.json). URL never leaves the server.
If FIREBASE_SA_JSON is set, requests carry an OAuth token so you can lock rules to
{".read": false, ".write": false} (Admin credentials bypass rules)."""
import time, httpx
from . import settings

_client = httpx.AsyncClient(timeout=12, limits=httpx.Limits(max_connections=100, max_keepalive_connections=30))
_tok = {"v": None, "exp": 0}


async def _auth_params():
    if not settings.FIREBASE_SA:
        return {}
    if _tok["exp"] < time.time() + 60:
        from google.oauth2 import service_account
        from google.auth.transport.requests import Request
        import asyncio
        creds = service_account.Credentials.from_service_account_info(
            settings.FIREBASE_SA,
            scopes=["https://www.googleapis.com/auth/firebase.database",
                    "https://www.googleapis.com/auth/userinfo.email"])
        await asyncio.to_thread(creds.refresh, Request())
        _tok["v"], _tok["exp"] = creds.token, time.time() + 3000
    return {"access_token": _tok["v"]}


async def _req(method, path, params=None, json=None):
    p = await _auth_params()
    if params:
        p.update(params)
    r = await _client.request(method, f"{settings.FIREBASE_DB_URL}/{path.strip('/')}.json", params=p, json=json)
    r.raise_for_status()
    return r.json()


import json as _json


def _q(v):
    return _json.dumps(v)


async def get(path, **q):
    return await _req("GET", path, {k: (_q(v) if k in ("orderBy", "startAt", "endAt", "equalTo") else v)
                                    for k, v in q.items()} or None)


async def put(path, value):
    return await _req("PUT", path, json=value)


async def patch(path, value):
    return await _req("PATCH", path, json=value)


async def push(path, value):
    return (await _req("POST", path, json=value))["name"]


async def delete(path):
    return await _req("DELETE", path)


def inc(n=1):
    return {".sv": {"increment": n}}


async def page(path, limit=20, after=None, order="$key"):
    """Cursor pagination on $key. Returns (items[(key,val)], next_cursor)."""
    q = {"orderBy": order, "limitToFirst": limit + 1}
    if after:
        q["startAt"] = after
    data = await get(path, **q) or {}
    items = sorted(data.items(), key=lambda kv: kv[0])
    nxt = None
    if len(items) > limit:
        nxt = items[limit][0]
        items = items[:limit]
    return items, nxt

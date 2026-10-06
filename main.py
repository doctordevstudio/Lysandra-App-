import asyncio, hashlib, json, os, re, time, secrets, logging
from contextlib import asynccontextmanager
from cachetools import TTLCache
import httpx
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse, Response, FileResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from core import settings, crypto, db, integrity
from core.store import store
from core.batch import batch
from core.ratelimit import rl
from core import ipist
from extractors import registry
from extractors.base import normalize_url, host_of
import admin as admin_mod

log = logging.getLogger("lysandra")
sem = asyncio.Semaphore(settings.MAX_PARALLEL)
results = TTLCache(maxsize=2000, ttl=1800)    # rid -> {formats, proxy, host}
grants = TTLCache(maxsize=50_000, ttl=900)    # device -> {action, exp}
ad_starts = TTLCache(maxsize=50_000, ttl=600)
fetch_cache = TTLCache(maxsize=1000, ttl=600)  # normalized url -> rid
seen = TTLCache(maxsize=300_000, ttl=86400)
http = httpx.AsyncClient(timeout=None, follow_redirects=True, limits=httpx.Limits(max_connections=200))


@asynccontextmanager
async def lifespan(app):
    try:
        await store.load()
    except Exception as e:
        log.error("store load failed %s", e)
    t1 = asyncio.create_task(batch.loop())
    t2 = asyncio.create_task(refresh_loop())
    yield
    t1.cancel(); t2.cancel()
    await batch.flush()


async def refresh_loop():
    while True:
        await asyncio.sleep(300)  # safety net; admin writes reload immediately
        try:
            await store.load()
        except Exception:
            pass


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)


def client_ip(req: Request) -> str:
    return req.headers.get("cf-connecting-ip") or (req.client.host if req.client else "0.0.0.0")


@app.middleware("http")
async def guard(req: Request, call_next):
    p = req.url.path
    if settings.ORIGIN_SECRET and p != "/healthz":
        if not secrets.compare_digest(req.headers.get("x-origin-secret", ""), settings.ORIGIN_SECRET):
            return Response(status_code=403)
    resp = await call_next(req)
    resp.headers.update({"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
                         "Referrer-Policy": "no-referrer", "Cache-Control": "no-store",
                         "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                         "Content-Security-Policy": "default-src 'self'; img-src * data:; style-src 'self' 'unsafe-inline'; script-src 'self'; frame-ancestors 'none'"})
    return resp


@app.get("/healthz")
async def healthz():
    return {"ok": 1}


@app.get("/")
async def root():
    return RedirectResponse("/admin/")  # looks like nothing else; API is not discoverable


# ---------------------------------------------------------------- app protocol
def bad(code=404):
    # uniform, uninformative failure (do not help reverse engineers)
    return JSONResponse({"e": 1}, status_code=code)


@app.post("/v1/init")
async def init(req: Request):
    ip = client_ip(req)
    if not rl.hit(f"init:{ip}", 15):
        return bad(429)
    try:
        b = await req.json()
        d, cn, ts, cert, vc, info = b["d"], b["cn"], int(b["ts"]), b["cert"].lower(), int(b["vc"]), b["info"]
        pi = b.get("pi", "")
        msg = f"init|{d}|{cn}|{ts}|{cert}|{vc}|{hashlib.sha256(info.encode()).hexdigest()}".encode()
        if not crypto.hmac.compare_digest(crypto.hmac_hex(settings.APP_SECRET, msg), b["sig"]):
            return bad()
        if settings.ALLOWED_CERTS and cert not in settings.ALLOWED_CERTS:
            return bad()                                  # server-side APK signature verification
        if not crypto.check_nonce("init", cn, ts) or len(d) < 8 or len(d) > 64:
            return bad()
        if not await integrity.verify(pi, cn):
            return bad()
    except Exception:
        return bad()

    sn = os.urandom(16)
    tok = crypto.make_token({"d": d, "cn": cn, "sn": crypto.b64e(sn), "exp": time.time() + 3600, "vc": vc})
    sk = crypto.session_key(crypto.b64d(cn), sn)
    await record_launch(d, ip, info, vc, req.headers.get("user-agent", ""))
    cfg = store.cfg
    m = cfg["maintenance"]
    if m["enabled"]:
        today = ipist.today()
        batch.inc(f"stats/daily/{today}/maint_opens")
        batch.set(f"maint_users/{today}/{d}", ipist.ts())
    data = {
        "app": cfg["app"], "ads": cfg["ads"], "maintenance": m, "now": ipist.ts(),
        "apps": sorted(cfg["supported_apps"], key=lambda a: a.get("sort", 0)) if isinstance(cfg["supported_apps"], list)
        else sorted(cfg["supported_apps"].values(), key=lambda a: a.get("sort", 0)),
        "unread_hint": len(store.active(store.notifications)),
    }
    return {"t": tok, "sn": crypto.b64e(sn), "r": crypto.encrypt(sk, data)}


async def record_launch(d, ip, info, vc, ua):
    day, ts = ipist.today(), ipist.ts()
    known = await db.get(f"devices/{d}/first_seen")
    try:
        meta = json.loads(info)
    except Exception:
        meta = {}
    if known is None:
        batch.set(f"devices/{d}/first_seen", ts)
        batch.set(f"devices/{d}/first_ip", ip)
        batch.inc(f"stats/daily/{day}/new_users")
        batch.set(f"new_users_by_day/{day}/{d}", ts)
    batch.set(f"devices/{d}/last_seen", ts)
    batch.set(f"devices/{d}/ip", ip)
    batch.set(f"devices/{d}/info", meta)
    batch.set(f"devices/{d}/version", vc)
    batch.inc(f"devices/{d}/launches")
    batch.set(f"daily_active/{day}/{d}", ts)
    batch.set(f"device_logs/{d}/{ts}_{secrets.token_hex(3)}", {"ts": ts, "ip": ip, "ua": ua[:200], "event": "launch", "vc": vc})


async def secure(req: Request):
    """Verify token, signature, replay; return (device, sk, payload)."""
    h = req.headers
    tok = crypto.read_token(h.get("authorization", "")[7:])
    if not tok:
        raise HTTPException(401)
    d, t, n, s = h.get("x-d", ""), h.get("x-t", "0"), h.get("x-n", ""), h.get("x-s", "")
    if d != tok["d"] or not t.isdigit() or len(n) < 8:
        raise HTTPException(401)
    sk = crypto.session_key(crypto.b64d(tok["cn"]), crypto.b64d(tok["sn"]))
    body = await req.body()
    good = crypto.sign_request(sk, req.method, req.url.path, t, n, body)
    if not crypto.hmac.compare_digest(good, s) or not crypto.check_nonce(d, n, int(t)):
        raise HTTPException(401)
    if store.cfg.get("maintenance", {}).get("enabled"):
        raise HTTPException(503)
    payload = {}
    if body:
        try:
            payload = crypto.decrypt(sk, json.loads(body)["p"])
        except Exception:
            raise HTTPException(400)
    return d, sk, payload


def reply(sk, obj):
    return {"r": crypto.encrypt(sk, obj)}


@app.exception_handler(HTTPException)
async def http_exc(req, exc):
    return JSONResponse({"e": 1}, status_code=exc.status_code)


@app.post("/v1/home")
async def home(req: Request):
    d, sk, _ = await secure(req)
    return reply(sk, {"dialogs": store.active(store.dialogs), "carousels": store.active(store.carousels),
                      "now": ipist.ts()})


@app.post("/v1/notifications")
async def notifications(req: Request):
    d, sk, p = await secure(req)
    items = sorted(store.active(store.notifications), key=lambda x: -x.get("created", 0))
    off, lim = int(p.get("offset", 0)), 20
    return reply(sk, {"items": items[off:off + lim], "total": len(items), "more": off + lim < len(items)})


@app.post("/v1/event")
async def event(req: Request):
    d, sk, p = await secure(req)
    kind, iid, t = p.get("k"), str(p.get("id", "")), p.get("t")
    coll = {"dialog": "dialogs", "carousel": "carousels", "notif": "notifications"}.get(kind)
    if not coll or t not in ("view", "click") or not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", iid):
        raise HTTPException(400)
    ck = f"{kind}:{iid}:{d}:{t}"
    if ck in seen:
        return reply(sk, {"ok": 1})
    seen[ck] = 1
    ev = await db.get(f"{kind}_events/{iid}/{d}") or {}
    if t[0] in ev:
        return reply(sk, {"ok": 1})
    day, ts = ipist.today(), ipist.ts()
    batch.set(f"{kind}_events/{iid}/{d}/{t[0]}", ts)
    batch.inc(f"{coll}/{iid}/{t}s")
    batch.inc(f"stats/daily/{day}/{kind}_{t}")
    batch.set(f"ev_day/{kind}/{day}/{iid}__{d}/id", iid)
    batch.set(f"ev_day/{kind}/{day}/{iid}__{d}/d", d)
    batch.set(f"ev_day/{kind}/{day}/{iid}__{d}/{t[0]}", ts)
    return reply(sk, {"ok": 1})


@app.post("/v1/fetch")
async def fetch(req: Request):
    d, sk, p = await secure(req)
    if not rl.hit(f"fetch:{d}", 20):
        raise HTTPException(429)
    raw = p.get("u", "")
    if hashlib.sha256(raw.encode()).hexdigest() != p.get("h") or len(raw) > 2048:
        raise HTTPException(400)
    url = normalize_url(raw)
    host = host_of(url)
    day = ipist.today()
    if not host or "." not in host:
        return reply(sk, {"err": "Please enter a valid link."})
    blk = store.blocked_for(host)
    if blk:
        batch.inc(f"stats/daily/{day}/blocked_hits")
        batch.set(f"block_hits/{day}/{ipist.ts()}_{secrets.token_hex(3)}", {"d": d, "host": host, "ts": ipist.ts()})
        return reply(sk, {"blocked": True, "message": blk.get("message", "This domain is not supported.")})
    batch.inc(f"stats/daily/{day}/fetch_total")
    batch.inc(f"devices/{d}/fetch_count")
    ex = registry.pick(url)
    ck = hashlib.sha1(url.encode()).hexdigest()
    rid = fetch_cache.get(ck)
    if rid and rid in results:
        info = results[rid]["info"]
    else:
        try:
            async with sem:
                info = await asyncio.wait_for(ex.extract(url), 40)
            if not info.get("formats"):
                raise ValueError("no formats")
        except Exception as e:
            log.info("fetch failed %s %s", host, e)
            batch.inc(f"stats/daily/{day}/fetch_failed")
            return reply(sk, {"err": "Could not fetch this video. Try again later."})
        rid = secrets.token_urlsafe(10)
        results[rid] = {"info": info, "proxy": ex.proxy_stream, "host": host}
        fetch_cache[ck] = rid
    batch.inc(f"stats/daily/{day}/fetch_success")
    out = {"rid": rid, "title": info["title"], "thumbnail": info["thumbnail"], "duration": info["duration"],
           "uploader": info.get("uploader", ""), "host": host,
           "formats": [{"i": i, "label": f["label"], "ext": f["ext"], "size": f["size"], "video": f["video"]}
                       for i, f in enumerate(info["formats"])]}
    return reply(sk, out)


@app.post("/v1/ad")
async def ad(req: Request):
    d, sk, p = await secure(req)
    phase, net, kind, action = p.get("phase"), p.get("net", "startio"), p.get("kind", "rewarded"), p.get("action", "fetch")
    if net not in ("startio", "monetag") or kind not in ("interstitial", "rewarded") or action not in ("fetch", "watch", "download", "status", "nav"):
        raise HTTPException(400)
    day = ipist.today()
    if phase == "start":
        ad_starts[d] = time.time()
        return reply(sk, {"ok": 1})
    if phase != "done":
        raise HTTPException(400)
    if kind == "rewarded":
        st = ad_starts.pop(d, None)
        need = store.cfg["app"].get("min_ad_seconds", 12)
        if st is None or time.time() - st < need:
            return reply(sk, {"ok": 0})
        grants[d] = {"action": action, "exp": time.time() + 600}
    batch.inc(f"stats/daily/{day}/ad_{net}_{kind}_{action}")
    batch.inc(f"devices/{d}/ads_{kind}")
    return reply(sk, {"ok": 1})


@app.post("/v1/ticket")
async def ticket(req: Request):
    """Resolve a quality to a downloadable URL. Needs a rewarded-ad grant when ads are enabled."""
    d, sk, p = await secure(req)
    ads_on = store.cfg["ads"].get("enabled") and store.cfg["ads"].get("rewarded")
    if ads_on:
        g = grants.pop(d, None)
        if not g or g["exp"] < time.time():
            return reply(sk, {"err": "ad_required"})
    r = results.get(p.get("rid"))
    try:
        f = r["info"]["formats"][int(p["i"])]
    except Exception:
        return reply(sk, {"err": "expired"})
    base = f"{req.url.scheme}://{req.headers.get('host', req.url.netloc)}"
    base = base.replace("http://", "https://")
    name = "".join(c for c in r["info"]["title"] if c.isalnum() or c in " -_")[:60].strip() or "video"
    out = {"name": f"{name}.{f['ext']}", "size": f["size"], "ext": f["ext"], "headers": f["headers"]}
    if r["proxy"]:
        tok = crypto.make_token({"rid": p["rid"], "i": int(p["i"]), "exp": time.time() + 3 * 3600})
        out.update(url=f"{base}/v1/s/{tok}", proxied=True, headers={})
    else:
        out.update(url=f["url"], proxied=False)
    return reply(sk, out)


@app.api_route("/v1/s/{tok}", methods=["GET", "HEAD"])
async def stream(tok: str, req: Request):
    t = crypto.read_token(tok)
    r = results.get(t["rid"]) if t else None
    if not r:
        return bad(404)
    f = r["info"]["formats"][t["i"]]
    hdrs = dict(f["headers"])
    if "range" in req.headers:
        hdrs["Range"] = req.headers["range"]
    px = settings.YT_PROXY or None
    c = httpx.AsyncClient(timeout=None, follow_redirects=True, proxy=px) if px else http
    up = await c.send(c.build_request(req.method, f["url"], headers=hdrs), stream=True)
    keep = {k: v for k, v in up.headers.items() if k.lower() in
            ("content-type", "content-length", "content-range", "accept-ranges")}

    async def gen():
        try:
            async for chunk in up.aiter_raw(65536):
                yield chunk
        finally:
            await up.aclose()
            if c is not http:
                await c.aclose()
    return StreamingResponse(gen(), status_code=up.status_code, headers=keep)


# ---------------------------------------------------------------- admin
app.include_router(admin_mod.router)
app.mount("/admin", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "admin_ui"), html=True), name="admin")

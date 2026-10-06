import asyncio, hashlib, re, secrets, time, datetime as dt
import bcrypt
from fastapi import APIRouter, Request, HTTPException, Response
from pydantic import BaseModel
from core import settings, db, ipist
from core.store import store, DEFAULTS
from core.batch import batch

router = APIRouter(prefix="/admin/api")
S = {"sid": None, "csrf": None, "last": 0, "fp": None}        # exactly one active session
fails = {}                                                     # fpkey -> count
_cache = {}


def ip_of(req):
    return req.headers.get("cf-connecting-ip") or (req.client.host if req.client else "?")


async def alog(kind, req, **kw):
    ts = ipist.ts()
    await db.put(f"admin_logs/{ts}_{secrets.token_hex(3)}", {"ts": ts, "type": kind, "ip": ip_of(req), **kw})


def fpkey(req, fp):
    return hashlib.sha256((fp + req.headers.get("user-agent", "")).encode()).hexdigest()[:32]


class Login(BaseModel):
    u: str
    p: str
    fp: str = ""


@router.post("/login")
async def login(b: Login, req: Request, res: Response):
    k = fpkey(req, b.fp)
    lock = await db.get(f"admin_locks/{k}")
    now = time.time()
    if lock and lock.get("until", 0) > now:
        await alog("login", req, ok=False, fp=k, note="locked")
        raise HTTPException(423, "Device locked for 24 hours")
    ok = (secrets.compare_digest(b.u.encode(), settings.ADMIN_USER.encode())
          and settings.ADMIN_PASS_BCRYPT
          and await asyncio.to_thread(bcrypt.checkpw, b.p.encode(), settings.ADMIN_PASS_BCRYPT))
    await alog("login", req, ok=bool(ok), fp=k, ua=req.headers.get("user-agent", "")[:160])
    if not ok:
        fails[k] = fails.get(k, 0) + 1
        await asyncio.sleep(1.0)
        if fails[k] >= settings.ADMIN_MAX_FAILS:
            await db.put(f"admin_locks/{k}", {"until": now + settings.ADMIN_LOCK_SECONDS, "ip": ip_of(req)})
            fails.pop(k, None)
            raise HTTPException(423, "Too many attempts. Device locked for 24 hours")
        raise HTTPException(401, f"Invalid credentials ({settings.ADMIN_MAX_FAILS - fails[k]} left)")
    fails.pop(k, None)
    S.update(sid=secrets.token_urlsafe(32), csrf=secrets.token_urlsafe(24), last=now, fp=k)  # kicks any older session
    res.set_cookie("sid", S["sid"], httponly=True, secure=True, samesite="strict", path="/admin")
    return {"csrf": S["csrf"], "idle": settings.SESSION_IDLE_SECONDS}


async def auth(req: Request):
    sid = req.cookies.get("sid")
    if not S["sid"] or not sid or not secrets.compare_digest(sid, S["sid"]):
        raise HTTPException(401, "auth")
    if time.time() - S["last"] > settings.SESSION_IDLE_SECONDS:
        S["sid"] = None
        raise HTTPException(401, "expired")
    if req.method != "GET" and not secrets.compare_digest(req.headers.get("x-csrf", ""), S["csrf"] or ""):
        raise HTTPException(403, "csrf")
    S["last"] = time.time()


def guard():
    from fastapi import Depends
    return Depends(auth)


@router.post("/logout")
async def logout(req: Request, res: Response):
    await auth(req)
    S["sid"] = None
    res.delete_cookie("sid", path="/admin")
    return {"ok": 1}


@router.get("/me", dependencies=[guard()])
async def me():
    return {"csrf": S["csrf"], "left": settings.SESSION_IDLE_SECONDS, "now": ipist.today()}


# ---------------------------------------------------------------- stats
def days(a, b):
    d0, d1 = dt.date.fromisoformat(a), dt.date.fromisoformat(b)
    return [(d0 + dt.timedelta(n)).isoformat() for n in range((d1 - d0).days + 1)][:400]


def total(daily, keys):
    out = {}
    for k in keys:
        for m, v in (daily.get(k) or {}).items():
            out[m] = out.get(m, 0) + (v or 0)
    return out


async def all_daily():
    c = _cache.get("daily")
    if c and time.time() - c[0] < 8:
        return c[1]
    d = await db.get("stats/daily") or {}
    _cache["daily"] = (time.time(), d)
    return d


@router.get("/dashboard", dependencies=[guard()])
async def dashboard(frm: str = "", to: str = ""):
    daily, t, y = await all_daily(), ipist.today(), ipist.yesterday()
    out = {"today": total(daily, [t]), "yesterday": total(daily, [y]), "all": total(daily, list(daily))}
    if frm and to:
        out["range"] = total(daily, days(frm, to))
    yact = await db.get(f"daily_active/{y}", shallow="true") or {}
    tact = await db.get(f"daily_active/{t}", shallow="true") or {}
    out["yesterday_active_today"] = len(set(yact) & set(tact))
    out["yesterday_active"] = len(yact)
    out["active_today"] = len(tact)
    out["total_users"] = len(await db.get("devices", shallow="true") or {})
    return out


async def top_users():
    try:
        d = await db.get("devices", orderBy="fetch_count", limitToLast=50) or {}
    except Exception:
        d = await db.get("devices") or {}
    rows = [{"d": k, "fetch": v.get("fetch_count", 0), "ip": v.get("ip"), "info": v.get("info"),
             "inter": v.get("ads_interstitial", 0), "rew": v.get("ads_rewarded", 0)} for k, v in d.items()]
    rows.sort(key=lambda r: -r["fetch"])
    for r in rows:
        r["ads"] = r["inter"] + r["rew"]
    return rows[:50]


@router.get("/top-users", dependencies=[guard()])
async def top_users_ep():
    return await top_users()


@router.get("/user", dependencies=[guard()])
async def user(d: str, cursor: str = ""):
    dev = await db.get(f"devices/{d}")
    logs, nxt = await db.page(f"device_logs/{d}", 30, cursor or None)
    return {"device": dev, "logs": [v for _, v in logs], "next": nxt}


SOURCES = {"new_users": "new_users_by_day/{day}", "active": "daily_active/{day}", "blocked": "block_hits/{day}",
           "maint": "maint_users/{day}", "dialog": "ev_day/dialog/{day}", "carousel": "ev_day/carousel/{day}",
           "notif": "ev_day/notif/{day}"}


@router.get("/list", dependencies=[guard()])
async def listing(what: str, frm: str = "", to: str = "", cursor: str = ""):
    """Paginated user lists for any dashboard counter. frm/to = single day, a range, or 'all'."""
    if what not in SOURCES:
        raise HTTPException(400)
    if what == "new_users" and frm == "all":
        items, nxt = await db.page("devices", 20, cursor or None)
        return {"rows": [{"d": k, "ts": v.get("first_seen"), "ip": v.get("ip")} for k, v in items], "next": nxt}
    ds = days(frm, to or frm)
    if len(ds) == 1:
        items, nxt = await db.page(SOURCES[what].format(day=ds[0]), 20, cursor or None)
        return {"rows": [norm_row(k, v) for k, v in items], "next": nxt}
    rows = []
    for dd in ds[:31]:
        data = await db.get(SOURCES[what].format(day=dd)) or {}
        rows += [norm_row(k, v) for k, v in data.items()]
    off = int(cursor or 0)
    return {"rows": rows[off:off + 20], "next": str(off + 20) if off + 20 < len(rows) else None}


def norm_row(k, v):
    if isinstance(v, dict):
        return {"d": v.get("d") or v.get("id") or k, **v}
    return {"d": k, "ts": v}


# ---------------------------------------------------------------- items (notif / dialog / carousel)
KINDS = {"notif": "notifications", "dialog": "dialogs", "carousel": "carousels"}
FIELDS = {"notif": ("image", "title", "message", "url"), "dialog": ("image", "message", "url", "sort"),
          "carousel": ("image", "url", "sort")}


def clean(kind, b: dict):
    out = {}
    for f in FIELDS[kind]:
        v = b.get(f, "")
        if f == "sort":
            v = int(v or 0)
        else:
            v = str(v or "").strip()[:4000]
            if f in ("image", "url") and v and not re.match(r"^(https?://|tg://)", v):
                raise HTTPException(400, f"{f} must start with http(s)://")
        out[f] = v
    if kind == "dialog":
        out["type"] = "imagewithtext" if out["image"] and out["message"] else ("image" if out["image"] else "text")
    if kind == "notif" and not (out["title"] or out["message"]):
        raise HTTPException(400, "title or message required")
    return out


async def make_room(coll, sort, skip=None):
    """Insert at `sort`; push the chain of colliding items down (2->3, 3->4 ...)."""
    items = await db.get(coll) or {}
    by = sorted(((v.get("sort", 0), k) for k, v in items.items() if k != skip))
    cur, upd = sort, {}
    for s, k in by:
        if s < cur:
            continue
        if s == cur:
            cur += 1
            upd[f"{coll}/{k}/sort"] = cur
        else:
            break
    if upd:
        await db.patch("", upd)


async def reload():
    await store.load()
    _cache.clear()


@router.get("/items/{kind}", dependencies=[guard()])
async def items(kind: str, frm: str = "", to: str = ""):
    coll = KINDS[kind]
    data = await db.get(coll) or {}
    rows = sorted(({"id": k, **v} for k, v in data.items()), key=lambda r: (r.get("sort", 0), -r.get("created", 0)))
    daily = await all_daily()
    key = lambda s: total(daily, s)
    sk = lambda m: {"today": key([ipist.today()]).get(m, 0), "yesterday": key([ipist.yesterday()]).get(m, 0),
                    "all": key(list(daily)).get(m, 0), "range": key(days(frm, to)).get(m, 0) if frm and to else None}
    return {"rows": rows, "views": sk(f"{kind}_view"), "clicks": sk(f"{kind}_click")}


@router.get("/items/{kind}/{iid}/users", dependencies=[guard()])
async def item_users(kind: str, iid: str, cursor: str = ""):
    rows, nxt = await db.page(f"{kind}_events/{iid}", 20, cursor or None)
    return {"rows": [{"d": k, **v} for k, v in rows], "next": nxt}


@router.post("/items/{kind}", dependencies=[guard()])
async def create_item(kind: str, b: dict, req: Request):
    coll, f = KINDS[kind], clean(kind, b)
    if kind != "notif":
        await make_room(coll, f["sort"])
    iid = secrets.token_hex(6)
    await db.put(f"{coll}/{iid}", {**f, "enabled": True, "created": ipist.ts(), "views": 0, "clicks": 0})
    await alog("create", req, kind=kind, id=iid)
    await reload()
    return {"id": iid}


@router.put("/items/{kind}/{iid}", dependencies=[guard()])
async def edit_item(kind: str, iid: str, b: dict, req: Request):
    coll, f = KINDS[kind], clean(kind, b)
    if kind != "notif":
        await make_room(coll, f["sort"], skip=iid)
    await db.patch(f"{coll}/{iid}", f)
    await alog("edit", req, kind=kind, id=iid)
    await reload()
    return {"ok": 1}


@router.post("/items/{kind}/{iid}/toggle", dependencies=[guard()])
async def toggle_item(kind: str, iid: str, req: Request):
    coll = KINDS[kind]
    cur = await db.get(f"{coll}/{iid}/enabled")
    await db.put(f"{coll}/{iid}/enabled", not (cur is not False))
    await alog("toggle", req, kind=kind, id=iid)
    await reload()
    return {"enabled": cur is False}


@router.delete("/items/{kind}/{iid}", dependencies=[guard()])
async def del_item(kind: str, iid: str, req: Request):
    await db.delete(f"{KINDS[kind]}/{iid}")
    await alog("delete", req, kind=kind, id=iid)
    await reload()
    return {"ok": 1}


# ---------------------------------------------------------------- block
class Block(BaseModel):
    domains: str
    message: str


@router.get("/block", dependencies=[guard()])
async def block_list(frm: str = "", to: str = ""):
    daily = await all_daily()
    h = lambda s: total(daily, s).get("blocked_hits", 0)
    return {"rows": [{"domain": k, **v} for k, v in (await db.get("blocked_domains") or {}).items()],
            "hits": {"today": h([ipist.today()]), "yesterday": h([ipist.yesterday()]), "all": h(list(daily)),
                     "range": h(days(frm, to)) if frm and to else None}}


@router.post("/block", dependencies=[guard()])
async def block_add(b: Block, req: Request):
    doms = {re.sub(r"^(https?://)?(www\.)?", "", d.strip().lower()).split("/")[0]
            for d in re.split(r"[\s,;]+", b.domains) if d.strip()}
    doms = {d for d in doms if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", d)}
    if not doms:
        raise HTTPException(400, "no valid domain")
    for d in doms:
        await db.put(f"blocked_domains/{d.replace('.', ',')}", {"domain": d, "message": b.message[:4000], "ts": ipist.ts()})
    await alog("block_add", req, domains=sorted(doms))
    await reload()
    return {"added": sorted(doms)}


@router.delete("/block/{key}", dependencies=[guard()])
async def block_del(key: str, req: Request):
    await db.delete(f"blocked_domains/{key}")
    await alog("block_del", req, key=key)
    await reload()
    return {"ok": 1}


# ---------------------------------------------------------------- settings
@router.get("/settings", dependencies=[guard()])
async def settings_get():
    raw = await db.get("config") or {}
    return {k: ({**v, **(raw.get(k) or {})} if isinstance(v, dict) else (raw.get(k) or v)) for k, v in DEFAULTS.items()}


@router.put("/settings/{section}", dependencies=[guard()])
async def settings_put(section: str, b: dict | list, req: Request):
    if section not in DEFAULTS:
        raise HTTPException(404)
    await db.put(f"config/{section}", b)
    await alog("settings", req, section=section)
    await reload()
    return {"ok": 1}


@router.get("/admin-logs", dependencies=[guard()])
async def admin_logs(cursor: str = ""):
    rows, nxt = await db.page("admin_logs", 30, cursor or None)
    return {"rows": [v for _, v in reversed(rows)], "next": nxt}


@router.get("/maintenance-stats", dependencies=[guard()])
async def maint_stats(frm: str = "", to: str = ""):
    daily = await all_daily()
    m = lambda s: total(daily, s).get("maint_opens", 0)
    return {"today": m([ipist.today()]), "yesterday": m([ipist.yesterday()]), "all": m(list(daily)),
            "range": m(days(frm, to)) if frm and to else None}

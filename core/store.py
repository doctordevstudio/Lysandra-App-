"""In-memory config cache. Reloaded on every admin write -> zero DB reads per app request."""
import time, asyncio
from . import db

DEFAULTS = {
    "app": {
        "app_name": "Lysandra", "min_version_code": 1, "latest_version": "1.0.0",
        "update_url": "https://t.me/lysandraapp",
        "update_message": "Latest version available. Please download it from our Telegram channel.",
        "share_url": "https://GitHub.com/doctordevstudio/myapp/lysandraapp.apk",
        "support_url": "https://t.me/drdevsupportbot", "hire_url": "https://t.me/drdevsupportapp",
        "developer_name": "Dr. Dev || Dr. Hamza", "developer_image": "",
        "developer_bio": "My name is Dr. Dev || Dr. Hamza currently NEET 1st year dropper student. I know python, java, php, kotlin, js. If you want to hire me for making Website, App, Telegram Bot, Automation then contact me on Telegram. $30/hour.",
        "privacy_html": "<h2>Privacy Policy</h2><p>Edit me in admin panel.</p>",
        "terms_html": "<h2>Terms and Conditions</h2><p>Edit me in admin panel.</p>",
        "how_to_html": "<ol><li>Open a video in any app/site and copy its link</li><li>Paste it in Lysandra and tap Fetch</li><li>Pick a quality and tap Download</li></ol>",
        "supported_note": "1000+ platforms supported",
        "min_ad_seconds": 12, "theme": "dark",
    },
    "ads": {
        "enabled": True, "startio_app_id": "205489527", "monetag_direct_url": "https://omg10.com/4/11957070",
        "banner": True, "native": True, "interstitial": True, "rewarded": True, "monetag_fallback": True,
        "interstitial_cooldown_s": 45,
    },
    "maintenance": {"enabled": False, "message": "<b>We'll be back soon.</b>"},
    "supported_apps": [],  # {name,url,icon,sort,highlight}
}


class Store:
    def __init__(self):
        self.cfg = {}
        self.notifications, self.dialogs, self.carousels, self.blocked = {}, {}, {}, {}
        self.loaded = 0

    async def load(self):
        raw = await db.get("config") or {}
        cfg = {}
        for k, v in DEFAULTS.items():
            cfg[k] = {**v, **(raw.get(k) or {})} if isinstance(v, dict) else (raw.get(k) or v)
        self.cfg = cfg
        self.notifications = await db.get("notifications") or {}
        self.dialogs = await db.get("dialogs") or {}
        self.carousels = await db.get("carousels") or {}
        rawb = await db.get("blocked_domains") or {}
        self.blocked = {v["domain"]: v for v in rawb.values() if isinstance(v, dict) and "domain" in v}
        self.loaded = time.time()

    def active(self, coll):
        items = [{"id": k, **v} for k, v in coll.items() if v.get("enabled", True)]
        return sorted(items, key=lambda x: (x.get("sort", 0), x.get("created", 0)))

    def blocked_for(self, host: str):
        host = host.lower()
        while host:
            if host in self.blocked:
                return self.blocked[host]
            host = host.partition(".")[2]
        return None


store = Store()

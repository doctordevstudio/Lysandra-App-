import hashlib
from .base import Extractor


class TeraboxExtractor(Extractor):
    """DUMMY implementation - replace `extract` body with your real API call.
    Shows the contract every custom extractor must follow."""
    name = "terabox"
    domains = ("terabox.com", "teraboxapp.com", "tera1024.com", "1024tera.com", "4funbox.com",
               "mirrobox.com", "nephobox.com", "terabox.app", "teraboxlink.com")

    async def extract(self, url: str) -> dict:
        # TODO: call your own Terabox resolver here, e.g.
        #   async with httpx.AsyncClient() as c: r = await c.get(MY_API, params={"url": url})
        sid = hashlib.md5(url.encode()).hexdigest()[:8]
        return {"title": f"Terabox demo {sid}", "thumbnail": "", "duration": 0, "uploader": "terabox",
                "formats": [{"label": "Original", "ext": "mp4", "size": 0,
                             "url": "https://example.com/dummy.mp4", "video": True, "audio": True,
                             "h": 0, "headers": {}}]}

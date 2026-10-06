import asyncio
from yt_dlp import YoutubeDL
from .base import Extractor


def _fmt_size(f):
    return f.get("filesize") or f.get("filesize_approx") or 0


def shape(info: dict) -> dict:
    """Convert a yt-dlp info dict into Lysandra's wire shape. Direct (http/https) files only."""
    out = []
    for f in info.get("formats") or []:
        if not f.get("url") or f.get("protocol") not in ("https", "http"):
            continue
        v, a = f.get("vcodec", "none") != "none", f.get("acodec", "none") != "none"
        if not (v or a) or (v and not a):   # skip video-only (needs ffmpeg merge on device)
            continue
        h = f.get("height") or 0
        label = f"{h}p" if v and h else (f"Audio {int(f.get('abr') or 0)}kbps" if not v else "Video")
        out.append({"label": label, "ext": f.get("ext") or "mp4", "size": _fmt_size(f), "url": f["url"],
                    "video": v, "audio": a, "h": h, "headers": f.get("http_headers") or {}})
    # de-duplicate by label keeping the largest, sort best first
    best = {}
    for o in out:
        if o["label"] not in best or o["size"] > best[o["label"]]["size"]:
            best[o["label"]] = o
    fmts = sorted(best.values(), key=lambda o: (not o["video"], -o["h"]))
    return {"title": info.get("title") or "Video", "thumbnail": info.get("thumbnail") or "",
            "duration": int(info.get("duration") or 0), "uploader": info.get("uploader") or "",
            "formats": fmts}


class YtDlpExtractor(Extractor):
    """Fallback for 1000+ sites. Also the base of the YouTube extractor."""
    name = "yt-dlp"
    domains = ()
    proxy = None

    def opts(self):
        o = {"quiet": True, "no_warnings": True, "noplaylist": True, "skip_download": True,
             "socket_timeout": 15, "retries": 2, "extract_flat": False}
        if self.proxy:
            o["proxy"] = self.proxy
        return o

    def _run(self, url):
        with YoutubeDL(self.opts()) as ydl:
            return ydl.extract_info(url, download=False)

    async def extract(self, url: str) -> dict:
        info = await asyncio.to_thread(self._run, url)
        if info.get("_type") == "playlist" and info.get("entries"):
            info = next(e for e in info["entries"] if e)
        return shape(info)

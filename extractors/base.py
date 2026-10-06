import re
from urllib.parse import urlparse


def normalize_url(raw: str) -> str:
    raw = (raw or "").strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "https://" + raw
    return raw


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower().lstrip(".")


def domain_matches(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


class Extractor:
    """Subclass this. Set `domains` and implement `extract`. See docs/ADDING_EXTRACTORS.md"""
    name = "base"
    domains: tuple = ()
    proxy_stream = False  # True => media URLs are IP-bound; app downloads through /v1/stream

    async def extract(self, url: str) -> dict:
        """Return {title, thumbnail, duration, uploader, formats:[{id,label,ext,size,url,
        audio:bool,video:bool,headers:{}}]}"""
        raise NotImplementedError

"""Route a URL to the right extractor. To add a site: write a class, add it to CUSTOM below."""
from .base import domain_matches, host_of
from .youtube import YouTubeExtractor
from .terabox import TeraboxExtractor
from .ytdlp_generic import YtDlpExtractor

CUSTOM = [YouTubeExtractor(), TeraboxExtractor()]
FALLBACK = YtDlpExtractor()


def pick(url: str):
    host = host_of(url)
    for ex in CUSTOM:
        if domain_matches(host, ex.domains):
            return ex
    return FALLBACK

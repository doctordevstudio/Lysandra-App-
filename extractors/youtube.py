from core import settings
from .ytdlp_generic import YtDlpExtractor


class YouTubeExtractor(YtDlpExtractor):
    name = "youtube"
    domains = ("youtube.com", "youtu.be", "youtube-nocookie.com", "music.youtube.com")
    proxy_stream = True  # googlevideo URLs are bound to the IP that extracted them

    @property
    def proxy(self):
        return settings.YT_PROXY or None

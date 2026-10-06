"""Write-behind batcher: collects counters / sets and flushes ONE multi-path PATCH every few seconds.
Keeps Firebase writes low and endpoint latency near zero."""
import asyncio, logging
from . import db

log = logging.getLogger("batch")


class Batcher:
    def __init__(self):
        self.incs, self.sets = {}, {}

    def inc(self, path, n=1):
        self.incs[path] = self.incs.get(path, 0) + n

    def set(self, path, value):
        self.sets[path] = value

    async def flush(self):
        if not (self.incs or self.sets):
            return
        incs, sets, self.incs, self.sets = self.incs, self.sets, {}, {}
        payload = {p: db.inc(n) for p, n in incs.items()}
        payload.update(sets)
        try:
            await db.patch("", payload)
        except Exception as e:  # re-queue on failure
            log.warning("flush failed: %s", e)
            for p, n in incs.items():
                self.inc(p, n)
            for p, v in sets.items():
                self.sets.setdefault(p, v)

    async def loop(self, every=3):
        while True:
            await asyncio.sleep(every)
            await self.flush()


batch = Batcher()

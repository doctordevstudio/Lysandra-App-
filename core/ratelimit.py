import time
from collections import defaultdict, deque


class RateLimiter:
    def __init__(self):
        self.h = defaultdict(deque)

    def hit(self, key, limit, window=60) -> bool:
        q, now = self.h[key], time.time()
        while q and q[0] < now - window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        if len(self.h) > 50_000:
            self.h.clear()
        return True


rl = RateLimiter()

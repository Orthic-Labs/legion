# Sample code change for council smoke test.
# Pretend this is a PR adding a global rate-limit gate to a streaming audio capture path.

import time
from collections import deque

class AudioRateLimiter:
    """Drops samples if the producer is faster than 16kHz +/- 5%."""
    MAX_RATE_HZ = 16800   # locked: 5% above nominal
    WINDOW_S = 1.0

    def __init__(self):
        self.timestamps = deque()

    def admit(self, sample) -> bool:
        now = time.time()
        # purge old
        while self.timestamps and now - self.timestamps[0] > self.WINDOW_S:
            self.timestamps.popleft()
        if len(self.timestamps) >= self.MAX_RATE_HZ:
            return False  # silently drop
        self.timestamps.append(now)
        return True

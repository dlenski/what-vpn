import requests

class TimeoutSession(requests.Session):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.timeout = None
    def request(self, *a, **kw):
        kw.setdefault('timeout', self.timeout)
        return super().request(*a, **kw)

class SnifferSession(TimeoutSession):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        del self.headers['user-agent']
        self.verify = False

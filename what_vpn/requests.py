import requests

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager
import ssl

# https://lukasa.co.uk/2013/01/Choosing_SSL_Version_In_Requests/
class SSLVersionAdapter(HTTPAdapter):
    '''An HTTPS Transport Adapter that uses an arbitrary SSL version.'''
    SSLv23 = ssl.PROTOCOL_SSLv23
    TLSv1 = ssl.PROTOCOL_TLSv1
    TLSv1_1 = ssl.PROTOCOL_TLSv1_1
    TLSv1_2 = ssl.PROTOCOL_TLSv1_2

    def __init__(self, ssl_version=None, **kwargs):
        self.ssl_version = ssl_version
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_version=self.ssl_version)

class TimeoutSession(requests.Session):
    def __init__(self, *a, **kw):
        self.timeout = kw.pop('timeout', None)
        super().__init__(*a, **kw)
    def request(self, *a, **kw):
        kw.setdefault('timeout', self.timeout)
        return super().request(*a, **kw)

class SnifferSession(TimeoutSession):
    def __init__(self, *a, **kw):
        ssl_version = kw.pop('ssl_version', None)
        super().__init__(*a, **kw)
        del self.headers['user-agent']
        self.verify = False
        if ssl_version:
            self.mount('https://', SSLVersionAdapter(ssl_version))

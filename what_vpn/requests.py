import requests

from requests.adapters import HTTPAdapter
from urllib3 import PoolManager
import ssl


# https://lukasa.co.uk/2013/01/Choosing_SSL_Version_In_Requests/
# https://github.com/psf/requests/issues/4775#issuecomment-478198879
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
        ssl_context = ssl.SSLContext(self.ssl_version) if self.ssl_version else ssl.SSLContext()
        ssl_context.set_ciphers('DEFAULT@SECLEVEL=0')
        ssl_context.options |= 1<<2  # OP_LEGACY_SERVER_CONNECT
        self.poolmanager = PoolManager(num_pools=connections,
                                       maxsize=maxsize,
                                       block=block,
                                       ssl_context=ssl_context)


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
        self.mount('https://', SSLVersionAdapter(ssl_version))

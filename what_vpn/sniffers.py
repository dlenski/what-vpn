from contextlib import closing
from urllib.parse import urlsplit
import re
import attr

@attr.s
class Hit(object):
    def __bool__(self):
        return self.confidence > 0.0

    @property
    def details(self):
        strings = []
        if self.name:
            strings.append(self.name)
        if self.version:
            strings.append(self.version)
        if self.components:
            strings.append('+'.join(self.components))
        if self.confidence < 1.0:
            strings.append('%d%%' % (self.confidence*100))
        return ', '.join(strings)

    confidence = attr.ib(default=1.0, validator=attr.validators.instance_of(float))
    name = attr.ib(default=None)
    version = attr.ib(default=None)
    components = attr.ib(default=None)

def _meaningless(x, *vals):
    if x not in vals:
        return x

def global_protect(sess, server):
    '''PAN GlobalProtect'''
    # with closing(sess.get('https://{}/ssl-tunnel-connect.sslvpn'.format(server), stream=True)) as r:
    #    if r.status_code==502:
    #        components.append('gateway')

    components = []
    version = hit = None

    for component, path in (('portal','global-protect'), ('gateway','ssl-vpn')):
        r = sess.get('https://{}/{}/prelogin.esp'.format(server, path), headers={'user-agent':'PAN GlobalProtect'})
        if r.headers.get('content-type','').startswith('application/xml') and b'<prelogin-response>' in r.content:
            hit = True

            if b'<status>Success</status>' in r.content:
                components.append(component)
            m = re.search(rb'<panos-version>([^<]+)</panos-version>', r.content)
            if m:
                version = m.group(1).decode()

    if hit:
        return Hit(components=components, version=_meaningless(version, '1'))

# Juniper is frustrating because mostly it just spits out standard HTML, sometimes along with DS* cookies
def juniper_nc(sess, server):
    '''Juniper Network Connect'''

    confidence = None
    r = sess.get('https://{}/dana-na'.format(server), headers={'user-agent':'ncsrv', 'NCP-Version': '3'})
    if any(c.name.startswith('DS') for c in sess.cookies):
        confidence = 1.0
    elif urlsplit(r.url).path.startswith('/dana-na/auth/'):
        confidence = 0.8

    return confidence and Hit(confidence=confidence)

# Similar to Juniper
def barracuda(sess, server):
    '''Barracuda'''

    r = sess.get('https://{}'.format(server))

    m = re.search(rb'(\d+-)?(\d+)\s+Barracuda Networks', r.content)
    version = m and m.group(2).decode()

    confidence = None
    if 'SSLX_SSESHID' in sess.cookies:
        confidence = 1.0
    elif urlsplit(r.url).path.startswith('/default/showLogon.do'):
        confidence = 0.9 if version else 0.8
    elif version:
        confidence = 0.2

    return confidence and Hit(version=version, confidence=confidence)

def check_point(sess, server):
    '''Check Point'''
    confidence = version = None

    # Try an empty client request in Check Point's parenthesis-heavy format
    r = sess.post('https://{}/clients/abc'.format(server), headers={'user-agent':'TRAC/986000125'}, data=b'(CCCclientRequest)')
    if r.content.startswith(b'(CCCserverResponse'):
        confidence = 1.0

    r = sess.get('https://{}/'.format(server), headers={'user-agent':'TRAC/986000125'})
    m = re.search(rb'(\d+-)?(\d+).+Check Point Software Technologies', r.content)
    if m:
        version = m.group(2).decode()
        confidence = confidence or 0.2

    return confidence and Hit(version=version, confidence=confidence)

def sstp(sess, server):
    '''SSTP'''
    # Yes, this is for real...
    # See section 3.2.4.1 of v17.0 doc at https://msdn.microsoft.com/en-us/library/cc247338.aspx

    with closing(sess.request('SSTP_DUPLEX_POST', 'https://{}/sra_%7BBA195980-CD49-458b-9E23-C84EE0ADCD75%7D/'.format(server), stream=True)) as r:
        if r.status_code==200 and r.headers.get('content-length')=='18446744073709551615':
            version = _meaningless( r.headers.get('server'), "Microsoft-HTTPAPI/2.0" )
            return Hit(version=version)

def anyconnect(sess, server):
    '''AnyConnect/OpenConnect'''
    # Try GET-tunnel (Cisco returns X-Reason, ocserv doesn't) and CONNECT-tunnel with bogus cookie (OpenConnect returns X-Reason)
    # "GET /+CSCOE+/logon.html" but this gives too many false positives.

    r = sess.get('https://{}/CSCOSSLC/tunnel'.format(server))
    if 'X-Reason' in r.headers:
        return Hit(name="Cisco", version=r.headers.get('server'))

    with closing(sess.request('CONNECT', 'https://{}/CSCOSSLC/tunnel'.format(server), headers={'Cookie': 'webvpn='}, stream=True)) as r:
        if 'X-Reason' in r.headers:
            return Hit(name="ocserv")

def openvpn(sess, server):
    '''OpenVPN'''
    r = sess.get('https://{}/'.format(server))
    if any(c.name.startswith('openvpn_sess_') for c in sess.cookies):
        return Hit(version=r.headers.get('server'))

sniffers = [
    anyconnect,
    juniper_nc,
    global_protect,
    barracuda,
    check_point,
    sstp,
    openvpn,
]

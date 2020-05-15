from contextlib import closing
from urllib.parse import urlsplit
from requests import exceptions as rex
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

#####
# Sniffers based on protocol details
#####

def global_protect(sess, server):
    '''PAN GlobalProtect'''
    # with closing(sess.get('https://{}/ssl-tunnel-connect.sslvpn'.format(server), stream=True)) as r:
    #    if r.status_code==502:
    #        components.append('gateway')

    components = []
    version = hit = None

    for component, path in (('portal','global-protect'), ('gateway','ssl-vpn')):
        r = sess.post('https://{}/{}/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Windows'.format(server, path), headers={'user-agent':'PAN GlobalProtect'})
        if r.headers.get('content-type','').startswith('application/xml') and b'<prelogin-response>' in r.content:
            hit = True

            if b'<status>Success</status>' in r.content:
                components.append(component)
            elif b'<status>Error</status>' in r.content and b'<msg>Valid client certificate is required</msg>' in r.content:
                components.append(component)
                components.append(component+' wants ccert')

            m = re.search(rb'<saml-auth-method>([^<]+)</saml-auth-method>', r.content)
            if m:
                saml = '%s wants SAML %s' % (component, m.group(1).decode())
                components.append(saml)

            m = re.search(rb'<panos-version>([^<]+)</panos-version>', r.content)
            if m:
                version = m.group(1).decode()

    if hit:
        return Hit(components=components, version=_meaningless(version, '1'))

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

    components = []

    # Use XML-post auth to check for client cert requirement
    try:
        r = sess.post('https://{}/'.format(server),
                      headers={'X-Aggregate-Auth':'1', 'X-Transcend-Version':'1'}, data=
                      '<?xml version="1.0" encoding="UTF-8"?>\n'
                      '<config-auth client="vpn" type="init">'
                      '<version who="vpn"/><device-id/>'
                      '<group-access>{}</group-access></config-auth>'.format(server))
        if b'<client-cert-request' in r.content:
            components.append('wants ccert')
    except rex.ChunkedEncodingError:
        pass # some servers barf on this

    with closing(sess.request('CONNECT', 'https://{}/CSCOSSLC/tunnel'.format(server), headers={'Cookie': 'webvpn='}, stream=True)) as r:
        # Cisco returns X-Reason in response to bad CONNECT-tunnel request (GET works too)...
        if 'X-Reason' in r.headers:
            return Hit(name="Cisco", version=r.headers.get('server'), components=components)
        elif r.reason=='Cookie is not acceptable':
            return Hit(name="ocserv", version='0.11.7+', components=components)
        # ... whereas ocserv 7e06e1ac..3feec670 inadvertently sends X-Reason header in the *body*
        elif r.raw.read(9)==b'X-Reason:':
            return Hit(name="ocserv", version='0.8.0-0.11.6', components=components)

def juniper_pulse(sess, server):
    '''Juniper/Pulse'''

    with closing(sess.get('https://{}/'.format(server), headers={'Content-Type':'EAP', 'Upgrade':'IF-T/TLS 1.0', 'Content-Length': '0'}, stream=True)) as r:
        if r.status_code == 101:
            return Hit(name='Pulse Secure', version=r.headers.get('NCP-Version'))

    confidence = None
    r = sess.get('https://{}/dana-na'.format(server), headers={'user-agent':'ncsrv', 'NCP-Version': '3'})
    if any(c.name.startswith('DS') for c in sess.cookies):
        confidence = 1.0
    elif urlsplit(r.url).path.startswith('/dana-na/auth/'):
        confidence = 0.8

    return confidence and Hit(name='Juniper NC', confidence=confidence, version=r.headers.get('NCP-Version'))

#####
# Sniffers based on behavior of web front-end
#####

def openvpn(sess, server):
    '''OpenVPN'''
    r = sess.get('https://{}/'.format(server))
    if any(c.name.startswith('openvpn_sess_') for c in sess.cookies):
        return Hit(version=r.headers.get('server'))

def barracuda(sess, server):
    '''Barracuda'''

    r = sess.get('https://{}/'.format(server))

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

def fortinet(sess, server):
    '''Fortinet'''

    # server sets *empty* SVPNCOOKIE/SVPNNETWORKCOOKIE
    r = sess.get('https://{}/remote/login'.format(server))
    if r.headers.get('set-cookie','').startswith('SVPNCOOKIE'):
        server = r.headers.get('server')
        confidence = 1.0 if server=='xxxxxxxx-xxxxx' else 0.9
        return Hit(confidence=confidence, version=_meaningless(server,'xxxxxxxx-xxxxx'))

def array_networks(sess, server):
    '''Array Networks'''

    r = sess.get('https://{}/'.format(server))

    confidence = 0
    if re.match(r'/prx/\d\d\d/', urlsplit(r.url).path):
        confidence += 0.1
        if b'array networks' in r.content.lower() or b'arraynetworks' in r.content.lower():
            confidence += 0.1
        if b'_AN_global_var_init' in r.content:
            confidence += 0.2

    return confidence and Hit(confidence=confidence)

def f5_bigip(sess, server):
    '''F5 BigIP'''

    r = sess.get('https://{}/my.policy'.format(server))

    confidence = 0.1 * sum(x in r.headers.get('set-cookie','') for x in ('MRHSession', 'LastMRH_Session', 'F5_'))
    if urlsplit(r.url).path.startswith('/my.logout'):
        confidence += 0.5
    if r.headers.get('server','') == 'BigIP':
        confidence += 0.2

    return confidence and Hit(confidence=confidence)

def sonicwall_nx(sess, server):
    '''SonicWall NX'''

    sess.cookies.set(domain=server, name='EXTRAWEB_REFERER', value='/preauthMI/microinterrogator.js')
    with closing(sess.get('https://{}/sslvpnclient?launchplatform=mac&neProto=3&supportipv6=yes'.format(server), stream=True,
                          headers={ "X-SSLVPN-PROTOCOL":"2.0", "X-SSLVPN-SERVICE": "NETEXTENDER", "X-NE-PROTOCOL": "2.0" })) as r:
        if 'EXTRAWEB_STATE' in sess.cookies and 400 <= r.status_code < 500:
            server = r.headers.get('server')
            return Hit(confidence=0.8, version=server)

sniffers = [
    anyconnect,
    juniper_pulse,
    global_protect,
    barracuda,
    check_point,
    sstp,
    openvpn,
    fortinet,
    array_networks,
    f5_bigip,
    sonicwall_nx,
]

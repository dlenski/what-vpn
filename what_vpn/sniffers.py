from contextlib import closing
from urllib.parse import urlsplit, parse_qs
from requests import exceptions as rex
import re
import attr
import ssl
import socket
try:
    import dtls
    dtls.do_patch()
    can_dtls = True
except ImportError:
    can_dtls = False


@attr.s
class Hit(object):
    def __bool__(self):
        return self.confidence > 0.0

    def __str__(self):
        return self.name + (' ({})'.format(self.details) if self.details else '')

    @property
    def details(self):
        strings = []
        if self.version:
            strings.append(self.version)
        if self.components:
            strings.append('+'.join(self.components))
        if self.confidence < 1.0:
            strings.append('%d%%' % (self.confidence * 100))
        return ', '.join(strings)

    name = attr.ib()
    confidence = attr.ib(default=1.0, validator=attr.validators.instance_of(float))
    version = attr.ib(default=None)
    components = attr.ib(default=None)


def _meaningless(x, *vals):
    if x not in vals:
        return x



def server_split(host_and_maybe_port):
    rest, *last = host_and_maybe_port.rsplit(':', 1)
    if not last:
        host, port = rest, 443
    elif ']' in last[0]:  # we mis-split an IPv6 address, something like '[2601::1234]':
        host, port = host_and_maybe_port, 443
    else:
        host, port = rest, int(last[0])
    return host, port


#####
# Sniffers based on protocol details
#####

def global_protect(sess, server):
    '''PAN GlobalProtect'''
    # with closing(sess.get('https://{}/ssl-tunnel-connect.sslvpn'.format(server), stream=True)) as r:
    #    if r.status_code==502:
    #        components.append('gateway')

    components = []
    version = confidence = None

    for component, path in (('portal', 'global-protect'), ('gateway', 'ssl-vpn')):
        r = sess.post('https://{}/{}/prelogin.esp?tmp=tmp&clientVer=4100&clientos=Windows'.format(server, path),
                      headers={'user-agent': 'PAN GlobalProtect'})
        if r.headers.get('content-type', '').startswith('application/xml') and b'<prelogin-response>' in r.content:
            confidence = 1.0

            if b'<status>Success</status>' in r.content:
                components.append(component)
                if 'gateway' in components:
                    # Gateway servers return '502 Bad Gateway' when they don't like the user/authcookie parameters
                    # for the SSL tunnel. It's theoretically possible, but I've literally never seen a gateway server
                    # that doesn't use the standard SSL tunnel path.
                    with closing(sess.get('https://{}/ssl-tunnel-connect.sslvpn?user=&authcookie='.format(server))) as r:
                        if r.status_code != 502:
                            confidence = 0.8
            elif b'<status>Error</status>' in r.content and b'<msg>Valid client certificate is required</msg>' in r.content:
                components.append(component)
                components.append(component + ' wants ccert')

            m = re.search(rb'<saml-auth-method>([^<]+)</saml-auth-method>', r.content)
            if m:
                saml = '%s wants SAML %s' % (component, m.group(1).decode())
                components.append(saml)

            m = re.search(rb'<panos-version>([^<]+)</panos-version>', r.content)
            if m:
                version = m.group(1).decode()

    if confidence:
        return Hit(name='PAN GlobalProtect', components=components, version=_meaningless(version, '1'), confidence=confidence)


def check_point(sess, server):
    '''Check Point'''
    confidence = protocols = None

    # ClientHello HTTP request in Check Point's parenthesis-heavy format
    r = sess.post('https://{}/clients'.format(server),
                  data=b'(CCCclientRequest\n:RequestHeader (\n:id (1)\n:session_id ()\n:type (ClientHello)\n:protocol_version (100)\n)\n:RequestData (\n:client_info (\n:client_type (TRAC)\n:client_version (0)\n)\n)\n)\n')
    if r.content.startswith(b'(CCCserverResponse'):
        confidence = 1.0
        protocols = re.search(rb':supported_data_tunnel_protocols\s*\(((?:\s*:\s*\([^\)]+\))*\s*\))', r.content, re.M)
        if protocols:
            protocols = [b.decode() for b in re.findall(rb'\(([^\)]+)\)', protocols.group(1))]

    # ClientHello request over bare TLS in Check Point's format
    if not confidence:
        sock = socket.socket(socket.AF_INET)
        sock.settimeout(sess.timeout)
        context = ssl._create_unverified_context()
        conn = context.wrap_socket(sock)

        client_hello = b'(client_hello\n:client_version (1)\n:protocol_version (1)\n:OM (\n:ipaddr (0.0.0.0)\n:keep_address (false)\n)\n:optional (\n:client_type (4)\n)\n:cookie (ff)\n)\n'
        client_hello = bytes((0, 0, 0, len(client_hello), 0, 0, 0, 1)) + client_hello  # Add length and packet-type prefix
        with closing(conn):
            conn.connect(server_split(server))
            conn.write(client_hello)
            resp = conn.recv(19)
            if resp[4:19] == b'\0\0\0\x01(disconnect':
                confidence = 1.0
                protocols = ('SSL',)

    return confidence and Hit(name='Check Point', confidence=confidence, components=protocols)


def sstp(sess, server):
    '''SSTP'''
    # Yes, this is for real...
    # See section 3.2.4.1 of v17.0 doc at https://msdn.microsoft.com/en-us/library/cc247338.aspx

    with closing(sess.request('SSTP_DUPLEX_POST', 'https://{}/sra_%7BBA195980-CD49-458b-9E23-C84EE0ADCD75%7D/'.format(server), stream=True)) as r:
        if r.status_code == 200 and r.headers.get('content-length') == '18446744073709551615':
            version = _meaningless(r.headers.get('server'), "Microsoft-HTTPAPI/2.0")
            return Hit(name='SSTP', version=version)


def anyconnect(sess, server):
    '''AnyConnect/OpenConnect'''

    platform = 'win'
    config_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<config-auth client="vpn" type="init">'
        '<version who="vpn"/><device-id>{}</device-id>'
        '<group-access>https://{}</group-access></config-auth>'.format(platform, server))

    components = []
    xml_post_ok = None

    # Use XML-post auth to check for client cert requirement
    # (This may actually vary by auth-group, but we don't try to enumerate the auth-groups)
    try:
        r = sess.post('https://{}/'.format(server), data=config_payload, headers={
            'X-Aggregate-Auth': '1', 'X-Transcend-Version': '1'})
        if b'<client-cert-request' in r.content:
            components.append('wants ccert')
        xml_post_ok = r.ok
    except rex.ChunkedEncodingError:
        pass  # some servers barf on this

    with closing(sess.request('CONNECT', 'https://{}/CSCOSSLC/tunnel'.format(server), headers={'Cookie': 'webvpn='}, stream=True)) as r:
        # Cisco returns X-Reason in response to bad CONNECT-tunnel request (GET works too)...
        if 'X-Reason' in r.headers:
            # At some point prior to February 24, 2020, Cisco introduced a new version of their servers which *reject* any
            # connections containing the X-AnyConnect-Platform header, and thus AnyConnect <v4.8 as well as OpenConnect <=8.10.
            r2 = sess.post('https://{}/'.format(server), data=config_payload, headers={
                'X-Aggregate-Auth': '1', 'X-Transcend-Version': '1', 'X-AnyConnect-Platform': platform})
            if xml_post_ok and not r2.ok:
                # We know that:
                # 1) the initial XML post *without* the X-AnyConnect-Platform header is okay
                # 2) the initial XML post *with* the X-AnyConnect-Platform header is NOT okay
                # That appears to happen *only* with the newer server version that requires AnyConnect v4.8+.
                # See https://gitlab.com/openconnect/openconnect/-/issues/101#note_531727013
                version = 'requires_AnyConnect_v4.8_or_newer'
            else:
                version = r.headers.get('server')
            return Hit(name="Cisco AnyConnect", version=version, components=components)
        elif r.reason == 'Cookie is not acceptable':
            return Hit(name="ocserv", version='0.11.7+', components=components)
        # ... whereas ocserv 7e06e1ac..3feec670 inadvertently sends X-Reason header in the *body*
        elif r.raw.read(9) == b'X-Reason:':
            return Hit(name="ocserv", version='0.8.0-0.11.6', components=components)


def juniper_pulse(sess, server):
    '''Juniper/Pulse'''

    with closing(sess.get('https://{}/'.format(server), headers={'Content-Type': 'EAP', 'Upgrade': 'IF-T/TLS 1.0', 'Content-Length': '0'}, stream=True)) as r:
        if r.status_code == 101:
            return Hit(name='Pulse Secure', version=r.headers.get('NCP-Version'))
        # TODO: it's possible to detect a client certificate requirement on a Pulse server
        # (see https://gitlab.com/openconnect/openconnect/commit/99bd5688fd7b9983b0bcea4a50b56e757f495e22)
        # but requires speaking the nasty binary Pulse protocol for a few packets

    confidence = None
    r = sess.get('https://{}/dana-na'.format(server), headers={'user-agent': 'ncsrv', 'NCP-Version': '3'})
    if any(c.name.startswith('DS') for c in sess.cookies):
        confidence = 1.0
    elif urlsplit(r.url).path.startswith('/dana-na/auth/'):
        confidence = 0.8

    return confidence and Hit(name='Juniper NC', confidence=confidence, version=r.headers.get('NCP-Version'))


def juniper_secure_connect(sess, server):
    '''Juniper Secure Connect'''

    r = sess.post('https://{}/remoteaccess/login'.format(server),
                  headers={'Accept': 'application/json'},
                  json={})
    try:
        j = r.json()
    except ValueError:
        pass
    else:
        confidence = 0.8
        # {"authenticated":"no","error":"Login data parsing failure"}
        if isinstance(j, dict) and ('authenticated' in j or 'error' in j):
            confidence = 1.0
        return Hit(name="Juniper Secure Connect", confidence=confidence)


def f5_bigip(sess, server):
    '''F5 BigIP'''
    confidence = 0.0

    tun_path = '/myvpn?sess=none&hdlc_framing=no&ipv4=1&ipv6=1&Z=none&hostname=none'
    with closing(sess.get('https://{}{}'.format(server, tun_path), stream=True)) as r:
        # F5 server sends '504 Gateway Timeout' when it doesn't like the GET-tunnel parameters
        if r.status_code == 504:
            confidence = 1.0 if r.headers.get('server', '') == 'BigIP' else 0.9

    if not confidence:
        # Look for F5-related cookies if tunnel query didn't work
        r = sess.get('https://{}/my.policy'.format(server))
        confidence = 0.1 * sum(x in r.headers.get('set-cookie', '') for x in ('MRHSession', 'LastMRH_Session', 'F5_'))
        if urlsplit(r.url).path.startswith('/my.logout'):
            confidence += 0.5
        if r.headers.get('server', '') == 'BigIP':
            confidence += 0.2

    # See if we can connect via DTLS
    dtls = None
    if confidence and can_dtls:
        host, port = server_split(server)
        for port in set((4433, port)):  # We don't actually know the port for DTLS; just guess
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(sess.timeout)
            # FIXME: _create_unverified_context() doesn't work with PyDTLS
            # context = ssl._create_unverified_context()
            # conn = context.wrap_socket(sock)
            conn = ssl.wrap_socket(sock)

            client_hello = 'GET {} HTTP/1.1\r\nHost: {}\r\n\r\n'.format(tun_path, host).encode()  # Yes, it's HTTP-over-DTLS (https://gitlab.com/openconnect/openconnect/-/blob/77ac1a99/f5.c?page=1#L740)
            try:
                conn.connect((host, port))
                dtls = 'possible DTLS on port {}'.format(port)
                conn.write(client_hello)
                resp = conn.recv()
                if resp:
                    confidence = 1.0
                    dtls = 'DTLS on port {}'.format(port)
                    break
            except socket.error:
                pass
            finally:
                conn.close()

    return confidence and Hit(name='F5 BigIP', confidence=confidence, components=([dtls] if dtls else None))


def array_networks(sess, server):
    '''Array Networks'''

    with closing(sess.get('https://{}/vpntunnel'.format(server), allow_redirects=False, stream=True)) as r:
        # Array server redirects to /prx/\d\d\d/.../cookietest when it doesn't like the GET-tunnel parameters
        if r.status_code == 302 and re.match(r'/prx/\d\d\d/\S+/cookietest', r.headers.get('location', '')):
            return Hit(name='Array Networks', confidence=1.0)

    r = sess.get('https://{}/'.format(server))
    confidence = 0
    if re.match(r'/prx/\d\d\d/', urlsplit(r.url).path):
        confidence += 0.1
        if b'array networks' in r.content.lower() or b'arraynetworks' in r.content.lower():
            confidence += 0.1
        if b'_AN_global_var_init' in r.content:
            confidence += 0.2

    return confidence and Hit(name='Array Networks', confidence=confidence)


#####
# Sniffers based on behavior of web front-end
#####

def openvpn(sess, server):
    '''OpenVPN'''
    r = sess.get('https://{}/'.format(server))
    if any(c.name.startswith('openvpn_sess_') for c in sess.cookies):
        return Hit(name='OpenVPN', version=r.headers.get('server'))


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

    return confidence and Hit(name='Barracuda', version=version, confidence=confidence)


def fortinet(sess, server):
    '''Fortinet'''

    # server sets *empty* SVPNCOOKIE/SVPNNETWORKCOOKIE
    r = sess.get('https://{}/remote/login'.format(server))
    if r.headers.get('set-cookie', '').startswith('SVPNCOOKIE'):
        version = r.headers.get('server')
        if version == 'xxxxxxxx-xxxxx':
            confidence = 1.0
            version = None
        else:
            confidence = 0.9

        # It seems that FortiGate v6.2 and newer (approximately?) respond to invalid/expired
        # SVPNCOOKIE with a 403, while older versions respond with a 302 redirect to
        # /remote/login (https://gitlab.com/openconnect/openconnect/-/issues/298#note_665752756)
        r = sess.get('https://{}/remote/fortisslvpn_xml'.format(server), allow_redirects=False)
        if r.status_code == 403:
            version = ((version + '; ') if version else '') + 'FortiGate >v6.2?'
        elif r.status_code == 302 and re.search(r'/remote/login', r.headers.get('location', '')):
            # Older FortiGate versions (we think) respond to invalid/expired SVPNCOOKIE thusly
            confidence = 1.0
            version = ((version + '; ') if version else '') + 'FortiGate <v6.2?'

        # See if we can connect via DTLS
        dtls = None
        if can_dtls:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(sess.timeout)
            # FIXME: _create_unverified_context() doesn't work with PyDTLS
            # context = ssl._create_unverified_context()
            # conn = context.wrap_socket(sock)
            conn = ssl.wrap_socket(sock)

            client_hello = b'GFtype\0clthello\0SVPNCOOKIE\0deadbeef\0'
            client_hello = bytes((len(client_hello)>>8, len(client_hello) & 0xff)) + client_hello  # Add length prefix (be16)
            try:
                conn.connect(server_split(server))
                conn.write(client_hello)
                resp = conn.recv()
                if resp[0] == (len(resp)>>8) and resp[1] == (len(resp)&0xff) and resp[2:9] == b'GFtype\0':
                    confidence = 1.0
                    dtls = True
            except socket.error:
                pass
            finally:
                conn.close()

        return Hit(name='Fortinet', confidence=confidence, version=version, components=(['DTLS'] if dtls else None))


def sonicwall_nx(sess, server):
    '''SonicWall NX (formerly Dell)'''

    confidence = serverh = None
    sess.cookies.set(domain=server, name='EXTRAWEB_REFERER', value='/preauthMI/microinterrogator.js')
    with closing(sess.get('https://{}/sslvpnclient?launchplatform=mac&neProto=3&supportipv6=yes'.format(server), stream=True,
                          headers={"X-SSLVPN-PROTOCOL": "2.0", "X-SSLVPN-SERVICE": "NETEXTENDER", "X-NE-PROTOCOL": "2.0"})) as r:
        if 400 <= r.status_code < 500:
            serverh = r.headers.get('server')
            if 'EXTRAWEB_STATE' in sess.cookies:
                confidence = 0.8
            elif 'SonicWall' in r.text:
                confidence = 0.2

    if confidence:
        return Hit(name='SonixWall NX', confidence=confidence, version=serverh)


def aruba_via(sess, server):
    '''Aruba VIA'''

    # server sets *empty* SESSION cookie and returns 401 invalid
    r = sess.get('https://{}'.format(server))
    if r.status_code == 401 and r.headers.get('set-cookie', '').startswith('SESSION'):
        confidence = 0.5 if 'Aruba Networks' in r.text else 0.3
        r = sess.get('https://{}/screens/wms/wms.login'.format(server))
        if r.status_code == 200 and r.headers.get('set-cookie', '').startswith('SESSION'):
            confidence += 0.3

        return Hit(name='Aruba VIA', confidence=confidence)


def h3c(sess, server):
    '''H3C TLS VPN'''
    r = sess.get('https://{}/svpn/index.cgi'.format(server), headers={'user-agent': 'SSLVPN-Client/3.0'})
    if '<gatewayinfo>' in r.text:
        # HTML/XML page containing server information, including auth methods
        serverh = r.headers.get('server')
        return Hit(name='H3C', confidence=0.9 if serverh == 'SSLVPN-Gateway/7.0' else 0.8,
                   version=_meaningless(server, 'SSLVPN-Gateway/7.0'))


def huawei(sess, server):
    '''Huawei SSL VPN'''
    r = sess.post('https://{}/login.html'.format(server), data={'UserName': '', 'Password': ''}, allow_redirects=False)
    final_url = urlsplit(r.headers.get('location', ''))
    if final_url.path.split('/')[-1] == 'relogin.html':
        # Server sends a bizarrely-formatted set-cookie header like 'Set-Cookie: UserID=0&SVN_SessionID='
        # HTTP cookie names aren't supposed to contain ampersands like this.
        bizarre_cookie = r.headers.get('set-cookie', '').startswith('UserID=') and '&' in r.headers.get('set-cookie', '')
        return Hit(name='Huawei',
                   confidence = 0.4 + (0.2 if parse_qs(final_url.query).get('ReloginCause') else 0) + (0.4 if bizarre_cookie else 0))


sniffers = [
    anyconnect,
    juniper_pulse,
    juniper_secure_connect,
    global_protect,
    barracuda,
    check_point,
    sstp,
    openvpn,
    fortinet,
    array_networks,
    f5_bigip,
    sonicwall_nx,
    aruba_via,
    h3c,
    huawei,
]

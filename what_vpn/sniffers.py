from contextlib import closing
from urllib.parse import urlsplit
import re

def _meaningless(x, *vals):
    if x not in vals:
        return x

def global_protect(sess, server):
    # with closing(sess.get('https://{}/ssl-tunnel-connect.sslvpn'.format(server), stream=True)) as r:
    #    if r.status_code==502:
    #        components.append('gateway')

    components = []
    version = None
    hit = False
    r = sess.get('https://{}/global-protect/prelogin.esp'.format(server), headers={'user-agent':'PAN GlobalProtect'})
    if r.headers['content-type'].startswith('application/xml') and b'<prelogin-response>' in r.content:
        hit = True
        if b'<status>Success</status>' in r.content:
            components.append('portal')
        m = re.search(r'<panos-version>([^<]+)</panos-version>', r.text)
        version = _meaningless(m and m.group(1), '1')
    r = sess.get('https://{}/ssl-vpn/prelogin.esp'.format(server), headers={'user-agent':'PAN GlobalProtect'})
    if r.headers['content-type'].startswith('application/xml') and b'<prelogin-response>' in r.content:
        hit = True
        if b'<status>Success</status>' in r.content:
            components.append('gateway')
        m = re.search(r'<panos-version>([^<]+)</panos-version>', r.text)
        version = _meaningless(m.group(1), '1') if m else version
    if components:
        return "PAN GlobalProtect {}".format('/'.join(components)), version
    elif hit:
        return "PAN GlobalProtect unknown", version

def juniper_nc(sess, server):
    # Juniper is frustrating because mostly it just spits out standard HTML, sometimes along with DS* cookies

    r = sess.get('https://{}/'.format(server), headers={'user-agent':'ncsrv'})
    if urlsplit(r.url).path.startswith('/dana-na/auth/') or any(c.name.startswith('DS') for c in sess.cookies):
        return "Juniper Network Connect", None

def barracuda(sess, server):
    # Similar to Juniper

    r = sess.get('https://{}'.format(server))
    if urlsplit(r.url).path.startswith('/default/showLogon.do') or 'SSLX_SSESHID' in sess.cookies:
        m = re.search(r'(\d+-)?(\d+)\s+Barracuda Networks', r.text)
        return "Barracuda", m and m.group(2)

def check_point(sess, server):
    version = hit = None

    # Try an empty client request in Check Point's parenthesis-heavy format
    r = sess.post('https://{}/clients/abc'.format(server), headers={'user-agent':'TRAC/986000125'}, data=b'(CCCclientRequest)')
    if r.content.startswith(b'(CCCserverResponse'):
        hit = True

    r = sess.get('https://{}/'.format(server), headers={'user-agent':'TRAC/986000125'})
    m = re.search(r'(\d+-)?(\d+).+Check Point Software Technologies', r.text)
    if m:
        hit, version = True, m.group(2)

    if hit:
        return "Check Point", version

def sstp(sess, server):
    # Yes, this is for real...
    # See section 3.2.4.1 of v17.0 doc at https://msdn.microsoft.com/en-us/library/cc247338.aspx

    with closing(sess.request('SSTP_DUPLEX_POST', 'https://{}/sra_{{BA195980-CD49-458b-9E23-C84EE0ADCD75}}/'.format(server), stream=True)) as r:
        if r.status_code==200 and r.headers.get('content-length')=='18446744073709551615':
            return "SSTP", _meaningless( r.headers.get('server'), "Microsoft-HTTPAPI/2.0" )

def anyconnect(sess, server):
    # Try GET-tunnel (Cisco returns X-Reason, ocserv doesn't) and CONNECT-tunnel with bogus cookie (OpenConnect returns X-Reason)
    # "GET /+CSCOE+/logon.html" but this gives too many false positives.

    r = sess.get('https://{}/CSCOSSLC/tunnel'.format(server))
    if 'X-Reason' in r.headers:
        return "Cisco AnyConnect", r.headers.get('server')

    with closing(sess.request('CONNECT', 'https://{}/CSCOSSLC/tunnel'.format(server), headers={'Cookie': 'webvpn='}, stream=True)) as r:
        if 'X-Reason' in r.headers:
            return "OpenConnect ocserv", None

def openvpn(sess, server):
    r = sess.get('https://{}/'.format(server))
    if any(c.name.startswith('openvpn_sess_') for c in sess.cookies):
        return "OpenVPN", r.headers.get('server')

sniffers = [
    ('AnyConnect/OpenConnect', anyconnect),
    ('Juniper Network Connect', juniper_nc),
    ('PAN GlobalProtect', global_protect),
    ('Barracuda', barracuda),
    ('Check Point', check_point),
    ('SSTP', sstp),
    ('OpenVPN', openvpn),
]

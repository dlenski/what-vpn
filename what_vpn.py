#!/usr/bin/env python3

import requests
from requests import exceptions as rex

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from contextlib import closing
import argparse
import os
import re
from sys import stderr

########################################

def global_protect(sess, server):
    # with closing(sess.get('https://{}/ssl-tunnel-connect.sslvpn'.format(server), stream=True)) as r:
    #    if r.status_code==502:
    #        components.append('gateway')

    components = []
    r = sess.get('https://{}/global-protect/prelogin.esp'.format(server), headers={'user-agent':'PAN GlobalProtect'})
    if b'<status>Success</status>' in r.content:
        components.append('portal')
    r = sess.get('https://{}/ssl-vpn/prelogin.esp'.format(server), headers={'user-agent':'PAN GlobalProtect'})
    if b'<status>Success</status>' in r.content:
        components.append('gateway')
    if components:
        return "PAN GlobalProtect ({})".format(' and '.join(components))

def juniper_nc(sess, server):
    # Juniper is frustrating because mostly it just spits out standard HTML, sometimes along with DS* cookies

    r = sess.get('https://{}/dana-na/auth/url_default/welcome.cgi'.format(server), headers={'user-agent':'ncsrv'})
    if (r.status_code==200 and b'/dana-na/' in r.content) or any(c.startswith('DS') for c in r.cookies.keys()):
        return "Juniper Network Connect"

def check_point(sess, server):
    # "GET /sslvpn/Login/Login" gives too many false positives

    r = sess.post('https://{}/clients/abc'.format(server), headers={'user-agent':'TRAC/986000125'}, data=b'(CCCclientRequest)')
    if r.content.startswith(b'(CCCserverResponse'):
        return "Check Point"

def sstp(sess, server):
    # Yes, this is for real...
    # See section 3.2.4.1 of v17.0 doc at https://msdn.microsoft.com/en-us/library/cc247338.aspx

    with closing(sess.request('SSTP_DUPLEX_POST', 'https://{}/sra_{{BA195980-CD49-458b-9E23-C84EE0ADCD75}}/'.format(server), stream=True)) as r:
        if r.status_code==200 and r.headers.get('content-length')=='18446744073709551615':
            return "SSTP"

def anyconnect(sess, server):
    # Try GET-tunnel (Cisco returns X-Reason, ocserv doesn't) and CONNECT-tunnel with bogus cookie (OpenConnect returns X-Reason)
    # "GET /+CSCOE+/logon.html" but this gives too many false positives.

    r = sess.get('https://{}/CSCOSSLC/tunnel'.format(server))
    if 'X-Reason' in r.headers:
        return "Cisco AnyConnect"

    with closing(sess.request('CONNECT', 'https://{}/CSCOSSLC/tunnel'.format(server), headers={'Cookie': 'webvpn='}, stream=True)) as r:
        if 'X-Reason' in r.headers:
            return "OpenConnect ocserv"

checkers =  [
    ('AnyConnect/OpenConnect', anyconnect),
    ('Juniper Network Connect', juniper_nc),
    ('PAN GlobalProtect', global_protect),
    ('Check Point', check_point),
    ('SSTP', sstp),
]

########################################

class tsess(requests.Session):
    def __init__(self, *a, **kw):
        self.timeout = None
        return super().__init__(*a, **kw)
    def request(self, *a, **kw):
        kw.setdefault('timeout', self.timeout)
        return super().request(*a, **kw)

########################################

def main():
    p = argparse.ArgumentParser()
    p.add_argument('-v','--verbose', default=0, action='count')
    p.add_argument('-1','--first', action='store_true', help='Stop after first hit')
    p.add_argument('-t','--timeout', metavar='SEC', type=lambda x: int(x) or None, default=10, help='Timeout in seconds (default %(default)s, 0 for none)')
    p.add_argument('server', nargs='+', help='suspected SSL-VPN server')
    args = p.parse_args()

    s = tsess()
    s.timeout = args.timeout
    s.verify = False

    for server in args.server:
        if args.verbose:
            print("\nSniffing {} ...".format(server))
        else:
            print("{}: ".format(server), end='')

        hits = []
        ssle = timeout = 0
        for desc, checker in checkers:
            if args.verbose:
                print("  Is it {}? ".format(desc), end='')
            s.cookies.clear()

            hit = ex = None
            try:
                hit = checker(s, server)
            except rex.Timeout as e:
                ex = 'timeout'
                timeout += 1
            except rex.SSLError as e:
                ex = 'SSL error'
                ssle += 1
            except rex.ConnectionError as e:
                ex = 'connection error'
            except Exception as e:
                ex = e.__class__.__name__
            else:
                ex = 'no match'

            if hit:
                hits.append(hit)
                if args.first:
                    break
            if args.verbose:
                print(hit or ex)
        else:
            if args.verbose:
                print("  => ", end='')

        if hits:
            print(', '.join(hits))
        elif ssle:
            print('SSL errors')
        elif timeout:
            print('timeout')
        else:
            print('no match')

if __name__=='__main__':
    main()

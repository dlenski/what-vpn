#!/usr/bin/env python3

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from requests import exceptions as rex
from .sniffers import sniffers
from .requests import SnifferSession, SSLVersionAdapter
from .version import __version__
import socket
import logging
import http.client
from ipaddress import ip_address

import argparse
import csv
import sys


def main():
    p = argparse.ArgumentParser()
    p.add_argument('-k', '--keep-going', action='store_true', help='Keep going after first hit')
    p.add_argument('-K', '--keep-going-after-exception', action='store_true', help='Keep going after an SSL or timeout exception')
    p.add_argument('-t', '--timeout', metavar='SEC', type=lambda x: int(x) or None, default=10, help='Timeout in seconds (default %(default)s, 0 for none)')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-v', '--verbose', default=0, action='count')
    x.add_argument('-c', '--csv', action='store_true', help='Output report in CSV format')
    p.add_argument('server', nargs='+', help='suspected SSL-VPN server', metavar="server[:port]")
    p.add_argument('-L', '--logging', default=0, action='count', help='Detailed logging for requests and httplib')
    p.add_argument('-V', '--version', action='version', version='%(prog)s ' + __version__)
    x = p.add_mutually_exclusive_group()
    x.add_argument('--ssl3', action='store_const', dest='ssl_version', const=SSLVersionAdapter.SSLv23,
                   help='Try connecting with SSLv3, rather than modern TLS')
    x.add_argument('--tlsv1', action='store_const', dest='ssl_version', const=SSLVersionAdapter.TLSv1,
                   help='Try connecting with TLS 1.0, rather than modern TLS')
    x.add_argument('--tlsv11', action='store_const', dest='ssl_version', const=SSLVersionAdapter.TLSv1_1,
                   help='Try connecting with TLS 1.1, rather than modern TLS')
    p.add_argument('-S', '--specific', metavar='SNIFFER', action='append', choices=[s.__name__ for s in sniffers],
                   help='Specific sniffer to try, may be specified multiple times (default is to try all; options are %s)' % ', '.join(s.__name__ for s in sniffers))
    p.add_argument('-P', '--proxy', help='HTTPS proxy (in any format accepted by python-requests, e.g. socks5://localhost:8080)')
    args = p.parse_args()

    if args.logging:
        http.client.HTTPConnection.debuglevel = 99
        logging.basicConfig(level=logging.DEBUG)

    if args.csv:
        wr = csv.writer(sys.stdout)
        wr.writerow(('Server', 'Errors', 'Sniffer', 'Confidence', 'Name', 'Version', 'Components'))

    if args.specific:
        print('Restricting list of sniffers to: {}'.format(', '.join(args.specific)))

    s = SnifferSession(timeout=args.timeout, ssl_version=args.ssl_version)
    s.proxies['https'] = args.proxy

    for server in args.server:
        if args.verbose:
            print("\nSniffing {} ...".format(server))
        elif not args.csv:
            print("{}: ".format(server), end='')

        if server.startswith('[') and ']' in server:
            # IPv6 address?
            domain = server[1:].split(']', 1)[0]
        else:
            domain = server.split(':', 1)[0]
        try:
            ip_address(domain)
        except ValueError:
            try:
                socket.gethostbyname(domain)
            except socket.error:
                if args.csv:
                    wr.writerow((server, "DNS lookup failed"))
                else:
                    print("DNS lookup failed")
                continue

        hits = []
        ssle = timeout = bail = tried = 0
        for sniffer in sniffers:
            if args.specific and sniffer.__name__ not in args.specific:
                continue
            desc = sniffer.__doc__ or sniffer.__name__
            if args.verbose:
                print("  Is it {}? ".format(desc), end='')

            s.cookies.clear()
            hit = ex = None
            try:
                hit = sniffer(s, server)
            except (rex.Timeout, socket.timeout):
                ex = 'timeout'
                timeout += 1
                bail += 1
            except rex.SSLError:
                ex = 'SSL error'
                ssle += 1
                bail += 1
            except (rex.ConnectionError, socket.error):
                ex = 'connection error'
            except Exception as e:
                if args.verbose > 1:
                    import traceback
                    print('\nException in {} sniffer:'.format(desc))
                    traceback.print_exc()
                ex = e.__class__.__name__
            else:
                ex = 'no match'
            tried += 1

            if hit:
                if args.csv:
                    wr.writerow((server, None, sniffer.__name__, hit.confidence, hit.name, hit.version, hit.components and '+'.join(hit.components)))
                else:
                    hits.append(str(hit))
            if args.verbose:
                print(str(hit) if hit else ex)

            if hit and not args.keep_going:
                break
            if bail and not args.keep_going_after_exception:
                break

        if args.verbose:
            print("  => ", end='')

        extra = ' (tried %d/%d sniffers)' % (tried, len(sniffers)) if tried < len(sniffers) else ''
        if ssle:
            errs = 'SSL errors' + extra
        elif timeout:
            errs = 'timeout' + extra
        elif not hits:
            errs = 'no match' + extra

        if args.csv and not hits:
            wr.writerow((server, errs))
        elif not args.csv:
            print(', '.join(hits) or errs)

########################################


if __name__ == '__main__':
    main()

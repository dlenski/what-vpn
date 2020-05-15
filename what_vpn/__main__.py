#!/usr/bin/env python3

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from requests import exceptions as rex
from .sniffers import sniffers, Hit
from .requests import SnifferSession
from .version import __version__
import socket
import logging
import http.client
from ipaddress import ip_address

import argparse
import os
import re
import csv
from sys import stderr, stdout

def main():
    p = argparse.ArgumentParser()
    p.add_argument('-k','--keep-going', action='store_true', help='Keep going after first hit')
    p.add_argument('-t','--timeout', metavar='SEC', type=lambda x: int(x) or None, default=10, help='Timeout in seconds (default %(default)s, 0 for none)')
    x = p.add_mutually_exclusive_group()
    x.add_argument('-v','--verbose', default=0, action='count')
    x.add_argument('-c','--csv', action='store_true', help='Output report in CSV format')
    p.add_argument('server', nargs='+', help='suspected SSL-VPN server')
    p.add_argument('-L','--logging', action='store_true', help='Detailed logging for requests and httplib')
    p.add_argument('-V','--version', action='version', version='%(prog)s ' + __version__)
    p.add_argument('-S','--specific', metavar='SNIFFER', action='append', choices=[s.__name__ for s in sniffers],
                   help='Specific sniffer to try, may be specified multiple times (default is to try all; options are %s)' % ', '.join(s.__name__ for s in sniffers))
    args = p.parse_args()

    if args.logging:
        http.client.HTTPConnection.debuglevel = 99
        logging.basicConfig(level=logging.DEBUG)

    if args.csv:
        wr = csv.writer(stdout)
        wr.writerow(('Server','Errors','Sniffer','Confidence','Name','Version','Components'))

    if args.specific:
        print('Restricting list of sniffers to: {}'.format(', '.join(args.specific)))

    s = SnifferSession()
    s.timeout = args.timeout

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
        ssle = timeout = 0
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
            except rex.Timeout as e:
                ex = 'timeout'
                timeout += 1
            except rex.SSLError as e:
                ex = 'SSL error'
                ssle += 1
            except rex.ConnectionError as e:
                ex = 'connection error'
            except Exception as e:
                if args.verbose > 1:
                    print('\nException in {} sniffer: {!r}\n'.format(desc, e))
                ex = e.__class__.__name__
            else:
                ex = 'no match'

            if hit:
                if args.csv:
                    wr.writerow((server, None, sniffer.__name__, hit.confidence, hit.name, hit.version, hit.components and '+'.join(hit.components)))
                elif hit.details:
                    desc += ' ({})'.format(hit.details)
                hits.append(desc)
            if args.verbose:
                print((hit.details or 'hit') if hit else ex)

            if hit and not args.keep_going:
                break

        if args.verbose:
            print("  => ", end='')

        if ssle:
            errs = 'SSL errors'
        elif timeout:
            errs = 'timeout'
        elif not hits:
            errs = 'no match'

        if args.csv and not hits:
            wr.writerow((server, errs))
        elif not args.csv:
            print(', '.join(hits) or errs)

########################################

if __name__=='__main__':
    main()

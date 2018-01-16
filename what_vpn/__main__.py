#!/usr/bin/env python3

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from requests import exceptions as rex
from .sniffers import sniffers
from .requests import SnifferSession

import argparse
import os
import re
from sys import stderr

def main():
    p = argparse.ArgumentParser()
    p.add_argument('-v','--verbose', default=0, action='count')
    p.add_argument('-k','--keep-going', action='store_true', help='Keep going after first hit')
    p.add_argument('-t','--timeout', metavar='SEC', type=lambda x: int(x) or None, default=10, help='Timeout in seconds (default %(default)s, 0 for none)')
    p.add_argument('server', nargs='+', help='suspected SSL-VPN server')
    args = p.parse_args()

    s = SnifferSession()
    s.timeout = args.timeout

    for server in args.server:
        if args.verbose:
            print("\nSniffing {} ...".format(server))
        else:
            print("{}: ".format(server), end='')

        hits = []
        ssle = timeout = 0
        for desc, sniffer in sniffers:
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
                ex = e.__class__.__name__
            else:
                ex = 'no match'

            if hit:
                hits.append(hit)
                if not args.keep_going:
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

########################################

if __name__=='__main__':
    main()

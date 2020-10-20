import urllib3
import warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter('ignore', category=ResourceWarning)

import logging
from requests import exceptions as rex
from random import shuffle

from what_vpn.requests import SnifferSession
from what_vpn.sniffers import Hit, sniffers

matched_vpns = ['vpn.{}.edu'.format(d) for d in (
    'syr',
    'northeastern',
    'yale',
    'fau',
    'uca',
    'simmons',
    'nl',
    'ycp',
    'smcvt',
    'louisville',
    'usmma',
    'tcu',
    'brown',
    'acu',
    'whitworth',
    )] + ['vpn.{}.com'.format(d) for d in (
    'yonyou',
    )] + [
    'new.vpn.msu.edu',
    'cpvpn.its.hawaii.edu',
    'remote.princeton.edu',
    'uod.vpn.dundee.ac.uk',
    ]

unmatched_vpns = ['vpn.{}.edu'.format(d) for d in (
    'aurora',
    'wisc',
    'valpo',
    'uu',
    'drew', # FIXME: false-negative SonicWall
    )]

class test_known_servers:
    def setUp(self):
        self.session = SnifferSession()
        self.session.timeout = 10

    def check_hits(self, expected_hits, server):
        hits = 0
        shuffle(sniffers)
        for sniffer in sniffers:
            try:
                logging.debug('sniffing {} for {}'.format(server, sniffer.__name__))
                self.session.cookies.clear()
                hits += bool(sniffer(self.session, server))
            except (rex.Timeout, rex.SSLError, rex.ConnectionError) as e:
                pass
        if hits != expected_hits:
            raise AssertionError("got {} hits for {}, instead of expected {}".format(hits, server, expected_hits))

    def test_matched_vpns(self):
        for s in matched_vpns:
            yield self.check_hits, 1, s

    def test_unmatched_vpns(self):
        for s in unmatched_vpns:
            yield self.check_hits, 0, s

import urllib3
import warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter('ignore', category=ResourceWarning)

import logging
from requests import exceptions as rex
from random import shuffle

from what_vpn.requests import SnifferSession
from what_vpn.sniffers import Hit, sniffers as all_sniffers
import what_vpn.sniffers as sn

matched_vpns = [('vpn.{}.edu'.format(d), s) for d, s in (
    ('syr', sn.sstp),                    # bad cert
    ('northeastern', sn.global_protect), # portal
    ('yale', sn.anyconnect),             # Cisco, bad cert
    ('fau', sn.juniper_pulse),
    ('uca', sn.barracuda),
    ('simmons', sn.check_point),
    ('nl', sn.anyconnect),
    ('ycp', sn.fortinet),
    ('smcvt', sn.fortinet),              # bad cert
    ('louisville', sn.global_protect),   # portal
    ('usmma', sn.global_protect),        # portal+gateway, ccert
    ('tcu', sn.f5_bigip),
    ('brown', sn.f5_bigip),
    ('acu', sn.sonicwall_nx),
    ('whitworth', sn.f5_bigip),
    )] + [('vpn.{}.com'.format(d), s) for d, s in (
    ('yonyou', sn.array_networks),
    )] + [
    ('new.vpn.msu.edu', sn.f5_bigip),
    ('cpvpn.its.hawaii.edu', sn.check_point),
    ('remote.princeton.edu', sn.sonicwall_nx),
    ('uod.vpn.dundee.ac.uk', sn.sonicwall_nx),
    ('vpn.sgh.waw.pl', sn.global_protect),    # portal
    ('vpn-gw.sgh.waw.pl', sn.global_protect), # gateway
    ('jvpn.tn.gov', sn.juniper_pulse),
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

    def check_hits(self, server, expected):
        if expected is not None:
            expected_hits = 1
            expected = getattr(sn, expected)
            sniffers = list(set(all_sniffers) - { expected })
            shuffle(sniffers)
            sniffers = [expected] + sniffers[:2]
        else:
            expected_hits = 0
            sniffers = all_sniffers[:]
            shuffle(sniffers)

        hits = errors = 0
        for sniffer in sniffers:
            try:
                logging.debug('sniffing {} for {}'.format(server, sniffer.__name__))
                self.session.cookies.clear()
                hits += bool(sniffer(self.session, server))
            except (rex.Timeout, rex.SSLError, rex.ConnectionError) as e:
                errors += 1
        if hits + errors <= expected_hits > hits:
            warnings.warn("got {} hits and {} errors for {}, instead of expected {} hits".format(hits, errors, server, expected_hits))
        elif hits != expected_hits:
            raise AssertionError("got {} hits for {}, instead of expected {}".format(hits, server, expected_hits))

    def test_matched_vpns(self):
        for domain, expected in matched_vpns:
            yield self.check_hits, domain, expected.__name__

    def test_unmatched_vpns(self):
        self.sniffers = all_sniffers[:]
        for domain in unmatched_vpns:
            shuffle(self.sniffers)
            yield self.check_hits, domain, None

import urllib3
import warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.simplefilter('ignore', category=ResourceWarning)

import logging
from requests import exceptions as rex
from random import shuffle
import socket

from what_vpn.requests import SnifferSession
from what_vpn.sniffers import sniffers as all_sniffers
import what_vpn.sniffers as sn

matched_vpns = [('vpn.{}.edu'.format(d), s) for d, s in (
    ('northeastern', sn.global_protect),  # portal
    ('yale', sn.anyconnect),              # Cisco, bad cert
    ('fau', sn.juniper_pulse),
    ('jh', sn.juniper_pulse),
    ('simmons', sn.check_point),
    ('nl', sn.anyconnect),
    ('ycp', sn.fortinet),
    ('uakron', sn.fortinet),              # bad cert
    ('louisville', sn.global_protect),    # portal
    ('usmma', sn.global_protect),         # portal+gateway, ccert
    ('tcu', sn.f5_bigip),
    ('brown', sn.f5_bigip),
    ('acu', sn.sonicwall_nx),
    )] + [
    ('access.astate.edu', sn.juniper_secure_connect),
    ('securesso.aurora.edu', sn.global_protect),
    ('vpn.physics.ox.ac.uk', sn.sstp),
    ('uwmadison.vpn.wisc.edu', sn.global_protect),
    ('umsovpn.umassp.edu', sn.check_point),
    ('gmhssl.gmha.org', sn.barracuda),
    ('sslvpn.co.adams.il.us', sn.barracuda),
    ('univpn.unibe.ch', sn.fortinet),
    ('vpn.tongji.cn', sn.array_networks),
    ('new.vpn.msu.edu', sn.f5_bigip),
    ('cpvpn.its.hawaii.edu', sn.check_point),
    ('remote.princeton.edu', sn.sonicwall_nx),
    ('uod-2.vpn.dundee.ac.uk', sn.sonicwall_nx),
    ('vpn.sgh.waw.pl', sn.global_protect),     # portal
    ('vpn-gw.sgh.waw.pl', sn.global_protect),  # gateway
    ('jvpn.tn.gov', sn.juniper_pulse),
    ('174.127.47.193', sn.check_point),        # no DNS?
    ('nomad.sandiego.edu', sn.aruba_via),
    ('viavpn.luther.edu', sn.aruba_via),
    ('vpn.wdc.softlayer.com', sn.array_networks),
    ('166.111.32.74:10443', sn.h3c),           # no DNS? tsinghua.edu.cn
    ('58.246.39.91:8899', sn.huawei),          # no DNS? China, non-edu
    ('[2620:0:e00:4e::2]', sn.anyconnect)      # address changes sometimes (https://dns.google/query?name=vpn.cites.illinois.edu&type=AAAA)
    ]

unmatched_vpns = ['vpn.{}.edu'.format(d) for d in (
    'valpo',
    'uu',
    'drew',  # FIXME: false-negative SonicWall
    )]


class test_known_servers:
    def setUp(self):
        self.session = SnifferSession()
        self.session.timeout = 10

    def check_hits(self, server, expected):
        if expected is not None:
            expected_hits = 1
            expected = getattr(sn, expected)
            sniffers = list(set(all_sniffers) - {expected})
            shuffle(sniffers)
            sniffers = [expected] + sniffers[:2]
        else:
            expected_hits = 0
            sniffers = all_sniffers[:]
            shuffle(sniffers)

        hits = errors = got_expected_hit = 0
        for sniffer in sniffers:
            try:
                logging.debug('sniffing {} for {}'.format(server, sniffer.__name__))
                self.session.cookies.clear()
                hit = sniffer(self.session, server)
                if hit:
                    hits += 1
                    got_expected_hit += (expected.__name__ == sniffer.__name__)
                    logging.debug('got hit for {}: {}'.format(server, hit))
            except (rex.Timeout, rex.SSLError, rex.ConnectionError, socket.error) as e:
                logging.warn('sniffing {} for {} resulted in exception {}'.format(server, sniffer.__name__, e))
                errors += 1
        if hits + errors <= expected_hits > hits:
            warnings.warn("got {} hits and {} errors for {}, instead of expected {} hits".format(hits, errors, server, expected_hits))
        assert hits == expected_hits, "got {} hits for {}, instead of expected {}".format(hits, server, expected_hits)
        assert expected_hits == 0 or got_expected_hit

    def test_matched_vpns(self):
        for domain, expected in matched_vpns:
            yield self.check_hits, domain, expected.__name__

    def test_unmatched_vpns(self):
        self.sniffers = all_sniffers[:]
        for domain in unmatched_vpns:
            shuffle(self.sniffers)
            yield self.check_hits, domain, None


def test_server_split():
    def check_server_split(netloc, expected):
        assert sn.server_split(netloc) == expected

    for netloc, expected in (
        ('foo.bar.com:123', ('foo.bar.com', 123)),
        ('foo.bar.com', ('foo.bar.com', 443)),
        ('[dead:beef::f00f]', ('[dead:beef::f00f]', 443)),
        ('[dead:beef::f00f]:789', ('[dead:beef::f00f]', 789)),
    ):
        yield check_server_split, netloc, expected

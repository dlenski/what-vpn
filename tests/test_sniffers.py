import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import logging
from requests import exceptions as rex
from random import shuffle

from what_vpn.requests import SnifferSession
from what_vpn.sniffers import Hit, sniffers

session = SnifferSession()
session.timeout = 10

matched_vpns = ['vpn.{}.edu'.format(d) for d in ('drew','syr','calvin','northeastern','albany','yale','fau','uca','holycross','simmons','nl')]
unmatched_vpns = ['vpn.{}.edu'.format(d) for d in ('acu','aurora','brown','ycp','wisc','whitworth','valpo','uu')]

def _count_hits(server):
    hits = 0
    shuffle(sniffers)
    for sniffer in sniffers:
        try:
            logging.debug('sniffing {} for {}'.format(server, sniffer.__name__))
            session.cookies.clear()
            hits += bool(sniffer(session, server))
        except (rex.Timeout, rex.SSLError, rex.ConnectionError) as e:
            pass
    return hits

def test_matched_vpns():
    for server in matched_vpns:
        assert _count_hits(server)==1

def test_unmatched_vpns():
    for server in unmatched_vpns:
        assert _count_hits(server)==0

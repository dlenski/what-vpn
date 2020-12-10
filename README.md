[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://github.com/dlenski/what-vpn/workflows/test_and_release/badge.svg)](https://github.com/dlenski/what-vpn/actions?query=workflow%3Atest_and_release)
[![PyPI](https://img.shields.io/pypi/v/what-vpn.svg)](https://pypi.python.org/pypi/what-vpn)

# what-vpn

Identifies servers running various SSL VPNs. (They should really be called
"TLS-based" VPNs, but "SSL VPN" has become the de facto standard jargon.)
Currently it can recognize…

* Cisco AnyConnect and [OpenConnect (ocserv)](https://ocserv.gitlab.io/www)
* Juniper Network Connect/Pulse
* PAN GlobalProtect
* Barracuda Networks
* Check Point
* Microsoft SSTP
* [OpenVPN](https://openvpn.net/)
* Fortinet
* Array Networks
* F5 BigIP
* SonicWall NX

## Install

Requires Python 3, `pip`, and [`requests`](https://docs.python-requests.org):

```sh
$ pip3 install https://github.com/dlenski/what-vpn/archive/master.zip
...
$ what-vpn
usage: what-vpn [-h] [-k] [-t SEC] [-v | -c] server [server ...]
what-vpn: error: the following arguments are required: server
```

## Examples

```sh
$ what-vpn vpn.colorado.edu vpn.northeastern.edu \
    vpn.tnstate.edu vpn.smith.edu vpn.caltech.edu \
    vpn.yale.edu vpn.drew.edu vpn.uca.edu vpn.simmons.edu \
    vpn.nl.edu cpvpn.its.hawaii.edu ssl-vpn.***.com
vpn.colorado.edu: AnyConnect/OpenConnect (Cisco)
vpn.northeastern.edu: PAN GlobalProtect (portal)
vpn.tnstate.edu: PAN GlobalProtect (portal+gateway)
vpn.smith.edu: Juniper Network Connect
vpn.caltech.edu: AnyConnect/OpenConnect (Cisco, ASA (9.1(6)6))
vpn.yale.edu: AnyConnect/OpenConnect (Cisco, ASA (8.4(5)))
vpn.uca.edu: Barracuda (2017)
vpn.simmons.edu: Check Point (2015, 20%)
vpn.nl.edu: Check Point
cpvpn.its.hawaii.edu: Check Point
vpn.***.com: Array Networks (40%)
ssl-vpn.***.com: no match

$ what-vpn -kv vpn.***.com

Sniffing ***.***.com ...
  Is it AnyConnect/OpenConnect? ocserv, 0.8.0-0.11.6
  Is it Juniper Network Connect? no match
  Is it PAN GlobalProtect? no match
  Is it Barracuda? no match
  Is it Check Point? no match
  Is it SSTP? no match
  Is it OpenVPN? no match
  => AnyConnect/OpenConnect (ocserv, 0.8.0-0.11.6)
```

# Interesting results

An interesting question for the open source community, including the indispensable
[OpenConnect](https://www.infradead.org/openconnect) (which I also contribute to) is…

> What are the most commonly-used SSL VPN protocols in the real world?

In April 2019, I took a list of major universities and companies in the USA, and
generated some guesses for the hostnames of their VPN endpoints
(e.g. `{vpn,ssl-vpn,sslvpn}.*.{edu,com}`). I then used `what-vpn` to probe them all
and looked at the subset of the results that matched to an identifiable SSL
VPN protocol:

```
  1  Check Point
  1  Citrix (manually inspected, don't know how to reliably autodetect)
  1  OpenVPN
  5  Dell or SonicWall (manually inspected, didn't know how to reliably autodetect at the time
  7  Fortinet
  7  Barracuda
  8  F5 (manually inspected, didn't know how to reliably autodetect at this time)
 14  SSTP
 53  PAN GlobalProtect (portal and/or gateway)
 72  Juniper Network Connect (or Junos/Pulse, hard to distinguish)
243  Cisco AnyConnect (including 1 ocserv)
```

Assuming these results are roughly representative of “SSL VPN” deployments
_in general_ (at least in the USA), they show that OpenConnect already supports
the top 3 most commonly-encountered SSL VPN protocols, or about 80% of SSL VPNs.
Additionally Microsoft SSTP is supported by the open-source
[`sstp-client`](http://sstp-client.sourceforge.net),
and of course OpenVPN is well-supported by open-source clients as well.

_(Excerpted from
[this post on the OpenConnect mailing list](https://lists.infradead.org/pipermail/openconnect-devel/2019-April/005335.html))_

## TODO

* Identify non-SSL/TLS-based VPNs? (e.g. IPSEC, à la [ike-scan](//github.com/royhills/ike-scan))
* Identify more SSL VPNs: Citrix, Dell… any others?
  * Fix apparent false-negatives for some SonicWall servers
* Identify specific versions or flavors of VPN servers?
* Better confidence levels?

## License

GPLv3 or later

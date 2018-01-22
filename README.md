[![Build Status](https://api.travis-ci.org/dlenski/what-vpn.png)](https://travis-ci.org/dlenski/what-vpn)

# what-vpn

Identifies servers running various SSL VPNs. Currently it can recognize…

* Cisco AnyConnect and [OpenConnect (ocserv)](https://ocserv.gitlab.io/www)
* Juniper Network Connect/Pulse
* PAN GlobalProtect
* Barracuda Networks
* Check Point
* Microsoft SSTP
* [OpenVPN](https://openvpn.net/)
* Fortinet

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
    vpn.nl.edu vpn.***.edu
vpn.colorado.edu: AnyConnect/OpenConnect (Cisco)
vpn.northeastern.edu: PAN GlobalProtect (portal)
vpn.tnstate.edu: PAN GlobalProtect (portal+gateway)
vpn.smith.edu: Juniper Network Connect
vpn.caltech.edu: AnyConnect/OpenConnect (Cisco, ASA (9.1(6)6))
vpn.yale.edu: AnyConnect/OpenConnect (Cisco, ASA (8.4(5)))
vpn.drew.edu: OpenVPN (OpenVPN-AS)
vpn.uca.edu: Barracuda (2017)
vpn.simmons.edu: Check Point (2015, 20%)
vpn.nl.edu: Check Point
ssl-vpn.***.com: no match

$ what-vpn -v vpn.***.com

Sniffing ***.***.com ...
  Is it AnyConnect/OpenConnect? AnyConnect/OpenConnect (ocserv)
  Is it Juniper Network Connect? no match
  Is it PAN GlobalProtect? no match
  Is it Barracuda? no match
  Is it Check Point? no match
  Is it SSTP? no match
  Is it OpenVPN? no match
  => OpenConnect
```

## TODO

* Identify non-SSL VPNs? (e.g. IPSEC, à la [ike-scan](//github.com/royhills/ike-scan))
* Identify more SSL VPNs: Citrix, Dell/SonicWall, F5 … any others?
* Identify specific versions or flavors of VPN servers?
* Better confidence levels?

## License

GPLv3 or later

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

## Install

Requires Python 3, `pip`, and [`requests`](https://docs.python-requests.org):

```sh
$ pip3 install https://github.com/dlenski/what-vpn/archive/master.zip
...
$ what-vpn
usage: what-vpn [-h] [-v] [-1] [-t SEC] server [server ...]
what-vpn: error: the following arguments are required: server
```

## Examples

```sh
$ what-vpn vpn.colorado.edu vpn.northeastern.edu \
>   vpn.tnstate.edu sslvpn.uconn.edu vpn.cc.columbia.edu \
>   vpn.yale.edu vpn.drew.edu vpn.uca.edu \
>   ssl-vpn.***.com
vpn.colorado.edu: Cisco AnyConnect
vpn.northeastern.edu: PAN GlobalProtect (portal)
vpn.tnstate.edu: PAN GlobalProtect (portal and gateway)
sslvpn.uconn.edu: Juniper Network Connect
vpn.cc.columbia.edu: Cisco AnyConnect
vpn.yale.edu: Cisco AnyConnect
vpn.drew.edu: OpenVPN
vpn.uca.edu: Barracuda
ssl-vpn.***.com: no match

$ what-vpn -v vpn.***.com

Sniffing ***.***.com ...
  Is it AnyConnect/OpenConnect? OpenConnect
  Is it Juniper Network Connect? no match
  Is it PAN GlobalProtect? no match
  Is it Barracuda? no match
  Is it Check Point? no match
  Is it SSTP? no match
  Is it OpenVPN? no match
  => OpenConnect
```

## TODO

* Identify non-SSL VPNs? (e.g. IPSEC)
* Identify more SSL VPNs: Citrix, Dell/SonicWall, F5, and Forti
* Identify specific versions or flavors of VPN servers?
* Confidence levels?

## License

GPLv3 or later

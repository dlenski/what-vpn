# what-vpn

Identifies servers running various SSL VPNs. Currently it can recognize…

* Cisco AnyConnect
* [OpenConnect (ocserv)](https://en.wikipedia.org/wiki/OpenConnect)
* Juniper Network Connect/Pulse
* Microsoft SSTP
* PAN GlobalProtect

## Install

Requires Python 3, `pip`, and [`requests`](https://docs.python-requests.org):

```sh
$ pip3 install https://github.com/dlenski/what-vpn/archive/master.zip
...
$ what-vpn
usage: what-vpn [-h] [-v] [-t SEC] server [server ...]
what-vpn: error: the following arguments are required: server
```

## Examples

```sh
$ what-vpn vpn.colorado.edu vpn.northeastern.edu \
>   vpn.tnstate.edu sslvpn.uconn.edu vpn.cc.columbia.edu \
>   vpn.yale.edu ssl-vpn.***.com
vpn.colorado.edu: Cisco AnyConnect
vpn.northeastern.edu: PAN GlobalProtect (portal)
vpn.tnstate.edu: PAN GlobalProtect (portal and gateway)
sslvpn.uconn.edu: Juniper Network Connect
vpn.cc.columbia.edu: Cisco AnyConnect
vpn.yale.edu: Cisco AnyConnect
ssl-vpn.***.com: no match

$ what-vpn -v vpn.***.com

Sniffing ***.***.com ...
  Is it PAN GlobalProtect? no match
  Is it Juniper Network Connect? no match
  Is it Check Point? no match
  Is it SSTP? no match
  Is it AnyConnect/OpenConnect? OpenConnect
  => OpenConnect
```

## TODO

* Identify non-SSL VPNs? (e.g. IPSEC)
* More SSL VPNs: Citrix, OpenVPN, etc.
* Identify specific versions or flavors of VPN servers?
* Confidence levels?

## License

GPLv3 or later

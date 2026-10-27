# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations

from cowrie.shell.command import HoneyPotCommand

commands = {}

IFACE = "eth0"
MAC = "2c:f0:5d:8a:41:e6"
IP4 = "198.51.100.146"
PREFIX = "24"
BRD = "198.51.100.255"
IP6LL = "fe80::2ef0:5dff:fe8a:41e6"
GW = "198.51.100.1"

ADDR = f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: {IFACE}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether {MAC} brd ff:ff:ff:ff:ff:ff
    inet {IP4}/{PREFIX} brd {BRD} scope global {IFACE}
       valid_lft forever preferred_lft forever
    inet6 {IP6LL}/64 scope link
       valid_lft forever preferred_lft forever
"""

LINK = f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: {IFACE}: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000
    link/ether {MAC} brd ff:ff:ff:ff:ff:ff
"""

ROUTE = f"""default via {GW} dev {IFACE} proto static
198.51.100.0/24 dev {IFACE} proto kernel scope link src {IP4}
"""

BR_ADDR = f"""lo               UNKNOWN        127.0.0.1/8 ::1/128
{IFACE}             UP             {IP4}/{PREFIX} {IP6LL}/64
"""

USAGE = """Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }
       ip [ -force ] -batch filename
where  OBJECT := { link | address | addrlabel | route | rule | neigh | ntable |
                   tunnel | tuntap | maddress | mroute | mrule | monitor | xfrm |
                   netns | l2tp | fou | macsec | tcp_metrics | token | netconf | ila |
                   vrf | sr | nexthop | mptcp }
       OPTIONS := { -V[ersion] | -s[tatistics] | -d[etails] | -r[esolve] |
                    -h[uman-readable] | -iec | -j[son] | -p[retty] |
                    -f[amily] { inet | inet6 | mpls | bridge | link } |
                    -4 | -6 | -M | -B | -0 |
                    -br[ief] | ... }
"""


class Command_ip(HoneyPotCommand):
    def call(self) -> None:
        args = [a for a in self.args]
        brief = False
        obj = None
        for a in args:
            if a in ("-br", "-brief", "-b"):
                brief = True
            elif a.startswith("-"):
                # family/other flags: ignore for output shaping
                continue
            elif obj is None:
                obj = a

        if obj is None:
            self.errorWrite(USAGE)
            return

        o = obj.lower()
        if "address".startswith(o) or o == "a" or o == "addr":
            self.write(BR_ADDR if brief else ADDR)
        elif "link".startswith(o) or o == "l":
            self.write(LINK)
        elif "route".startswith(o) or o == "r":
            self.write(ROUTE)
        elif "neigh".startswith(o) or o == "n":
            self.write(f"{GW} dev {IFACE} lladdr 40:9b:cd:2a:11:84 REACHABLE\n")
        else:
            self.errorWrite(f'Object "{obj}" is unknown, try "ip help".\n')


commands["ip"] = Command_ip
commands["/usr/bin/ip"] = Command_ip
commands["/sbin/ip"] = Command_ip

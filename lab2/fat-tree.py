"""
  Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""

#!/usr/bin/env python3

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import OVSKernelSwitch, RemoteController
from mininet.topo import Topo

import topo


class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet
    """

    def __init__(self, ft_topo):

        Topo.__init__(self)

        print("Servers:", len(ft_topo.servers))
        print("Switches:", len(ft_topo.switches))

        # TODO: please complete the network generation logic here

        Topo.__init__(self)

        node_map = {}
        k    = 4
        half = k // 2

        # Build host IP and gateway maps
        host_ip_map = {}
        host_gw_map = {}

        for pod in range(k):
            for ei in range(half):
                edge_name = f"e{pod}{ei}"
                edge_node = None
                for sw in ft_topo.switches:
                    if sw.id == edge_name:
                        edge_node = sw
                        break
                if edge_node is None:
                    continue
                hosts_under = []
                for edge in edge_node.edges:
                    nb = edge.lnode if edge.rnode.id == edge_name else edge.rnode
                    if nb.type == "host":
                        hosts_under.append(nb)
                gateway = f"10.{pod}.{ei}.1"
                for idx, host_node in enumerate(hosts_under):
                    ip = f"10.{pod}.{ei}.{idx + 2}"
                    host_ip_map[host_node.id] = ip
                    host_gw_map[host_node.id] = gateway

        # Create switches — pass EXPLICIT dpid from topo.dpid_map
        for sw in ft_topo.switches:
            explicit_dpid = ft_topo.dpid_map[sw.id]
            dpid_hex = format(explicit_dpid, '016x')   # Mininet expects hex string
            node_map[sw.id] = self.addSwitch(
                sw.id,
                dpid=dpid_hex,
                protocols='OpenFlow13'
            )

        # Create hosts with correct IP (/24 mask) and default gateway
        for host in ft_topo.servers:
            ip = host_ip_map.get(host.id)
            gw = host_gw_map.get(host.id)
            if ip and gw:
                node_map[host.id] = self.addHost(
                    host.id,
                    ip=f"{ip}/24",
                    defaultRoute=f"via {gw}"
                )
            else:
                node_map[host.id] = self.addHost(host.id)

        # Create links (15 Mbps, 5 ms)
        added_links = set()
        for node in ft_topo.switches + ft_topo.servers:
            for edge in node.edges:
                left  = edge.lnode.id
                right = edge.rnode.id
                key   = tuple(sorted([left, right]))
                if key in added_links:
                    continue
                added_links.add(key)
                self.addLink(node_map[left], node_map[right], bw=15, delay='5ms')

        for sw in ft_topo.switches:
            print(f"Switch {sw.id} dpid={ft_topo.dpid_map[sw.id]}")
        for host in ft_topo.servers:
            print(f"Host {host.id} IP={host_ip_map.get(host.id)} GW={host_gw_map.get(host.id)}")


def make_mininet_instance(graph_topo):
    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):
    lg.setLogLevel('info')
    net = make_mininet_instance(graph_topo)
    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()
    mininet.clean.cleanup()


if __name__ == '__main__':
    ft_topo = topo.Fattree(4)
    run(ft_topo)
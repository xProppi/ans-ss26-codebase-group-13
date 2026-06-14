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

import os
import subprocess
import time

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

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

        #
        # Create switches
        #

        switch_counter = 1

        for sw in ft_topo.switches:

            node_map[sw.id] = self.addSwitch(
                sw.id,
                dpid=str(switch_counter).zfill(16),
                protocols='OpenFlow13'
            )

            switch_counter += 1

        #
        # Create hosts
        #
        for host in ft_topo.servers:

            node_map[host.id] = self.addHost(host.id)

        #
        # Create links
        #
        added_links = set()

        all_nodes = ft_topo.switches + ft_topo.servers

        for node in all_nodes:

            for edge in node.edges:

                left = edge.lnode.id
                right = edge.rnode.id

                link_key = tuple(sorted([left, right]))

                if link_key in added_links:
                    continue

                added_links.add(link_key)

                self.addLink(
                    node_map[left],
                    node_map[right],
                    bw=15,
                    delay='5ms'
                )

        for sw in ft_topo.switches:
            print("Adding switch:", sw.id)

        for host in ft_topo.servers:
            print("Adding host:", host.id)


        


def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True)
    net.addController('controller', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    # mininet.clean.cleanup()
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

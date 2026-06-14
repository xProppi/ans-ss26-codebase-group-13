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

from importlib.resources import path

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase

import topo

class SPRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        
        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4)
        self.adjacency = {}
        self.datapaths = {}
        self.hosts = {}


    # Topology discovery
    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):

        switch_list = get_switch(self, None)

        self.adjacency = {}

        for sw in switch_list:

            dpid = sw.dp.id

            self.adjacency.setdefault(dpid, {})

            self.datapaths[dpid] = sw.dp

        link_list = get_link(self, None)

        for link in link_list:

            src = link.src.dpid
            dst = link.dst.dpid

            self.adjacency.setdefault(src, {})
            self.adjacency.setdefault(dst, {})

            self.adjacency[src][dst] = link.src.port_no
            self.adjacency[dst][src] = link.dst.port_no

        print("TOPOLOGY:")
        print(self.adjacency)

        print("LINKS")

        for src in self.adjacency:
            for dst in self.adjacency[src]:
                print(src, "->", dst,
                    "port", self.adjacency[src][dst])        
        print("DATAPATHS:", self.datapaths)


    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath

        # Install entry-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        print("DATAPATH CONNECTED:", datapath.id)


    # Add a flow entry to the flow-table
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def dijkstra(self, src, dst):

        dist = {}
        prev = {}

        for node in self.adjacency:
            dist[node] = float('inf')
            prev[node] = None

        dist[src] = 0

        unvisited = set(self.adjacency.keys())

        while unvisited:

            current = min(
                unvisited,
                key=lambda x: dist[x]
            )

            if current == dst:
                break

            unvisited.remove(current)

            for neighbor in self.adjacency[current]:

                alt = dist[current] + 1

                if alt < dist[neighbor]:

                    dist[neighbor] = alt
                    prev[neighbor] = current

        path = []

        node = dst

        while node is not None:

            path.insert(0, node)
            node = prev[node]

        
        if dist[dst] == float('inf'):
            return []
        
        return path

    # TODO: handle new packets at the controller
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        #print("\nPACKET IN")

        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        pkt = packet.Packet(msg.data)

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)

        #if arp_pkt:
         #   print(f"ARP: switch={dpid} src={arp_pkt.src_ip} dst={arp_pkt.dst_ip}")

        #if ip_pkt:
         #   print(f"IP: switch={dpid} src={ip_pkt.src} dst={ip_pkt.dst}")

        #print("DPID:", dpid)
        #print("ARP:", arp_pkt)
        #print("IP :", ip_pkt)
        
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        #
        # ARP handling
        #
        if arp_pkt:

            #if arp_pkt:
                #print("ARP PACKET")
            
           

    # Learn only from host-facing ports
            if in_port >= 3:
                self.hosts[arp_pkt.src_ip] = (
                    dpid,
                    in_port
                )

            actions = [
                parser.OFPActionOutput(
                    ofproto.OFPP_FLOOD
                )
            ]

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )

            datapath.send_msg(out)

            return

        #
        # Ignore non-IP packets
        #
        
       # print("NOT ARP")
        if ip_pkt is None:
            return

        src_ip = ip_pkt.src
        dst_ip = ip_pkt.dst

        #
        # Learn source host location
        #

        if in_port >= 3:
            self.hosts[src_ip] = (
                dpid,
                in_port
            )

        #
        # Destination not learned yet
        #
        
        
        if dst_ip not in self.hosts:

            actions = [
                parser.OFPActionOutput(
                    ofproto.OFPP_FLOOD
                )
            ]

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )

            datapath.send_msg(out)
            return

        dst_switch, dst_host_port = self.hosts[dst_ip]

        #
        # Same switch
        #
        if dpid == dst_switch:

            out_port = dst_host_port

        else:

            path = self.dijkstra(
                dpid,
                dst_switch
            )

      
            print(
                "PATH",
                src_ip,
                "->",
                dst_ip,
                path
            )

            if len(path) < 2:
                return

            next_hop = path[1]

            out_port = self.adjacency[
                dpid
            ][
                next_hop
            ]

        packet_actions = [
            parser.OFPActionOutput(out_port)
        ]

        if dpid == dst_switch:
            path = [dpid]
        else:
            path = self.dijkstra(dpid, dst_switch)

        for i in range(len(path)):

            current_switch = path[i]

            if current_switch not in self.datapaths:
                continue

            dp = self.datapaths[current_switch]

            parser = dp.ofproto_parser

            #
            # Last switch in path
            #
            if current_switch == dst_switch:

                port = dst_host_port

            else:

                next_switch = path[i + 1]

                port = self.adjacency[current_switch][next_switch]

            match = parser.OFPMatch(
                eth_type=0x0800,
                ipv4_dst=dst_ip
            )

            actions = [
                parser.OFPActionOutput(port)
            ]

            self.add_flow(
                dp,
                10,
                match,
                actions
            )

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=packet_actions,
            data=msg.data
        )

        datapath.send_msg(out)






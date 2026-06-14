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

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4
from ryu.lib.packet import arp

from ryu.topology import event, switches
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.lib import hub

import topo

# One MAC per subnet gateway — used for ARP proxy replies
GATEWAY_MAC = "00:00:00:00:ff:ff"


class FTRouter(app_manager.RyuApp):

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FTRouter, self).__init__(*args, **kwargs)

        # Initialize the topology with #ports=4
        self.topo_net = topo.Fattree(4)
        self.k    = 4
        self.half = 2

        # dpid -> datapath
        self.datapaths = {}

        # name -> dpid  (from topo.dpid_map — guaranteed unique)
        self.name_to_dpid = dict(self.topo_net.dpid_map)

        # port_map[src_dpid][dst_dpid] = port_no
        self.port_map = {}

        # host_mac[host_ip] = mac  (learned from ARP)
        self.host_mac = {}

        # host_port[host_ip] = (dpid, port)  (learned from ARP)
        self.host_port = {}

        # gateway_ip -> edge_switch_name that owns it
        # e.g. "10.0.0.1" -> "e00"
        self.gateway_to_edge = {}

        # Build classification and IP tables
        self._build_tables()

  
    def _build_tables(self):
        k    = self.k
        half = self.half

        self.switch_info = {}   # name -> (pod, layer, idx)
        self.host_ip     = {}   # host_name -> ip string
        self.ip_to_host  = {}   # ip string -> host_name

        for sw in self.topo_net.switches:
            name = sw.id
            if name.startswith('e'):
                pod = int(name[1]); idx = int(name[2])
                self.switch_info[name] = (pod, 'edge', idx)
                # This edge switch is the gateway for subnet 10.pod.idx.0/24
                self.gateway_to_edge[f"10.{pod}.{idx}.1"] = name
            elif name.startswith('a'):
                pod = int(name[1]); idx = int(name[2])
                self.switch_info[name] = (pod, 'aggr', idx)
            elif name.startswith('c'):
                idx = int(name[1:])
                self.switch_info[name] = (None, 'core', idx)

        for pod in range(k):
            for ei in range(half):
                edge_name = f"e{pod}{ei}"
                edge_node = next((s for s in self.topo_net.switches
                                  if s.id == edge_name), None)
                if edge_node is None:
                    continue
                # Get hosts directly connected to this edge switch
                host_nodes = []
                for e in edge_node.edges:
                    nb = e.rnode if e.lnode.id == edge_name else e.lnode
                    if nb.type == 'host':
                        host_nodes.append(nb)
                for offset, h in enumerate(host_nodes):
                    ip = f"10.{pod}.{ei}.{offset + 2}"
                    self.host_ip[h.id]  = ip
                    self.ip_to_host[ip] = h.id

        self.logger.info("Tables: %d switches, %d hosts, %d gateways",
                         len(self.switch_info), len(self.host_ip),
                         len(self.gateway_to_edge))
        self.logger.info("gateway_to_edge: %s", self.gateway_to_edge)

    
    # Topology discovery

    @set_ev_cls(event.EventSwitchEnter)
    def get_topology_data(self, ev):
        # Switches and links in the network
        switches = get_switch(self, None)
        links    = get_link(self, None)
        hub.spawn_after(5, self._install_routing)

    def _install_routing(self):
        links = get_link(self, None)
        if not links:
            self.logger.warning("No links yet, retrying in 3s")
            hub.spawn_after(3, self._install_routing)
            return

        for link in links:
            self.port_map.setdefault(link.src.dpid, {})[link.dst.dpid] = \
                link.src.port_no

        self.logger.info("port_map: %d entries", len(self.port_map))

        installed = 0
        for sw in self.topo_net.switches:
            info = self.switch_info.get(sw.id)
            if info is None:
                continue
            pod, layer, idx = info
            dp = self._dp(sw.id)
            if dp is None:
                self.logger.warning("No datapath for %s", sw.id)
                continue
            p = dp.ofproto_parser
            if layer == 'core':
                self._core_rules(sw, dp, p)
            elif layer == 'aggr':
                self._aggr_rules(sw, pod, idx, dp, p)
            elif layer == 'edge':
                self._edge_rules(sw, pod, idx, dp, p)
            installed += 1

        self.logger.info("Rules installed on %d/20 switches", installed)

    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        self.logger.info("Switch connected dpid=%d", datapath.id)

        # Install entry-miss flow entry
        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)


    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser  = datapath.ofproto_parser

        # Construct flow_mod message and send it
        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)


    def _dp(self, name):
        dpid = self.name_to_dpid.get(name)
        if dpid is None:
            return None
        return self.datapaths.get(dpid)

    def _out_port(self, src_name, dst_name):
        src = self.name_to_dpid.get(src_name)
        dst = self.name_to_dpid.get(dst_name)
        if src is None or dst is None:
            return None
        return self.port_map.get(src, {}).get(dst)

    def _sw_nb(self, sw_node, layer=None, pod=None):
        result = []
        for edge in sw_node.edges:
            nb = edge.rnode if edge.lnode.id == sw_node.id else edge.lnode
            if nb.type != 'switch':
                continue
            info = self.switch_info.get(nb.id)
            if info is None:
                continue
            nb_pod, nb_layer, nb_idx = info
            if layer is not None and nb_layer != layer:
                continue
            if pod is not None and nb_pod != pod:
                continue
            port = self._out_port(sw_node.id, nb.id)
            result.append((nb, port, nb_pod, nb_layer, nb_idx))
        return result


    # ROUTING RULES

    def _core_rules(self, sw_node, dp, parser):
        """Core: /16 prefix per pod, priority 1."""
        for nb, port, nb_pod, nb_layer, nb_idx in self._sw_nb(sw_node, layer='aggr'):
            if port is None:
                continue
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=(f"10.{nb_pod}.0.0", "255.255.0.0")
            )
            self.add_flow(dp, 1, match, [parser.OFPActionOutput(port)])
            self.logger.info("CORE %s: 10.%d.0.0/16 -> port %d",
                             sw_node.id, nb_pod, port)

    def _aggr_rules(self, sw_node, pod, aggr_idx, dp, parser):
        """Aggr: /24 intra-pod (priority 10), /32 inter-pod (priority 1)."""
        half = self.half
        edge_nbs = self._sw_nb(sw_node, layer='edge', pod=pod)
        core_nbs = [(nb, port) for nb, port, _, _, _
                    in self._sw_nb(sw_node, layer='core') if port is not None]

        # Intra-pod /24 rules
        for nb, port, _, _, edge_idx in edge_nbs:
            if port is None:
                continue
            match = parser.OFPMatch(
                eth_type=ether_types.ETH_TYPE_IP,
                ipv4_dst=(f"10.{pod}.{edge_idx}.0", "255.255.255.0")
            )
            self.add_flow(dp, 10, match, [parser.OFPActionOutput(port)])

        # Inter-pod /32 per external host
        for host_ip in self.ip_to_host:
            parts = host_ip.split('.')
            if int(parts[1]) == pod:
                continue
            host_id = int(parts[3])
            ci = (host_id - 2 + aggr_idx) % half
            if ci < len(core_nbs):
                _, port = core_nbs[ci]
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=host_ip
                )
                self.add_flow(dp, 1, match, [parser.OFPActionOutput(port)])

    def _edge_rules(self, sw_node, pod, edge_idx, dp, parser):
        """Edge: /32 per remote host toward agg (priority 1).
        Local host rules installed dynamically on PacketIn (priority 100)."""
        half = self.half
        agg_ports = [(nb, port, nb_idx)
                     for nb, port, _, _, nb_idx
                     in self._sw_nb(sw_node, layer='aggr', pod=pod)
                     if port is not None]

        for host_ip in self.ip_to_host:
            parts  = host_ip.split('.')
            h_pod  = int(parts[1])
            h_edge = int(parts[2])
            if h_pod == pod and h_edge == edge_idx:
                continue
            host_id = int(parts[3])
            ai = (host_id - 2 + edge_idx) % half
            if ai < len(agg_ports):
                _, port, _ = agg_ports[ai]
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=host_ip
                )
                self.add_flow(dp, 1, match, [parser.OFPActionOutput(port)])

   
    # ARP PROXY — the missing piece

    def _send_arp_reply(self, datapath, in_port, src_mac, src_ip,
                        dst_mac, dst_ip, ofproto, parser):
        """Send an ARP reply from the controller acting as the gateway."""
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            ethertype=ether_types.ETH_TYPE_ARP,
            dst=src_mac,
            src=GATEWAY_MAC
        ))
        reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=GATEWAY_MAC,
            src_ip=dst_ip,        # the gateway IP the host asked about
            dst_mac=src_mac,
            dst_ip=src_ip
        ))
        reply.serialize()

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=reply.data
        )
        datapath.send_msg(out)


    # PacketIn handler
   
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        dpid     = datapath.id
        ofproto  = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt     = packet.Packet(msg.data)
        eth_pkt = pkt.get_protocol(ethernet.ethernet)
        if eth_pkt is None:
            return
        if eth_pkt.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        if not arp_pkt:
            return

        src_ip  = arp_pkt.src_ip
        dst_ip  = arp_pkt.dst_ip
        src_mac = arp_pkt.src_mac

        # Learn host location and MAC
        if src_ip in self.ip_to_host:
            if src_ip not in self.host_mac:
                self.host_mac[src_ip]  = src_mac
                self.host_port[src_ip] = (dpid, in_port)
                self.logger.info("Learned host %s mac=%s dpid=%d port=%d",
                                 src_ip, src_mac, dpid, in_port)
                # Install high-priority exact rule for this host
                match = parser.OFPMatch(
                    eth_type=ether_types.ETH_TYPE_IP,
                    ipv4_dst=src_ip
                )
                self.add_flow(datapath, 100, match,
                              [parser.OFPActionOutput(in_port)])

        if arp_pkt.opcode != arp.ARP_REQUEST:
            return

        # Case 1: host is ARPing for its GATEWAY (e.g. h1 ARPs for 10.0.0.1)
        # The controller replies with GATEWAY_MAC on behalf of the gateway
        if dst_ip in self.gateway_to_edge:
            self.logger.info("ARP proxy: replying to %s asking for gateway %s",
                             src_ip, dst_ip)
            self._send_arp_reply(datapath, in_port,
                                 src_mac, src_ip,
                                 GATEWAY_MAC, dst_ip,
                                 ofproto, parser)
            return

        # Case 2: host is ARPing for another host on same subnet
        # (intra-subnet, shouldn't happen much but handle it)
        if dst_ip in self.host_mac:
            # We know the destination MAC — reply directly
            self._send_arp_reply(datapath, in_port,
                                 src_mac, src_ip,
                                 self.host_mac[dst_ip], dst_ip,
                                 ofproto, parser)
        else:
            # Unknown — flood it (only within this switch)
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=[parser.OFPActionOutput(ofproto.OFPP_FLOOD)],
                data=msg.data
            )
            datapath.send_msg(out)
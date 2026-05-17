"""
 Copyright (c) 2026 Computer Networks Group @ UPB

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


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4, icmp

class LearningSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(LearningSwitch, self).__init__(*args, **kwargs)
        
        # Data structure for the learning switches (s1 and s2)
        self.mac_to_port = {}

        # Router port MACs assumed by the controller (s3)
        self.port_to_own_mac = {
            1: "00:00:00:00:01:01",
            2: "00:00:00:00:01:02",
            3: "00:00:00:00:01:03"
        }
        
        # Router port (gateways) IP addresses assumed by the controller (s3)
        self.port_to_own_ip = {
            1: "10.0.1.1",
            2: "10.0.2.1",
            3: "192.168.1.1"
        }
        
        # ARP cache for the router
        self.arp_cache = {} 
        # buffer for packets that are waiting for arp replies 
        self.pend_packets = {}

        self.EXT_IP       = "192.168.1.123"
        self.SER_IP       = "10.0.2.2"
        self.INTERNAL_IPS = ["10.0.1.2", "10.0.1.3", "10.0.2.2"]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Table-miss flow entry (sends unknown packets to the controller)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

        if datapath.id == 3:
            self._install_security_rules(datapath, parser)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id, 
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        # Extract packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # ROUTER LOGIC (s3)
        
        if dpid == 3:
            if arp_pkt:
                self.handle_arp(datapath, in_port, eth, arp_pkt, parser, ofproto)
                return
    
            if ipv4_pkt:
                self.handle_ipv4(datapath, in_port, eth, ipv4_pkt, parser, ofproto, msg, pkt)
                return

        # SWITCH LOGIC (s1, s2)

        elif dpid in [1, 2]:
            dst = eth.dst
            src = eth.src

            # Learn source MAC address
            self.mac_to_port[dpid][src] = in_port

            # Determine destination port
            if dst in self.mac_to_port[dpid]:
                out_port = self.mac_to_port[dpid][dst]
            else:
                out_port = ofproto.OFPP_FLOOD

            actions = [parser.OFPActionOutput(out_port)]

            # Install flow rule if destination is known
            if out_port != ofproto.OFPP_FLOOD:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
                
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return 
                else:
                    self.add_flow(datapath, 1, match, actions)

            # Send packet out (PacketOut)
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)

    def _install_security_rules(self, datapath, parser):
        drop = []
        for ip in self.INTERNAL_IPS:
            self.add_flow(datapath, 100, parser.OFPMatch(
                eth_type=0x0800, ip_proto=1,
                ipv4_src=self.EXT_IP, ipv4_dst=ip), drop)
        self.add_flow(datapath, 100, parser.OFPMatch(
            eth_type=0x0800, ip_proto=6,
            ipv4_src=self.EXT_IP, ipv4_dst=self.SER_IP), drop)
        self.add_flow(datapath, 100, parser.OFPMatch(
            eth_type=0x0800, ip_proto=6,
            ipv4_src=self.SER_IP, ipv4_dst=self.EXT_IP), drop)
        self.add_flow(datapath, 100, parser.OFPMatch(
            eth_type=0x0800, ip_proto=17,
            ipv4_src=self.EXT_IP, ipv4_dst=self.SER_IP), drop)
        self.add_flow(datapath, 100, parser.OFPMatch(
            eth_type=0x0800, ip_proto=17,
            ipv4_src=self.SER_IP, ipv4_dst=self.EXT_IP), drop)

    def _send_icmp_reply(self, datapath, in_port, eth, ipv4_pkt, icmp_pkt, parser, ofproto):
        router_ip  = self.port_to_own_ip[in_port]
        router_mac = self.port_to_own_mac[in_port]
        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            dst=eth.src, src=router_mac, ethertype=ether_types.ETH_TYPE_IP))
        reply.add_protocol(ipv4.ipv4(
            dst=ipv4_pkt.src, src=router_ip, proto=1, ttl=64))
        # copy the original echo data as-is so id/seq are preserved in the raw bytes
        echo_data = icmp_pkt.data
        reply.add_protocol(icmp.icmp(
            type_=icmp.ICMP_ECHO_REPLY, code=0, csum=0,
            data=echo_data))
        reply.serialize()
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=reply.data)
        datapath.send_msg(out)

    def handle_arp(self, datapath, in_port, eth, arp_pkt, parser, ofproto):
        # Add IP to MAC mapping to cache
        self.arp_cache[arp_pkt.src_ip] = arp_pkt.src_mac
        
        resolved_ip = arp_pkt.src_ip

        # process and rease any bueffered packerts waiting for this ips mac
        if resolved_ip in self.pend_packets:
            for pending_dp, pending_in_port, pending_msg, pending_out_port in self.pend_packets[resolved_ip]:
                router_mac_out = self.port_to_own_mac[pending_out_port]
                dst_mac = arp_pkt.src_mac

                match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=resolved_ip)
                actions = [
                                parser.OFPActionSetField(eth_src=router_mac_out),
                                parser.OFPActionSetField(eth_dst=dst_mac),
                                parser.OFPActionDecNwTtl(),
                                parser.OFPActionOutput(pending_out_port)
                            ]
                self.add_flow(pending_dp, 10, match, actions, pending_msg.buffer_id)

                if pending_msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    out = parser.OFPPacketOut(
                        datapath=pending_dp,
                        buffer_id=pending_msg.buffer_id,
                        in_port=pending_in_port,
                        actions=actions,
                        data=pending_msg.data
                    )
                    pending_dp.send_msg(out)
            
            # Clear the buffer for this IP once handled
            del self.pend_packets[resolved_ip]

        if arp_pkt.opcode != arp.ARP_REQUEST:
            return

        target_ip = arp_pkt.dst_ip
        router_ip = self.port_to_own_ip.get(in_port)

        if target_ip == router_ip:
            router_mac = self.port_to_own_mac[in_port]
            
            reply_pkt = packet.Packet()

            # Ethernet header for the reply
            eth_reply = ethernet.ethernet(
                dst=eth.src,
                src=router_mac,
                ethertype=ether_types.ETH_TYPE_ARP
            )
            reply_pkt.add_protocol(eth_reply)
            
            # ARP header for the reply
            arp_reply = arp.arp(
                hwtype=1,
                proto=0x0800,
                hlen=6,
                plen=4,
                opcode=arp.ARP_REPLY,
                src_mac=router_mac,
                src_ip=router_ip,
                dst_mac=arp_pkt.src_mac,
                dst_ip=arp_pkt.src_ip
            )
            reply_pkt.add_protocol(arp_reply)

            # Serialize to bytestream
            reply_pkt.serialize()

            actions = [parser.OFPActionOutput(in_port)]

            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions,
                data=reply_pkt.data
            )
            datapath.send_msg(out)

    def handle_ipv4(self, datapath, in_port, eth, ipv4_pkt, parser, ofproto, msg, pkt=None): 
        dst_ip = ipv4_pkt.dst

        if dst_ip in self.port_to_own_ip.values():
            for port, ip in self.port_to_own_ip.items():
                if ip == dst_ip and port == in_port and pkt is not None:
                    icmp_pkt = pkt.get_protocol(icmp.icmp)
                    if icmp_pkt and icmp_pkt.type == icmp.ICMP_ECHO_REQUEST:
                        self._send_icmp_reply(datapath, in_port, eth,
                                              ipv4_pkt, icmp_pkt, parser, ofproto)
            return

        # Determine output port based on subnet
        out_port = None
        for port, ip in self.port_to_own_ip.items():
            if dst_ip.rsplit('.', 1)[0] == ip.rsplit('.', 1)[0]:
                out_port = port
                break
        
        if out_port is None:
            return 

        dst_mac = self.arp_cache.get(dst_ip)

        if not dst_mac:
            if dst_ip not in self.pend_packets:
                self.pend_packets[dst_ip] = []
            self.pend_packets[dst_ip].append((datapath, in_port, msg, out_port))
            # Generate and send an ARP request for the unknown MAC
            router_ip_out = self.port_to_own_ip[out_port]
            router_mac_out = self.port_to_own_mac[out_port]

            req_pkt = packet.Packet()
            
            # Ethernet header for broadcast
            eth_req = ethernet.ethernet(
                dst="ff:ff:ff:ff:ff:ff",
                src=router_mac_out,
                ethertype=ether_types.ETH_TYPE_ARP
            )
            req_pkt.add_protocol(eth_req)

            # ARP header for the request
            arp_req = arp.arp(
                hwtype=1,
                proto=0x0800,
                hlen=6,
                plen=4,
                opcode=arp.ARP_REQUEST,
                src_mac=router_mac_out,
                src_ip=router_ip_out,
                dst_mac="00:00:00:00:00:00",
                dst_ip=dst_ip
            )
            req_pkt.add_protocol(arp_req)

            req_pkt.serialize()

            actions_req = [parser.OFPActionOutput(out_port)]
            out_req = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=ofproto.OFPP_CONTROLLER,
                actions=actions_req,
                data=req_pkt.data
            )
            datapath.send_msg(out_req)
            return
        
        router_mac_out = self.port_to_own_mac[out_port]
        match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=dst_ip)

        actions = [
            parser.OFPActionSetField(eth_src=router_mac_out),
            parser.OFPActionSetField(eth_dst=dst_mac),
            parser.OFPActionDecNwTtl(),
            parser.OFPActionOutput(out_port)
        ]

        self.add_flow(datapath, 10, match, actions, msg.buffer_id)

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=msg.buffer_id,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)

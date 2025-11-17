#!/usr/bin/env python3
"""
Ryu SDN Controller with ARP Spoofing Detection
Detects MiTM attacks by monitoring ARP table inconsistencies
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp
from datetime import datetime
import logging

class MiTMDetectionController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MiTMDetectionController, self).__init__(*args, **kwargs)
        
        # MAC learning table
        self.mac_to_port = {}
        
        # ARP table: IP -> MAC mapping
        self.arp_table = {}
        
        # Track ARP requests and replies
        self.arp_history = []
        
        # Attack detection flags
        self.mitm_detected = False
        self.attack_logs = []
        
        # Configure logging
        self.logger.setLevel(logging.INFO)
        
        self.logger.info("="*60)
        self.logger.info("MiTM Detection Controller Started")
        self.logger.info("Monitoring for ARP spoofing attacks...")
        self.logger.info("="*60)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle switch connection"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info("Switch connected: DPID=%s", datapath.id)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, idle_timeout=0):
        """Add a flow entry to the switch"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout)
        datapath.send_msg(mod)

    def detect_arp_spoofing(self, ip_addr, mac_addr, arp_op):
        """
        Detect ARP spoofing by checking for IP-MAC inconsistencies
        Returns: True if attack detected, False otherwise
        """
        
        if ip_addr in self.arp_table:
            stored_mac = self.arp_table[ip_addr]
            
            # Check if MAC address changed for the same IP
            if stored_mac != mac_addr:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                attack_info = {
                    'timestamp': timestamp,
                    'ip': ip_addr,
                    'original_mac': stored_mac,
                    'spoofed_mac': mac_addr,
                    'arp_operation': 'Reply' if arp_op == 2 else 'Request'
                }
                
                self.attack_logs.append(attack_info)
                self.mitm_detected = True
                
                self.logger.critical("="*60)
                self.logger.critical("⚠️  MITM ATTACK DETECTED!")
                self.logger.critical("="*60)
                self.logger.critical("Timestamp: %s", timestamp)
                self.logger.critical("Target IP: %s", ip_addr)
                self.logger.critical("Original MAC: %s", stored_mac)
                self.logger.critical("Spoofed MAC: %s", mac_addr)
                self.logger.critical("Attack Type: ARP Spoofing")
                self.logger.critical("="*60)
                
                return True
        else:
            # First time seeing this IP-MAC binding
            self.arp_table[ip_addr] = mac_addr
            self.logger.info("ARP Entry Added: IP=%s -> MAC=%s", ip_addr, mac_addr)
        
        return False

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle incoming packets"""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88cc:  # LLDP packet
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        # Learn MAC address - ALWAYS learn, even during attack
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        
        self.logger.debug("Learned: %s is at port %s", src, in_port)

        # Check for ARP packets
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.handle_arp(datapath, in_port, eth, arp_pkt)
            return

        # Handle IPv4 packets (temperature data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self.handle_ipv4(datapath, in_port, eth, ipv4_pkt, pkt)
            return

        # Default forwarding for other packets
        # Use learned MAC table to forward
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]

        # Install flow to avoid packet_in next time
        # Install flows even during attack (controller detects but allows traffic)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, buffer_id=msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def handle_arp(self, datapath, in_port, eth, arp_pkt):
        """Handle ARP packets and detect spoofing"""
        
        arp_src_ip = arp_pkt.src_ip
        arp_src_mac = arp_pkt.src_mac
        arp_dst_ip = arp_pkt.dst_ip
        arp_opcode = arp_pkt.opcode

        operation = "Request" if arp_opcode == 1 else "Reply"
        
        self.logger.info("-"*60)
        self.logger.info("ARP %s: %s (%s) -> %s", 
                        operation, arp_src_ip, arp_src_mac, arp_dst_ip)
        
        # Detect ARP spoofing
        is_attack = self.detect_arp_spoofing(arp_src_ip, arp_src_mac, arp_opcode)
        
        if is_attack:
            self.logger.warning("⚠️  Suspicious ARP packet detected - possible MiTM")
            # IMPORTANT: Still forward the packet for educational purposes
            # In production, you would DROP this packet
        
        # Forward ARP packet (ALWAYS forward, even if attack detected)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        
        # Serialize the packet data
        from ryu.lib.packet import packet as pkt_lib
        pkt = pkt_lib.Packet()
        pkt.add_protocol(eth)
        pkt.add_protocol(arp_pkt)
        pkt.serialize()
        
        out = parser.OFPPacketOut(
            datapath=datapath, 
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port, 
            actions=actions, 
            data=pkt.data
        )
        datapath.send_msg(out)
        
        # Update MAC learning table even during attack
        # This ensures traffic flows through the attacker
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][arp_src_mac] = in_port

    def handle_ipv4(self, datapath, in_port, eth, ipv4_pkt, pkt):
        """Handle IPv4 packets (temperature data)"""
        
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        
        # Check for TCP/UDP payload (temperature data)
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        udp_pkt = pkt.get_protocol(udp.udp)
        
        if tcp_pkt or udp_pkt:
            protocol = "TCP" if tcp_pkt else "UDP"
            self.logger.info("Temperature Data: %s -> %s (%s)", src_ip, dst_ip, protocol)
            
            # Check if this communication is happening during a MiTM attack
            if self.mitm_detected:
                self.logger.warning("⚠️  Data transmission during active MiTM attack!")
                self.logger.warning("   Source: %s, Destination: %s", src_ip, dst_ip)
        
        # Forward the packet using MAC-based forwarding (NOT IP-based)
        # This allows ARP spoofing to work
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        # Use MAC address from Ethernet header for forwarding decision
        dst_mac = eth.dst
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        
        self.logger.debug("Forwarding to MAC %s via port %s", dst_mac, out_port)
        
        # CRITICAL: Install MAC-based flow entry (NOT IP-based)
        # This ensures ARP spoofing can redirect traffic
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_dst=dst_mac  # Match on MAC, not IP!
            )
            # Lower priority than table-miss, short timeout
            self.add_flow(datapath, 1, match, actions, idle_timeout=10)
        
        # Serialize packet
        pkt.serialize()
            
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)

    def get_attack_summary(self):
        """Return summary of detected attacks"""
        return {
            'total_attacks': len(self.attack_logs),
            'attacks': self.attack_logs,
            'arp_table': self.arp_table
        }

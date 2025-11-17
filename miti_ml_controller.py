#!/usr/bin/env python3
"""
Production ML-Based SDN Controller with Active Mitigation
- Detects MiTM attacks using ML
- Actively mitigates by blocking attacker
- Redirects traffic back to legitimate path
- Provides manual mitigation control
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
from datetime import datetime
import logging
import pickle
import os
import json
import numpy as np
from collections import defaultdict, deque
import time

class ProductionMLController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(ProductionMLController, self).__init__(*args, **kwargs)
        
        # Network state
        self.mac_to_port = {}
        self.ip_mac_history = defaultdict(set)
        self.legitimate_ip_mac = {}  # Store legitimate IP-MAC bindings
        
        # Time window configuration
        self.window_size = 10  # seconds
        self.window_start = time.time()
        
        # Traffic statistics per MAC
        self.window_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'arp_count': 0,
            'arp_request_count': 0,
            'arp_reply_count': 0,
            'tcp_count': 0,
            'tcp_syn_count': 0,
            'tcp_syn_ack_count': 0,
            'tcp_fin_count': 0,
            'tcp_rst_count': 0,
            'udp_count': 0,
            'icmp_count': 0,
            'unique_dst_ips': set(),
            'unique_dst_ports': set(),
            'unique_src_ips': set(),
            'packet_sizes': [],
            'inter_arrival_times': [],
            'last_packet_time': None,
        })
        
        # ML Model components
        self.ml_model = None
        self.scaler = None
        self.feature_names = []
        self.metadata = {}
        
        # Detection and Mitigation state
        self.detected_attacks = []
        self.blocked_macs = set()
        self.alert_history = deque(maxlen=100)
        self.mitigation_enabled = True  # Enable/disable mitigation
        self.mitigation_mode = 'block'  # 'block' or 'redirect'
        
        # Datapath reference for mitigation
        self.datapath = None
        
        # Configure logging
        self.logger.setLevel(logging.INFO)
        
        # Load ML model
        self.load_ml_model()
        
        self.logger.info("="*70)
        self.logger.info("Production ML-Based MiTM Detection Controller")
        self.logger.info("WITH ACTIVE MITIGATION")
        self.logger.info("="*70)
        if self.ml_model:
            self.logger.info("✓ ML Model loaded successfully")
            self.logger.info(f"  Model type: {type(self.ml_model).__name__}")
            self.logger.info(f"  Features: {len(self.feature_names)}")
        else:
            self.logger.error("✗ ML Model not loaded - using rule-based only")
        self.logger.info(f"Mitigation: {'ENABLED' if self.mitigation_enabled else 'DISABLED'}")
        self.logger.info(f"Mode: {self.mitigation_mode.upper()}")
        self.logger.info("="*70)

    def load_ml_model(self):
        """Load trained ML model and preprocessing components"""
        try:
            with open('mitm_detector_model.pkl', 'rb') as f:
                self.ml_model = pickle.load(f)
            
            if os.path.exists('feature_scaler.pkl'):
                with open('feature_scaler.pkl', 'rb') as f:
                    self.scaler = pickle.load(f)
            
            if os.path.exists('model_metadata.json'):
                with open('model_metadata.json', 'r') as f:
                    self.metadata = json.load(f)
                    self.feature_names = self.metadata.get('feature_names', [])
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error loading ML model: {e}")
            return False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapath = datapath  # Store for later use
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        
        self.logger.info(f"Switch connected: DPID={datapath.id}")

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, 
                 idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,
                                    idle_timeout=idle_timeout,
                                    hard_timeout=hard_timeout)
        datapath.send_msg(mod)
    
    def delete_flow(self, datapath, match):
        """Delete a specific flow rule"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        datapath.send_msg(mod)
    
    def extract_features(self, mac_addr):
        """Extract ML features from traffic statistics"""
        stats = self.window_stats[mac_addr]
        
        if stats['packet_count'] == 0:
            return None
        
        duration = time.time() - self.window_start
        if duration == 0:
            duration = 1
        
        # Calculate rates
        packet_rate = stats['packet_count'] / duration
        byte_rate = stats['byte_count'] / duration
        arp_rate = stats['arp_count'] / duration
        tcp_rate = stats['tcp_count'] / duration
        udp_rate = stats['udp_count'] / duration
        icmp_rate = stats['icmp_count'] / duration
        
        # Protocol ratios
        arp_reply_ratio = 0
        if stats['arp_count'] > 0:
            arp_reply_ratio = stats['arp_reply_count'] / stats['arp_count']
        
        tcp_syn_ack_ratio = 0
        if stats['tcp_syn_count'] > 0:
            tcp_syn_ack_ratio = stats['tcp_syn_ack_count'] / stats['tcp_syn_count']
        
        # Anomaly indicators
        ip_mac_changes = sum(1 for ip in stats['unique_src_ips'] 
                            if len(self.ip_mac_history[ip]) > 1)
        unique_dst_ips = len(stats['unique_dst_ips'])
        unique_dst_ports = len(stats['unique_dst_ports'])
        
        # Statistical features
        avg_packet_size = np.mean(stats['packet_sizes']) if stats['packet_sizes'] else 0
        std_packet_size = np.std(stats['packet_sizes']) if stats['packet_sizes'] else 0
        avg_iat = np.mean(stats['inter_arrival_times']) if stats['inter_arrival_times'] else 0
        
        features = np.array([
            packet_rate,
            byte_rate,
            arp_rate,
            tcp_rate,
            udp_rate,
            icmp_rate,
            arp_reply_ratio,
            tcp_syn_ack_ratio,
            ip_mac_changes,
            unique_dst_ips,
            unique_dst_ports,
            avg_packet_size,
            std_packet_size,
            avg_iat,
        ]).reshape(1, -1)
        
        return features
    
    def predict_attack(self, mac_addr):
        """Use ML model to predict if traffic is malicious"""
        if self.ml_model is None:
            return False, 0.0, "Model not loaded"
        
        features = self.extract_features(mac_addr)
        
        if features is None:
            return False, 0.0, "No features"
        
        try:
            if self.scaler:
                features = self.scaler.transform(features)
            
            prediction = self.ml_model.predict(features)[0]
            
            if hasattr(self.ml_model, 'predict_proba'):
                probability = self.ml_model.predict_proba(features)[0]
                confidence = probability[1]
            else:
                confidence = 1.0 if prediction == 1 else 0.0
            
            is_attack = bool(prediction == 1)
            method = f"ML ({confidence:.2%} confidence)"
            
            return is_attack, confidence, method
            
        except Exception as e:
            self.logger.error(f"Prediction error: {e}")
            return False, 0.0, f"Error: {e}"
    
    def mitigate_attack(self, attacker_mac, victim_ip=None):
        """
        Actively mitigate the attack
        
        Options:
        1. Block attacker completely (DROP all traffic)
        2. Redirect traffic back to legitimate path
        3. Rate limit attacker
        """
        if not self.mitigation_enabled or self.datapath is None:
            return False
        
        parser = self.datapath.ofproto_parser
        ofproto = self.datapath.ofproto
        
        try:
            if self.mitigation_mode == 'block':
                # Option 1: Complete block (DROP)
                # Block all traffic FROM attacker
                match = parser.OFPMatch(eth_src=attacker_mac)
                actions = []  # Empty = DROP
                self.add_flow(self.datapath, 1000, match, actions, hard_timeout=300)
                
                self.logger.warning(f"🚫 BLOCKED (DROP): {attacker_mac}")
                
            elif self.mitigation_mode == 'redirect':
                # Option 2: Redirect traffic to legitimate destination
                if victim_ip and victim_ip in self.legitimate_ip_mac:
                    legitimate_mac = self.legitimate_ip_mac[victim_ip]
                    legitimate_port = self.mac_to_port.get(1, {}).get(legitimate_mac)
                    
                    if legitimate_port:
                        # Block attacker's ARP packets
                        match_arp = parser.OFPMatch(
                            eth_src=attacker_mac,
                            eth_type=0x0806  # ARP
                        )
                        actions_arp = []  # DROP ARP from attacker
                        self.add_flow(self.datapath, 1000, match_arp, actions_arp, 
                                     hard_timeout=300)
                        
                        # Redirect IP traffic to legitimate destination
                        match_ip = parser.OFPMatch(
                            eth_type=0x0800,  # IPv4
                            ipv4_dst=victim_ip
                        )
                        actions_ip = [
                            parser.OFPActionSetField(eth_dst=legitimate_mac),
                            parser.OFPActionOutput(legitimate_port)
                        ]
                        self.add_flow(self.datapath, 500, match_ip, actions_ip, 
                                     hard_timeout=300)
                        
                        self.logger.warning(f"🔀 REDIRECTED: Traffic to {victim_ip} "
                                          f"→ legitimate MAC {legitimate_mac}")
            
            self.blocked_macs.add(attacker_mac)
            return True
            
        except Exception as e:
            self.logger.error(f"Mitigation error: {e}")
            return False
    
    def restore_normal_operation(self, attacker_mac):
        """Remove mitigation rules and restore normal operation"""
        if self.datapath is None:
            return False
        
        try:
            parser = self.datapath.ofproto_parser
            
            # Delete blocking rule for this MAC
            match = parser.OFPMatch(eth_src=attacker_mac)
            self.delete_flow(self.datapath, match)
            
            # Delete ARP blocking rule
            match_arp = parser.OFPMatch(eth_src=attacker_mac, eth_type=0x0806)
            self.delete_flow(self.datapath, match_arp)
            
            self.blocked_macs.discard(attacker_mac)
            
            self.logger.info(f"✓ Restored normal operation for {attacker_mac}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error restoring: {e}")
            return False
    
    def handle_attack_detection(self, mac_addr, confidence, method, datapath=None):
        """Handle detected attack with mitigation"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Find which IP this attacker is spoofing
        victim_ips = [ip for ip in self.ip_mac_history 
                     if mac_addr in self.ip_mac_history[ip]]
        
        attack_info = {
            'timestamp': timestamp,
            'attacker_mac': mac_addr,
            'victim_ips': victim_ips,
            'confidence': confidence,
            'method': method,
            'mitigated': False
        }
        
        self.detected_attacks.append(attack_info)
        self.alert_history.append(attack_info)
        
        # Log attack
        self.logger.critical("="*70)
        self.logger.critical("⚠️  MITM ATTACK DETECTED!")
        self.logger.critical("="*70)
        self.logger.critical(f"Timestamp: {timestamp}")
        self.logger.critical(f"Attacker MAC: {mac_addr}")
        self.logger.critical(f"Victim IP(s): {', '.join(victim_ips)}")
        self.logger.critical(f"Detection Method: {method}")
        self.logger.critical(f"Confidence: {confidence:.2%}")
        self.logger.critical("="*70)
        
        # Mitigation
        if confidence > 0.70 and mac_addr not in self.blocked_macs:
            self.logger.critical("🛡️  INITIATING MITIGATION...")
            
            # Find victim IP for redirection
            victim_ip = victim_ips[0] if victim_ips else None
            
            success = self.mitigate_attack(mac_addr, victim_ip)
            
            if success:
                attack_info['mitigated'] = True
                self.logger.critical(f"✓ Attack mitigated successfully!")
                self.logger.critical(f"   Attacker {mac_addr} blocked for 5 minutes")
                self.logger.critical(f"   Traffic protected")
            else:
                self.logger.error("✗ Mitigation failed!")
            
            self.logger.critical("="*70)
    
    def check_and_predict(self, mac_addr, datapath=None):
        """Check traffic and make ML prediction"""
        is_attack, confidence, method = self.predict_attack(mac_addr)
        
        if is_attack and confidence > 0.70:
            self.handle_attack_detection(mac_addr, confidence, method, datapath)
            return True
        
        return False
    
    def aggregate_window(self):
        """Aggregate current window and make predictions"""
        for mac_addr in list(self.window_stats.keys()):
            if self.window_stats[mac_addr]['packet_count'] > 0:
                self.check_and_predict(mac_addr)
        
        self.window_stats.clear()
        self.window_start = time.time()

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == 0x88cc:
            return

        dst = eth.dst
        src = eth.src
        dpid = datapath.id
        
        # Check if this MAC is blocked
        if src in self.blocked_macs:
            self.logger.debug(f"Dropped packet from blocked MAC: {src}")
            return  # Drop packet silently
        
        current_time = time.time()
        
        if current_time - self.window_start >= self.window_size:
            self.aggregate_window()
        
        # Update statistics
        stats = self.window_stats[src]
        stats['packet_count'] += 1
        stats['byte_count'] += len(msg.data)
        stats['packet_sizes'].append(len(msg.data))
        
        if stats['last_packet_time']:
            iat = current_time - stats['last_packet_time']
            stats['inter_arrival_times'].append(iat)
        stats['last_packet_time'] = current_time
        
        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Handle ARP
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self.handle_arp(datapath, in_port, eth, arp_pkt)
            return

        # Handle IPv4
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self.handle_ipv4(datapath, in_port, eth, ipv4_pkt, pkt)
            return

        # Default forwarding
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD
        
        actions = [parser.OFPActionOutput(out_port)]

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
        arp_src_ip = arp_pkt.src_ip
        arp_src_mac = arp_pkt.src_mac
        arp_opcode = arp_pkt.opcode

        # Store legitimate IP-MAC bindings (first seen)
        if arp_src_ip not in self.legitimate_ip_mac:
            self.legitimate_ip_mac[arp_src_ip] = arp_src_mac
            self.logger.debug(f"Learned legitimate: {arp_src_ip} → {arp_src_mac}")

        # Update statistics
        stats = self.window_stats[arp_src_mac]
        stats['arp_count'] += 1
        stats['unique_src_ips'].add(arp_src_ip)
        
        if arp_opcode == 1:
            stats['arp_request_count'] += 1
        elif arp_opcode == 2:
            stats['arp_reply_count'] += 1
        
        # Track IP-MAC binding
        self.ip_mac_history[arp_src_ip].add(arp_src_mac)
        
        # Forward ARP
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        out_port = ofproto.OFPP_FLOOD
        actions = [parser.OFPActionOutput(out_port)]
        
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
        
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][arp_src_mac] = in_port

    def handle_ipv4(self, datapath, in_port, eth, ipv4_pkt, pkt):
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        src_mac = eth.src
        
        stats = self.window_stats[src_mac]
        stats['unique_src_ips'].add(src_ip)
        stats['unique_dst_ips'].add(dst_ip)
        
        self.ip_mac_history[src_ip].add(src_mac)
        
        # TCP
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt:
            stats['tcp_count'] += 1
            stats['unique_dst_ports'].add(tcp_pkt.dst_port)
            
            if tcp_pkt.bits & tcp.TCP_SYN:
                stats['tcp_syn_count'] += 1
            if (tcp_pkt.bits & tcp.TCP_SYN) and (tcp_pkt.bits & tcp.TCP_ACK):
                stats['tcp_syn_ack_count'] += 1
            if tcp_pkt.bits & tcp.TCP_FIN:
                stats['tcp_fin_count'] += 1
            if tcp_pkt.bits & tcp.TCP_RST:
                stats['tcp_rst_count'] += 1
        
        # UDP
        udp_pkt = pkt.get_protocol(udp.udp)
        if udp_pkt:
            stats['udp_count'] += 1
            stats['unique_dst_ports'].add(udp_pkt.dst_port)
        
        # ICMP
        icmp_pkt = pkt.get_protocol(icmp.icmp)
        if icmp_pkt:
            stats['icmp_count'] += 1
        
        # Forwarding
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        dst_mac = eth.dst
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac)
            self.add_flow(datapath, 1, match, actions, idle_timeout=10)
        
        pkt.serialize()
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)
    
    def save_detection_log(self):
        """Save detection log for analysis"""
        if self.detected_attacks:
            filename = f"detection_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(self.detected_attacks, f, indent=2, default=str)
            self.logger.info(f"✓ Detection log saved to {filename}")

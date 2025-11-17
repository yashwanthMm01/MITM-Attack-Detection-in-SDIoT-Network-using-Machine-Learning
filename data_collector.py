#!/usr/bin/env python3
"""
Real-Time Network Traffic Data Collector
Collects features from live network traffic for ML training
Run this BEFORE training to collect real dataset
"""

from scapy.all import sniff, ARP, IP, TCP, UDP, ICMP, Ether
import csv
import json
import time
from datetime import datetime
from collections import defaultdict
import signal
import sys

class TrafficDataCollector:
    def __init__(self, interface='sensor-eth0'):
        self.interface = interface
        self.running = True
        
        # Time window for feature aggregation
        self.window_size = 10  # seconds
        self.current_window_start = time.time()
        
        # Statistics per MAC address
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
            'flow_durations': [],
            'packet_sizes': [],
            'inter_arrival_times': [],
            'last_packet_time': None,
        })
        
        # Global IP-MAC tracking
        self.ip_mac_history = defaultdict(set)  # IP -> set of MACs
        
        # Collected features
        self.collected_data = []
        
        # Current label (user sets this)
        self.current_label = 0  # 0=normal, 1=attack
        
        print("="*70)
        print("Real-Time Traffic Data Collector")
        print("="*70)
        print(f"Interface: {interface}")
        print(f"Window size: {self.window_size} seconds")
        print("="*70)
        
    def set_label(self, label):
        """Set current traffic label (0=normal, 1=attack)"""
        self.current_label = label
        label_name = "NORMAL" if label == 0 else "ATTACK"
        print(f"\n🏷️  Label changed to: {label} ({label_name})")
    
    def process_packet(self, packet):
        """Process each captured packet"""
        
        if not self.running:
            return
        
        current_time = time.time()
        
        # Check if we need to start a new window
        if current_time - self.current_window_start >= self.window_size:
            self.aggregate_and_save()
            self.current_window_start = current_time
        
        # Extract Ethernet layer
        if not packet.haslayer(Ether):
            return
        
        src_mac = packet[Ether].src
        dst_mac = packet[Ether].dst
        
        stats = self.window_stats[src_mac]
        
        # Update basic stats
        stats['packet_count'] += 1
        stats['byte_count'] += len(packet)
        stats['packet_sizes'].append(len(packet))
        
        # Inter-arrival time
        if stats['last_packet_time']:
            iat = current_time - stats['last_packet_time']
            stats['inter_arrival_times'].append(iat)
        stats['last_packet_time'] = current_time
        
        # ARP processing
        if packet.haslayer(ARP):
            stats['arp_count'] += 1
            
            arp_op = packet[ARP].op
            if arp_op == 1:  # Request
                stats['arp_request_count'] += 1
            elif arp_op == 2:  # Reply
                stats['arp_reply_count'] += 1
            
            # Track IP-MAC bindings
            src_ip = packet[ARP].psrc
            src_mac_arp = packet[ARP].hwsrc
            self.ip_mac_history[src_ip].add(src_mac_arp)
        
        # IP layer processing
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            stats['unique_src_ips'].add(src_ip)
            stats['unique_dst_ips'].add(dst_ip)
            
            # Track IP-MAC binding
            self.ip_mac_history[src_ip].add(src_mac)
            
            # TCP processing
            if packet.haslayer(TCP):
                stats['tcp_count'] += 1
                stats['unique_dst_ports'].add(packet[TCP].dport)
                
                flags = packet[TCP].flags
                if flags & 0x02:  # SYN
                    stats['tcp_syn_count'] += 1
                if flags & 0x12:  # SYN-ACK
                    stats['tcp_syn_ack_count'] += 1
                if flags & 0x01:  # FIN
                    stats['tcp_fin_count'] += 1
                if flags & 0x04:  # RST
                    stats['tcp_rst_count'] += 1
            
            # UDP processing
            if packet.haslayer(UDP):
                stats['udp_count'] += 1
                stats['unique_dst_ports'].add(packet[UDP].dport)
            
            # ICMP processing
            if packet.haslayer(ICMP):
                stats['icmp_count'] += 1
    
    def aggregate_and_save(self):
        """Aggregate window statistics and save features"""
        
        if not self.window_stats:
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        for mac, stats in self.window_stats.items():
            
            if stats['packet_count'] == 0:
                continue
            
            # Calculate rates (per second)
            duration = self.window_size
            
            packet_rate = stats['packet_count'] / duration
            byte_rate = stats['byte_count'] / duration
            arp_rate = stats['arp_count'] / duration
            tcp_rate = stats['tcp_count'] / duration
            udp_rate = stats['udp_count'] / duration
            icmp_rate = stats['icmp_count'] / duration
            
            # ARP reply ratio
            arp_reply_ratio = 0
            if stats['arp_count'] > 0:
                arp_reply_ratio = stats['arp_reply_count'] / stats['arp_count']
            
            # TCP SYN/ACK ratio
            syn_ack_ratio = 0
            if stats['tcp_syn_count'] > 0:
                syn_ack_ratio = stats['tcp_syn_ack_count'] / stats['tcp_syn_count']
            
            # IP-MAC changes (spoofing indicator)
            ip_mac_changes = sum(1 for ip in stats['unique_src_ips'] 
                                if len(self.ip_mac_history[ip]) > 1)
            
            # Connection diversity
            unique_dst_ips = len(stats['unique_dst_ips'])
            unique_dst_ports = len(stats['unique_dst_ports'])
            
            # Packet size statistics
            avg_packet_size = 0
            std_packet_size = 0
            if stats['packet_sizes']:
                import numpy as np
                avg_packet_size = np.mean(stats['packet_sizes'])
                std_packet_size = np.std(stats['packet_sizes'])
            
            # Inter-arrival time statistics
            avg_iat = 0
            std_iat = 0
            if stats['inter_arrival_times']:
                import numpy as np
                avg_iat = np.mean(stats['inter_arrival_times'])
                std_iat = np.std(stats['inter_arrival_times'])
            
            # Feature vector (15 features)
            features = {
                'timestamp': timestamp,
                'src_mac': mac,
                
                # Rate features
                'packet_rate': round(packet_rate, 4),
                'byte_rate': round(byte_rate, 4),
                'arp_rate': round(arp_rate, 4),
                'tcp_rate': round(tcp_rate, 4),
                'udp_rate': round(udp_rate, 4),
                'icmp_rate': round(icmp_rate, 4),
                
                # Protocol features
                'arp_reply_ratio': round(arp_reply_ratio, 4),
                'tcp_syn_ack_ratio': round(syn_ack_ratio, 4),
                
                # Anomaly indicators
                'ip_mac_changes': ip_mac_changes,
                'unique_dst_ips': unique_dst_ips,
                'unique_dst_ports': unique_dst_ports,
                
                # Statistical features
                'avg_packet_size': round(avg_packet_size, 2),
                'std_packet_size': round(std_packet_size, 2),
                'avg_inter_arrival_time': round(avg_iat, 6),
                
                # Label
                'label': self.current_label
            }
            
            self.collected_data.append(features)
        
        # Print summary
        label_name = "NORMAL" if self.current_label == 0 else "ATTACK"
        print(f"[{timestamp}] Collected {len(self.window_stats)} samples ({label_name})")
        print(f"  Total collected: {len(self.collected_data)} samples")
        
        # Reset window statistics
        self.window_stats.clear()
    
    def save_to_csv(self, filename='collected_dataset.csv'):
        """Save collected data to CSV"""
        
        if not self.collected_data:
            print("No data to save!")
            return
        
        keys = self.collected_data[0].keys()
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(self.collected_data)
        
        print(f"\n✓ Dataset saved to {filename}")
        print(f"  Total samples: {len(self.collected_data)}")
        
        # Count by label
        normal_count = sum(1 for d in self.collected_data if d['label'] == 0)
        attack_count = sum(1 for d in self.collected_data if d['label'] == 1)
        
        print(f"  Normal samples: {normal_count}")
        print(f"  Attack samples: {attack_count}")
    
    def start_collection(self):
        """Start packet capture"""
        
        print(f"\n🎯 Starting packet capture on {self.interface}...")
        print("Commands:")
        print("  - Type 'normal' to mark traffic as NORMAL")
        print("  - Type 'attack' to mark traffic as ATTACK")
        print("  - Type 'save' to save dataset")
        print("  - Type 'quit' to stop and save")
        print("="*70)
        
        # Start sniffing in background
        import threading
        
        def sniff_packets():
            sniff(iface=self.interface, prn=self.process_packet, 
                  store=False, stop_filter=lambda x: not self.running)
        
        sniff_thread = threading.Thread(target=sniff_packets)
        sniff_thread.daemon = True
        sniff_thread.start()
        
        # Command loop
        try:
            while self.running:
                cmd = input("\n> ").strip().lower()
                
                if cmd == 'normal':
                    self.set_label(0)
                elif cmd == 'attack':
                    self.set_label(1)
                elif cmd == 'save':
                    self.aggregate_and_save()
                    self.save_to_csv()
                elif cmd == 'quit' or cmd == 'exit':
                    self.stop_collection()
                    break
                elif cmd == 'stats':
                    self.print_statistics()
                elif cmd == 'help':
                    self.print_help()
                else:
                    print("Unknown command. Type 'help' for commands.")
        
        except KeyboardInterrupt:
            self.stop_collection()
    
    def stop_collection(self):
        """Stop collection and save"""
        print("\n\nStopping collection...")
        self.running = False
        self.aggregate_and_save()
        self.save_to_csv()
        print("✓ Collection stopped")
    
    def print_statistics(self):
        """Print current statistics"""
        print("\n" + "="*70)
        print("COLLECTION STATISTICS")
        print("="*70)
        print(f"Total samples collected: {len(self.collected_data)}")
        
        if self.collected_data:
            normal = sum(1 for d in self.collected_data if d['label'] == 0)
            attack = sum(1 for d in self.collected_data if d['label'] == 1)
            print(f"  Normal: {normal} ({normal/len(self.collected_data)*100:.1f}%)")
            print(f"  Attack: {attack} ({attack/len(self.collected_data)*100:.1f}%)")
        
        print(f"\nCurrent window:")
        print(f"  Active MACs: {len(self.window_stats)}")
        print(f"  Tracked IP-MAC bindings: {len(self.ip_mac_history)}")
        print("="*70)
    
    def print_help(self):
        """Print help"""
        print("\n" + "="*70)
        print("COMMANDS")
        print("="*70)
        print("  normal  - Mark current traffic as NORMAL")
        print("  attack  - Mark current traffic as ATTACK")
        print("  save    - Save dataset to CSV")
        print("  stats   - Show collection statistics")
        print("  quit    - Stop collection and save")
        print("  help    - Show this help")
        print("="*70)


def main():
    """Main function"""
    
    print("="*70)
    print("SDIoT MiTM Detection - Data Collection Tool")
    print("="*70)
    print("\nUsage:")
    print("  1. Start normal traffic (sensor sending data)")
    print("  2. Type 'normal' and let it run for 5-10 minutes")
    print("  3. Start attack (attacker script)")
    print("  4. Type 'attack' and let it run for 3-5 minutes")
    print("  5. Type 'save' to save dataset")
    print("="*70)
    
    # Get interface from user
    interface = input("\nEnter interface name (default: sensor-eth0): ").strip()
    if not interface:
        interface = 'sensor-eth0'
    
    collector = TrafficDataCollector(interface=interface)
    
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        collector.stop_collection()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    collector.start_collection()


if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("✗ This script must be run as root (use sudo)")
        sys.exit(1)
    
    main()

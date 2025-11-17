#!/usr/bin/env python3
"""
Receiver - Receives temperature data from sensor
Run this on the receiver node """

import socket
import json
import threading
from datetime import datetime

HOST = "10.0.0.2"
PORT = 5000

class TemperatureReceiver:
    def __init__(self):
        self.running = True
        self.received_data = []
    
    def handle_client(self, client_socket, address):
        """Handle incoming connection from sensor"""
        
        try:
            # Receive data
            data = client_socket.recv(4096).decode()
            
            if data:
                # Parse JSON data
                temp_data = json.loads(data.strip())
                
                # Store received data
                self.received_data.append({
                    'source': address[0],
                    'data': temp_data,
                    'received_at': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                })
                
                # Display received data
                print("\n" + "="*60)
                print("📊 TEMPERATURE DATA RECEIVED")
                print("="*60)
                print(f"Source IP: {address[0]}")
                print(f"Sensor ID: {temp_data.get('sensor_id', 'Unknown')}")
                print(f"Temperature: {temp_data.get('temperature', 'N/A')}°C")
                print(f"Timestamp: {temp_data.get('timestamp', 'N/A')}")
                print(f"Location: {temp_data.get('location', 'N/A')}")
                print("="*60)
                
                # Send acknowledgment
                ack = f"ACK: Data received at {datetime.now().strftime('%H:%M:%S')}"
                client_socket.sendall(ack.encode())
                
        except json.JSONDecodeError:
            print(f"✗ Invalid data format from {address[0]}")
        except Exception as e:
            print(f"✗ Error handling client {address[0]}: {e}")
        finally:
            client_socket.close()
    
    def start_server(self):
        """Start the receiver server"""
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            # Bind and listen
            server_socket.bind((HOST, PORT))
            server_socket.listen(5)
            server_socket.settimeout(1.0)  # Timeout for checking self.running
            
            print("="*60)
            print("Temperature Receiver Started")
            print("="*60)
            print(f"Listening on {HOST}:{PORT}")
            print("Waiting for sensor data...")
            print("="*60)
            print()
            
            while self.running:
                try:
                    # Accept connection
                    client_socket, address = server_socket.accept()
                    
                    # Handle client in a new thread
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                    
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"Error accepting connection: {e}")
            
        except Exception as e:
            print(f"✗ Server error: {e}")
        finally:
            server_socket.close()
            print("\nReceiver stopped")
    
    def stop(self):
        """Stop the receiver"""
        self.running = False

def main():
    """Main function"""
    
    receiver = TemperatureReceiver()
    
    try:
        receiver.start_server()
    except KeyboardInterrupt:
        print("\n\nShutting down receiver...")
        receiver.stop()

if __name__ == "__main__":
    main()

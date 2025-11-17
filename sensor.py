#!/usr/bin/env python3
"""
Temperature Sensor - Sends temperature data to receiver
Run this on the sensor node """

import socket
import json
import time
from datetime import datetime

RECEIVER_IP = "10.0.0.2"
RECEIVER_PORT = 5000

def send_temperature(temp_value):
    """Send temperature data to receiver"""

    try:
        # Create socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)

        # Connect to receiver
        print(f"Connecting to receiver at {RECEIVER_IP}:{RECEIVER_PORT}...")
        sock.connect((RECEIVER_IP, RECEIVER_PORT))

        # Prepare temperature data
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        data = {
            "sensor_id": "TEMP_SENSOR_001",
            "temperature": temp_value,
            "unit": "Celsius",
            "timestamp": timestamp,
            "location": "IoT Node"
        }
 
        # Send data
        message = json.dumps(data) + "\n"
        sock.sendall(message.encode())
        
        print(f"✓ Temperature sent: {temp_value}°C at {timestamp}")
        
        # Receive acknowledgment
        response = sock.recv(1024).decode()
        if response:
            print(f"✓ Receiver response: {response.strip()}")
        
        sock.close()
        
    except socket.timeout:
        print("✗ Connection timeout - receiver not responding")
    except ConnectionRefusedError:
        print("✗ Connection refused - is receiver running?")
    except Exception as e:
        print(f"✗ Error sending data: {e}")

def main():
    """Main function - interactive temperature input"""
    
    print("="*60)
    print("Temperature Sensor - SDIoT Network")
    print("="*60)
    print(f"Sensor IP: 10.0.0.1")
    print(f"Receiver IP: {RECEIVER_IP}")
    print(f"Port: {RECEIVER_PORT}")
    print("="*60)
    print()
    
    while True:
        try:
            # Get temperature input from user
            temp_input = input("\nEnter temperature (°C) or 'quit' to exit: ")
            
            if temp_input.lower() in ['quit', 'exit', 'q']:
                print("Exiting sensor...")
                break
            
            # Validate input
            try:
                temperature = float(temp_input)
            except ValueError:
                print("Invalid input. Please enter a numeric value.")
                continue
            
            # Send temperature
            send_temperature(temperature)
            
        except KeyboardInterrupt:
            print("\n\nSensor stopped by user")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
SDIoT Network Topology with Temperature Sensor
Topology: sensor -- switch -- [receiver, attacker]
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink

def create_topology():
    """Create SDIoT network topology"""
    
    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )
    
    info('*** Adding Ryu controller\n')
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )
    
    info('*** Adding switch\n')
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    
    info('*** Adding hosts\n')
    # Temperature sensor (IoT device)
    sensor = net.addHost('sensor', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    
    # Legitimate receiver
    receiver = net.addHost('receiver', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    
    # Attacker
    attacker = net.addHost('attacker', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    
    info('*** Creating links\n')
    net.addLink(sensor, s1)
    net.addLink(receiver, s1)
    net.addLink(attacker, s1)
    
    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])
    
    # Wait for controller connection
    info('*** Waiting for switch to connect to controller\n')
    import time
    time.sleep(2)
    
    info('*** Network started successfully\n')
    info('*** Hosts:\n')
    info('    Sensor: 10.0.0.1 (MAC: 00:00:00:00:00:01)\n')
    info('    Receiver: 10.0.0.2 (MAC: 00:00:00:00:00:02)\n')
    info('    Attacker: 10.0.0.3 (MAC: 00:00:00:00:00:03)\n')
    info('\n*** To test:\n')
    info('    1. On receiver: xterm receiver\n')
    info('    2. On attacker: xterm attacker\n')
    info('    3. On sensor: xterm sensor\n')
    
    CLI(net)
    
    info('*** Stopping network\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    create_topology()

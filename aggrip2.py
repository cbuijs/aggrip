#!/usr/bin/env python3
'''
==========================================================================
 aggrip2.py v0.11-20251124 Copyright 2019-2025 by cbuijs@chrisbuijs.com
==========================================================================

 Aggregate IPs into a CIDR list using ipaddress
 Note: Faster but more memory then aggrip.py

==========================================================================
'''

import sys
import ipaddress
from ipaddress import IPv4Network, IPv6Network

def get_valid_networks():
    ipv4_networks = []
    ipv6_networks = []

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            network = ipaddress.ip_network(line)
            
            if isinstance(network, IPv4Network):
                ipv4_networks.append(network)
            elif isinstance(network, IPv6Network):
                ipv6_networks.append(network)

        except ValueError:
            continue
            
    return ipv4_networks, ipv6_networks

if __name__ == '__main__':
    try:
        ipv4_networks, ipv6_networks = get_valid_networks()
        
        merged_v4 = list(ipaddress.collapse_addresses(ipv4_networks))
        merged_v6 = list(ipaddress.collapse_addresses(ipv6_networks))
        merged_list = merged_v4 + merged_v6

        for cidr in merged_list:
            sys.stdout.write(f'{cidr}\n')

    except KeyboardInterrupt:
        sys.exit(0)

sys.exit(0)


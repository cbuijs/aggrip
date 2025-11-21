#!/usr/bin/env python3
'''
=========================================================================
 revip.py v0.03-20251121 Copyright 2019-2025 by cbuijs@chrisbuijs.com
=========================================================================

 Genereate reverse DNS names from IP-Addresses

=========================================================================
'''

import sys, ipaddress

if __name__ == '__main__':
    try:
        raw_lines = sys.stdin.read().splitlines()

    except KeyboardInterrupt:
        sys.exit(0)

    valid_networks = []
    
    ip_net = ipaddress.ip_network 

    for line in raw_lines:
        if not line or line.isspace():
            continue

        try:
            valid_networks.append(ip_net(line.strip(), strict=False))

        except ValueError:
            continue

    if not valid_networks:
        sys.exit(0)

    collapsed_networks = ipaddress.collapse_addresses(valid_networks)

    output_buffer = []
    output_append = output_buffer.append

    for net in collapsed_networks:
        ver = net.version
        prefix = net.prefixlen

        if ver == 4:
            target_prefix = ((prefix + 7) // 8) * 8
            
            if prefix == target_prefix:
                subnets = (net,)

            else:
                subnets = net.subnets(new_prefix=target_prefix)

            for subnet in subnets:
                num_octets = target_prefix // 8
                parts = str(subnet.network_address).split('.')
                rev_zone = '.'.join(parts[:num_octets][::-1]) + '.in-addr.arpa'
                output_append(rev_zone)

        else:
            target_prefix = ((prefix + 3) // 4) * 4

            if prefix == target_prefix:
                subnets = (net,)

            else:
                subnets = net.subnets(new_prefix=target_prefix)

            for subnet in subnets:
                full_hex = subnet.exploded.replace(':', '')
                num_nibbles = target_prefix // 4
                rev_zone = '.'.join(full_hex[:num_nibbles][::-1]) + '.ip6.arpa'
                output_append(rev_zone)

    if output_buffer:
        sys.stdout.write('\n'.join(output_buffer) + '\n')

sys.exit(0)

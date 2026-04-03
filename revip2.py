#!/usr/bin/env python3
'''
==========================================================================
 revip2.py v0.16-20260403 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================
 Changes/Fixes:
 - v0.16-20260403: Initial revip2.py - Fast memory-heavy version utilizing
                   bulk reads, string slice optimization, and bulk writes.
==========================================================================

 Generate reverse DNS names from IP-Addresses (Fast Version).
 
 Logic:
 1. Bulk reads all standard input into memory.
 2. Filters and parses networks aggressively.
 3. Collapses overlapping subnets in memory.
 4. Extracts delegation zones (in-addr.arpa / ip6.arpa) using slice logic.
 5. Caches output strings and performs a single bulk write to STDOUT.

==========================================================================
'''

import sys, ipaddress

def main():
    try:
        # Bulk read and filter empty lines instantly
        raw_lines = sys.stdin.read().split()
    except KeyboardInterrupt:
        sys.exit(0)

    if not raw_lines:
        return

    valid_networks = []
    ip_net = ipaddress.ip_network 

    # Fast parsing loop
    for line in raw_lines:
        try:
            valid_networks.append(ip_net(line, strict=False))
        except ValueError:
            continue

    if not valid_networks:
        return

    # Native C-backed collapse
    collapsed_networks = ipaddress.collapse_addresses(valid_networks)

    output_buffer = []
    out_add = output_buffer.append

    # Process reverse pointers
    for net in collapsed_networks:
        ver = net.version
        prefix = net.prefixlen

        if ver == 4:
            target_prefix = ((prefix + 7) // 8) * 8
            subnets = (net,) if prefix == target_prefix else net.subnets(new_prefix=target_prefix)

            for subnet in subnets:
                num_octets = target_prefix // 8
                parts = str(subnet.network_address).split('.')
                # Reverse slice and join for fast zone generation
                out_add('.'.join(parts[:num_octets][::-1]) + '.in-addr.arpa')

        else:
            target_prefix = ((prefix + 3) // 4) * 4
            subnets = (net,) if prefix == target_prefix else net.subnets(new_prefix=target_prefix)

            for subnet in subnets:
                full_hex = subnet.exploded.replace(':', '')
                num_nibbles = target_prefix // 4
                # Reverse slice hex string for fast ipv6 zone generation
                out_add('.'.join(full_hex[:num_nibbles][::-1]) + '.ip6.arpa')

    # Bulk output
    if output_buffer:
        sys.stdout.write('\n'.join(output_buffer) + '\n')

if __name__ == '__main__':
    main()
    sys.exit(0)


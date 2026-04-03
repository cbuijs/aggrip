#!/usr/bin/env python3
'''
==========================================================================
 range2cidr2.py v0.16-20260403 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================
 Changes/Fixes:
 - v0.16-20260403: Initial range2cidr2.py - Fast memory-heavy version
                   utilizing bulk reads, fast token parsing, and bulk
                   stdout generation.
==========================================================================

 Aggregate IP-Range list and convert to CIDR (Fast Version).
 
 Logic:
 1. Reads all lines into memory simultaneously.
 2. Rapidly splits lines based on spaces or dashes.
 3. Converts single IPs and ranges to ipaddress network objects.
 4. Collapses overlapping v4 and v6 networks separately.
 5. Formats and writes output blocks instantly.

==========================================================================
'''

import sys, ipaddress

def main():
    v4_networks = []
    v6_networks = []
    
    # Fast references for inner loops
    add_v4 = v4_networks.extend
    add_v6 = v6_networks.extend

    try:
        raw_lines = sys.stdin.read().splitlines()
    except KeyboardInterrupt:
        sys.exit(0)

    for line in raw_lines:
        parts = line.replace('-', ' ').split()

        if not parts:
            continue

        try:
            if len(parts) == 1:
                token = parts[0]
                net = ipaddress.ip_network(token, strict=False) if '/' in token else ipaddress.ip_network(token)
                (add_v4 if net.version == 4 else add_v6)([net])

            elif len(parts) == 2:
                start_ip = ipaddress.ip_address(parts[0])
                end_ip = ipaddress.ip_address(parts[1])
                
                if start_ip.version != end_ip.version:
                    continue
                
                if start_ip > end_ip:
                    start_ip, end_ip = end_ip, start_ip

                nets = list(ipaddress.summarize_address_range(start_ip, end_ip))
                (add_v4 if start_ip.version == 4 else add_v6)(nets)

        except ValueError:
            continue

    # Collapse and buffer outputs for speed
    out_buffer = []
    if v4_networks:
        out_buffer.extend(str(net) for net in ipaddress.collapse_addresses(v4_networks))
    if v6_networks:
        out_buffer.extend(str(net) for net in ipaddress.collapse_addresses(v6_networks))

    if out_buffer:
        sys.stdout.write('\n'.join(out_buffer) + '\n')

if __name__ == '__main__':
    main()
    sys.exit(0)


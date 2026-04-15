#!/usr/bin/env python3
'''
==========================================================================
 Filename: ipsort.py
 Version: 0.11
 Date: 2026-04-15 19:08 CEST
 Description: Reads STDIN, identifies logical sections based on non-IP text, 
              and performs an IP-aware sort strictly within those sections.
              Supports optional CIDR aggregation within sections.
 
 Changes/Fixes:
 - v0.11 (2026-04-15): Added -a/--aggregate toggle.
 - v0.10 (2026-04-15): Initial ipsort.py - Segmented IP/CIDR sorting.
==========================================================================
'''

import sys
import argparse
import ipaddress

def flush_block(block, out_write, aggregate):
    """
    Sorts or aggregates the currently accumulated block of IP objects,
    then flushes them to the output stream.
    """
    if not block:
        return
        
    if aggregate:
        v4_nets = [item[0] for item in block if item[0].version == 4]
        v6_nets = [item[0] for item in block if item[0].version == 6]
        
        # ipaddress.collapse_addresses automatically sorts the generated CIDRs
        if v4_nets:
            for net in ipaddress.collapse_addresses(v4_nets):
                out_write(f"{net}\n")
        if v6_nets:
            for net in ipaddress.collapse_addresses(v6_nets):
                out_write(f"{net}\n")
    else:
        # Sort by IP version first (IPv4 -> IPv6), then by network address
        block.sort(key=lambda x: (x[0].version, x[0]))
        for _, original_line in block:
            out_write(original_line + '\n')
            
    block.clear()

def main():
    parser = argparse.ArgumentParser(description="Segmented layout-preserving IP/CIDR sort.")
    parser.add_argument("-a", "--aggregate", action="store_true", help="Aggregate/merge CIDRs within their respective sections")
    args = parser.parse_args()

    current_block = []
    write = sys.stdout.write

    try:
        for line in sys.stdin:
            stripped = line.strip()
            parts = stripped.split()

            is_ip_line = False
            
            if parts:
                try:
                    net = ipaddress.ip_network(parts[0], strict=False)
                    current_block.append((net, line.rstrip('\r\n')))
                    is_ip_line = True
                except ValueError:
                    pass

            if not is_ip_line:
                flush_block(current_block, write, args.aggregate)
                write(line.rstrip('\r\n') + '\n')

        flush_block(current_block, write, args.aggregate)

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()
    sys.exit(0)


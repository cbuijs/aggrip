#!/usr/bin/env python3
'''
==========================================================================
 Filename: ipsort.py
 Version: 0.12
 Date: 2026-04-16 08:22 CEST
 Description: Reads STDIN, identifies logical sections based on non-IP text, 
              and performs an IP-aware sort strictly within those sections.
              Supports optional CIDR aggregation within sections and reverse sorting.
 
 Changes/Fixes:
 - v0.12 (2026-04-16): Added -r/--reverse parameter for reverse IP sorting.
 - v0.11 (2026-04-15): Added -a/--aggregate toggle.
 - v0.10 (2026-04-15): Initial ipsort.py - Segmented IP/CIDR sorting.
==========================================================================
'''

import sys
import argparse
import ipaddress

def flush_block(block, out_write, aggregate, reverse_sort=False):
    """
    Sorts or aggregates the currently accumulated block of IP objects,
    then flushes them to the output stream, respecting reverse sorting.
    """
    if not block:
        return
        
    if aggregate:
        v4_nets = [item[0] for item in block if item[0].version == 4]
        v6_nets = [item[0] for item in block if item[0].version == 6]
        
        # ipaddress.collapse_addresses automatically sorts the generated CIDRs in ascending order
        if v4_nets:
            collapsed_v4 = list(ipaddress.collapse_addresses(v4_nets))
            if reverse_sort:
                collapsed_v4.reverse()
            for net in collapsed_v4:
                out_write(f"{net}\n")
        if v6_nets:
            collapsed_v6 = list(ipaddress.collapse_addresses(v6_nets))
            if reverse_sort:
                collapsed_v6.reverse()
            for net in collapsed_v6:
                out_write(f"{net}\n")
    else:
        # Sort by IP version first (IPv4 -> IPv6), then by network address
        # If reverse_sort is True, IPv6 comes first, then largest IPs to smallest
        block.sort(key=lambda x: (x[0].version, x[0]), reverse=reverse_sort)
        for _, original_line in block:
            out_write(original_line + '\n')
            
    block.clear()

def main():
    parser = argparse.ArgumentParser(description="Segmented layout-preserving IP/CIDR sort.")
    parser.add_argument("-a", "--aggregate", action="store_true", help="Aggregate/merge CIDRs within their respective sections")
    parser.add_argument("-r", "--reverse", action="store_true", help="Sort IP/CIDRs in reverse order")
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
                    # Strict is false to auto-truncate host bits if needed
                    net = ipaddress.ip_network(parts[0], strict=False)
                    current_block.append((net, line.rstrip('\r\n')))
                    is_ip_line = True
                except ValueError:
                    pass

            # Non-IP text acts as boundary; flush sorted IPs first, then output the text
            if not is_ip_line:
                flush_block(current_block, write, args.aggregate, args.reverse)
                write(line.rstrip('\r\n') + '\n')

        flush_block(current_block, write, args.aggregate, args.reverse)

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()
    sys.exit(0)


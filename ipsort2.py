#!/usr/bin/env python3
'''
==========================================================================
 Filename: ipsort2.py
 Version: 0.12
 Date: 2026-04-16 08:22 CEST
 Description: Fast, memory-heavy variant of ipsort.py. Performs bulk memory 
              reads, heuristic text skipping, and segmented array sorting.
              Supports optional CIDR aggregation within sections and reverse sorting.
 
 Changes/Fixes:
 - v0.12 (2026-04-16): Added -r/--reverse parameter for reverse IP sorting.
 - v0.11 (2026-04-15): Added -a/--aggregate toggle.
 - v0.10 (2026-04-15): Initial ipsort2.py - Segmented IP/CIDR sorting (Fast).
==========================================================================
'''

import sys
import argparse
import ipaddress

def is_fast_ip(token):
    """Heuristic fast-path validation to bypass expensive exceptions."""
    if not token: 
        return False
    c = token[0]
    return c.isdigit() or ':' in c

def main():
    parser = argparse.ArgumentParser(description="Segmented layout-preserving IP/CIDR sort (Fast Variant).")
    parser.add_argument("-a", "--aggregate", action="store_true", help="Aggregate/merge CIDRs within their respective sections")
    parser.add_argument("-r", "--reverse", action="store_true", help="Sort IP/CIDRs in reverse order")
    args = parser.parse_args()

    try:
        # Load everything into memory for high-speed segment processing
        raw_lines = sys.stdin.read().splitlines()
    except KeyboardInterrupt:
        sys.exit(0)

    if not raw_lines:
        return

    out_buffer = []
    out_add = out_buffer.append
    current_block = []
    
    def process_current_block():
        """Helper to sort/aggregate and flush the current block of IP items."""
        if not current_block:
            return
        if args.aggregate:
            v4_nets = [item[1] for item in current_block if item[0] == 4]
            v6_nets = [item[1] for item in current_block if item[0] == 6]
            if v4_nets:
                collapsed = list(ipaddress.collapse_addresses(v4_nets))
                if args.reverse:
                    collapsed.reverse()
                out_buffer.extend(str(net) for net in collapsed)
            if v6_nets:
                collapsed = list(ipaddress.collapse_addresses(v6_nets))
                if args.reverse:
                    collapsed.reverse()
                out_buffer.extend(str(net) for net in collapsed)
        else:
            # Sort logic supporting reverse
            current_block.sort(key=lambda x: (x[0], x[1]), reverse=args.reverse)
            for item in current_block:
                out_add(item[2])
        current_block.clear()

    for line in raw_lines:
        stripped = line.strip()
        parts = stripped.split()
        
        is_ip_line = False
        
        if parts and is_fast_ip(parts[0]):
            try:
                net = ipaddress.ip_network(parts[0], strict=False)
                # Store tuple: (IP Version, IP Object, Original Line String)
                current_block.append((net.version, net, line))
                is_ip_line = True
            except ValueError:
                pass

        if not is_ip_line:
            process_current_block()
            out_add(line)

    # Process dangling block at EOF
    process_current_block()

    # Bulk flush
    if out_buffer:
        sys.stdout.write('\n'.join(out_buffer) + '\n')

if __name__ == '__main__':
    main()
    sys.exit(0)


#!/usr/bin/env python3
'''
==========================================================================
 getip2.py v0.10-20260403 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================
 Changes/Fixes:
 - v0.10-20260403: Initial getip2.py - Fast memory-heavy version utilizing
                   bulk reads, fast character heuristics, and bulk writes.
==========================================================================

 Grep IP-Addresses, IP-Ranges, and CIDRs from input and aggregate them.
 Note: Faster memory-optimized alternative utilizing bulk line processing.

==========================================================================
'''

import sys
import argparse
import ipaddress

def is_fast_ip(token):
    """Fast-path heuristic to avoid catching ValueErrors on standard words."""
    if not token: return False
    c = token[0]
    return c.isdigit() or ':' in c or c == '-'

def main():
    parser = argparse.ArgumentParser(description="Grep, aggregate, and sort IP/CIDRs (Fast Version).")
    parser.add_argument("-a", "--anywhere", action="store_true", help="Find IPs/CIDRs anywhere in the line")
    args = parser.parse_args()

    v4_networks = []
    v6_networks = []
    
    # Fast references for inner loops
    add_v4 = v4_networks.extend
    add_v6 = v6_networks.extend
    app_v4 = v4_networks.append
    app_v6 = v6_networks.append

    try:
        # Bulk read into memory
        raw_lines = sys.stdin.read().splitlines()
    except KeyboardInterrupt:
        sys.exit(0)

    for line in raw_lines:
        tokens = line.replace('-', ' - ').split()
        if not tokens: 
            continue
        
        i = 0
        while i < len(tokens):
            token = tokens[i]
            
            # Fast-fail non-IPs to save exception handling overhead
            if not args.anywhere and not is_fast_ip(token):
                break
                
            try:
                net = ipaddress.ip_network(token, strict=False)
                is_single_ip = ('/' not in token)
                is_range = False

                if is_single_ip and i + 1 < len(tokens):
                    if tokens[i+1] == '-' and i + 2 < len(tokens):
                        try:
                            end_ip = ipaddress.ip_address(tokens[i+2])
                            start_ip = ipaddress.ip_address(token)
                            if start_ip.version == end_ip.version:
                                start, end = min(start_ip, end_ip), max(start_ip, end_ip)
                                summarized = list(ipaddress.summarize_address_range(start, end))
                                (add_v4 if start_ip.version == 4 else add_v6)(summarized)
                                i += 3
                                is_range = True
                        except ValueError:
                            pass
                    
                    elif not is_range:
                        try:
                            end_ip = ipaddress.ip_address(tokens[i+1])
                            start_ip = ipaddress.ip_address(token)
                            if start_ip.version == end_ip.version:
                                start, end = min(start_ip, end_ip), max(start_ip, end_ip)
                                summarized = list(ipaddress.summarize_address_range(start, end))
                                (add_v4 if start_ip.version == 4 else add_v6)(summarized)
                                i += 2
                                is_range = True
                        except ValueError:
                            pass
                
                if not is_range:
                    (app_v4 if net.version == 4 else app_v6)(net)
                    i += 1

                if not args.anywhere:
                    break

            except ValueError:
                if not args.anywhere:
                    break
                i += 1

    # Output buffer consolidation
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


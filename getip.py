#!/usr/bin/env python3
'''
==========================================================================
 getip.py v0.10-20260403 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================
 Changes/Fixes:
 - v0.10-20260403: Initial getip.py - Grep, aggregate, and sort IP/CIDRs.
==========================================================================

 Grep IP-Addresses, IP-Ranges, and CIDRs from input and aggregate them.
 
 Logic:
 1. By default, checks only the beginning of each line for valid networks,
    dropping any trailing text or arguments.
 2. With --anywhere (-a), acts like `grep -o`, scanning the entire line.
 3. Converts IP ranges (dash or space separated) to CIDRs natively.
 4. Truncates invalid host bits in CIDRs via strict=False.
 5. Aggregates and IP-sorts the final list using ipaddress.

==========================================================================
'''

import sys
import argparse
import ipaddress

def main():
    parser = argparse.ArgumentParser(description="Grep, aggregate, and sort IP/CIDRs.")
    parser.add_argument("-a", "--anywhere", action="store_true", help="Find IPs/CIDRs anywhere in the line")
    args = parser.parse_args()

    v4_networks = []
    v6_networks = []

    for line in sys.stdin:
        # Normalize dashes to ensure they are tokenized separately
        tokens = line.replace('-', ' - ').split()
        
        i = 0
        while i < len(tokens):
            token = tokens[i]
            
            try:
                # Attempt to parse as an individual IP or CIDR (strict=False truncates invalid host bits)
                net = ipaddress.ip_network(token, strict=False)
                is_single_ip = ('/' not in token)
                is_range = False

                # Check for ranges if it's a single IP
                if is_single_ip and i + 1 < len(tokens):
                    # Dash-separated range: IP - IP
                    if tokens[i+1] == '-' and i + 2 < len(tokens):
                        try:
                            end_ip = ipaddress.ip_address(tokens[i+2])
                            start_ip = ipaddress.ip_address(token)
                            if start_ip.version == end_ip.version:
                                start, end = min(start_ip, end_ip), max(start_ip, end_ip)
                                summarized = list(ipaddress.summarize_address_range(start, end))
                                if start_ip.version == 4:
                                    v4_networks.extend(summarized)
                                else:
                                    v6_networks.extend(summarized)
                                i += 3
                                is_range = True
                        except ValueError:
                            pass
                    
                    # Space-separated range: IP IP
                    elif not is_range:
                        try:
                            end_ip = ipaddress.ip_address(tokens[i+1])
                            start_ip = ipaddress.ip_address(token)
                            if start_ip.version == end_ip.version:
                                start, end = min(start_ip, end_ip), max(start_ip, end_ip)
                                summarized = list(ipaddress.summarize_address_range(start, end))
                                if start_ip.version == 4:
                                    v4_networks.extend(summarized)
                                else:
                                    v6_networks.extend(summarized)
                                i += 2
                                is_range = True
                        except ValueError:
                            pass
                
                # Standard IP/CIDR append if not resolved as a range
                if not is_range:
                    if net.version == 4:
                        v4_networks.append(net)
                    else:
                        v6_networks.append(net)
                    i += 1

                # If we only check the start of the line, break after processing the first valid target
                if not args.anywhere:
                    break 

            except ValueError:
                # If the very first token is garbage and we aren't scanning the whole line, skip the line entirely
                if not args.anywhere:
                    break 
                i += 1

    # Collapse, Aggregate, and IP-Sort (collapse_addresses handles sorting inherently)
    if v4_networks:
        for net in ipaddress.collapse_addresses(v4_networks):
            sys.stdout.write(f"{net}\n")
    
    if v6_networks:
        for net in ipaddress.collapse_addresses(v6_networks):
            sys.stdout.write(f"{net}\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    
sys.exit(0)


#!/usr/bin/env python3
'''
==========================================================================
 Filename: getip2.py
 Version: 0.12
 Date: 2026-04-07
 Description: Fast, memory-heavy IP & CIDR grep tool. Scans raw text to 
              extract valid IPv4/IPv6 addresses, CIDRs, and IP-Ranges, 
              then aggregates them natively.
 
 Changes/Fixes:
 - v0.12 (2026-04-07): Added docstrings, optimized tokenizer via replace logic.
 - v0.11 (2026-04-03): Added strict mode parameter (-s).
==========================================================================
'''

import sys
import argparse
import ipaddress

def is_fast_ip(token):
    """
    Heuristic validation check. Prevents standard text from triggering 
    expensive try/except IP parsing blocks.
    """
    if not token: return False
    c = token[0]
    return c.isdigit() or ':' in c or c == '-'

def main():
    parser = argparse.ArgumentParser(description="Grep, aggregate, and sort IP/CIDRs (Fast Version).")
    parser.add_argument("-a", "--anywhere", action="store_true", help="Deep scan lines instead of just checking start.")
    parser.add_argument("-s", "--strict", action="store_true", help="Reject CIDRs with dirty host bits instead of truncating.")
    args = parser.parse_args()

    v4_networks, v6_networks = [], []
    add_v4, add_v6 = v4_networks.extend, v6_networks.extend
    app_v4, app_v6 = v4_networks.append, v6_networks.append

    try:
        raw_lines = sys.stdin.read().splitlines()
    except KeyboardInterrupt:
        sys.exit(0)

    for line in raw_lines:
        # Pre-process dashes so IP ranges (1.1.1.1-2.2.2.2) tokenize easily
        tokens = line.replace('-', ' - ').split()
        if not tokens: continue
        
        i = 0
        while i < len(tokens):
            token = tokens[i]
            
            if not args.anywhere and not is_fast_ip(token):
                break
                
            try:
                net = ipaddress.ip_network(token, strict=args.strict)
                is_range = False

                # Lookahead for standard Space or Dash-separated IP ranges
                if ('/' not in token) and (i + 1 < len(tokens)):
                    # Handles token format: [IP] [-] [IP] OR [IP] [IP]
                    offset = 2 if tokens[i+1] == '-' else 1
                    if i + offset < len(tokens):
                        try:
                            end_ip = ipaddress.ip_address(tokens[i+offset])
                            start_ip = ipaddress.ip_address(token)
                            if start_ip.version == end_ip.version:
                                start, end = min(start_ip, end_ip), max(start_ip, end_ip)
                                summarized = list(ipaddress.summarize_address_range(start, end))
                                (add_v4 if start_ip.version == 4 else add_v6)(summarized)
                                i += (offset + 1)
                                is_range = True
                        except ValueError:
                            pass
                
                if not is_range:
                    (app_v4 if net.version == 4 else app_v6)(net)
                    i += 1

                if not args.anywhere:
                    break

            except ValueError:
                if not args.anywhere: break
                i += 1

    # Final Buffer & Print via standard collapse_addresses sorting
    out_buffer = []
    out_buffer.extend(str(net) for net in ipaddress.collapse_addresses(v4_networks))
    out_buffer.extend(str(net) for net in ipaddress.collapse_addresses(v6_networks))

    if out_buffer:
        sys.stdout.write('\n'.join(out_buffer) + '\n')

if __name__ == '__main__':
    main()


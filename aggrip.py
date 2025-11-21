#!/usr/bin/env python3
'''
==========================================================================
 aggrip.py v0.11-20251121 Copyright 2019-2025 by cbuijs@chrisbuijs.com
==========================================================================

 Aggregate IPs into a CIDR list

==========================================================================
'''

import sys, netaddr

def get_valid_cidrs():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            yield netaddr.IPNetwork(line)

        except netaddr.AddrFormatError:
            continue

if __name__ == '__main__':
    try:
        merged_list = netaddr.cidr_merge(get_valid_cidrs())
        
        for cidr in merged_list:
            sys.stdout.write(f'{cidr}\n')
            
    except KeyboardInterrupt:
        sys.exit(0)

sys.exit(0)


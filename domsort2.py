#!/usr/bin/env python3
'''
==========================================================================
 domsort2.py v0.15-20260401 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================

 Validate and sort a domain list from root level down (TLD-first).
 Note: Faster memory-optimized alternative using C-level regex & bulk reads.

==========================================================================
'''

import sys
import re

# Support for standard and IDN (Punycode) TLDs included.
DOMAIN_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,}$')

def get_sort_key(domain):
    """Splits the domain by dots and reverses the list for TLD-first sorting."""
    return domain.split('.')[::-1]

def main():
    # 1. BULK READ & NORMALIZE
    raw_data = sys.stdin.read().lower().split()
    
    # 2. C-LEVEL FILTERING
    valid_domains = filter(DOMAIN_PATTERN.match, raw_data)
    
    # 3. SORT
    sorted_domains = sorted(valid_domains, key=get_sort_key)
    
    # 4. BULK WRITE
    if sorted_domains:
        sys.stdout.write('\n'.join(sorted_domains) + '\n')

if __name__ == "__main__":
    main()


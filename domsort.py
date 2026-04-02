#!/usr/bin/env python3
'''
==========================================================================
 domsort.py v0.15-20260401 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================

 Validate and sort a domain list from root level down (TLD-first).
 
 Logic:
 1. Reads standard input and normalizes to lowercase.
 2. Strictly validates domains via regex (now supporting IDN TLDs).
 3. Sorts tree-wise (e.g., 'com' -> 'example' -> 'sub').

==========================================================================
'''

import sys
import re

# Matches: alphanumeric/hyphen subdomains + dot + alphabetic/numeric/hyphen TLD (min 2 chars)
# IDN TLDs like "xn--p1ai" are now permitted.
DOMAIN_PATTERN = re.compile(
    r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,}$'
)

def domain_sort_key(domain):
    """
    Splits the domain by dots and reverses the list.
    Example: 'sub.example.com' becomes ['com', 'example', 'sub']
    """
    return domain.split('.')[::-1]

def main():
    valid_domains = []
    
    for line in sys.stdin:
        clean_line = line.strip().lower()
        
        if DOMAIN_PATTERN.match(clean_line):
            valid_domains.append(clean_line)

    sorted_domains = sorted(valid_domains, key=domain_sort_key)

    for domain in sorted_domains:
        print(domain)

if __name__ == "__main__":
    main()


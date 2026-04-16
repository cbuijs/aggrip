#!/usr/bin/env python3
'''
==========================================================================
 Filename: undup.py
 Version: 0.16
 Date: 2026-04-16 08:45 CEST
 Description: Undup DNS Domainlist (Remove sub-domains when parent exists).
              Supports optional less-strict validation allowing '_' and '*'.
 
 Changes/Fixes:
 - v0.16 (2026-04-16): Added -l/--less-strict toggle for domain validation.
 - v0.15 (2026-04-01): Original version.
==========================================================================
'''

import sys
import re
import argparse

# Standard pattern vs Less-Strict pattern allowing Wildcards/SRV records
STRICT_PATTERN = re.compile(r'^[a-z0-9.-]+$')
LESS_STRICT_PATTERN = re.compile(r'^[a-z0-9._*-]+$')

def main():
    parser = argparse.ArgumentParser(description="Deduplicate DNS domains (remove subdomains if parent exists).")
    parser.add_argument("-l", "--less-strict", action="store_true", help="Allow underscores (_) and asterisks (*) in domain names")
    args = parser.parse_args()

    active_pattern = LESS_STRICT_PATTERN if args.less_strict else STRICT_PATTERN

    seen = set()
    processed_list = []
    write = sys.stdout.write

    try:
        for line in sys.stdin:
            dom = line.strip().lower().strip('.')
            
            if not dom or dom in seen:
                continue
            
            # Validate domain against selected strictness pattern
            if active_pattern.match(dom):
                seen.add(dom)
                processed_list.append((dom[::-1], dom))
    except KeyboardInterrupt:
        sys.exit(0)

    if not processed_list:
        return

    # Reversed string sorting forces Parent Domains to evaluate before Subdomains
    processed_list.sort()
    last_rev = ''
    
    for rev_dom, original_dom in processed_list:
        # If the reversed child starts with the reversed parent + a dot, it's a redundant subdomain
        if last_rev and rev_dom.startswith(last_rev + '.'):
            continue

        write(f'{original_dom}\n')
        last_rev = rev_dom

if __name__ == '__main__':
    main()
    sys.exit(0)


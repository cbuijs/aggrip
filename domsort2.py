#!/usr/bin/env python3
'''
==========================================================================
 Filename: domsort2.py
 Version: 0.20
 Date: 2026-04-16 08:30 CEST
 Description: Fast memory-optimized variant of domsort.py. Performs bulk 
              reads, segmented layout preservation, and fast-path text 
              skipping for domain sorting.
              Supports TLD-first (default) or Alphabetical sorting, 
              less-strict validation ('_', '*'), and reverse sorting.
 
 Changes/Fixes:
 - v0.20 (2026-04-16): Added -a/--alphabetical toggle for A-Z sorting instead of TLD-down.
 - v0.19 (2026-04-16): Added -r/--reverse parameter for reverse sorting.
 - v0.18 (2026-04-15): Ignored '_' and '*' in sorting key to preserve alphabetical order.
 - v0.17 (2026-04-15): Added -l/--less-strict toggle for domain validation.
 - v0.16 (2026-04-15): Added segmented layout-preserving sorting logic.
==========================================================================
'''

import sys
import re
import argparse

# Pre-compiled regex patterns for standard and wildcard domain matching
STRICT_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,}$')
LESS_STRICT_PATTERN = re.compile(r'^([a-z0-9_*]([a-z0-9\-_*]{0,61}[a-z0-9_*])?\.)+[a-z0-9\-_*]{2,}$')

def domain_sort_key_tld(item):
    """Sorting key for tree-down (TLD to subdomain) output. Strips '_' and '*'."""
    clean_domain = item[0].replace('_', '').replace('*', '')
    return clean_domain.split('.')[::-1]

def domain_sort_key_alpha(item):
    """Sorting key for standard alphabetical output. Strips '_' and '*'."""
    return item[0].replace('_', '').replace('*', '')

def main():
    parser = argparse.ArgumentParser(description="Segmented layout-preserving domain sort (Fast Variant).")
    parser.add_argument("-l", "--less-strict", action="store_true", help="Allow underscores (_) and asterisks (*) in domain names")
    parser.add_argument("-r", "--reverse", action="store_true", help="Sort domains in reverse order")
    parser.add_argument("-a", "--alphabetical", action="store_true", help="Sort domains strictly alphabetically instead of TLD-down")
    args = parser.parse_args()

    active_pattern = LESS_STRICT_PATTERN if args.less_strict else STRICT_PATTERN
    sort_key_func = domain_sort_key_alpha if args.alphabetical else domain_sort_key_tld

    try:
        # Bulk read into memory for speed
        raw_lines = sys.stdin.read().splitlines()
    except KeyboardInterrupt:
        sys.exit(0)

    if not raw_lines:
        return

    out_buffer = []
    out_add = out_buffer.append
    current_block = []

    for line in raw_lines:
        stripped = line.strip()
        parts = stripped.split()
        
        is_domain_line = False
        
        if parts:
            candidate = parts[0].lower()
            
            # Fast-path check: avoid running regex on obvious comments/headers
            # Expands fast-path chars if less-strict mode is active
            is_valid_start = candidate[0].isalnum() or (args.less_strict and candidate[0] in '_*')
            
            if is_valid_start and active_pattern.match(candidate):
                current_block.append((candidate, line))
                is_domain_line = True

        # End of a block (comment/blank line found)
        if not is_domain_line:
            if current_block:
                current_block.sort(key=sort_key_func, reverse=args.reverse)
                for item in current_block:
                    out_add(item[1])
                current_block.clear()
            
            out_add(line)

    # Process dangling block at EOF
    if current_block:
        current_block.sort(key=sort_key_func, reverse=args.reverse)
        for item in current_block:
            out_add(item[1])

    # Output everything at once
    if out_buffer:
        sys.stdout.write('\n'.join(out_buffer) + '\n')

if __name__ == "__main__":
    main()
    sys.exit(0)


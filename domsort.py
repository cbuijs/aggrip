#!/usr/bin/env python3
'''
==========================================================================
 Filename: domsort.py
 Version: 0.18
 Date: 2026-04-15 19:55 CEST
 Description: Reads STDIN, identifies logical sections based on non-domain
              text, and strictly validates/sorts domains (TLD-first) 
              within those sections while preserving document layout.
              Supports less-strict validation allowing '_' and '*'.
 
 Changes/Fixes:
 - v0.18 (2026-04-15): Ignored '_' and '*' in sorting key to preserve alphabetical order.
 - v0.17 (2026-04-15): Added -l/--less-strict toggle for domain validation.
 - v0.16 (2026-04-15): Added segmented layout-preserving sorting logic.
==========================================================================
'''

import sys
import re
import argparse

# Matches: alphanumeric/hyphen subdomains + dot + alphabetic/numeric/hyphen TLD
STRICT_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,}$')

# Less strict: allows underscores and asterisks (e.g., wildcards or SRV records)
LESS_STRICT_PATTERN = re.compile(r'^([a-z0-9_*]([a-z0-9\-_*]{0,61}[a-z0-9_*])?\.)+[a-z0-9\-_*]{2,}$')

def domain_sort_key(item):
    """
    Splits the domain by dots and reverses the list for TLD-first sorting.
    Strips '_' and '*' to collapse them out of the alphabetical sort order.
    Expects a tuple: (domain_string, original_line_string)
    """
    clean_domain = item[0].replace('_', '').replace('*', '')
    return clean_domain.split('.')[::-1]

def flush_block(block, out_write):
    """Sorts the currently accumulated block of domains and flushes them."""
    if not block:
        return
        
    block.sort(key=domain_sort_key)
    
    for _, original_line in block:
        out_write(original_line + '\n')
        
    block.clear()

def main():
    parser = argparse.ArgumentParser(description="Segmented layout-preserving domain sort.")
    parser.add_argument("-l", "--less-strict", action="store_true", help="Allow underscores (_) and asterisks (*) in domain names")
    args = parser.parse_args()

    active_pattern = LESS_STRICT_PATTERN if args.less_strict else STRICT_PATTERN
    current_block = []
    write = sys.stdout.write

    try:
        for line in sys.stdin:
            stripped = line.strip()
            parts = stripped.split()
            
            is_domain_line = False
            
            if parts:
                candidate = parts[0].lower()
                if active_pattern.match(candidate):
                    # Store tuple: (Parsed Domain, Original Line)
                    current_block.append((candidate, line.rstrip('\r\n')))
                    is_domain_line = True

            # Any non-domain line acts as a section boundary
            if not is_domain_line:
                flush_block(current_block, write)
                write(line.rstrip('\r\n') + '\n')

        # Flush any remaining items in the buffer at EOF
        flush_block(current_block, write)

    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == "__main__":
    main()
    sys.exit(0)


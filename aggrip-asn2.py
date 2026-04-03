#!/usr/bin/env python3
'''
==========================================================================
 aggrip-asn2.py v0.16-20260403 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================
 Changes/Fixes:
 - v0.16-20260403: Initial aggrip-asn2.py - Fast memory-heavy version
                   utilizing bulk reads, tuple pre-computation, and
                   bulk writes.
==========================================================================

 Aggregate IPs into a CIDR list based on a composite identifier (Fast).
 
 Logic:
 1. Bulk reads lines from STDIN.
 2. Parses Fields and pre-computes integer sort keys to avoid exception
    handling during the expensive list.sort() phase.
 3. Replaces dictionaries with lightweight Python tuples.
 4. Groups by pre-computed metadata and merges CIDRs via netaddr.
 5. Flushes aggregated results using bulk list joining.

==========================================================================
'''

import sys
import netaddr
import itertools

def main():
    try:
        raw_lines = sys.stdin.read().splitlines()
    except KeyboardInterrupt:
        sys.exit(0)

    if not raw_lines:
        return

    parsed_data = []

    # --- Step 1: Bulk Parse Input & Pre-compute Types ---
    for line in raw_lines:
        if not line or line.isspace():
            continue

        parts = line.split('\t')
        if len(parts) < 2:
            continue

        cidr_str = parts[0].strip()
        f2_id_str = parts[1].strip()
        f3_name = parts[2].strip() if len(parts) > 2 else ""

        try:
            network = netaddr.IPNetwork(cidr_str)
        except netaddr.AddrFormatError:
            continue

        # Pre-compute integer casting for rapid numeric sorting later.
        # Boolean fallback ensures ints and strings don't crash Python 3's Timsort.
        try:
            f2_sort_val = int(f2_id_str)
            is_str = False
        except ValueError:
            f2_sort_val = f2_id_str
            is_str = True

        # Use tuples instead of dicts for memory efficiency and access speed
        parsed_data.append((is_str, f2_sort_val, f2_id_str, f3_name, network))

    if not parsed_data:
        return

    # --- Step 2: High-Speed Sorting ---
    # Sort hierarchy:
    # 1. is_str (groups integers before strings)
    # 2. f2_sort_val (Numeric or Alphabetic ID)
    # 3. f3_name (Alphabetic Name)
    parsed_data.sort(key=lambda x: (x[0], x[1], x[3]))

    # --- Step 3: Loop, Aggregate, and Buffer ---
    out_buffer = []
    out_append = out_buffer.append

    # Groupby matching the exact sort keys (is_str, f2_sort_val, f3_name)
    for key, group in itertools.groupby(parsed_data, key=lambda x: (x[0], x[1], x[3])):
        group_items = list(group)
        
        # Merge all networks belonging to this specific grouping
        merged_list = netaddr.cidr_merge([item[4] for item in group_items])
        
        # Grab the original string ID (item[2]) and Name (item[3]) from the first matched record
        identifier = group_items[0][2]
        name = group_items[0][3]

        for cidr in merged_list:
            out_append(f"{cidr}\t{identifier}\t{name}")

    # --- Step 4: Bulk Output ---
    if out_buffer:
        sys.stdout.write('\n'.join(out_buffer) + '\n')

if __name__ == '__main__':
    main()
    sys.exit(0)


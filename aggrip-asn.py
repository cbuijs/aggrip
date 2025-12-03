#!/usr/bin/env python3
'''
==========================================================================
 aggrip.py v0.15-20251203 Copyright 2019-2025 by cbuijs@chrisbuijs.com
==========================================================================

 Aggregate IPs into a CIDR list based on a composite identifier.
 
 Logic:
 1. Reads all input lines.
 2. Parses Field 2 (ID) and Field 3 (Name).
 3. Sorts by Field 2 (Numeric) FIRST, then Field 3 (Alphabetic).
 4. Groups by the combination of (Field 2 + Field 3).
 5. Aggregates CIDRs within those specific groups.

 Input Format (Tab Separated):
 CIDR <tab> Identifier <tab> Name/Comment

 Output Format (Tab Separated):
 Aggregated_CIDR <tab> Identifier <tab> Name/Comment

==========================================================================
'''

import sys
import netaddr
import itertools

def main():
    raw_data = []

    # --- Step 1: Read and Parse Input ---
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        parts = line.split('\t')

        if len(parts) < 2:
            continue

        cidr_str = parts[0].strip()
        f2_id = parts[1].strip()
        f3_name = parts[2].strip() if len(parts) > 2 else ""

        try:
            network = netaddr.IPNetwork(cidr_str)
            
            raw_data.append({
                'net': network,
                'f2': f2_id,
                'f3': f3_name
            })

        except netaddr.AddrFormatError:
            continue

    # --- Step 2: Define Sorting Logic ---
    # We sort by Field 2 (numerically if possible) THEN by Field 3 (alphabetically).
    # This tuple approach ( (Primary, Secondary) ) handles the sort order cleanly.
    def sort_key_func(item):
        id_val = item['f2']
        name_val = item['f3']
        
        try:
            # Try to return identifier as an integer for proper numeric sorting
            return (int(id_val), name_val)
        except ValueError:
            # Fallback: if identifier isn't a number, sort it as a string
            # We explicitly cast to str to avoid type comparison errors
            return (str(id_val), name_val)

    # Sort the data using the custom key
    # Note: If the list contains mixed types (some IDs are ints, some strings),
    # Python 3 cannot sort them together easily. We assume IDs are consistent.
    try:
        raw_data.sort(key=sort_key_func)
    except TypeError:
        # Fallback for mixed types: treat everything as strings
        sys.stderr.write("Warning: Mixed numeric/string identifiers. Falling back to string sort.\n")
        raw_data.sort(key=lambda x: (x['f2'], x['f3']))

    # --- Step 3: Loop and Aggregate ---
    # We group by the EXACT SAME tuple (Field 2, Field 3)
    for (identifier, name), group in itertools.groupby(raw_data, key=lambda x: (x['f2'], x['f3'])):
        
        group_items = list(group)
        cidrs_to_merge = [item['net'] for item in group_items]
        
        # Merge
        merged_list = netaddr.cidr_merge(cidrs_to_merge)

        # Output
        for cidr in merged_list:
            sys.stdout.write(f'{cidr}\t{identifier}\t{name}\n')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    
sys.exit(0)


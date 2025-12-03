#!/usr/bin/env python3
'''
==========================================================================
 aggrip.py v0.14-20251203 Copyright 2019-2025 by cbuijs@chrisbuijs.com
==========================================================================

 Aggregate IPs into a CIDR list based on grouping identifiers.
 
 Logic:
 1. Reads all input lines.
 2. Sorts the data numerically by Field 2 (Identifier).
 3. Aggregates CIDRs within those sorted groups.
 4. Uses the Name/Comment from the FIRST line of the group for the output.

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
    # List to hold parsed rows: dictionaries of {id, net, name}
    raw_data = []

    # --- Step 1: Read and Parse Input ---
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        parts = line.split('\t')

        # We need at least CIDR (0) and Identifier (1)
        if len(parts) < 2:
            continue

        cidr_str = parts[0].strip()
        identifier = parts[1].strip()
        name = parts[2].strip() if len(parts) > 2 else "UNKNOWN"

        try:
            # Create valid network object
            network = netaddr.IPNetwork(cidr_str)
            
            raw_data.append({
                'id': identifier,
                'net': network,
                'name': name
            })

        except netaddr.AddrFormatError:
            continue
        except ValueError:
            continue

    # --- Step 2: Sort by Identifier (Numeric) ---
    # Python's sort is stable; it preserves the original order of lines 
    # for items that have the same Identifier.
    try:
        raw_data.sort(key=lambda x: int(x['id']))
    except ValueError:
        sys.stderr.write("Warning: Non-numeric identifiers detected, sorting alphabetically.\n")
        raw_data.sort(key=lambda x: x['id'])

    # --- Step 3: Loop and Aggregate ---
    for identifier, group in itertools.groupby(raw_data, key=lambda x: x['id']):
        
        # Convert the iterator to a list so we can access data
        group_items = list(group)
        
        # Extract just the network objects for merging
        cidrs_to_merge = [item['net'] for item in group_items]
        
        # --- Logic Change: Use the name of the first CIDR in this group ---
        # Because the sort was stable, item [0] is the first line from the input
        # that belonged to this identifier.
        group_name = group_items[0]['name']

        # Perform the aggregation
        merged_list = netaddr.cidr_merge(cidrs_to_merge)

        # Output the results
        for cidr in merged_list:
            sys.stdout.write(f'{cidr}\t{identifier}\t{group_name}\n')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    
sys.exit(0)


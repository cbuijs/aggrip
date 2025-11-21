#!/usr/bin/env python3
'''
===========================================================================
 range2cidr.py v0.11-20251121 Copyright 2019-2025 by cbuijs@chrisbuijs.com
===========================================================================

 Aggregate IP-Range list and convert to CIDR

===========================================================================
'''

import sys, ipaddress

# Process line and get start and end IP-Address
def get_networks_from_line(line):
    # Split values, delimiter can be blankspace or dash
    parts = line.replace('-', ' ').split()

    # If empty return empty
    if not parts:
        return []

    try:
        # if only one part is given, treat it as an IP or a CIDR and return it
        if len(parts) == 1:
            token = parts[0]
            if '/' in token:
                return [ipaddress.ip_network(token, strict=False)]

            else:
                return [ipaddress.ip_network(token)]

        # The magic starts here
        elif len(parts) == 2:
            start_ip = ipaddress.ip_address(parts[0])
            end_ip = ipaddress.ip_address(parts[1])
            
            # If start and end are not the same version of IP, return empty
            if start_ip.version != end_ip.version:
                return []
            
            # Swap if start address is higher then end address
            if start_ip > end_ip:
                start_ip, end_ip = end_ip, start_ip

            # Aggregate and return list of cidrs for this range
            return list(ipaddress.summarize_address_range(start_ip, end_ip))
            
    except ValueError:
        return []

    return []

if __name__ == '__main__':
    v4_networks = []
    v6_networks = []

    try:
        for line in sys.stdin:
            # get all possible cidrs
            networks = get_networks_from_line(line)
            for net in networks:
                if net.version == 4:
                    v4_networks.append(net)

                else:
                    v6_networks.append(net)

    except KeyboardInterrupt:
        sys.exit(0)

    # Aggregate all cidrs and flush them out
    if v4_networks:
        for net in ipaddress.collapse_addresses(v4_networks):
            sys.stdout.write(f"{net}\n")

    if v6_networks:
        for net in ipaddress.collapse_addresses(v6_networks):
            sys.stdout.write(f"{net}\n")

sys.exit(0)


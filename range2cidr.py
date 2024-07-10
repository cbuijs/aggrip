#!/usr/bin/env python3
'''
===========================================================================
 range2cidr.py v0.10-20240709 Copyright 2019-2024 by cbuijs@chrisbuijs.com
===========================================================================

 Aggregate IP-Range list and convert to CIDR

===========================================================================
'''

# Standard Stuff
import sys, socket

# Regex
import regex

# Netaddr/IPy
from IPy import IP
import netaddr

# Lists
lip = list()

# IP Regexes
ip_rx4 = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(/(3[0-2]|[12]?[0-9]))*)'
ip_rx6 = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))*)'
#is_ip4 = regex.compile('^' + ip_rx4 + '$', regex.I)
#is_ip6 = regex.compile('^' + ip_rx6 + '$', regex.I)
is_ip = regex.compile('^(' + ip_rx4 + '|' + ip_rx6 + ')$', regex.I)

##########################################################################

def nice_ip(ip):
    ip = ip.strip().lower()
    if is_ip.search(ip):
        return str(IP(ip, make_net=True).strNormal(1))
    return None

if __name__ == '__main__':

    for line in sys.stdin:
        startip, endip = line.strip().lower().split()
        for line in list(map(str, netaddr.iprange_to_cidrs(nice_ip(startip), nice_ip(endip)))):
            sys.stdout.write('{0}\n'.format(line))

sys.exit(0)


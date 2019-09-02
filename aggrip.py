#!/usr/bin/env python3
'''
=======================================================================
 aggrip.py v0.01-20190902 Copyright 2019 by cbuijs@chrisbuijs.com
=======================================================================

 Aggregate IP list

=======================================================================
'''

# Standard Stuff
import sys, socket

# Regex
import regex

# Use module PyTricia for CIDR/Subnet stuff
import pytricia

# IPy
from IPy import IP, IPSet

# Lists
lip4 = pytricia.PyTricia(32, socket.AF_INET)
lip6 = pytricia.PyTricia(128, socket.AF_INET6)

# IP Regexes
ip_rx4 = '((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}(/(3[0-2]|[12]?[0-9]))*)'
ip_rx6 = '(((:(:[0-9a-f]{1,4}){1,7}|::|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,6}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,5}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,4}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,3}|::|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){1,2}|::|:[0-9a-f]{1,4}(::[0-9a-f]{1,4}|::|:[0-9a-f]{1,4}(::|:[0-9a-f]{1,4}))))))))|(:(:[0-9a-f]{1,4}){0,5}|[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,4}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,3}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4}){0,2}|:[0-9a-f]{1,4}(:(:[0-9a-f]{1,4})?|:[0-9a-f]{1,4}(:|:[0-9a-f]{1,4})))))):(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})(/(12[0-8]|1[01][0-9]|[1-9]?[0-9]))*)'
is_ip4 = regex.compile('^' + ip_rx4 + '$', regex.I)
is_ip6 = regex.compile('^' + ip_rx6 + '$', regex.I)
is_ip = regex.compile('^(' + ip_rx4 + '|' + ip_rx6 + ')$', regex.I)

######################################################################

def ip_sort(iplist):
    ips = list()
    for ip in iplist:
        ips.append(IP(ip))

    ipset = IPSet(ips) # Here is the magic for aggregation

    newlist = list()
    for ip in ipset:
        newlist.append(ip.strNormal(1))

    return newlist

######################################################################

if __name__ == '__main__':

    for line in sys.stdin:
        line = line.strip().lower()
        if is_ip4.search(line):
            lip4[line] = line
        elif is_ip6.search(line):
            lip6[line] = line

    for line in ip_sort(lip4) + ip_sort(lip6):
        sys.stdout.write(line + '\n')
	


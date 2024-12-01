#!/usr/bin/env python3
'''
==========================================================================
 undup.py v0.01-20241201 Copyright 2019-2024 by cbuijs@chrisbuijs.com
==========================================================================

 Undup DNS Domainlist (Remove sub-domains)

==========================================================================
'''

# Standard Stuff
import sys, socket

# Regex
import regex

# Netaddr/IPy
from IPy import IP
import netaddr

# Lists
doms = list()

# IP Regexes
dom_rx = '^[a-zA-Z0-9\.\-]+$'
is_dom = regex.compile(dom_rx, regex.I)

#########################################################################

def nice_dom(dom):
    dom = dom.strip().lower()
    if is_dom.search(dom):
        return str(dom)
    return None


def dom_sort(domlist):
    unique_domains = set(domlist)
    sorted_domains = sorted(unique_domains, key=lambda domain: domain.split('.')[::-1])
    return list(sorted_domains)


if __name__ == '__main__':
    doms = dom_sort(list(filter(None, map(nice_dom, sys.stdin))))

    parent = '.invalid'
    undupped = set()

    for domain in doms:
        parent_domain = '.' + domain.strip('.')
        if not domain.endswith(parent):
            parent = parent_domain
            sys.stdout.write('{0}\n'.format(domain))

sys.exit(0)

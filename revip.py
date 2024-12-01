#!/usr/bin/env python3

'''
=========================================================================
 revip.py v0.02-20240709 Copyright 2019-2024 by cbuijs@chrisbuijs.com
=========================================================================

 Genereate reverse DNS names from IP-Addresses

=========================================================================
'''

# Standard Stuff
import sys
import socket

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
is_ip4 = regex.compile('^' + ip_rx4 + '$', regex.I)
is_ip6 = regex.compile('^' + ip_rx6 + '$', regex.I)
is_ip = regex.compile('^(' + ip_rx4 + '|' + ip_rx6 + ')$', regex.I)

#########################################################################

def nice_ip(ip):
    ip = ip.strip().lower()

    if is_ip.search(ip):
        return str(IP(ip, make_net=True).strNormal(1))

    return None


# Expand IPv6 address
def expand_ip(ip):
    if ':' not in ip:
        if len(ip.split('.')) != 4:
            new_ip = '0.0.0.0/32'
            return new_ip
        if '/' in ip:
            return ip
        else:
            return ip + '/32'

    new_ip = ip
    if new_ip.startswith(':'):
        new_ip = '0' + new_ip

    prefix = '128'

    if '/' in new_ip:
        new_ip, prefix = new_ip.split('/')[0:2]

    if new_ip.endswith(':'):
        new_ip = new_ip + '0'

    if '::' in new_ip:
        padding = 9 - new_ip.count(':')
        new_ip = new_ip.replace('::', ':' * padding)

    parts = new_ip.split(':')

    if len(parts) != 8:
        new_ip = '0000:0000:0000:0000:0000:0000:0000:0000/128'
        return new_ip

    for part in range(8):
        parts[part] = str(parts[part]).zfill(4)

    new_ip = ':'.join(parts) + '/' + prefix

    return new_ip


# Reverse IP DNS Name
def rev_ip(ip):
    revip = list()
    eip = expand_ip(ip)
    prefix = False

    if '/' in eip:
        eip, prefix = regex.split('/', eip)[0:2]
    else:
        if is_ip4.search(eip):
            prefix = '32'
        elif is_ip6.search(eip):
            prefix = '128'

    if prefix:
        prefix = int(prefix)

    if is_ip4.search(eip):
        if prefix in (8, 16, 24, 32):
            revip.append('.'.join(eip.split('.')[0:prefix // 8][::-1]) + '.in-addr.arpa')
        else:
            p = ((prefix + 8) // 8) * 8
            if p > 7:
                for subnet in list(netaddr.IPNetwork(eip + '/' + str(prefix)).subnet(p)):
                    subnetip, subnetprefix = regex.split('/', str(subnet))[0:2]
                    revip.append('.'.join(str(subnetip).split('.')[0:p // 8][::-1]) + '.in-addr.arpa')

    elif is_ip6.search(eip):
        if prefix in (4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124, 128):
            revip.append('.'.join(filter(None, regex.split('(.)', regex.sub(':', '', eip))))[0:(prefix // 4) * 2][::-1].strip('.') + '.ip6.arpa')
        else:
            p = ((prefix + 4) // 4) * 4
            if p > 3:
                for subnet in list(netaddr.IPNetwork(eip + '/' + str(prefix)).subnet(p)):
                    subnetip, subnetprefix = regex.split('/', expand_ip(str(subnet)))[0:2]
                    revip.append('.'.join(filter(None, regex.split('(.)', regex.sub(':', '', str(subnetip)))))[0:(p // 4) * 2][::-1].strip('.') + '.ip6.arpa')

    return revip


if __name__ == '__main__':
    lip = list(filter(None, map(nice_ip, sys.stdin)))

    for line in list(map(str, netaddr.cidr_merge(lip))):
        for revip in list(rev_ip(line)):
            sys.stdout.write('{0}\n'.format(revip))

    sys.exit(0)


#!/usr/bin/env python3
'''
==========================================================================
 undup.py v0.03-20251121 Copyright 2019-2025 by cbuijs@chrisbuijs.com
==========================================================================

 Undup DNS Domainlist (Remove sub-domains when parent exists)

==========================================================================
'''

import sys, re

is_dom = re.compile(r'^[a-zA-Z0-9.-]+$')

def main():
    seen = set()
    processed_list = []
    write = sys.stdout.write

    for line in sys.stdin:
        dom = line.strip().lower().strip('.')
        
        if not dom or dom in seen:
            continue
        
        if is_dom.match(dom):
            seen.add(dom)
            processed_list.append((dom[::-1], dom))

    if not processed_list:
        sys.exit(0)

    processed_list.sort()
    last_rev = ''
    
    for rev_dom, original_dom in processed_list:
        if last_rev and rev_dom.startswith(last_rev + '.'):
            continue

        write(f'{original_dom}\n')
        last_rev = rev_dom

if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        sys.exit(0)

sys.exit(0)


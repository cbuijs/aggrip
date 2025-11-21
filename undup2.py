#!/usr/bin/env python3
'''
==========================================================================
 undup2.py v0.03-20251020 Copyright 2019-2025 by cbuijs@chrisbuijs.com
==========================================================================

 Undup DNS Domainlist (Remove sub-domains)
 Note: Faster but more memory then undup.py

==========================================================================
'''

import sys

def main():
    write = sys.stdout.buffer.write
    newline = b'\n'
    dot = b'.'

    try:
        raw_data = sys.stdin.buffer.read()

    except Exception:
        return

    if not raw_data:
        return

    unique_lines = set(
        line.strip().lower().strip(b'.') 
        for line in raw_data.splitlines() 
        if line.strip()
    )

    rev_list = [x[::-1] for x in unique_lines]

    rev_list.sort()
    
    last_kept = b''
    
    for curr in rev_list:
        if last_kept and curr.startswith(last_kept) and curr[len(last_kept):len(last_kept)+1] == dot:
            continue
            
        write(curr[::-1])
        write(newline)
        last_kept = curr

if __name__ == '__main__':
    try:
        main()

    except KeyboardInterrupt:
        sys.exit(0)

    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)

sys.exit(0)


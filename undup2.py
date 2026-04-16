#!/usr/bin/env python3
'''
==========================================================================
 Filename: undup2.py
 Version: 0.17
 Date: 2026-04-16 08:45 CEST
 Description: Blazing fast binary-level domain deduplicator. Removes 
              redundant subdomains when parent domains exist in the feed.
              Supports optional less-strict validation allowing '_' and '*'.
 
 Changes/Fixes:
 - v0.17 (2026-04-16): Added regex strictness validation (-l/--less-strict).
 - v0.16 (2026-04-07): Merged stripping rules, added docstrings.
 - v0.15 (2026-04-01): Original version.
==========================================================================
'''

import sys
import re
import argparse

# Compiled bytes regex to maintain blazing fast execution
STRICT_PATTERN = re.compile(b'^[a-z0-9.-]+$')
LESS_STRICT_PATTERN = re.compile(b'^[a-z0-9._*-]+$')

def main():
    parser = argparse.ArgumentParser(description="Blazing fast binary-level domain deduplicator.")
    parser.add_argument("-l", "--less-strict", action="store_true", help="Allow underscores (_) and asterisks (*) in domain names")
    args = parser.parse_args()

    active_pattern = LESS_STRICT_PATTERN if args.less_strict else STRICT_PATTERN

    write = sys.stdout.buffer.write
    newline = b'\n'
    dot = b'.'

    try:
        raw_data = sys.stdin.buffer.read()
    except Exception:
        return

    if not raw_data:
        return

    # Bulk byte-level parsing: Strips whitespace, carriage returns, and trailing dots instantly
    unique_lines = set()
    for line in raw_data.splitlines():
        cleaned = line.strip(b' .\r\n').lower()
        if cleaned and active_pattern.match(cleaned):
            unique_lines.add(cleaned)

    if not unique_lines:
        return

    # Reverse string logic forces Parent Domains to sort BEFORE their subdomains.
    # e.g., 'com.example' is processed before 'com.example.sub'
    rev_list = sorted([x[::-1] for x in unique_lines])
    last_kept = b''
    
    for curr in rev_list:
        # Check if the current reversed string strictly falls under the last parent
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


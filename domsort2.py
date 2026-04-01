#!/usr/bin/env python3
import sys
import re

# Since we lowercase the entire input block upfront, the regex only needs to check a-z.
# This slightly reduces the complexity and speeds up the regex engine.
DOMAIN_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$')

def get_sort_key(domain):
    """Splits the domain by dots and reverses the list for TLD-first sorting."""
    return domain.split('.')[::-1]

def main():
    # 1. BULK READ & NORMALIZE: 
    # sys.stdin.read() grabs all piped text at once.
    # .lower() converts the massive string block in C.
    # .split() inherently drops all whitespace (including spaces, tabs, and empty lines).
    raw_data = sys.stdin.read().lower().split()
    
    # 2. C-LEVEL FILTERING:
    # filter() applies the regex match method directly in C, avoiding Python 'for' loops.
    valid_domains = filter(DOMAIN_PATTERN.match, raw_data)
    
    # 3. SORT:
    # Timsort is highly optimized; providing a direct function pointer is the fastest approach.
    sorted_domains = sorted(valid_domains, key=get_sort_key)
    
    # 4. BULK WRITE:
    # Join the sorted list into a single string and write it to stdout in one operation.
    # This avoids the immense overhead of calling print() on every single domain.
    if sorted_domains:
        sys.stdout.write('\n'.join(sorted_domains) + '\n')

if __name__ == "__main__":
    main()


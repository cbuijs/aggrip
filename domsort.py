#!/usr/bin/env python3
import sys
import re

# Regex pattern for strict domain validation
# Matches: alphanumeric/hyphen subdomains + dot + alphabetic TLD (min 2 chars)
DOMAIN_PATTERN = re.compile(
    r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)

def domain_sort_key(domain):
    """
    Splits the domain by dots and reverses the list.
    Example: 'sub.example.com' becomes ['com', 'example', 'sub']
    """
    return domain.split('.')[::-1]

def main():
    valid_domains = []
    
    # Read lines from standard input
    for line in sys.stdin:
        # Strip whitespace and normalize to lowercase
        clean_line = line.strip().lower()
        
        # If the line is a valid domain, add it to our list. Otherwise, discard.
        if DOMAIN_PATTERN.match(clean_line):
            valid_domains.append(clean_line)

    # Sort the list using the reverse-order key
    sorted_domains = sorted(valid_domains, key=domain_sort_key)

    # Output the sorted domains
    for domain in sorted_domains:
        print(domain)

if __name__ == "__main__":
    main()


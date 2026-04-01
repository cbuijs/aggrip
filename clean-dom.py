#!/usr/bin/env python3
'''
==========================================================================
 clean-dom.py v0.15-20260401 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================

 Optimize a highly efficient DNS blocklist.
 
 Logic:
 1. Reads and consolidates multiple blocklists, allowlists, and Top-N lists.
 2. Sorts domains by depth (number of dots) to ensure parent domains 
    are evaluated before subdomains.
 3. Cross-references against the consolidated allowlists and Top-N lists.
 4. Deduplicates subdomains on the fly.

==========================================================================
'''

import argparse
import sys

def read_domains(filename, is_topn=False):
    """Reads a file and returns a list of cleaned, lowercase domains."""
    domains = []
    with open(filename, 'r') as f:
        for line in f:
            clean_line = line.strip().lower()
            if clean_line and not clean_line.startswith('#'):
                if is_topn and ',' in clean_line:
                    parts = clean_line.split(',', 1)
                    if len(parts) > 1:
                        clean_line = parts[1].strip()
                
                if clean_line: 
                    domains.append(clean_line)
    return domains

def get_parents(domain):
    """Yields the domain and all its parent domains using fast string slicing."""
    yield domain
    idx = domain.find('.')
    while idx != -1:
        yield domain[idx + 1:]
        idx = domain.find('.', idx + 1)

def domain_sort_key(item):
    """Generates a sorting key for tree-down (TLD to subdomain) sorting."""
    if item.startswith('# '):
        domain = item[2:].split(' - ', 1)[0]
    else:
        domain = item
        
    return domain.split('.')[::-1]

def main():
    parser = argparse.ArgumentParser(description="Optimize a highly efficient DNS blocklist.")
    parser.add_argument("--blocklist", nargs='+', required=True, 
                        help="Path(s) to the DNS blocklist file(s)")
    parser.add_argument("--allowlist", nargs='+', 
                        help="Optional path(s) to the DNS allowlist file(s)")
    parser.add_argument("--topnlist", nargs='+', 
                        help="Optional path(s) to Top-N list file(s)")
    parser.add_argument("--suppress-comments", action="store_true", 
                        help="Suppress the audit log of removed domains in the output")
    args = parser.parse_args()

    try:
        # Consolidate all provided blocklists
        blocklist_domains = []
        for bl_file in args.blocklist:
            blocklist_domains.extend(read_domains(bl_file))
        
        # Consolidate all provided allowlists
        allowlist_domains = set()
        if args.allowlist:
            for al_file in args.allowlist:
                allowlist_domains.update(read_domains(al_file))
        
        # Consolidate all provided Top-N lists
        topn_domains = set()
        if args.topnlist:
            for topn_file in args.topnlist:
                topn_domains.update(read_domains(topn_file, is_topn=True))
            
    except FileNotFoundError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    removed_log = []
    final_blocklist = []
    active_blocks = set()

    # OPTIMIZATION 1: Sort by depth guarantees parents are processed before subdomains.
    # Sorting a unified blocklist ensures cross-file deduplication works perfectly.
    blocklist_domains.sort(key=lambda d: d.count('.'))

    # OPTIMIZATION 2: Single-pass processing.
    for domain in blocklist_domains:
        domain_parents = list(get_parents(domain))
        
        # Check against consolidated Allowlist
        if allowlist_domains:
            is_allowlisted = False
            for parent in domain_parents:
                if parent in allowlist_domains:
                    removed_log.append(f"# {domain} - Removed because of Allowlisted by {parent}")
                    is_allowlisted = True
                    break
            if is_allowlisted:
                continue
            
        # Check against consolidated Top-N list
        if topn_domains:
            is_topn = False
            for parent in domain_parents:
                if parent in topn_domains:
                    is_topn = True
                    break
            if not is_topn:
                removed_log.append(f"# {domain} - Removed because of Not a TOP-N")
                continue
                
        # Deduplication check against previously processed domains
        is_deduped = False
        for parent in domain_parents:
            if parent in active_blocks:
                removed_log.append(f"# {domain} - Removed because of Parent domain {parent} exists")
                is_deduped = True
                break
        if is_deduped:
            continue
            
        final_blocklist.append(domain)
        active_blocks.add(domain)

    output_lines = final_blocklist
    if not args.suppress_comments:
        output_lines.extend(removed_log)

    for line in sorted(output_lines, key=domain_sort_key):
        print(line)

if __name__ == "__main__":
    main()


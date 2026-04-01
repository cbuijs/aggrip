#!/usr/bin/env python3
import argparse
import sys

def read_domains(filename, is_topn=False):
    """Reads a file and returns a list of cleaned, lowercase domains.
    If is_topn is True, it handles both plain text and CSV formats (like Tranco).
    """
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
    """Yields the domain and all its parent domains using fast string slicing.
    Much faster than split() and join() in tight loops.
    """
    yield domain
    idx = domain.find('.')
    while idx != -1:
        yield domain[idx + 1:]
        idx = domain.find('.', idx + 1)

def domain_sort_key(item):
    """Generates a sorting key for tree-down (TLD to subdomain) sorting."""
    if item.startswith('# '):
        # Use a maxsplit of 1 for speed
        domain = item[2:].split(' - ', 1)[0]
    else:
        domain = item
        
    return domain.split('.')[::-1]

def main():
    parser = argparse.ArgumentParser(description="Optimize a highly efficient DNS blocklist.")
    parser.add_argument("blocklist", help="Path to the DNS blocklist file")
    parser.add_argument("allowlist", help="Path to the DNS allowlist file")
    parser.add_argument("topnlist", nargs='?', default=None, help="Optional path to a Top-N list file")
    parser.add_argument("--suppress-comments", action="store_true", 
                        help="Suppress the audit log of removed domains in the output")
    args = parser.parse_args()

    try:
        blocklist_domains = read_domains(args.blocklist)
        allowlist_domains = set(read_domains(args.allowlist))
        
        topn_domains = set()
        if args.topnlist:
            topn_domains = set(read_domains(args.topnlist, is_topn=True))
            
    except FileNotFoundError as e:
        print(f"Error reading file: {e}", file=sys.stderr)
        sys.exit(1)

    removed_log = []
    final_blocklist = []
    active_blocks = set()

    # OPTIMIZATION 1: Sort by depth (number of dots) first. 
    # This guarantees parents are processed before their subdomains.
    blocklist_domains.sort(key=lambda d: d.count('.'))

    # OPTIMIZATION 2: Single-pass processing.
    for domain in blocklist_domains:
        # Pre-calculate parents once per domain using the fast generator
        domain_parents = list(get_parents(domain))
        
        # Check 1: Allowlist
        is_allowlisted = False
        for parent in domain_parents:
            if parent in allowlist_domains:
                removed_log.append(f"# {domain} - Removed because of Allowlisted by {parent}")
                is_allowlisted = True
                break
        if is_allowlisted:
            continue # Skip remaining checks and move to the next domain
            
        # Check 2: Top-N List
        if topn_domains:
            is_topn = False
            for parent in domain_parents:
                if parent in topn_domains:
                    is_topn = True
                    break
            if not is_topn:
                removed_log.append(f"# {domain} - Removed because of Not a TOP-N")
                continue
                
        # Check 3: Deduplication (Active Blocks)
        # Because we sorted by depth earlier, if 'example.com' was valid, 
        # it is ALREADY in active_blocks by the time we evaluate 'sub.example.com'
        is_deduped = False
        for parent in domain_parents:
            if parent in active_blocks:
                removed_log.append(f"# {domain} - Removed because of Parent domain {parent} exists")
                is_deduped = True
                break
        if is_deduped:
            continue
            
        # If the domain survived all checks, it's a valid, unique block
        final_blocklist.append(domain)
        active_blocks.add(domain)

    # Combine output and run the final tree-down sort
    output_lines = final_blocklist
    if not args.suppress_comments:
        output_lines.extend(removed_log)

    for line in sorted(output_lines, key=domain_sort_key):
        print(line)

if __name__ == "__main__":
    main()


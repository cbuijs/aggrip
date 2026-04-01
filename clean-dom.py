#!/usr/bin/env python3
'''
==========================================================================
 clean-dom.py v0.15-20260401 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================

 Optimize a highly efficient DNS blocklist.
 
 Logic:
 1. Reads and consolidates multiple blocklists, allowlists, and Top-N lists 
    from local files or remote URLs.
 2. Normalizes domains (lowercasing, wildcard removal, adblock syntax 
    stripping, leading/trailing dot removal).
 3. Supports Plain Domain lists, HOSTS syntax, and Adblock DNS syntax.
 4. Sorts domains by depth (number of dots) to ensure parent domains 
    are evaluated before subdomains.
 5. Cross-references against the consolidated allowlists and Top-N lists.
 6. Deduplicates subdomains on the fly.

==========================================================================
'''

import argparse
import sys
import ipaddress
import urllib.request

NULL_IPS = {'0.0.0.0', '127.0.0.1', '::', '::1'}

def log_msg(msg, is_verbose):
    """Prints a message to STDERR if verbose mode is enabled."""
    if is_verbose:
        print(f"[*] {msg}", file=sys.stderr)

def is_valid_ip(token):
    """Fast-path check for IP addresses to avoid exception overhead on standard domains."""
    if not token:
        return False
    # Only try to parse if it starts with a digit (IPv4/IPv6) or colon (IPv6)
    c = token[0]
    if c.isdigit() or c == ':':
        try:
            ipaddress.ip_address(token)
            return True
        except ValueError:
            pass
    return False

def normalize_domain(domain):
    """Normalizes a domain by stripping adblock syntax, wildcards, and dots."""
    domain = domain.lower().strip()
    
    # Strip Adblock syntax prefixes
    if domain.startswith('@@||'):
        domain = domain[4:]
    elif domain.startswith('||'):
        domain = domain[2:]
        
    # Strip Adblock syntax suffix
    if domain.endswith('^'):
        domain = domain[:-1]
        
    # Remove leading wildcards
    while domain.startswith('*.'):
        domain = domain[2:]
        
    # Remove leading and trailing dots
    domain = domain.strip('.')
    
    return domain

def get_lines(source):
    """Yields lines efficiently from either a remote URL or a local file."""
    if source.startswith('http://') or source.startswith('https://'):
        # Use a standard user-agent as some blocklist providers block bare python-urllib
        req = urllib.request.Request(source, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            for line in response:
                yield line.decode('utf-8', errors='ignore')
    else:
        with open(source, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                yield line

def read_domains(source, is_topn=False, is_verbose=False):
    """Reads a file or URL and returns a list of cleaned, normalized domains."""
    domains = []
    log_msg(f"Loading data from: {source}", is_verbose)
    
    for line in get_lines(source):
        # Remove inline comments and strip whitespace
        line = line.split('#')[0].strip()
        
        # Skip empty lines or adblock comments
        if not line or line.startswith('!'):
            continue
        
        # Top-N parsing
        if is_topn and ',' in line:
            parts = line.split(',', 1)
            if len(parts) > 1:
                dom = normalize_domain(parts[1])
                if dom:
                    domains.append(dom)
            continue
        
        parts = line.split()
        if not parts:
            continue
            
        first_token = parts[0]
        
        # Check for HOSTS syntax
        if is_valid_ip(first_token):
            if first_token in NULL_IPS:
                # Parse all domains following the null/localhost IP
                for part in parts[1:]:
                    dom = normalize_domain(part)
                    if dom:
                        domains.append(dom)
            # If it's an IP but not a null IP, skip the entry entirely
            continue
        
        # Standard Domain or Adblock parsing
        dom = normalize_domain(first_token)
        if dom:
            domains.append(dom)
            
    log_msg(f"Loaded {len(domains):,} domains.", is_verbose)    
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
                        help="Path(s) or URL(s) to the DNS blocklist(s)")
    parser.add_argument("--allowlist", nargs='+', 
                        help="Optional path(s) or URL(s) to the DNS allowlist(s)")
    parser.add_argument("--topnlist", nargs='+', 
                        help="Optional path(s) or URL(s) to Top-N list(s)")
    parser.add_argument("--suppress-comments", action="store_true", 
                        help="Suppress the audit log of removed domains in the output")
    parser.add_argument("-v", "--verbose", action="store_true", 
                        help="Show progress and statistics on STDERR")
    args = parser.parse_args()

    v = args.verbose

    try:
        # Consolidate all provided blocklists
        blocklist_domains = []
        if v: log_msg("--- Stage 1: Consolidating Blocklists ---", v)
        for bl_source in args.blocklist:
            blocklist_domains.extend(read_domains(bl_source, is_verbose=v))
        
        # Consolidate all provided allowlists
        allowlist_domains = set()
        if args.allowlist:
            if v: log_msg("--- Stage 2: Consolidating Allowlists ---", v)
            for al_source in args.allowlist:
                allowlist_domains.update(read_domains(al_source, is_verbose=v))
        
        # Consolidate all provided Top-N lists
        topn_domains = set()
        if args.topnlist:
            if v: log_msg("--- Stage 3: Consolidating Top-N Lists ---", v)
            for topn_source in args.topnlist:
                topn_domains.update(read_domains(topn_source, is_topn=True, is_verbose=v))
            
    except Exception as e:
        print(f"Error reading source data: {e}", file=sys.stderr)
        sys.exit(1)

    log_msg(f"--- Stage 4: Preparing for Deduplication ---", v)
    log_msg(f"Sorting {len(blocklist_domains):,} domains by depth...", v)

    # OPTIMIZATION 1: Sort by depth guarantees parents are processed before subdomains.
    blocklist_domains.sort(key=lambda d: d.count('.'))

    log_msg(f"--- Stage 5: Processing & Optimizing ---", v)

    removed_log = []
    final_blocklist = []
    active_blocks = set()

    stats_allowlisted = 0
    stats_topn = 0
    stats_deduped = 0

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
                    stats_allowlisted += 1
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
                stats_topn += 1
                continue
                
        # Deduplication check against previously processed domains
        is_deduped = False
        for parent in domain_parents:
            if parent in active_blocks:
                removed_log.append(f"# {domain} - Removed because of Parent domain {parent} exists")
                is_deduped = True
                stats_deduped += 1
                break
        if is_deduped:
            continue
            
        final_blocklist.append(domain)
        active_blocks.add(domain)

    # Output printing phase
    log_msg(f"--- Stage 6: Generating Output ---", v)
    output_lines = final_blocklist
    if not args.suppress_comments:
        output_lines.extend(removed_log)

    for line in sorted(output_lines, key=domain_sort_key):
        print(line)

    if v:
        log_msg("===========================================", v)
        log_msg("          OPTIMIZATION STATISTICS          ", v)
        log_msg("===========================================", v)
        log_msg(f"Total Blocklist Domains Read: {len(blocklist_domains):,}", v)
        log_msg(f"Removed (Allowlisted)       : {stats_allowlisted:,}", v)
        log_msg(f"Removed (Not in Top-N)      : {stats_topn:,}", v)
        log_msg(f"Removed (Sub-domain Dedup)  : {stats_deduped:,}", v)
        log_msg("-------------------------------------------", v)
        log_msg(f"Final Active Domains        : {len(active_blocks):,}", v)
        log_msg("===========================================", v)

if __name__ == "__main__":
    main()


#!/usr/bin/env python3
'''
==========================================================================
 clean-dom.py v0.17.1 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================

 Optimize a highly efficient DNS blocklist.
 
 Logic:
 1. Reads and consolidates multiple blocklists, allowlists, and Top-N lists 
    from local files or remote URLs.
 2. Normalizes domains (lowercasing, wildcard removal, adblock syntax 
    stripping, leading/trailing dot removal).
 3. Supports Plain Domain lists, HOSTS syntax, and Adblock DNS syntax.
 4. Dynamically routes inline Adblock allowlist rules (@@) to the allowlist.
 5. Parses and enforces Adblock $denyallow modifiers (correctly inversing 
    exceptions based on primary rule intent).
 6. Sorts domains by depth (number of dots) to ensure parent domains 
    are evaluated before subdomains.
 7. Cross-references against the consolidated allowlists and Top-N lists.
 8. Deduplicates subdomains on the fly.
 9. Outputs in Plain Domain, HOSTS, or Advanced Adblock syntax.

==========================================================================
'''

import argparse
import sys
import ipaddress
import urllib.request
import time

NULL_IPS = {'0.0.0.0', '127.0.0.1', '::', '::1'}

def log_msg(msg, is_verbose):
    """Prints a message to STDERR if verbose mode is enabled."""
    if is_verbose:
        print(f"[*] {msg}", file=sys.stderr)

def is_valid_ip(token):
    """Fast-path check for IP addresses to avoid exception overhead on standard domains."""
    if not token:
        return False
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

def parse_domain_token(token):
    """Parses Adblock syntax, extracting the domain, allowlist status, and denyallow subdomains."""
    is_allow = False
    denyallow_domains = []
    
    # Handle allowlist prefix before modifier checks
    if token.startswith('@@'):
        is_allow = True
        token = token[2:]
        
    # Extract modifiers (e.g., $denyallow=...)
    if '$' in token:
        parts = token.split('$', 1)
        domain_part = parts[0]
        modifiers = parts[1]
        
        for mod in modifiers.split(','):
            if mod.startswith('denyallow='):
                da_list = mod[len('denyallow='):].split('|')
                for da_dom in da_list:
                    clean_da = normalize_domain(da_dom)
                    if clean_da:
                        denyallow_domains.append(clean_da)
    else:
        domain_part = token
        
    clean_dom = normalize_domain(domain_part)
    
    return {
        'domain': clean_dom,
        'is_allow': is_allow,
        'denyallow': denyallow_domains,
        'original_token': token
    }

def get_lines(source):
    """Yields lines efficiently from either a remote URL or a local file."""
    if source.startswith('http://') or source.startswith('https://'):
        req = urllib.request.Request(source, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            for line in response:
                yield line.decode('utf-8', errors='ignore')
    else:
        with open(source, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                yield line

def read_domains(source, is_topn=False, force_allow=False, is_verbose=False):
    """Reads a file or URL and routes domains into block, allow, and denyallow lists."""
    block_domains = []
    allow_domains = []
    denyallow_overrides = []
    
    log_msg(f"Loading data from: {source}", is_verbose)
    
    def process_parsed(parsed, raw_token):
        """Helper to append parsed domains and apply logical inverses for $denyallow."""
        if parsed['domain']:
            if parsed['is_allow'] and not force_allow:
                log_msg(f"Routed inline rule to allowlist : {parsed['domain']} (from '{raw_token}')", is_verbose)
                
            if parsed['is_allow'] or force_allow:
                allow_domains.append(parsed['domain'])
            else:
                block_domains.append(parsed['domain'])
                
        if parsed['denyallow']:
            log_msg(f"Extracted $denyallow domain(s): {', '.join(parsed['denyallow'])} (from '{raw_token}')", is_verbose)
            
            # The 'denyallow' modifier is an exception to the primary rule.
            if parsed['is_allow'] or force_allow:
                # Primary is ALLOW, so exceptions are BLOCKED.
                block_domains.extend(parsed['denyallow'])
                # Protect these blocked subdomains from being wiped by their allowlisted parent
                denyallow_overrides.extend(parsed['denyallow'])
            else:
                # Primary is BLOCK, so exceptions are ALLOWED.
                allow_domains.extend(parsed['denyallow'])

    for line in get_lines(source):
        line = line.split('#')[0].strip()
        if not line or line.startswith('!'):
            continue
        
        if is_topn and ',' in line:
            parts = line.split(',', 1)
            if len(parts) > 1:
                dom = normalize_domain(parts[1])
                if dom:
                    block_domains.append(dom)
            continue
        
        parts = line.split()
        if not parts:
            continue
            
        first_token = parts[0]
        
        if is_valid_ip(first_token):
            if first_token in NULL_IPS:
                for part in parts[1:]:
                    process_parsed(parse_domain_token(part), part)
            continue
        
        process_parsed(parse_domain_token(first_token), first_token)
            
    log_msg(f"Loaded {len(block_domains):,} blocks, {len(allow_domains):,} allows.", is_verbose)    
    return block_domains, allow_domains, denyallow_overrides

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
    parser.add_argument("--blocklist", nargs='+', required=True, help="Path(s) or URL(s) to the DNS blocklist(s)")
    parser.add_argument("--allowlist", nargs='+', help="Optional path(s) or URL(s) to the DNS allowlist(s)")
    parser.add_argument("--topnlist", nargs='+', help="Optional path(s) or URL(s) to Top-N list(s)")
    parser.add_argument("-o", "--output", choices=["domain", "hosts", "adblock"], default="domain", 
                        help="Output format: 'domain' (default), 'hosts', or 'adblock'")
    parser.add_argument("--suppress-comments", action="store_true", help="Suppress the audit log of removed domains")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show progress and statistics on STDERR")
    args = parser.parse_args()

    v = args.verbose

    blocklist_domains = []
    allowlist_domains = set()
    denyallow_overrides = set()

    try:
        if v: log_msg("--- Stage 1: Consolidating Blocklists ---", v)
        for bl_source in args.blocklist:
            b, a, d = read_domains(bl_source, is_verbose=v)
            blocklist_domains.extend(b)
            allowlist_domains.update(a)
            denyallow_overrides.update(d)
        
        if args.allowlist:
            if v: log_msg("--- Stage 2: Consolidating Allowlists ---", v)
            for al_source in args.allowlist:
                b, a, d = read_domains(al_source, force_allow=True, is_verbose=v)
                blocklist_domains.extend(b)
                allowlist_domains.update(a)
                denyallow_overrides.update(d)
        
        topn_domains = set()
        if args.topnlist:
            if v: log_msg("--- Stage 3: Consolidating Top-N Lists ---", v)
            for topn_source in args.topnlist:
                b, _, _ = read_domains(topn_source, is_topn=True, is_verbose=v)
                topn_domains.update(b)
            
    except Exception as e:
        print(f"Error reading source data: {e}", file=sys.stderr)
        sys.exit(1)

    log_msg(f"--- Stage 4: Preparing for Deduplication ---", v)
    log_msg(f"Sorting {len(blocklist_domains):,} domains by depth...", v)

    # Sort by depth guarantees parents are processed before subdomains.
    blocklist_domains.sort(key=lambda d: d.count('.'))

    log_msg(f"--- Stage 5: Processing & Optimizing ---", v)

    removed_log = []
    final_blocklist = []
    active_blocks = set()

    stats_allowlisted = 0
    stats_topn = 0
    stats_deduped = 0

    for domain in blocklist_domains:
        domain_parents = list(get_parents(domain))
        
        # Check against consolidated Allowlist with Denyallow priority
        if allowlist_domains:
            is_allowlisted = False
            for parent in domain_parents:
                if parent in denyallow_overrides:
                    # Log when an exception override blocks an allowlist action
                    log_msg(f"Enforced exception override : {domain} (Protected from allowlist rule on '{parent}')", v)
                    break
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
    
    # Print Adblock headers
    if args.output == "adblock":
        print("[Adblock Plus]")
        print(f"! Version: {int(time.time())}")
    
    # Build Adblock specific structures if needed
    adblock_rules = {}
    standalone_allows = []
    
    if args.output == "adblock":
        for dom in active_blocks:
            adblock_rules[dom] = []
            
        for allow_dom in allowlist_domains:
            has_blocked_parent = False
            for parent in get_parents(allow_dom):
                if parent != allow_dom and parent in active_blocks:
                    # Map the allowlisted subdomain to its blocked parent as a $denyallow exception
                    adblock_rules[parent].append(allow_dom)
                    has_blocked_parent = True
                    break 
            
            # If the allowed domain doesn't fall under any active block rule, print it standalone
            if not has_blocked_parent:
                standalone_allows.append(allow_dom)

    # Output standalone allows first (standard adblock list convention)
    if args.output == "adblock" and standalone_allows:
        for dom in sorted(standalone_allows, key=domain_sort_key):
            print(f"@@||{dom}^")

    # Combine blocks and comments for sorted output
    output_items = list(final_blocklist)
    if not args.suppress_comments:
        output_items.extend(removed_log)

    for item in sorted(output_items, key=domain_sort_key):
        if item.startswith('#'):
            # Format comments based on output type
            if args.output == "adblock":
                print(f"! {item[2:]}")
            else:
                print(item)
        else:
            # Format domains based on output type
            if args.output == "hosts":
                print(f"0.0.0.0 {item}")
            elif args.output == "adblock":
                exceptions = adblock_rules.get(item, [])
                if exceptions:
                    print(f"||{item}^$denyallow={'|'.join(sorted(exceptions))}")
                else:
                    print(f"||{item}^")
            else:
                print(item)

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


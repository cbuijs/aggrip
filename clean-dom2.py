#!/usr/bin/env python3
'''
==========================================================================
 Filename: clean-dom2.py
 Version: 0.21
 Date: 2026-04-07
 Description: Enterprise-grade DNS blocklist optimizer. Ingests massive 
              blocklists, cross-references allowlists/Top-N lists, strictly 
              enforces Adblock modifiers ($denyallow), and deduplicates 
              redundant subdomains using an O(N log N) reverse-string sort 
              and bulk memory processing.

 Changes/Fixes:
 - v0.21 (2026-04-07): Restored missing execution flow and output logic.
 - v0.20 (2026-04-07): Embedded manual into code comments, optimized string parsing.
 - v0.19 (2026-04-03): Re-aligned evaluation logic to strictly match clean-dom.py.
==========================================================================
'''

import argparse
import sys
import ipaddress
import urllib.request
import time

# Pre-compiled set of sinkhole IPs to discard during HOSTS parsing
NULL_IPS = {'0.0.0.0', '127.0.0.1', '::', '::1'}

def log_msg(msg, is_verbose):
    """Outputs progress to STDERR to keep STDOUT clean for piping."""
    if is_verbose:
        sys.stderr.write(f"[*] {msg}\n")

def is_valid_ip(token):
    """Fast-path heuristic check for IP addresses to prevent slow exception handling."""
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
    """
    Strips noise from input data:
    - Adblock syntax (@@||, ||, ^)
    - Leading wildcards (*.)
    - Trailing/Leading dots
    """
    domain = domain.lower().strip()
    if domain.startswith('@@||'): domain = domain[4:]
    elif domain.startswith('||'): domain = domain[2:]
    if domain.endswith('^'): domain = domain[:-1]
    while domain.startswith('*.'): domain = domain[2:]
    return domain.strip('.')

def parse_domain_token(token):
    """
    Parses Adblock advanced syntax.
    Extracts modifiers like $denyallow to enforce strict exceptions where 
    a subdomain might be allowed even if the parent is blocked.
    """
    is_allow = False
    denyallow_domains = []
    
    if token.startswith('@@'):
        is_allow = True
        token = token[2:]
        
    if '$' in token:
        parts = token.split('$', 1)
        domain_part = parts[0]
        # Parse comma-separated modifiers
        for mod in parts[1].split(','):
            if mod.startswith('denyallow='):
                denyallow_domains.extend(
                    [normalize_domain(d) for d in mod[10:].split('|') if normalize_domain(d)]
                )
    else:
        domain_part = token
        
    return {
        'domain': normalize_domain(domain_part),
        'is_allow': is_allow,
        'denyallow': denyallow_domains,
        'original_token': token
    }

def get_lines_bulk(source):
    """Fetches payload in bulk from either an HTTP stream or Local file."""
    if source.startswith('http://') or source.startswith('https://'):
        req = urllib.request.Request(source, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8', errors='ignore').splitlines()
    else:
        with open(source, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read().splitlines()

def read_domains_bulk(source, is_topn=False, force_allow=False, is_verbose=False):
    """
    Parses lists and automatically routes domains.
    Inline allowlists (@@) inside blocklists are detected and routed automatically.
    """
    block_domains = []
    allow_domains = []
    denyallow_overrides = []
    
    log_msg(f"Bulk loading data from: {source}", is_verbose)
    
    def process_parsed(parsed, raw_token):
        if parsed['domain']:
            if parsed['is_allow'] or force_allow: allow_domains.append(parsed['domain'])
            else: block_domains.append(parsed['domain'])
                
        if parsed['denyallow']:
            # Logical inversion: If primary rule is block, exceptions are allowed (and vice versa)
            if parsed['is_allow'] or force_allow:
                block_domains.extend(parsed['denyallow'])
                denyallow_overrides.extend(parsed['denyallow'])
            else:
                allow_domains.extend(parsed['denyallow'])

    for line in get_lines_bulk(source):
        line = line.split('#')[0].strip()
        if not line or line.startswith('!'): continue
        
        # CSV support for Top-N list processing
        if is_topn and ',' in line:
            parts = line.split(',', 1)
            if len(parts) > 1:
                dom = normalize_domain(parts[1])
                if dom: block_domains.append(dom)
            continue
        
        parts = line.split()
        if not parts: continue
            
        first_token = parts[0]
        
        # Handle HOSTS file logic (0.0.0.0 domain.com)
        if is_valid_ip(first_token):
            if first_token in NULL_IPS:
                for part in parts[1:]:
                    process_parsed(parse_domain_token(part), part)
            continue
        
        process_parsed(parse_domain_token(first_token), first_token)
            
    return block_domains, allow_domains, denyallow_overrides

def get_parents(domain):
    """Yields all parent domains tree-upwards (e.g., sub.example.com -> example.com -> com)."""
    yield domain
    idx = domain.find('.')
    while idx != -1:
        yield domain[idx + 1:]
        idx = domain.find('.', idx + 1)

def domain_sort_key(item):
    """Generates a sorting key for tree-down (TLD to subdomain) formatting output."""
    if item.startswith('# '):
        domain = item[2:].split(' - ', 1)[0]
    else:
        domain = item
    return domain.split('.')[::-1]

def main():
    parser = argparse.ArgumentParser(description="DNS blocklist compiler, router, and optimizer.")
    parser.add_argument("--blocklist", nargs='+', required=True)
    parser.add_argument("--allowlist", nargs='+')
    parser.add_argument("--topnlist", nargs='+')
    parser.add_argument("-o", "--output", choices=["domain", "hosts", "adblock"], default="domain")
    parser.add_argument("--out-blocklist")
    parser.add_argument("--out-allowlist")
    parser.add_argument("--suppress-comments", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    v = args.verbose
    blocklist_domains = []
    allowlist_domains = set()
    denyallow_overrides = set()

    # --- Ingestion Phase ---
    try:
        if v: log_msg("Consolidating Blocklists...", v)
        for bl_source in args.blocklist:
            b, a, d = read_domains_bulk(bl_source, is_verbose=v)
            blocklist_domains.extend(b)
            allowlist_domains.update(a)
            denyallow_overrides.update(d)
        
        if args.allowlist:
            if v: log_msg("Consolidating Allowlists...", v)
            for al_source in args.allowlist:
                b, a, d = read_domains_bulk(al_source, force_allow=True, is_verbose=v)
                blocklist_domains.extend(b)
                allowlist_domains.update(a)
                denyallow_overrides.update(d)
        
        topn_domains = set()
        if args.topnlist:
            if v: log_msg("Consolidating Top-N Lists...", v)
            for topn_source in args.topnlist:
                b, _, _ = read_domains_bulk(topn_source, is_topn=True, is_verbose=v)
                topn_domains.update(b)
            
    except Exception as e:
        sys.stderr.write(f"Error reading source data: {e}\n")
        sys.exit(1)

    # --- Filtering Phase ---
    log_msg("Filtering against Allowlist and Top-N...", v)
    filtered_blocks = set()
    removed_log = []

    for domain in blocklist_domains:
        parents = list(get_parents(domain))
        
        # Cross-reference Allowlists (enforcing explicit denyallow exclusions)
        if allowlist_domains:
            if any((p in allowlist_domains and p not in denyallow_overrides) for p in parents):
                if not args.suppress_comments:
                    removed_log.append(f"# {domain} - Removed because of Allowlist")
                continue
                
        # Cross-reference Top-N lists
        if topn_domains:
            if not any(p in topn_domains for p in parents):
                if not args.suppress_comments:
                    removed_log.append(f"# {domain} - Removed because of Not a TOP-N")
                continue
                
        filtered_blocks.add(domain)

    # --- O(N log N) Fast Deduplication Phase ---
    log_msg("Executing O(N log N) subdomain deduplication...", v)
    
    # Reversing strings causes parent domains to sort instantly BEFORE subdomains
    rev_list = sorted([x[::-1] for x in filtered_blocks])
    final_active = set()
    last_kept = ""
    
    for curr in rev_list:
        # If the reversed string is a subset of the previous parent with a dot boundary, it is a redundant subdomain
        if last_kept and curr.startswith(last_kept) and curr[len(last_kept):len(last_kept)+1] == '.':
            if not args.suppress_comments:
                removed_log.append(f"# {curr[::-1]} - Removed because of Parent domain deduplication")
            continue
            
        final_active.add(curr[::-1])
        last_kept = curr

    # --- Formatting & Output Phase ---
    log_msg("Generating Outputs...", v)
    
    try:
        out_block = open(args.out_blocklist, 'w', encoding='utf-8') if args.out_blocklist else sys.stdout
        out_allow = open(args.out_allowlist, 'w', encoding='utf-8') if args.out_allowlist else None
    except Exception as e:
        sys.stderr.write(f"Error opening output files: {e}\n")
        sys.exit(1)

    # Handle standard Adblock mapping logic for standalones and overrides
    adblock_rules = {dom: [] for dom in final_active}
    standalone_allows = []
    
    for allow_dom in allowlist_domains:
        has_blocked_parent = False
        for parent in get_parents(allow_dom):
            if parent != allow_dom and parent in final_active:
                adblock_rules[parent].append(allow_dom)
                has_blocked_parent = True
                if args.output in ("domain", "hosts") and not args.suppress_comments:
                    removed_log.append(f"# {allow_dom} - Allowlisted but blocked by parent domain {parent}")
                break 
        if not has_blocked_parent:
            standalone_allows.append(allow_dom)

    # Stream Adblock Metadata Headers
    if args.output == "adblock":
        out_block.write("[Adblock Plus]\n")
        out_block.write(f"! version: {int(time.time())}\n")
        if out_allow:
            out_allow.write("[Adblock Plus]\n")
            out_allow.write(f"! version: {int(time.time())}\n")

    # Stream Allowlist targets
    if out_allow:
        for dom in sorted(allowlist_domains, key=domain_sort_key):
            out_allow.write(f"@@||{dom}^\n" if args.output == "adblock" else f"{dom}\n")
    elif args.output == "adblock" and standalone_allows:
        for dom in sorted(standalone_allows, key=domain_sort_key):
            out_block.write(f"@@||{dom}^\n")

    # Final Buffer Output Join 
    output_items = list(final_active)
    if not args.suppress_comments:
        output_items.extend(removed_log)

    for item in sorted(output_items, key=domain_sort_key):
        if item.startswith('#'):
            if args.output == "adblock": out_block.write(f"! {item[2:]}\n")
            else: out_block.write(f"{item}\n")
        else:
            if args.output == "hosts":
                out_block.write(f"0.0.0.0 {item}\n")
            elif args.output == "adblock":
                exc = adblock_rules.get(item, [])
                out_block.write(f"||{item}^$denyallow={'|'.join(sorted(exc))}\n" if exc else f"||{item}^\n")
            else:
                out_block.write(f"{item}\n")

    if args.out_blocklist: out_block.close()
    if args.out_allowlist: out_allow.close()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)


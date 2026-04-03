#!/usr/bin/env python3
'''
==========================================================================
 clean-dom2.py v0.19-20260403 Copyright 2019-2026 by cbuijs@chrisbuijs.com
==========================================================================
 Changes/Fixes:
 - v0.19-20260403: Re-aligned evaluation logic to strictly match clean-dom.py
                   while keeping O(N log N) bulk memory reverse-string dedup.
==========================================================================

 Optimize a highly efficient DNS blocklist.
 Note: Faster memory-optimized alternative using bulk reads and reverse-sort.
 
 Logic:
 1. Reads and consolidates multiple lists from local files or remote URLs in bulk.
 2. Normalizes domains (lowercasing, wildcard removal, syntax stripping).
 3. Supports Plain Domain lists, HOSTS syntax, and Adblock DNS syntax.
 4. Dynamically routes inline Adblock allowlist rules (@@).
 5. Parses and enforces Adblock $denyallow modifiers.
 6. Sorts reversed domains alphabetically to process parents before subdomains.
 7. Cross-references against allowlists and Top-N lists strictly tree-down.
 8. Deduplicates subdomains on the fly using O(N log N) string checks.
 9. Outputs in Plain Domain, HOSTS, or Advanced Adblock syntax via bulk writes.

==========================================================================
'''

import argparse
import sys
import ipaddress
import urllib.request
import time

NULL_IPS = {'0.0.0.0', '127.0.0.1', '::', '::1'}

def log_msg(msg, is_verbose):
    if is_verbose:
        sys.stderr.write(f"[*] {msg}\n")

def is_valid_ip(token):
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
    domain = domain.lower().strip()
    if domain.startswith('@@||'): domain = domain[4:]
    elif domain.startswith('||'): domain = domain[2:]
    if domain.endswith('^'): domain = domain[:-1]
    while domain.startswith('*.'): domain = domain[2:]
    return domain.strip('.')

def parse_domain_token(token):
    is_allow = False
    denyallow_domains = []
    
    if token.startswith('@@'):
        is_allow = True
        token = token[2:]
        
    if '$' in token:
        parts = token.split('$', 1)
        domain_part = parts[0]
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
    if source.startswith('http://') or source.startswith('https://'):
        req = urllib.request.Request(source, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.read().decode('utf-8', errors='ignore').splitlines()
    else:
        with open(source, 'r', encoding='utf-8', errors='ignore') as f:
            return f.read().splitlines()

def read_domains_bulk(source, is_topn=False, force_allow=False, is_verbose=False):
    block_domains = []
    allow_domains = []
    denyallow_overrides = []
    
    log_msg(f"Bulk loading data from: {source}", is_verbose)
    
    def process_parsed(parsed, raw_token):
        if parsed['domain']:
            if parsed['is_allow'] and not force_allow:
                log_msg(f"Routed inline rule to allowlist : {parsed['domain']} (from '{raw_token}')", is_verbose)
                
            if parsed['is_allow'] or force_allow: allow_domains.append(parsed['domain'])
            else: block_domains.append(parsed['domain'])
                
        if parsed['denyallow']:
            log_msg(f"Extracted $denyallow domain(s): {', '.join(parsed['denyallow'])} (from '{raw_token}')", is_verbose)
            if parsed['is_allow'] or force_allow:
                block_domains.extend(parsed['denyallow'])
                denyallow_overrides.extend(parsed['denyallow'])
            else:
                allow_domains.extend(parsed['denyallow'])

    for line in get_lines_bulk(source):
        line = line.split('#')[0].strip()
        if not line or line.startswith('!'):
            continue
        
        if is_topn and ',' in line:
            parts = line.split(',', 1)
            if len(parts) > 1:
                dom = normalize_domain(parts[1])
                if dom: block_domains.append(dom)
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
    yield domain
    idx = domain.find('.')
    while idx != -1:
        yield domain[idx + 1:]
        idx = domain.find('.', idx + 1)

def domain_sort_key(item):
    if item.startswith('# '):
        domain = item[2:].split(' - ', 1)[0]
    else:
        domain = item
    return domain.split('.')[::-1]

def main():
    parser = argparse.ArgumentParser(description="Optimize a highly efficient DNS blocklist (Fast Version).")
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

    try:
        if v: log_msg("--- Stage 1: Bulk Consolidating Blocklists ---", v)
        for bl_source in args.blocklist:
            b, a, d = read_domains_bulk(bl_source, is_verbose=v)
            blocklist_domains.extend(b)
            allowlist_domains.update(a)
            denyallow_overrides.update(d)
        
        if args.allowlist:
            if v: log_msg("--- Stage 2: Bulk Consolidating Allowlists ---", v)
            for al_source in args.allowlist:
                b, a, d = read_domains_bulk(al_source, force_allow=True, is_verbose=v)
                blocklist_domains.extend(b)
                allowlist_domains.update(a)
                denyallow_overrides.update(d)
        
        topn_domains = set()
        if args.topnlist:
            if v: log_msg("--- Stage 3: Bulk Consolidating Top-N Lists ---", v)
            for topn_source in args.topnlist:
                b, _, _ = read_domains_bulk(topn_source, is_topn=True, is_verbose=v)
                topn_domains.update(b)
            
    except Exception as e:
        sys.stderr.write(f"Error reading source data: {e}\n")
        sys.exit(1)

    log_msg(f"--- Stage 4: Filtering & Deduplication ---", v)
    log_msg(f"Sorting {len(blocklist_domains):,} domains via fast reverse-sort...", v)

    # Sort reversed strings to process TLDs and parents before subdomains
    rev_blocks = [d[::-1] for d in blocklist_domains]
    rev_blocks.sort()

    removed_log = []
    final_blocklist = []
    active_blocks = set()

    stats_allowlisted = 0
    stats_topn = 0
    stats_deduped = 0
    
    last_kept = ''

    for r_dom in rev_blocks:
        domain = r_dom[::-1]
        domain_parents = list(get_parents(domain))
        
        if allowlist_domains:
            is_allowlisted = False
            for parent in domain_parents:
                if parent in denyallow_overrides:
                    log_msg(f"Enforced exception override : {domain} (Protected from allowlist rule on '{parent}')", v)
                    break
                if parent in allowlist_domains:
                    removed_log.append(f"# {domain} - Removed because of Allowlisted by {parent}")
                    is_allowlisted = True
                    stats_allowlisted += 1
                    break
            if is_allowlisted:
                continue
            
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
                
        is_deduped = False
        if last_kept:
            if r_dom == last_kept:
                removed_log.append(f"# {domain} - Removed because of Parent domain {domain} exists")
                is_deduped = True
            elif r_dom.startswith(last_kept) and r_dom[len(last_kept):len(last_kept)+1] == '.':
                removed_log.append(f"# {domain} - Removed because of Parent domain {last_kept[::-1]} exists")
                is_deduped = True
                
        if is_deduped:
            stats_deduped += 1
            continue
            
        last_kept = r_dom
        final_blocklist.append(domain)
        active_blocks.add(domain)

    log_msg(f"--- Stage 5: Generating Output ---", v)
    
    out_block = open(args.out_blocklist, 'w', encoding='utf-8') if args.out_blocklist else sys.stdout
    out_allow = open(args.out_allowlist, 'w', encoding='utf-8') if args.out_allowlist else None
        
    if args.output == "adblock":
        out_block.write("[Adblock Plus]\n")
        out_block.write(f"! version: {int(time.time())}\n")
        if out_allow:
            out_allow.write("[Adblock Plus]\n")
            out_allow.write(f"! version: {int(time.time())}\n")
    
    adblock_rules = {dom: [] for dom in active_blocks}
    standalone_allows = []
    stats_allow_ignored = 0
    
    for allow_dom in allowlist_domains:
        has_blocked_parent = False
        for parent in get_parents(allow_dom):
            if parent != allow_dom and parent in active_blocks:
                adblock_rules[parent].append(allow_dom)
                has_blocked_parent = True
                if args.output in ("domain", "hosts"):
                    removed_log.append(f"# {allow_dom} - Allowlisted but blocked by parent domain {parent}")
                    stats_allow_ignored += 1
                break 
        
        if not has_blocked_parent:
            standalone_allows.append(allow_dom)

    if out_allow:
        out_allow_buf = []
        for dom in sorted(allowlist_domains, key=domain_sort_key):
            out_allow_buf.append(f"@@||{dom}^" if args.output == "adblock" else dom)
        out_allow.write('\n'.join(out_allow_buf) + '\n')
    elif args.output == "adblock" and standalone_allows:
        out_block.write('\n'.join([f"@@||{dom}^" for dom in sorted(standalone_allows, key=domain_sort_key)]) + '\n')

    out_buffer = []
    output_items = list(active_blocks)
    if not args.suppress_comments:
        output_items.extend(removed_log)

    for item in sorted(output_items, key=domain_sort_key):
        if item.startswith('#'):
            out_buffer.append(f"! {item[2:]}" if args.output == "adblock" else item)
        else:
            if args.output == "hosts":
                out_buffer.append(f"0.0.0.0 {item}")
            elif args.output == "adblock":
                exceptions = adblock_rules.get(item, [])
                out_buffer.append(f"||{item}^$denyallow={'|'.join(sorted(exceptions))}" if exceptions else f"||{item}^")
            else:
                out_buffer.append(item)

    out_block.write('\n'.join(out_buffer) + '\n')

    if args.out_blocklist: out_block.close()
    if args.out_allowlist: out_allow.close()

    if v:
        log_msg("===========================================", v)
        log_msg("          OPTIMIZATION STATISTICS          ", v)
        log_msg("===========================================", v)
        log_msg(f"Total Blocklist Domains Read: {len(blocklist_domains):,}", v)
        log_msg(f"Removed (Allowlisted)       : {stats_allowlisted:,}", v)
        log_msg(f"Removed (Not in Top-N)      : {stats_topn:,}", v)
        log_msg(f"Removed (Sub-domain Dedup)  : {stats_deduped:,}", v)
        if args.output in ("domain", "hosts"):
            log_msg(f"Ignored Allows (Blocked)    : {stats_allow_ignored:,}", v)
        log_msg("-------------------------------------------", v)
        log_msg(f"Final Active Domains        : {len(active_blocks):,}", v)
        if args.out_allowlist:
            log_msg(f"Exported Allowlist Domains  : {len(allowlist_domains):,}", v)
        log_msg("===========================================", v)

if __name__ == "__main__":
    main()


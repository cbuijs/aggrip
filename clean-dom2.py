#!/usr/bin/env python3
'''
==========================================================================
 Filename: clean-dom2.py
 Version: 0.36
 Date: 2026-04-22 10:50 CEST
 Description: Enterprise-grade DNS blocklist optimizer. Ingests massive 
              blocklists, applying cross-references, modifiers ($denyallow), 
              optionally optimizes allowlists, and deduplicates via reverse sort.
 
 Changes/Fixes:
 - v0.36 (2026-04-22): Added --sort parameter for domain, alphabetically (natural), and tld sort.
 - v0.35 (2026-04-22): Suppressed creation of empty output files (or files containing only comments).
 - v0.34 (2026-04-22): Strictly rejected Adblock rules with non-DNS modifiers (e.g., $ping).
 - v0.33 (2026-04-22): Fixed false-positives caused by truncating Adblock element hiding rules (##, #@#).
 - v0.32 (2026-04-22): Added -w/--work parameter to save unmodified raw source files.
 - v0.31 (2026-04-22): Added explicit filtering to drop any IPs or CIDR blocks.
 - v0.30 (2026-04-22): Explicitly ignored Adblock/AdGuard regex rules (/regex/).
 - v0.29 (2026-04-22): Added -i/--input parameter to strictly enforce input formats.
 - v0.28 (2026-04-22): Added strict regex validation to drop invalid paths/URLs.
 - v0.27 (2026-04-16): Added $TTL and fake SOA record to RPZ header.
==========================================================================
'''

import argparse
import sys
import os
import hashlib
import ipaddress
import urllib.request
import time
import re

NULL_IPS = {'0.0.0.0', '127.0.0.1', '::', '::1'}

# Strict regex to ensure we only extract clean, valid domain names. Drops paths/URLs.
DOMAIN_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,}$')

def log_msg(msg, is_verbose):
    """Outputs progress to STDERR to keep STDOUT clean for piping."""
    if is_verbose:
        sys.stderr.write(f"[*] {msg}\n")

def is_ip_or_cidr(token):
    """Fast-path heuristic check for IPs/CIDRs to prevent slow exception handling."""
    if not token:
        return False
    c = token[0]
    if c.isdigit() or c == ':':
        try:
            ipaddress.ip_network(token, strict=False)
            return True
        except ValueError:
            pass
    return False

def normalize_domain(domain):
    """Strips noise from input data: Adblock syntax, wildcards, dots."""
    domain = domain.lower().strip()
    if domain.startswith('@@||'): domain = domain[4:]
    elif domain.startswith('||'): domain = domain[2:]
    if domain.endswith('^'): domain = domain[:-1]
    while domain.startswith('*.'): domain = domain[2:]
    return domain.strip('.')

def parse_domain_token(token):
    """Parses Adblock advanced syntax, extracting modifiers like $denyallow."""
    is_allow = False
    denyallow_domains = []
    original_token = token
    
    if token.startswith('@@'):
        is_allow = True
        token = token[2:]
        
    # Explicitly drop Adblock/AdGuard regex rules (e.g., /banner\d+/)
    if token.startswith('/'):
        return {
            'domain': None,
            'is_allow': False,
            'denyallow': [],
            'original_token': original_token
        }
        
    if '$' in token:
        parts = token.split('$', 1)
        domain_part = parts[0]
        for mod in parts[1].split(','):
            mod = mod.strip()
            if mod.startswith('denyallow='):
                for d in mod[10:].split('|'):
                    clean_da = normalize_domain(d)
                    if clean_da and DOMAIN_PATTERN.match(clean_da) and not is_ip_or_cidr(clean_da):
                        denyallow_domains.append(clean_da)
            elif mod:
                # Unsupported meta-option (e.g. $ping), discard the entire rule safely
                return {
                    'domain': None,
                    'is_allow': False,
                    'denyallow': [],
                    'original_token': original_token
                }
    else:
        domain_part = token
        
    clean_dom = normalize_domain(domain_part)
    
    # Strictly enforce valid domain syntax, dropping pure URL/Path rules and IP/CIDRs
    if clean_dom and (not DOMAIN_PATTERN.match(clean_dom) or is_ip_or_cidr(clean_dom)):
        clean_dom = None
        
    return {
        'domain': clean_dom,
        'is_allow': is_allow,
        'denyallow': denyallow_domains,
        'original_token': original_token
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

def read_domains_bulk(source, is_topn=False, force_allow=False, is_verbose=False, input_format=None, work_dir=None, list_type="Unknown"):
    """Parses lists and automatically routes domains (blocks, allows, exceptions)."""
    block_domains = []
    allow_domains = []
    denyallow_overrides = []
    
    log_msg(f"Bulk loading data from: {source}", is_verbose)
    
    def process_parsed(parsed, raw_token):
        if parsed['domain']:
            if parsed['is_allow'] or force_allow: allow_domains.append(parsed['domain'])
            else: block_domains.append(parsed['domain'])
                
        if parsed['denyallow']:
            if parsed['is_allow'] or force_allow:
                block_domains.extend(parsed['denyallow'])
                denyallow_overrides.extend(parsed['denyallow'])
            else:
                allow_domains.extend(parsed['denyallow'])

    lines = get_lines_bulk(source)

    if work_dir:
        source_hash = hashlib.sha256(source.encode('utf-8')).hexdigest()[:16]
        raw_path = os.path.join(work_dir, f"{source_hash}.raw")
        with open(raw_path, 'w', encoding='utf-8') as raw_file:
            raw_file.write(f"# Type: {list_type} | Source: {source}\n")
            raw_file.write('\n'.join(lines) + '\n')

    for raw_line in lines:
        raw_line = raw_line.strip()
        if not raw_line or raw_line.startswith('!'): continue
        
        # If a '#' appears before any space, it's an Adblock element hiding rule (domain.com##...)
        # snippet/injection (domain.com#%#), URL anchor, or full line comment. Skip it to prevent
        # truncating it into a false-positive domain.
        first_hash = raw_line.find('#')
        if first_hash != -1:
            if first_hash == 0:
                continue
            first_space = raw_line.find(' ')
            if first_space == -1 or first_hash < first_space:
                continue
                
        line = raw_line.split('#')[0].strip()
        if not line: continue
        
        if is_topn and ',' in line:
            if input_format and input_format != "domain":
                continue
            parts = line.split(',', 1)
            if len(parts) > 1:
                dom = normalize_domain(parts[1])
                if dom and DOMAIN_PATTERN.match(dom) and not is_ip_or_cidr(dom): 
                    block_domains.append(dom)
            continue
        
        parts = line.split()
        if not parts: continue
            
        first_token = parts[0]
        
        # Determine the line syntax heuristic for strict format checking
        is_hosts = is_ip_or_cidr(first_token)
        is_adblock = not is_hosts and (first_token.startswith('@@') or first_token.startswith('||') or '^' in first_token or '$' in first_token or first_token.startswith('/'))
        is_domain = not is_hosts and not is_adblock

        if input_format:
            if input_format == 'hosts' and not is_hosts: continue
            if input_format == 'adblock' and not is_adblock: continue
            if input_format == 'domain' and not is_domain: continue
        
        if is_hosts:
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

def get_sort_key_func(sort_type):
    """Returns the appropriate sorting lambda based on the selected algorithm."""
    def extract_domain(item):
        if item.startswith('# ') or item.startswith('; '):
            return item[2:].split(' - ', 1)[0]
        return item

    def natural_keys(text):
        return [int(c) if c.isdigit() else c for c in re.split(r'(\d+)', text)]

    if sort_type == "alphabetically":
        return lambda item: natural_keys(extract_domain(item))
    elif sort_type == "tld":
        return lambda item: (extract_domain(item).split('.')[-1], natural_keys(extract_domain(item)))
    else:
        # Default: "domain" (tree-down: TLD -> subdomain)
        return lambda item: extract_domain(item).split('.')[::-1]

def main():
    parser = argparse.ArgumentParser(description="DNS blocklist compiler, router, and optimizer.")
    parser.add_argument("--blocklist", nargs='+', required=True)
    parser.add_argument("--allowlist", nargs='+')
    parser.add_argument("--topnlist", nargs='+')
    parser.add_argument("-i", "--input", choices=["domain", "hosts", "adblock"], help="Strictly enforce an input format to skip non-matching lines")
    parser.add_argument("-o", "--output", choices=["domain", "hosts", "adblock", "dnsmasq", "unbound", "rpz"], default="domain")
    parser.add_argument("-w", "--work", help="Directory to save unmodified raw source files")
    parser.add_argument("--sort", choices=["domain", "alphabetically", "tld"], default="domain", help="Sorting algorithm for output")
    parser.add_argument("--out-blocklist")
    parser.add_argument("--out-allowlist")
    parser.add_argument("--optimize-allowlist", action="store_true", help="Drop unused allowlist entries that do not match any blocked targets")
    parser.add_argument("--suppress-comments", action="store_true")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    v = args.verbose
    sort_key = get_sort_key_func(args.sort)

    if args.work:
        os.makedirs(args.work, exist_ok=True)

    blocklist_domains = []
    allowlist_domains = set()
    denyallow_overrides = set()

    # --- Ingestion Phase ---
    try:
        if v: log_msg("Consolidating Blocklists...", v)
        for bl_source in args.blocklist:
            b, a, d = read_domains_bulk(bl_source, is_verbose=v, input_format=args.input, work_dir=args.work, list_type="Blocklist")
            blocklist_domains.extend(b)
            allowlist_domains.update(a)
            denyallow_overrides.update(d)
        
        if args.allowlist:
            if v: log_msg("Consolidating Allowlists...", v)
            for al_source in args.allowlist:
                b, a, d = read_domains_bulk(al_source, force_allow=True, is_verbose=v, input_format=args.input, work_dir=args.work, list_type="Allowlist")
                blocklist_domains.extend(b)
                allowlist_domains.update(a)
                denyallow_overrides.update(d)
        
        topn_domains = set()
        if args.topnlist:
            if v: log_msg("Consolidating Top-N Lists...", v)
            for topn_source in args.topnlist:
                b, _, _ = read_domains_bulk(topn_source, is_topn=True, is_verbose=v, input_format=args.input, work_dir=args.work, list_type="Top-N")
                topn_domains.update(b)
            
    except Exception as e:
        sys.stderr.write(f"Error reading source data: {e}\n")
        sys.exit(1)

    # --- Filtering Phase ---
    log_msg("Filtering against Allowlist and Top-N...", v)
    filtered_blocks = set()
    removed_log = []
    used_allows = set()

    for domain in blocklist_domains:
        parents = list(get_parents(domain))
        
        if allowlist_domains:
            allow_match = next((p for p in parents if p in allowlist_domains and p not in denyallow_overrides), None)
            if allow_match:
                used_allows.add(allow_match)
                if not args.suppress_comments:
                    removed_log.append(f"# {domain} - Removed because allowlisted by parent/apex {allow_match}")
                continue
                
        if topn_domains:
            if not any(p in topn_domains for p in parents):
                if not args.suppress_comments:
                    removed_log.append(f"# {domain} - Removed because not present in Top-N list")
                continue
                
        filtered_blocks.add(domain)

    # --- O(N log N) Fast Deduplication Phase ---
    log_msg("Executing O(N log N) subdomain deduplication...", v)
    
    rev_list = sorted([x[::-1] for x in filtered_blocks])
    final_active = set()
    last_kept = ""
    
    for curr in rev_list:
        if last_kept and curr.startswith(last_kept) and curr[len(last_kept):len(last_kept)+1] == '.':
            if not args.suppress_comments:
                removed_log.append(f"# {curr[::-1]} - Removed because redundant to blocked parent domain {last_kept[::-1]}")
            continue
            
        final_active.add(curr[::-1])
        last_kept = curr

    # --- Formatting & Output Phase ---
    log_msg("Generating Outputs...", v)
    
    adblock_rules = {dom: [] for dom in final_active}
    standalone_allows = []
    
    for allow_dom in allowlist_domains:
        has_blocked_parent = False
        for parent in get_parents(allow_dom):
            if parent != allow_dom and parent in final_active:
                adblock_rules[parent].append(allow_dom)
                has_blocked_parent = True
                used_allows.add(allow_dom)
                
                if args.output in ("domain", "hosts", "dnsmasq", "unbound", "rpz") and not args.suppress_comments:
                    removed_log.append(f"# {allow_dom} - Allowlisted but blocked by parent domain {parent}")
                break 
                
        if not has_blocked_parent:
            if not args.optimize_allowlist or allow_dom in used_allows:
                standalone_allows.append(allow_dom)

    if args.optimize_allowlist:
        unused_allows = allowlist_domains - used_allows
        for dom in unused_allows:
            if not args.suppress_comments:
                removed_log.append(f"# {dom} - Removed from allowlist because it is unused (no blocked targets matched)")
        final_allows = used_allows
    else:
        final_allows = allowlist_domains

    has_block_payload = bool(final_active)
    if args.output == "adblock" and not args.out_allowlist and standalone_allows:
        has_block_payload = True
        
    has_allow_payload = bool(final_allows)

    try:
        if args.out_blocklist:
            out_block = open(args.out_blocklist, 'w', encoding='utf-8') if has_block_payload else None
        else:
            out_block = sys.stdout if has_block_payload else None

        if args.out_allowlist:
            out_allow = open(args.out_allowlist, 'w', encoding='utf-8') if has_allow_payload else None
        else:
            out_allow = None
    except Exception as e:
        sys.stderr.write(f"Error opening output files: {e}\n")
        sys.exit(1)

    if out_block:
        if args.output == "adblock":
            out_block.write("[Adblock Plus]\n")
            out_block.write(f"! version: {int(time.time())}\n")
        elif args.output == "rpz":
            rpz_header = "$TTL 3600\n@ IN SOA localhost. root.localhost. 1 3600 900 2592000 300\n"
            out_block.write(rpz_header)
            
    if out_allow:
        if args.output == "adblock":
            out_allow.write("[Adblock Plus]\n")
            out_allow.write(f"! version: {int(time.time())}\n")
        elif args.output == "rpz":
            rpz_header = "$TTL 3600\n@ IN SOA localhost. root.localhost. 1 3600 900 2592000 300\n"
            out_allow.write(rpz_header)

    if out_allow:
        for dom in sorted(final_allows, key=sort_key):
            if args.output == "adblock":
                out_allow.write(f"@@||{dom}^\n")
            elif args.output == "rpz":
                out_allow.write(f"{dom} CNAME rpz-passthru.\n*.{dom} CNAME rpz-passthru.\n")
            else:
                out_allow.write(f"{dom}\n")
    elif args.output == "adblock" and standalone_allows and out_block:
        for dom in sorted(standalone_allows, key=sort_key):
            out_block.write(f"@@||{dom}^\n")

    if out_block:
        output_items = list(final_active)
        if not args.suppress_comments:
            output_items.extend(removed_log)

        for item in sorted(output_items, key=sort_key):
            if item.startswith('#'):
                if args.output == "adblock": out_block.write(f"! {item[2:]}\n")
                elif args.output == "rpz": out_block.write(f"; {item[2:]}\n")
                else: out_block.write(f"{item}\n")
            else:
                if args.output == "hosts":
                    out_block.write(f"0.0.0.0 {item}\n")
                elif args.output == "dnsmasq":
                    out_block.write(f"address=/{item}/0.0.0.0\n")
                elif args.output == "unbound":
                    out_block.write(f"local-zone: \"{item}\" always_nxdomain\n")
                elif args.output == "rpz":
                    out_block.write(f"{item} CNAME .\n*.{item} CNAME .\n")
                elif args.output == "adblock":
                    exc = adblock_rules.get(item, [])
                    out_block.write(f"||{item}^$denyallow={'|'.join(sorted(exc))}\n" if exc else f"||{item}^\n")
                else:
                    out_block.write(f"{item}\n")

        if args.out_blocklist:
            out_block.close()

    if args.out_allowlist and out_allow:
        out_allow.close()

    if v:
        stats_unused_allows = len(allowlist_domains) - len(used_allows) if args.optimize_allowlist else 0
        log_msg("===========================================", v)
        log_msg("          OPTIMIZATION STATISTICS          ", v)
        log_msg("===========================================", v)
        log_msg(f"Total Blocklist Domains Read: {len(blocklist_domains):,}", v)
        log_msg(f"Removed (Allowlisted)       : {stats_allowlisted:,}", v)
        log_msg(f"Removed (Not in Top-N)      : {stats_topn:,}", v)
        log_msg(f"Removed (Sub-domain Dedup)  : {stats_deduped:,}", v)
        if args.optimize_allowlist:
            log_msg(f"Dropped (Unused Allows)     : {stats_unused_allows:,}", v)
        if args.output in ("domain", "hosts", "dnsmasq", "unbound", "rpz"):
            log_msg(f"Ignored Allows (Blocked)    : {stats_allow_ignored:,}", v)
        log_msg("-------------------------------------------", v)
        log_msg(f"Final Active Domains        : {len(final_active):,}", v)
        if args.out_allowlist:
            log_msg(f"Exported Allowlist Domains  : {len(final_allows):,}", v)
        log_msg("===========================================", v)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)


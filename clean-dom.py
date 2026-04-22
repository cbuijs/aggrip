#!/usr/bin/env python3
'''
==========================================================================
 Filename: clean-dom.py
 Version: 0.33
 Date: 2026-04-22 10:50 CEST
 Description: Optimize a highly efficient DNS blocklist. Consolidates lists, 
              routes dynamically, enforces $denyallow modifiers, deduplicates 
              redundant subdomains, optionally optimizes allowlists, and exports.
 
 Changes/Fixes:
 - v0.33 (2026-04-22): Added --sort parameter for domain, alphabetically (natural), and tld sort.
 - v0.32 (2026-04-22): Suppressed creation of empty output files (or files containing only comments).
 - v0.31 (2026-04-22): Strictly rejected Adblock rules with non-DNS modifiers (e.g., $ping).
 - v0.30 (2026-04-22): Fixed false-positives caused by truncating Adblock element hiding rules (##, #@#).
 - v0.29 (2026-04-22): Added -w/--work parameter to save unmodified raw source files.
 - v0.28 (2026-04-22): Added explicit filtering to drop any IPs or CIDR blocks.
 - v0.27 (2026-04-22): Explicitly ignored Adblock/AdGuard regex rules (/regex/).
 - v0.26 (2026-04-22): Added -i/--input parameter to strictly enforce input formats.
 - v0.25 (2026-04-22): Added strict regex validation to drop invalid paths/URLs.
 - v0.24 (2026-04-16): Added $TTL and fake SOA record to RPZ header.
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
    """Prints a message to STDERR if verbose mode is enabled."""
    if is_verbose:
        print(f"[*] {msg}", file=sys.stderr)

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
    """Normalizes a domain by stripping adblock syntax, wildcards, and dots."""
    domain = domain.lower().strip()
    
    if domain.startswith('@@||'):
        domain = domain[4:]
    elif domain.startswith('||'):
        domain = domain[2:]
        
    if domain.endswith('^'):
        domain = domain[:-1]
        
    while domain.startswith('*.'):
        domain = domain[2:]
        
    domain = domain.strip('.')
    return domain

def parse_domain_token(token):
    """Parses Adblock syntax, extracting the domain, allowlist status, and denyallow subdomains."""
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
        modifiers = parts[1]
        
        mod_list = [m.strip() for m in modifiers.split(',') if m.strip()]
        
        # Strictly enforce that only a single '$denyallow' modifier is permitted.
        # Any other modifiers (e.g., $ping, $third-party), or multiple modifiers, 
        # invalidate the rule for pure DNS blocking purposes.
        if len(mod_list) > 1 or (len(mod_list) == 1 and not mod_list[0].startswith('denyallow=')):
            return {
                'domain': None,
                'is_allow': False,
                'denyallow': [],
                'original_token': original_token
            }
            
        if len(mod_list) == 1 and mod_list[0].startswith('denyallow='):
            da_list = mod_list[0][len('denyallow='):].split('|')
            for da_dom in da_list:
                clean_da = normalize_domain(da_dom)
                if clean_da and DOMAIN_PATTERN.match(clean_da) and not is_ip_or_cidr(clean_da):
                    denyallow_domains.append(clean_da)
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

def read_domains(source, is_topn=False, force_allow=False, is_verbose=False, input_format=None, work_dir=None, list_type="Unknown"):
    """Reads a file or URL and routes domains into block, allow, and denyallow lists."""
    block_domains = []
    allow_domains = []
    denyallow_overrides = []
    
    log_msg(f"Loading data from: {source}", is_verbose)
    
    def process_parsed(parsed, raw_token):
        if parsed['domain']:
            if parsed['is_allow'] and not force_allow:
                log_msg(f"Routed inline rule to allowlist : {parsed['domain']} (from '{raw_token}')", is_verbose)
                
            if parsed['is_allow'] or force_allow:
                allow_domains.append(parsed['domain'])
            else:
                block_domains.append(parsed['domain'])
                
        if parsed['denyallow']:
            log_msg(f"Extracted $denyallow domain(s): {', '.join(parsed['denyallow'])} (from '{raw_token}')", is_verbose)
            
            if parsed['is_allow'] or force_allow:
                block_domains.extend(parsed['denyallow'])
                denyallow_overrides.extend(parsed['denyallow'])
            else:
                allow_domains.extend(parsed['denyallow'])

    raw_file = None
    if work_dir:
        source_hash = hashlib.sha256(source.encode('utf-8')).hexdigest()[:16]
        raw_path = os.path.join(work_dir, f"{source_hash}.raw")
        raw_file = open(raw_path, 'w', encoding='utf-8')
        raw_file.write(f"# Type: {list_type} | Source: {source}\n")

    try:
        for line in get_lines(source):
            if raw_file:
                raw_file.write(line)
                
            raw_line = line.strip()
            if not raw_line or raw_line.startswith('!'):
                continue
                
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
            if not line:
                continue
            
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
            if not parts:
                continue
                
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
    finally:
        if raw_file:
            raw_file.close()
            
    log_msg(f"Loaded {len(block_domains):,} blocks, {len(allow_domains):,} allows.", is_verbose)    
    return block_domains, allow_domains, denyallow_overrides

def get_parents(domain):
    """Yields the domain and all its parent domains using fast string slicing."""
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
    parser = argparse.ArgumentParser(description="Optimize a highly efficient DNS blocklist.")
    parser.add_argument("--blocklist", nargs='+', required=True, help="Path(s) or URL(s) to the DNS blocklist(s)")
    parser.add_argument("--allowlist", nargs='+', help="Optional path(s) or URL(s) to the DNS allowlist(s)")
    parser.add_argument("--topnlist", nargs='+', help="Optional path(s) or URL(s) to Top-N list(s)")
    parser.add_argument("-i", "--input", choices=["domain", "hosts", "adblock"], help="Strictly enforce an input format to skip non-matching lines")
    parser.add_argument("-o", "--output", choices=["domain", "hosts", "adblock", "dnsmasq", "unbound", "rpz"], default="domain", 
                        help="Output format: 'domain' (default), 'hosts', 'adblock', 'dnsmasq', 'unbound', or 'rpz'")
    parser.add_argument("-w", "--work", help="Directory to save unmodified raw source files")
    parser.add_argument("--sort", choices=["domain", "alphabetically", "tld"], default="domain", help="Sorting algorithm for output")
    parser.add_argument("--out-blocklist", help="Optional file path to write the blocklist output (default: STDOUT)")
    parser.add_argument("--out-allowlist", help="Optional file path to write the allowlist output")
    parser.add_argument("--optimize-allowlist", action="store_true", help="Drop unused allowlist entries that do not match any blocked targets")
    parser.add_argument("--suppress-comments", action="store_true", help="Suppress the audit log of removed domains")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show progress and statistics on STDERR")
    args = parser.parse_args()

    v = args.verbose
    sort_key = get_sort_key_func(args.sort)

    if args.work:
        os.makedirs(args.work, exist_ok=True)

    blocklist_domains = []
    allowlist_domains = set()
    denyallow_overrides = set()

    try:
        if v: log_msg("--- Stage 1: Consolidating Blocklists ---", v)
        for bl_source in args.blocklist:
            b, a, d = read_domains(bl_source, is_verbose=v, input_format=args.input, work_dir=args.work, list_type="Blocklist")
            blocklist_domains.extend(b)
            allowlist_domains.update(a)
            denyallow_overrides.update(d)
        
        if args.allowlist:
            if v: log_msg("--- Stage 2: Consolidating Allowlists ---", v)
            for al_source in args.allowlist:
                b, a, d = read_domains(al_source, force_allow=True, is_verbose=v, input_format=args.input, work_dir=args.work, list_type="Allowlist")
                blocklist_domains.extend(b)
                allowlist_domains.update(a)
                denyallow_overrides.update(d)
        
        topn_domains = set()
        if args.topnlist:
            if v: log_msg("--- Stage 3: Consolidating Top-N Lists ---", v)
            for topn_source in args.topnlist:
                b, _, _ = read_domains(topn_source, is_topn=True, is_verbose=v, input_format=args.input, work_dir=args.work, list_type="Top-N")
                topn_domains.update(b)
            
    except Exception as e:
        print(f"Error reading source data: {e}", file=sys.stderr)
        sys.exit(1)

    log_msg(f"--- Stage 4: Preparing for Deduplication ---", v)
    log_msg(f"Sorting {len(blocklist_domains):,} domains by depth...", v)

    blocklist_domains.sort(key=lambda d: d.count('.'))

    log_msg(f"--- Stage 5: Processing & Optimizing ---", v)

    removed_log = []
    final_blocklist = []
    active_blocks = set()
    used_allows = set()

    stats_allowlisted = 0
    stats_topn = 0
    stats_deduped = 0

    for domain in blocklist_domains:
        domain_parents = list(get_parents(domain))
        
        if allowlist_domains:
            is_allowlisted = False
            for parent in domain_parents:
                if parent in denyallow_overrides:
                    log_msg(f"Enforced exception override : {domain} (Protected from allowlist rule on '{parent}')", v)
                    break
                if parent in allowlist_domains:
                    used_allows.add(parent)
                    removed_log.append(f"# {domain} - Removed because allowlisted by parent/apex {parent}")
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
                removed_log.append(f"# {domain} - Removed because not present in Top-N list")
                stats_topn += 1
                continue
                
        is_deduped = False
        for parent in domain_parents:
            if parent in active_blocks:
                removed_log.append(f"# {domain} - Removed because redundant to blocked parent domain {parent}")
                is_deduped = True
                stats_deduped += 1
                break
        if is_deduped:
            continue
            
        final_blocklist.append(domain)
        active_blocks.add(domain)

    log_msg(f"--- Stage 6: Generating Output ---", v)
    
    adblock_rules = {}
    standalone_allows = []
    stats_allow_ignored = 0
    
    for dom in active_blocks:
        adblock_rules[dom] = []
        
    for allow_dom in allowlist_domains:
        has_blocked_parent = False
        for parent in get_parents(allow_dom):
            if parent != allow_dom and parent in active_blocks:
                adblock_rules[parent].append(allow_dom)
                has_blocked_parent = True
                used_allows.add(allow_dom)
                
                if args.output in ("domain", "hosts", "dnsmasq", "unbound", "rpz"):
                    if not args.suppress_comments:
                        removed_log.append(f"# {allow_dom} - Allowlisted but blocked by parent domain {parent}")
                    stats_allow_ignored += 1
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

    has_block_payload = bool(active_blocks)
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
        print(f"Error opening output file(s): {e}", file=sys.stderr)
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
        output_items = list(final_blocklist)
        if not args.suppress_comments:
            output_items.extend(removed_log)

        for item in sorted(output_items, key=sort_key):
            if item.startswith('#'):
                if args.output == "adblock":
                    out_block.write(f"! {item[2:]}\n")
                elif args.output == "rpz":
                    out_block.write(f"; {item[2:]}\n")
                else:
                    out_block.write(f"{item}\n")
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
                    exceptions = adblock_rules.get(item, [])
                    if exceptions:
                        out_block.write(f"||{item}^$denyallow={'|'.join(sorted(exceptions))}\n")
                    else:
                        out_block.write(f"||{item}^\n")
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
        log_msg(f"Final Active Domains        : {len(active_blocks):,}", v)
        if args.out_allowlist:
            log_msg(f"Exported Allowlist Domains  : {len(final_allows):,}", v)
        log_msg("===========================================", v)

if __name__ == "__main__":
    main()


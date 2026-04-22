#!/usr/bin/env python3
'''
==========================================================================
 Filename: clean-ip.py
 Version: 0.16
 Date: 2026-04-22 16:30 CEST
 Changes:
 - v0.16 (2026-04-22): Added netmask output/input format, optimized range output to remove whitespaces, and added --range-sep param.
 - v0.15 (2026-04-22): Fixed TypeError during final subnet collapse of mixed IPv4/IPv6 blocks.
 - v0.14 (2026-04-22): Added IP-aware sorting lambda to safely process mixed IPv4/IPv6 lists and force IPv4 output first.
 - v0.13 (2026-04-22): Moved punch-hole comments inline directly between the fragmented CIDR blocks.
 Description: Optimizes IP blocklists by aggregating IPs, CIDRs, and ranges.
              Cross-references against allowlists, collapses redundant 
              subnets, mathematically excludes exceptions (punch-holing),
              and exports directly to firewall-ready configurations.
==========================================================================
'''

import argparse
import sys
import os
import ipaddress
import urllib.request

def log_msg(msg, is_verbose):
    """Outputs progress to STDERR to keep STDOUT clean."""
    if is_verbose:
        sys.stderr.write(f"[*] {msg}\n")

def get_lines(source):
    """Yields lines from either a remote URL or a local file."""
    if source.startswith('http://') or source.startswith('https://'):
        req = urllib.request.Request(source, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as response:
            for line in response:
                yield line.decode('utf-8', errors='ignore')
    else:
        with open(source, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                yield line

def read_ips(source, is_verbose, strict):
    """Reads a source file, parsing IPs, CIDRs, and IP-Ranges (including native ipaddress netmask support)."""
    networks = []
    log_msg(f"Loading data from: {source}", is_verbose)
    
    for raw_line in get_lines(source):
        line = raw_line.split('#')[0].strip()
        if not line or line.startswith('!'):
            continue
            
        # Normalizing spaces and dashes to easily tokenize IP ranges formats like IP-IP, IP - IP, or IP IP.
        tokens = line.replace('-', ' - ').split()
        i = 0
        while i < len(tokens):
            token = tokens[i]
            try:
                # Natively supports both CIDR notation and Netmask notation via Python's ipaddress library
                net = ipaddress.ip_network(token, strict=strict)
                is_range = False

                # Handle extraction of IP-Range syntax logic
                if ('/' not in token) and (i + 1 < len(tokens)):
                    offset = 2 if tokens[i+1] == '-' else 1
                    if i + offset < len(tokens):
                        try:
                            end_ip = ipaddress.ip_address(tokens[i+offset])
                            start_ip = ipaddress.ip_address(token)
                            if start_ip.version == end_ip.version:
                                start, end = min(start_ip, end_ip), max(start_ip, end_ip)
                                networks.extend(list(ipaddress.summarize_address_range(start, end)))
                                i += (offset + 1)
                                is_range = True
                        except ValueError:
                            pass
                
                if not is_range:
                    networks.append(net)
                    i += 1

            except ValueError:
                i += 1
                
    return networks

def format_network(net, fmt, range_sep="dash"):
    """Formats the IP network block into the requested output syntax."""
    if fmt == "cidr": return str(net)
    elif fmt == "netmask": return f"{net.network_address}/{net.netmask}"
    elif fmt == "range": 
        sep = " " if range_sep == "space" else "-"
        return f"{net[0]}{sep}{net[-1]}"
    elif fmt == "cisco": return f"deny ip {net.network_address} {net.hostmask} any"
    elif fmt == "iptables": return f"-A INPUT -s {net} -j DROP"
    elif fmt == "mikrotik": return f"add address={net} list=blocklist"
    elif fmt == "padded":
        if net.version == 4:
            parts = str(net.network_address).split('.')
            padded_ip = '.'.join(f"{int(p):03}" for p in parts)
            return f"{padded_ip}/{net.prefixlen}"
        else:
            return f"{net.network_address.exploded}/{net.prefixlen}"
    return str(net)

def format_allow_network(net, fmt, range_sep="dash"):
    """Formats allowlist output syntax."""
    if fmt == "cisco": return f"permit ip {net.network_address} {net.hostmask} any"
    elif fmt == "iptables": return f"-A INPUT -s {net} -j ACCEPT"
    elif fmt == "mikrotik": return f"add address={net} list=allowlist"
    return format_network(net, fmt, range_sep)

def main():
    parser = argparse.ArgumentParser(description="Optimize a highly efficient IP blocklist.")
    parser.add_argument("--blocklist", nargs='+', required=True, help="Path(s) or URL(s) to the IP blocklist(s)")
    parser.add_argument("--allowlist", nargs='+', help="Optional path(s) or URL(s) to the IP allowlist(s)")
    parser.add_argument("-o", "--output", choices=["cidr", "netmask", "range", "cisco", "iptables", "mikrotik", "padded"], default="cidr", help="Output format")
    parser.add_argument("--range-sep", choices=["space", "dash"], default="dash", help="Separator for range output (default: dash)")
    parser.add_argument("--out-blocklist", help="Optional file path to write the blocklist output (default: STDOUT)")
    parser.add_argument("--out-allowlist", help="Optional file path to write the allowlist output")
    parser.add_argument("--optimize-allowlist", action="store_true", help="Drop unused allowlist entries")
    parser.add_argument("--suppress-comments", action="store_true", help="Suppress the audit log of removed IPs")
    parser.add_argument("-s", "--strict", action="store_true", help="Reject CIDRs with dirty host bits instead of truncating")
    parser.add_argument("-v", "--verbose", action="store_true", help="Show progress and statistics on STDERR")
    args = parser.parse_args()

    v = args.verbose
    raw_blocks, raw_allows = [], []

    if v: log_msg("--- Stage 1: Consolidating Blocklists ---", v)
    for bl_source in args.blocklist:
        try:
            raw_blocks.extend(read_ips(bl_source, v, args.strict))
        except Exception as e:
            sys.stderr.write(f"Error reading source '{bl_source}': {e}\n")
            
    if args.allowlist:
        if v: log_msg("--- Stage 2: Consolidating Allowlists ---", v)
        for al_source in args.allowlist:
            try:
                raw_allows.extend(read_ips(al_source, v, args.strict))
            except Exception as e:
                sys.stderr.write(f"Error reading source '{al_source}': {e}\n")

    if v: log_msg("--- Stage 3: Aggregating & Collapsing Subnets ---", v)
    blocks_v4 = [n for n in raw_blocks if n.version == 4]
    blocks_v6 = [n for n in raw_blocks if n.version == 6]
    allows_v4 = [n for n in raw_allows if n.version == 4]
    allows_v6 = [n for n in raw_allows if n.version == 6]

    collapsed_blocks = list(ipaddress.collapse_addresses(blocks_v4)) + list(ipaddress.collapse_addresses(blocks_v6))
    collapsed_allows = list(ipaddress.collapse_addresses(allows_v4)) + list(ipaddress.collapse_addresses(allows_v6))

    if v: log_msg("--- Stage 4: Cross-Referencing & Punch-Holing ---", v)
    
    filtered_blocks = []
    used_allows = set()
    removed_log_general = []
    punched_holes = []

    stats_allowlisted = 0
    stats_holes_punched = 0

    # Pass 1: Total Eclipse (Remove blocks completely covered by an allowlist subnet)
    for block in collapsed_blocks:
        is_allowed = False
        for allow in collapsed_allows:
            if block.version == allow.version and block.subnet_of(allow):
                used_allows.add(allow)
                is_allowed = True
                if not args.suppress_comments:
                    removed_log_general.append(f"# {block} - Removed because allowlisted by encompassing subnet {allow}")
                stats_allowlisted += 1
                break
        if not is_allowed:
            filtered_blocks.append(block)

    # Pass 2: Mathematical Hole-Punching (Exclude allowed subsets from blocked supersets)
    final_blocks = []
    for block in filtered_blocks:
        current_pieces = [block]
        for allow in collapsed_allows:
            if allow.version != block.version:
                continue
            
            next_pieces = []
            for piece in current_pieces:
                if allow.subnet_of(piece):
                    used_allows.add(allow)
                    stats_holes_punched += 1
                    if not args.suppress_comments:
                        punched_holes.append((allow, block))
                    next_pieces.extend(list(piece.address_exclude(allow)))
                else:
                    next_pieces.append(piece)
            current_pieces = next_pieces
        
        final_blocks.extend(current_pieces)

    # Final cleanup of the resulting fragmented blocks (split by version to avoid TypeErrors)
    fb_v4 = [n for n in final_blocks if n.version == 4]
    fb_v6 = [n for n in final_blocks if n.version == 6]
    final_blocks = list(ipaddress.collapse_addresses(fb_v4)) + list(ipaddress.collapse_addresses(fb_v6))

    final_allows = []
    removed_log_unused_allows = []

    for allow in collapsed_allows:
        if not args.optimize_allowlist or allow in used_allows:
            final_allows.append(allow)
        else:
            if not args.suppress_comments:
                removed_log_unused_allows.append(f"# {allow} - Removed from allowlist because it is unused")

    if v: log_msg("--- Stage 5: Exporting Formats ---", v)
    
    try:
        out_b = open(args.out_blocklist, 'w', encoding='utf-8') if args.out_blocklist else sys.stdout
        out_a = open(args.out_allowlist, 'w', encoding='utf-8') if args.out_allowlist else None
    except Exception as e:
        sys.stderr.write(f"Error opening output files: {e}\n")
        sys.exit(1)

    if out_a:
        # Strict IP-aware sort guarantees IPv4 first, then IPv6
        for net in sorted(final_allows, key=lambda x: (x.version, int(x.network_address), x.prefixlen)):
            out_a.write(f"{format_allow_network(net, args.output, args.range_sep)}\n")
        out_a.close()

    # Output General Comments at the top
    output_top_comments = []
    if not args.suppress_comments:
        output_top_comments.extend(removed_log_general)
        output_top_comments.extend(removed_log_unused_allows)
        
    for item in output_top_comments:
        out_b.write(f"{item}\n")

    # Combine blocks and punch-hole comments into an inline sortable stream
    inline_stream = []
    for net in final_blocks:
        # Tuple format: (IP Version, Network Integer, Prefix, Is_Block, String)
        inline_stream.append((net.version, int(net.network_address), net.prefixlen, 1, format_network(net, args.output, args.range_sep)))
        
    for allow, orig_block in punched_holes:
        comment = f"# {allow} - Punched mathematical exception hole inside {orig_block}"
        inline_stream.append((allow.version, int(allow.network_address), allow.prefixlen, 0, comment))

    # This sort guarantees: IPv4 before IPv6 -> Ascending Subnets -> Comments flush exactly before the punched hole block
    inline_stream.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
    
    for item in inline_stream:
        out_b.write(f"{item[4]}\n")

    if args.out_blocklist:
        out_b.close()

    if v:
        log_msg("========== OPTIMIZATION STATS ==========", v)
        log_msg(f"Total Blocks Parsed         : {len(raw_blocks):,}", v)
        log_msg(f"Collapsed Block Subnets     : {len(collapsed_blocks):,}", v)
        log_msg(f"Removed (Allowlisted)       : {stats_allowlisted:,}", v)
        log_msg(f"Holes Punched (Exclusions)  : {stats_holes_punched:,}", v)
        log_msg("----------------------------------------", v)
        log_msg(f"Final Active Block CIDRs    : {len(final_blocks):,}", v)
        if args.out_allowlist:
            log_msg(f"Exported Allowlist CIDRs    : {len(final_allows):,}", v)
        log_msg("========================================", v)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)


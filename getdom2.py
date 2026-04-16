#!/usr/bin/env python3
'''
==========================================================================
 Filename: getdom2.py
 Version: 0.13
 Date: 2026-04-16 09:45 CEST
 Description: Fast, memory-heavy variant of getdom.py. Greps DNS domains 
              using bulk memory ingestion and customizable output formats.
              Supports Plain, Adblock, HOSTS, and URL extraction.
 
 Changes/Fixes:
 - v0.13 (2026-04-16): Added -o/--output parameter (plain, adblock, hosts).
 - v0.12 (2026-04-16): Enhanced URL parsing to strip ports and strictly 
                       enforce a plain domain list output format.
 - v0.11 (2026-04-16): Added $denyallow modifier routing, and explicitly 
                       handled multiple domains per line in HOSTS syntax.
 - v0.10 (2026-04-16): Initial getdom2.py implementation.
==========================================================================
'''

import sys
import re
import argparse
import ipaddress

# Pre-compiled optimized regex patterns
STRICT_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,}$')
LESS_STRICT_PATTERN = re.compile(r'^([a-z0-9_*]([a-z0-9\-_*]{0,61}[a-z0-9_*])?\.)+[a-z0-9\-_*]{2,}$')

def is_fast_ip(token):
    """Bypasses standard IPs from hitting exception blocks."""
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

def main():
    parser = argparse.ArgumentParser(description="Grep DNS domains from text inputs (Fast Variant).")
    parser.add_argument("-l", "--less-strict", action="store_true", help="Allow underscores (_) and asterisks (*) in domain names")
    parser.add_argument("-a", "--allow", action="store_true", help="Grep only 'allowed' domains (rules starting with @@ or $denyallow exceptions)")
    parser.add_argument("-o", "--output", choices=["plain", "adblock", "hosts"], default="plain", help="Output format: 'plain' (default), 'adblock', or 'hosts'")
    args = parser.parse_args()
    
    active_pattern = LESS_STRICT_PATTERN if args.less_strict else STRICT_PATTERN
    
    try:
        # Bulk read entirely into memory for blazing fast processing
        raw_lines = sys.stdin.read().splitlines()
    except KeyboardInterrupt:
        sys.exit(0)
        
    if not raw_lines:
        return
        
    # Standard array for unified buffer flushing
    out_buffer = []
    out_add = out_buffer.append
    
    for line in raw_lines:
        line = line.split('#')[0].strip()
        
        if not line or line.startswith('!'):
            continue
        
        # Split processes HOSTS file spaces implicitly allowing multiple domains
        for token in line.split():
            token = token.lower()
            
            if is_fast_ip(token):
                continue
                
            # URL normalization (removes protocol, paths, and ports)
            if '://' in token:
                token = token.split('://', 1)[1].split('/')[0].split(':')[0]
                
            is_allow = False
            if token.startswith('@@'):
                is_allow = True
                token = token[2:]
                
            if token.startswith('||'):
                token = token[2:]
                
            denyallow_domains = []
            if '$' in token:
                parts = token.split('$', 1)
                token = parts[0]
                modifiers = parts[1]
                for mod in modifiers.split(','):
                    if mod.startswith('denyallow='):
                        denyallow_domains.extend(mod[10:].split('|'))
                        
            if token.endswith('^'):
                token = token[:-1]
            token = token.strip('.')
            
            # Cross-reference the extraction target (-a flag)
            candidates = []
            if args.allow:
                if is_allow and token:
                    candidates.append(token)
                if not is_allow and denyallow_domains:
                    candidates.extend(denyallow_domains)
            else:
                if not is_allow and token:
                    candidates.append(token)
                if is_allow and denyallow_domains:
                    candidates.extend(denyallow_domains)
                    
            # Loop, validate, and append formatted strings to output buffer
            for cand in candidates:
                cand = cand.strip('.')
                if active_pattern.match(cand) and not is_fast_ip(cand):
                    if args.output == "hosts":
                        out_add(f"0.0.0.0 {cand}")
                    elif args.output == "adblock":
                        if args.allow:
                            out_add(f"@@||{cand}^")
                        else:
                            out_add(f"||{cand}^")
                    else:
                        out_add(cand)
                
    # Bulk write to STDOUT bypassing Python's slow stream I/O per loop
    if out_buffer:
        sys.stdout.write('\n'.join(out_buffer) + '\n')
        
if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        sys.stderr.close()
        sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(0)


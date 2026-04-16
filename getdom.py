#!/usr/bin/env python3
'''
==========================================================================
 Filename: getdom.py
 Version: 0.16
 Date: 2026-04-16 15:00 CEST
 Description: Greps DNS domains from various input syntaxes (Plain, Adblock,
              HOSTS, and URLs). Discards empty lines, comments, and non-domain 
              text. Supports customizable output formats.
 
 Changes/Fixes:
 - v0.16 (2026-04-16): Added $TTL and fake SOA record to RPZ header.
 - v0.15 (2026-04-16): Updated RPZ output to include wildcard subdomains.
 - v0.14 (2026-04-16): Added dnsmasq, unbound, and rpz output formats.
==========================================================================
'''

import sys
import re
import argparse
import ipaddress

# Standard regex for domains, requires at least a 2-char TLD.
STRICT_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,}$')
# Less strict regex allowing underscores and asterisks (wildcards/SRV).
LESS_STRICT_PATTERN = re.compile(r'^([a-z0-9_*]([a-z0-9\-_*]{0,61}[a-z0-9_*])?\.)+[a-z0-9\-_*]{2,}$')

def is_fast_ip(token):
    """
    Heuristic check to validate IP addresses rapidly. Prevents numerical
    noise from accidentally passing through domain regex evaluations.
    """
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
    parser = argparse.ArgumentParser(description="Grep DNS domains from text inputs.")
    parser.add_argument("-l", "--less-strict", action="store_true", help="Allow underscores (_) and asterisks (*) in domain names")
    parser.add_argument("-a", "--allow", action="store_true", help="Grep only 'allowed' domains (rules starting with @@ or $denyallow exceptions)")
    parser.add_argument("-o", "--output", choices=["plain", "adblock", "hosts", "dnsmasq", "unbound", "rpz"], default="plain", help="Output format")
    args = parser.parse_args()
    
    active_pattern = LESS_STRICT_PATTERN if args.less_strict else STRICT_PATTERN

    if args.output == "rpz":
        sys.stdout.write("$TTL 3600\n@ IN SOA localhost. root.localhost. 1 3600 900 2592000 300\n")
    
    try:
        for line in sys.stdin:
            # Strip trailing inline comments and whitespace
            line = line.split('#')[0].strip()
            
            # Skip empty lines or pure Adblock full-line comments
            if not line or line.startswith('!'):
                continue
            
            # Tokenize by whitespace to natively support multiple domains in HOSTS files
            for token in line.split():
                token = token.lower()
                
                # Skip HOSTS file routing IP addresses
                if is_fast_ip(token):
                    continue
                    
                # Extract pure hostname from URL feeds, stripping paths and ports
                if '://' in token:
                    token = token.split('://', 1)[1].split('/')[0].split(':')[0]
                    
                # Evaluate Adblock exception syntax (@@)
                is_allow = False
                if token.startswith('@@'):
                    is_allow = True
                    token = token[2:]
                    
                # Strip core Adblock blocking markers
                if token.startswith('||'):
                    token = token[2:]
                    
                # Process advanced Adblock modifiers and isolate the domain
                denyallow_domains = []
                if '$' in token:
                    parts = token.split('$', 1)
                    token = parts[0]
                    modifiers = parts[1]
                    for mod in modifiers.split(','):
                        if mod.startswith('denyallow='):
                            denyallow_domains.extend(mod[10:].split('|'))
                            
                # Strip Adblock trailing anchors and cleanup dots
                if token.endswith('^'):
                    token = token[:-1]
                token = token.strip('.')
                
                # Route domains based on the active grepping mode (-a)
                candidates = []
                if args.allow:
                    # If hunting allows: grab main domains of @@ rules, and denyallows of block rules
                    if is_allow and token:
                        candidates.append(token)
                    if not is_allow and denyallow_domains:
                        candidates.extend(denyallow_domains)
                else:
                    # If hunting blocks: grab main domains of block rules, and denyallows of @@ rules
                    if not is_allow and token:
                        candidates.append(token)
                    if is_allow and denyallow_domains:
                        candidates.extend(denyallow_domains)
                        
                # Validate and format the output based on requested configuration
                for cand in candidates:
                    cand = cand.strip('.')
                    if active_pattern.match(cand) and not is_fast_ip(cand):
                        if args.output == "hosts":
                            sys.stdout.write(f"0.0.0.0 {cand}\n")
                        elif args.output == "dnsmasq":
                            if args.allow: sys.stdout.write(f"server=/{cand}/#\n")
                            else: sys.stdout.write(f"address=/{cand}/0.0.0.0\n")
                        elif args.output == "unbound":
                            if args.allow: sys.stdout.write(f"local-zone: \"{cand}\" transparent\n")
                            else: sys.stdout.write(f"local-zone: \"{cand}\" always_nxdomain\n")
                        elif args.output == "rpz":
                            if args.allow: 
                                sys.stdout.write(f"{cand} CNAME rpz-passthru.\n*.{cand} CNAME rpz-passthru.\n")
                            else: 
                                sys.stdout.write(f"{cand} CNAME .\n*.{cand} CNAME .\n")
                        elif args.output == "adblock":
                            if args.allow: sys.stdout.write(f"@@||{cand}^\n")
                            else: sys.stdout.write(f"||{cand}^\n")
                        else:
                            sys.stdout.write(f"{cand}\n")
                        
    except KeyboardInterrupt:
        sys.exit(0)

if __name__ == '__main__':
    main()
    sys.exit(0)


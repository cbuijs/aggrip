#!/usr/bin/env python3
'''
==========================================================================
 Filename: categorize.py
 Version: 0.22
 Date: 2026-04-16 20:00 CEST
 Description: Categorizes a mixed input of IPs, CIDRs, and Domains into 
              highly specific logical sections based on advanced RFCs.
              Strictly discards garbage text. Supports sectioned output
              or inline comments via the -i/--inline parameter.
 
 Changes/Fixes:
 - v0.22 (2026-04-16): Added first-label heuristic regex for Ads & Trackers.
 - v0.21 (2026-04-16): Mapped pure ccTLDs to explicit Country Names. 
 - v0.20 (2026-04-16): Added reverse DNS (.arpa) translation to IP/CIDR.
 - v0.19 (2026-04-16): Added IPv6 RFC definitions and Web3 domains.
 - v0.18 (2026-04-16): Added detections for 224.0.0.0/4 and 240.0.0.0/4.
 - v0.17 (2026-04-16): Added -i/--inline parameter for unified flat sorting.
 - v0.16 (2026-04-16): Added alphabetical and IP-aware sorting per section.
 - v0.15 (2026-04-16): Restored 'Unknown' section for unidentified targets.
 - v0.14 (2026-04-16): Strictly drops garbage text.
 - v0.13 (2026-04-16): Added extensive RFC support, WPAD, and BOGON mapping.
==========================================================================
'''

import sys
import re
import argparse
import ipaddress
from collections import defaultdict

# --- Regex & Static Data Lookups ---
DOMAIN_PATTERN = re.compile(r'^([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,}$|^wpad$', re.IGNORECASE)
ADS_PATTERN = re.compile(r'^(a(d|dim(age|g)|dser(v|ve[r]*|vice)|dmob|dword|dsrv|d(v|vert))|banner)[sz]*[0-9]*$')
TRACKERS_PATTERN = re.compile(r'^(analytic|colle(c|ctor)|log|matomo|[sz]*metric|piwik|pixel|sentry|sta(t|tistic)|telemetry|trac(k|king|ker))[sz]*[0-9]*$')

CLASSIC_GTLDS = {'com', 'net', 'org', 'info', 'biz', 'name', 'pro'}
SPONSORED_TLDS = {'edu', 'gov', 'mil', 'aero', 'asia', 'cat', 'coop', 'int', 'jobs', 'mobi', 'museum', 'post', 'travel', 'xxx'}
TEST_TLDS = {'test', 'example', 'invalid', 'localhost'} 
INFRA_TLDS = {'arpa'}
PRIVATE_TLDS = {'lan', 'home', 'corp', 'internal', 'onion'}
WEB3_TLDS = {'eth', 'crypto', 'nft', 'zil', 'x', 'polygon', 'bitcoin', 'dao', '888', 'wallet', 'sol', 'bnb', 'arb', 'algo'}

CCTLD_MAP = {
    'ac': 'Ascension Island', 'ad': 'Andorra', 'ae': 'United Arab Emirates', 'af': 'Afghanistan', 'ag': 'Antigua and Barbuda',
    'ai': 'Anguilla', 'al': 'Albania', 'am': 'Armenia', 'ao': 'Angola', 'aq': 'Antarctica', 'ar': 'Argentina',
    'as': 'American Samoa', 'at': 'Austria', 'au': 'Australia', 'aw': 'Aruba', 'ax': 'Aland Islands', 'az': 'Azerbaijan',
    'ba': 'Bosnia and Herzegovina', 'bb': 'Barbados', 'bd': 'Bangladesh', 'be': 'Belgium', 'bf': 'Burkina Faso',
    'bg': 'Bulgaria', 'bh': 'Bahrain', 'bi': 'Burundi', 'bj': 'Benin', 'bm': 'Bermuda', 'bn': 'Brunei Darussalam',
    'bo': 'Bolivia', 'br': 'Brazil', 'bs': 'Bahamas', 'bt': 'Bhutan', 'bv': 'Bouvet Island', 'bw': 'Botswana',
    'by': 'Belarus', 'bz': 'Belize', 'ca': 'Canada', 'cc': 'Cocos (Keeling) Islands', 'cd': 'Democratic Republic of the Congo',
    'cf': 'Central African Republic', 'cg': 'Republic of the Congo', 'ch': 'Switzerland', 'ci': 'Cote d\'Ivoire',
    'ck': 'Cook Islands', 'cl': 'Chile', 'cm': 'Cameroon', 'cn': 'China', 'co': 'Colombia', 'cr': 'Costa Rica',
    'cu': 'Cuba', 'cv': 'Cape Verde', 'cw': 'Curacao', 'cx': 'Christmas Island', 'cy': 'Cyprus', 'cz': 'Czech Republic',
    'de': 'Germany', 'dj': 'Djibouti', 'dk': 'Denmark', 'dm': 'Dominica', 'do': 'Dominican Republic', 'dz': 'Algeria',
    'ec': 'Ecuador', 'ee': 'Estonia', 'eg': 'Egypt', 'er': 'Eritrea', 'es': 'Spain', 'et': 'Ethiopia', 'eu': 'European Union',
    'fi': 'Finland', 'fj': 'Fiji', 'fk': 'Falkland Islands', 'fm': 'Micronesia', 'fo': 'Faroe Islands', 'fr': 'France',
    'ga': 'Gabon', 'gb': 'United Kingdom', 'gd': 'Grenada', 'ge': 'Georgia', 'gf': 'French Guiana', 'gg': 'Guernsey',
    'gh': 'Ghana', 'gi': 'Gibraltar', 'gl': 'Greenland', 'gm': 'Gambia', 'gn': 'Guinea', 'gp': 'Guadeloupe',
    'gq': 'Equatorial Guinea', 'gr': 'Greece', 'gs': 'South Georgia / Sandwich Islands', 'gt': 'Guatemala', 'gu': 'Guam',
    'gw': 'Guinea-Bissau', 'gy': 'Guyana', 'hk': 'Hong Kong', 'hm': 'Heard Island and McDonald Islands', 'hn': 'Honduras',
    'hr': 'Croatia', 'ht': 'Haiti', 'hu': 'Hungary', 'id': 'Indonesia', 'ie': 'Ireland', 'il': 'Israel', 'im': 'Isle of Man',
    'in': 'India', 'io': 'British Indian Ocean Territory', 'iq': 'Iraq', 'ir': 'Iran', 'is': 'Iceland', 'it': 'Italy',
    'je': 'Jersey', 'jm': 'Jamaica', 'jo': 'Jordan', 'jp': 'Japan', 'ke': 'Kenya', 'kg': 'Kyrgyzstan', 'kh': 'Cambodia',
    'ki': 'Kiribati', 'km': 'Comoros', 'kn': 'Saint Kitts and Nevis', 'kp': 'North Korea', 'kr': 'South Korea',
    'kw': 'Kuwait', 'ky': 'Cayman Islands', 'kz': 'Kazakhstan', 'la': 'Laos', 'lb': 'Lebanon', 'lc': 'Saint Lucia',
    'li': 'Liechtenstein', 'lk': 'Sri Lanka', 'lr': 'Liberia', 'ls': 'Lesotho', 'lt': 'Lithuania', 'lu': 'Luxembourg',
    'lv': 'Latvia', 'ly': 'Libya', 'ma': 'Morocco', 'mc': 'Monaco', 'md': 'Moldova', 'me': 'Montenegro', 'mg': 'Madagascar',
    'mh': 'Marshall Islands', 'mk': 'North Macedonia', 'ml': 'Mali', 'mm': 'Myanmar', 'mn': 'Mongolia', 'mo': 'Macau',
    'mp': 'Northern Mariana Islands', 'mq': 'Martinique', 'mr': 'Mauritania', 'ms': 'Montserrat', 'mt': 'Malta',
    'mu': 'Mauritius', 'mv': 'Maldives', 'mw': 'Malawi', 'mx': 'Mexico', 'my': 'Malaysia', 'mz': 'Mozambique',
    'na': 'Namibia', 'nc': 'New Caledonia', 'ne': 'Niger', 'nf': 'Norfolk Island', 'ng': 'Nigeria', 'ni': 'Nicaragua',
    'nl': 'Netherlands', 'no': 'Norway', 'np': 'Nepal', 'nr': 'Nauru', 'nu': 'Niue', 'nz': 'New Zealand', 'om': 'Oman',
    'pa': 'Panama', 'pe': 'Peru', 'pf': 'French Polynesia', 'pg': 'Papua New Guinea', 'ph': 'Philippines', 'pk': 'Pakistan',
    'pl': 'Poland', 'pm': 'Saint Pierre and Miquelon', 'pn': 'Pitcairn', 'pr': 'Puerto Rico', 'ps': 'Palestine',
    'pt': 'Portugal', 'pw': 'Palau', 'py': 'Paraguay', 'qa': 'Qatar', 're': 'Reunion', 'ro': 'Romania', 'rs': 'Serbia',
    'ru': 'Russia', 'rw': 'Rwanda', 'sa': 'Saudi Arabia', 'sb': 'Solomon Islands', 'sc': 'Seychelles', 'sd': 'Sudan',
    'se': 'Sweden', 'sg': 'Singapore', 'sh': 'Saint Helena', 'si': 'Slovenia', 'sj': 'Svalbard and Jan Mayen', 'sk': 'Slovakia',
    'sl': 'Sierra Leone', 'sm': 'San Marino', 'sn': 'Senegal', 'so': 'Somalia', 'sr': 'Suriname', 'ss': 'South Sudan',
    'st': 'Sao Tome and Principe', 'su': 'Soviet Union', 'sv': 'El Salvador', 'sx': 'Sint Maarten', 'sy': 'Syria',
    'sz': 'Eswatini', 'tc': 'Turks and Caicos Islands', 'td': 'Chad', 'tf': 'French Southern Territories', 'tg': 'Togo',
    'th': 'Thailand', 'tj': 'Tajikistan', 'tk': 'Tokelau', 'tl': 'Timor-Leste', 'tm': 'Turkmenistan', 'tn': 'Tunisia',
    'to': 'Tonga', 'tr': 'Turkey', 'tt': 'Trinidad and Tobago', 'tv': 'Tuvalu', 'tw': 'Taiwan', 'tz': 'Tanzania',
    'ua': 'Ukraine', 'ug': 'Uganda', 'uk': 'United Kingdom', 'us': 'United States', 'uy': 'Uruguay', 'uz': 'Uzbekistan',
    'va': 'Vatican City', 'vc': 'Saint Vincent and the Grenadines', 've': 'Venezuela', 'vg': 'British Virgin Islands',
    'vi': 'U.S. Virgin Islands', 'vn': 'Vietnam', 'vu': 'Vanuatu', 'wf': 'Wallis and Futuna', 'ws': 'Samoa', 'ye': 'Yemen',
    'yt': 'Mayotte', 'za': 'South Africa', 'zm': 'Zambia', 'zw': 'Zimbabwe'
}

# --- IP Pre-computations for advanced RFCs ---
CGNAT_NET = ipaddress.ip_network('100.64.0.0/10')
DOC_NETS_V4 = (ipaddress.ip_network('192.0.2.0/24'), ipaddress.ip_network('198.51.100.0/24'), ipaddress.ip_network('203.0.113.0/24'))
DOC_NETS_V6 = (ipaddress.ip_network('2001:db8::/32'),)
THIS_NET = ipaddress.ip_network('0.0.0.0/8')
SIX_TO_FOUR = ipaddress.ip_network('192.88.99.0/24')
BM_V4 = ipaddress.ip_network('198.18.0.0/15')
MULTICAST_V4 = ipaddress.ip_network('224.0.0.0/4')
CLASS_E_V4 = ipaddress.ip_network('240.0.0.0/4')
LIMIT_BROADCAST = ipaddress.ip_network('255.255.255.255/32')

# --- Specific IPv6 RFCs ---
ULA_V6 = ipaddress.ip_network('fc00::/7')
LL_V6 = ipaddress.ip_network('fe80::/10')
LL_MC_V6 = ipaddress.ip_network('ff02::/16')

def parse_network(token):
    token_lower = token.lower()
    if token_lower.endswith('.in-addr.arpa'):
        base = token_lower[:-13].strip('.')
        if not base: raise ValueError
        parts = base.split('.')
        if len(parts) > 4 or not all(p.isdigit() for p in parts): raise ValueError
        parts.reverse()
        prefix = len(parts) * 8
        parts.extend(['0'] * (4 - len(parts)))
        net_str = f"{'.'.join(parts)}/{prefix}" if prefix < 32 else '.'.join(parts)
        return ipaddress.ip_network(net_str, strict=False)
        
    elif token_lower.endswith('.ip6.arpa'):
        base = token_lower[:-9].strip('.')
        if not base: raise ValueError
        parts = base.split('.')
        if len(parts) > 32 or not all(c in '0123456789abcdef' for c in parts): raise ValueError
        parts.reverse()
        prefix = len(parts) * 4
        hex_str = ''.join(parts).ljust(32, '0')
        groups = [hex_str[i:i+4] for i in range(0, 32, 4)]
        net_str = f"{':'.join(groups)}/{prefix}" if prefix < 128 else ':'.join(groups)
        return ipaddress.ip_network(net_str, strict=False)
        
    return ipaddress.ip_network(token, strict=False)

def categorize_ip(net):
    if net.version == 4:
        if net.subnet_of(CGNAT_NET): return "IP: Carrier-Grade NAT (RFC 6598 / BOGON)"
        if any(net.subnet_of(d) for d in DOC_NETS_V4): return "IP: Documentation (RFC 5737 / BOGON)"
        if net.subnet_of(THIS_NET): return "IP: 'This' Network (RFC 1122 / RFC 3330 / BOGON)"
        if net.subnet_of(SIX_TO_FOUR): return "IP: 6to4 Relay Anycast (RFC 3068 / RFC 3330)"
        if net.subnet_of(BM_V4): return "IP: Benchmarking (RFC 2544 / BOGON)"
        if net.subnet_of(MULTICAST_V4): return "IP: Multicast Networks (RFC 5771 / BOGON)"
        if net.subnet_of(CLASS_E_V4): return "IP: Reserved / Class E (RFC 3330 / BOGON)"
        if net.subnet_of(LIMIT_BROADCAST): return "IP: Limited Broadcast (RFC 919 / BOGON)"
    else:
        if net.subnet_of(ULA_V6): return "IP: Unique Local Unicast ULA (RFC 4193 / BOGON)"
        if net.subnet_of(LL_V6): return "IP: Link-Local Unicast (RFC 4291 / BOGON)"
        if net.subnet_of(LL_MC_V6): return "IP: Link-Local Multicast (RFC 4291 / BOGON)"
        if any(net.subnet_of(d) for d in DOC_NETS_V6): return "IP: Documentation (RFC 3849 / BOGON)"

    if net.is_loopback: return "IP: Loopback Addresses (RFC 1122 / BOGON)"
    if net.is_private: return "IP: Private / Local Networks (RFC 1918 / RFC 4193 / BOGON)"
    if net.is_link_local: return "IP: Link-Local Addresses (RFC 3927 / BOGON)"
    if net.is_multicast: return "IP: Multicast Networks (RFC 5771 / BOGON)"
    if net.is_reserved or net.is_unspecified: return "IP: Reserved / Unspecified / BOGON"
    
    return "IP: Public / Global Internet Routable"

def categorize_domain(domain):
    first_label = domain.split('.', 1)[0]
    if ADS_PATTERN.match(first_label): return "Domain: Ads / Banners (Heuristic)"
    if TRACKERS_PATTERN.match(first_label): return "Domain: Trackers / Metrics (Heuristic)"

    if domain.startswith("wpad.") or domain == "wpad":
        return "Domain: Web Proxy Auto-Discovery (WPAD)"
        
    if domain.endswith(".in-addr.arpa") or domain.endswith(".ip6.arpa"):
        return "Domain: Reverse DNS Pointers (arpa)"

    if domain.endswith("home.arpa"): return "Domain: Home Network (RFC 8880)"
    if domain.endswith("resolver.arpa"): return "Domain: Discovery of Designated Resolvers (RFC 9462)"
    if domain.endswith("service.arpa"): return "Domain: DNS-SD over Unicast (RFC 9665)"
    if domain.endswith("empty.as112.arpa"): return "Domain: AS112 Redirection (RFC 7535)"
    if domain.endswith("in-addr-servers.arpa") or domain.endswith("ip6-servers.arpa"): 
        return "Domain: Address Registration Nameservers (RFC 5855)"
    if domain in ("id.server", "version.server", "version.bind", "hostname.bind"): 
        return "Domain: Name Server Identity (RFC 4892 / CHAOS)"

    parts = domain.rsplit('.', 2)
    tld = parts[-1].lower()
    
    if len(tld) == 2:
        if len(parts) == 3:
            sld = parts[-2].lower()
            if sld in ('co', 'com', 'tm'): return "Domain: Commercial / General (eTLD/ccTLD)"
            if sld in ('org', 'or'): return "Domain: Organizations / Non-Profits (eTLD/ccTLD)"
            if sld in ('gov', 'go', 'gob', 'gv'): return "Domain: Government (eTLD/ccTLD)"
            if sld in ('edu', 'ac', 'ed'): return "Domain: Educational / Academic (eTLD/ccTLD)"
            if sld in ('net', 'ne'): return "Domain: Network Infrastructure (eTLD/ccTLD)"
            if sld in ('mil', 'mi'): return "Domain: Military (eTLD/ccTLD)"
            
        country_name = CCTLD_MAP.get(tld, tld.upper())
        return f"Domain: Country Code - {country_name} (ccTLD)"

    if tld in CLASSIC_GTLDS: return "Domain: Classic Generic (gTLD)"
    if tld in SPONSORED_TLDS: return "Domain: Sponsored (sTLD)"
    if tld in INFRA_TLDS: return "Domain: Infrastructure (arpa/int)"
    if tld in TEST_TLDS: return "Domain: Test / Reserved (RFC 2606 / RFC 6761)"
    if tld in WEB3_TLDS: return "Domain: Web3 / Decentralized Crypto"
    if tld == 'local': return "Domain: Multicast DNS (mDNS / RFC 6762)"
    if tld in PRIVATE_TLDS: return "Domain: Private / Internal / Unregistered"
    
    return "Unknown / Undetermined"

def main():
    parser = argparse.ArgumentParser(description="Categorize IPs, CIDRs, and Domains.")
    parser.add_argument("-i", "--inline", action="store_true", help="Output only valid targets with inline comment designations instead of sections")
    args = parser.parse_args()

    categories = defaultdict(list)
    
    try:
        for line in sys.stdin:
            token = line.strip()
            if not token: continue
            
            try:
                net = parse_network(token)
                categories[categorize_ip(net)].append(token)
            except ValueError:
                token_lower = token.lower()
                if DOMAIN_PATTERN.match(token_lower):
                    categories[categorize_domain(token_lower)].append(token)
                    
    except KeyboardInterrupt:
        sys.exit(0)

    if args.inline:
        ip_objs = []
        domain_items = []
        
        for key, items in categories.items():
            if key.startswith("IP:"):
                for item in items:
                    net = parse_network(item)
                    ip_objs.append((net.version, net, item, key))
            else:
                for item in items:
                    domain_items.append((item, key))
        
        ip_objs.sort(key=lambda x: (x[0], x[1]))
        domain_items.sort(key=lambda x: x[0].lower())
        
        for _, _, item, cat in ip_objs:
            sys.stdout.write(f"{item} # {cat}\n")
        for item, cat in domain_items:
            sys.stdout.write(f"{item} # {cat}\n")

    else:
        sorted_keys = sorted([k for k in categories.keys() if k != "Unknown / Undetermined"])
        if "Unknown / Undetermined" in categories:
            sorted_keys.append("Unknown / Undetermined")

        for key in sorted_keys:
            items = categories[key]
            if not items: continue

            if key.startswith("IP:"):
                parsed = [(parse_network(x).version, parse_network(x), x) for x in items]
                parsed.sort(key=lambda x: (x[0], x[1]))
                items = [x[2] for x in parsed]
            else:
                items.sort(key=str.lower)

            sys.stdout.write(f"# --- {key} ---\n")
            for item in items:
                sys.stdout.write(f"{item}\n")
            sys.stdout.write("\n")

if __name__ == '__main__':
    main()
    sys.exit(0)


# Aggrip  - IP, CIDR and DNS Domain Utilities

A collection of highly optimized Python 3 command-line utilities for processing, aggregating, and sorting IP addresses, CIDR networks, and DNS domain lists. These tools are designed for high-performance pipeline operations in Unix-like environments.

NOTE: Check out [aggrip-go](https://github.com/cbuijs/aggrip-go), the GO version of it that proabbaly will surpase these scripts.

---

## INTRO

I spent years as a networking and security consultant, eating "data" and "migrations" for breakfast. Funny enough, that madness bled right into my personal life as "hobby". Being a proper Dutch nerd, tinkering with "DNS" is genuinely what I do on a lazy Sunday afternoon... yes, really!

To keep my sanity intact with all the weird edge-cases I found at work, I built these scripts to support my home-lab (and let's be honest, they still save my ass at work too). The result is this highly optimized toolkit to grep, categorize, aggregate, and sort IPs, CIDRs, and domains. 

Just `cat` some messy data through it, chain them in your Unix pipelines, and have fun playing around. And remember... it is *always* DNS! (and anything TCP/IP of course).

---

## Detailed Manuals

For deep-dive instructions, logic explanations, and comprehensive format coverage, refer to the included manuals:
* **[clean-ip-manual.md](clean-ip-manual.md)** - Comprehensive documentation for IP/CIDR blocklist cross-referencing, punch-holing, and exporting.
* **[clean-dom-manual.md](clean-dom-manual.md)** - Comprehensive documentation for DNS blocklist cross-referencing, modifier routing, Top-N filtering, and exporting.

---

## Tool Overview

### Categorization & Analysis Tools

* **`categorize.py`**
  Categorizes a mixed input stream of IPs, CIDRs, and Domains into highly specific logical sections. 

* **`categorize2.py`**
  Performs the exact same deep categorization, RFC mapping, and heuristic scanning as `categorize.py`, but utilizes high-speed bulk memory reads.

### IP Address & CIDR Tools

* **`aggrip.py`**
  Aggregates a raw list of IP addresses and CIDR blocks into a merged, optimized CIDR list. Uses the `netaddr` library.

* **`aggrip2.py`**
  Performs the same aggregation as `aggrip.py` but uses Python's built-in `ipaddress` module. 

* **`aggrip-asn.py`**
  Aggregates IPs into CIDR lists based on a composite identifier. 

* **`aggrip-asn2.py`**
  Performs the exact same composite identifier aggregation as `aggrip-asn.py`, but utilizes high-speed bulk memory reads.

* **`clean-ip.py`**
  A comprehensive, enterprise-grade optimization script for IP blocklists. It cross-references blocklists against allowlists, seamlessly aggregates overlapping subnets, mathematically punches holes for IP exceptions, optimizes allowlists on the fly, and exports to firewall-ready formats. **Supports CIDR, Range, Netmask, Cisco ACL, iptables, MikroTik, and padded notation.** Automatically processes mixed delimiters for IP-Ranges on input (e.g. `IP-IP`, `IP - IP`, or `IP IP`).

* **`clean-ip2.py`**
  Performs the exact same IP optimization, cross-referencing, and formatting as `clean-ip.py`, but utilizes high-speed bulk memory reads and string buffering to maximize throughput on massive datasets.

* **`getip.py`**
  A powerful extraction tool that acts as an IP-aware `grep`.

* **`getip2.py`**
  Performs the exact same extraction, consolidation, and formatting as `getip.py` using bulk memory buffers.

* **`ipsort.py`**
  Segmented layout-preserving IP-aware sort logic.

* **`ipsort2.py`**
  Performs segmented IP sorts utilizing high-speed bulk memory arrays.

* **`range2cidr.py`**
  Converts and aggregates IP-Range syntax into standard CIDR notation.

* **`range2cidr2.py`**
  Bulk converting IP-Range to CIDR notation.

* **`revip.py`**
  Converts a list of IP addresses or CIDRs into their corresponding reverse DNS lookup names.

* **`revip2.py`**
  Bulk memory reverse lookup pointer generator.

### DNS Domain Tools

* **`clean-dom.py`**
  A comprehensive, enterprise-grade optimization script for DNS blocklists. It ingests massive lists, cross-references against allowlists, safely deduplicates redundant subdomains using O(N log N) depth-sorting, optimizes allowlists on the fly, dynamically routes Adblock modifiers like `$denyallow`, handles Unicode/Punycode conversions, and exports optimized results. **Supports Domain, HOSTS, Adblock, DNSMasq, Unbound, RPZ, RouteDNS, and Squid formats.** Can output all formats simultaneously and process Top-N filtered lists.

* **`clean-dom2.py`**
  Performs the exact same DNS optimization, deduplication, and formatting as `clean-dom.py`, but utilizes high-speed bulk memory reads and instant file format heuristics to maximize throughput on massive datasets.

* **`domsort.py`**
  Segmented layout-preserving domain sort.

* **`domsort2.py`**
  Bulk-memory segmented domain sort.

* **`getdom.py`**
  A powerful extraction tool acting as a domain-aware `grep`.

* **`getdom2.py`**
  Bulk domain extractions.

* **`undup.py`**
  Deduplicates a DNS domain list by removing unnecessary subdomains if the parent exists.

* **`undup2.py`**
  Bulk domain deduplicator.

---

## Usage Instructions

### Pipeline Examples:

    cat raw_ips.txt | ./aggrip.py > optimized_cidrs.txt
    cat ranges.txt | ./range2cidr.py | ./aggrip.py
    cat mixed_sources.txt | ./getdom2.py -l | ./undup2.py -l | ./domsort2.py > clean_domains.txt
    cat messy_adblock.txt | ./getdom2.py -a -o adblock > clean_allowlist.txt
    cat mixed_ips_and_comments.txt | ./ipsort.py -r > nicely_sorted_sections.txt

### For `clean-ip.py` and `clean-ip2.py`:

    ./clean-ip.py --blocklist ips.txt bad_ranges.txt \
                  [--allowlist whitelist.txt] \
                  [-o {cidr,netmask,range,cisco,iptables,mikrotik,padded}] \
                  [--range-sep {dash,space}] \
                  [--out-blocklist out_bl.txt] \
                  [--out-allowlist out_al.txt] \
                  [--optimize-allowlist] \
                  [--suppress-comments] \
                  [-s | --strict] \
                  [-v | --verbose]

*Use the `--range-sep` parameter when compiling ranges to dictate output format spacings (IP-IP or IP IP).*
*Use the `-v` or `--verbose` flag to print loading progress, processing stages, and a final deduplication statistics summary to STDERR.*
*See [clean-ip-manual.md](clean-ip-manual.md) for more details.*

### For `clean-dom.py` and `clean-dom2.py`:

    ./clean-dom.py --blocklist ads.txt tracking.txt \
                   [--allowlist whitelist.txt] \
                   [--topnlist top-1m.csv] \
                   [-i {domain,hosts,adblock,routedns,squid}] \
                   [-o {all,domain,hosts,adblock,dnsmasq,unbound,rpz,routedns,squid}] \
                   [--all-dir /path/to/exports/] \
                   [--sort {domain,alphabetically,tld}] \
                   [--out-blocklist out_bl.txt] \
                   [--out-allowlist out_al.txt] \
                   [--optimize-allowlist] \
                   [--suppress-comments] \
                   [-v | --verbose]

*Use the `-o all` parameter combined with `--all-dir` to dynamically generate all supported output formats in a single pass.*
*Use the `-v` or `--verbose` flag to print loading progress, processing stages, and a final statistics summary to STDERR.*
*See [clean-dom-manual.md](clean-dom-manual.md) for more details.*

---

## Dependencies & Installation

Some tools (`aggrip.py`, `aggrip-asn.py`) require the external `netaddr` library.
To install or upgrade the required dependencies, run:

    pip install -r requirements.txt


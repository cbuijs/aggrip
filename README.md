# Aggrip  - IP, CIDR and DNS Domain Utilities

A collection of highly optimized Python 3 command-line utilities for processing, aggregating, and sorting IP addresses, CIDR networks, and DNS domain lists. These tools are designed for high-performance pipeline operations in Unix-like environments.

---

## INTRO

I spent years as a networking and security consultant, eating "data" and "migrations" for breakfast. Funny enough, that madness bled right into my personal life as "hobby". Being a proper Dutch nerd, tinkering with "DNS" is genuinely what I do on a lazy Sunday afternoon... yes, really!

To keep my sanity intact with all the weird edge-cases I found at work, I built these scripts to support my home-lab (and let's be honest, they still save my ass at work too). The result is this highly optimized toolkit to grep, categorize, aggregate, and sort IPs, CIDRs, and domains. 

Just `cat` some messy data through it, chain them in your Unix pipelines, and have fun playing around. And remember... it is *always* DNS!

---

## Tool Overview

### Categorization & Analysis Tools

* **`categorize.py`**
  Categorizes a mixed input stream of IPs, CIDRs, and Domains into highly specific logical sections. 
  * **IPs/CIDRs:** Supports advanced RFC definitions (e.g., Carrier-Grade NAT, Multicast, Link-Local, Class E), Special-Use IP addresses, and standard BOGON mapping. Natively decodes reverse-DNS (`.arpa`) pointers back into their true IP representations for accurate routing.
  * **Domains:** Supports exact Special-Use Domain RFCs, ccTLD country mapping, eTLD heuristics, Web3/crypto domains, and WPAD detection.
  * **Heuristics:** Features fast-path regex detection for Ad and Tracker subdomains based on first-label analysis.
  * **Formatting:** Strictly discards invalid garbage text. By default, outputs beautifully grouped and alphabetically/IP-sorted document sections. Supports an `-i` / `--inline` flag to flatten the output and append the specific RFC/Category designation as an inline comment instead.

* **`categorize2.py`**
  Performs the exact same deep categorization, RFC mapping, and heuristic scanning as `categorize.py`, but utilizes high-speed bulk memory reads, fast-path text skipping, and unified output buffering to maximize throughput on massive datasets. 
  *Note: Significantly faster execution but requires more memory.*

### IP Address & CIDR Tools

* **`aggrip.py`**
  Aggregates a raw list of IP addresses and CIDR blocks into a merged, optimized CIDR list. Uses the `netaddr` library.

* **`aggrip2.py`**
  Performs the same aggregation as `aggrip.py` but uses Python's built-in `ipaddress` module. 
  *Note: This version is significantly faster but consumes more memory.*

* **`aggrip-asn.py`**
  Aggregates IPs into CIDR lists based on a composite identifier. It reads tab-separated input (`CIDR \t ID \t Name`), sorts by ID/Name, groups them, and merges the CIDRs without losing the identifying metadata.

* **`aggrip-asn2.py`**
  Performs the exact same composite identifier aggregation as `aggrip-asn.py`, but utilizes high-speed bulk memory reads, pre-computed integer metadata sorting, and tuple mapping to execute significantly faster. 
  *Note: Faster execution but requires more memory.*

* **`getip.py`**
  A powerful extraction tool that acts as an IP-aware `grep`. It reads input and explicitly targets valid IP Addresses, IP-Ranges (both space and dash-separated), and CIDRs while automatically discarding garbage text. Invalid CIDR host bits are auto-truncated by default, but can be strictly rejected by using the `-s` / `--strict` parameter. Defaults to strictly validating the beginning of a line, but supports an "anywhere" (`-a` / `--anywhere`) deep-scan parameter. Outputs a strictly consolidated, deduplicated, and IP-sorted list of native CIDRs.

* **`getip2.py`**
  Performs the exact same extraction, consolidation, and formatting as `getip.py` (including the `-s` / `--strict` capabilities), but utilizes high-speed bulk line reads, bulk string buffers, and fast-character heuristic skipping to dramatically speed up deep scans over large texts.
  *Note: Faster execution but requires more memory.*

* **`ipsort.py`**
  Reads STDIN, identifies logical document sections based on non-IP text (such as comments, headers, or blank lines), and performs a strict IP-aware sort (IPv4 first, then IPv6) *within* those sections. Perfectly preserves the original document layout and section comments. Optionally supports CIDR aggregation within the preserved sections using the `-a` / `--aggregate` flag, and descending sorting using the `-r` / `--reverse` flag.

* **`ipsort2.py`**
  Performs the exact same segmented layout-preserving IP sort, optional aggregation (`-a` / `--aggregate`), and reverse sorting (`-r` / `--reverse`) as `ipsort.py`, but utilizes high-speed bulk memory reads, heuristic text skipping, and segmented array sorting. 
  *Note: Faster execution but requires more memory.*

* **`range2cidr.py`**
  Converts and aggregates IP-Range syntax (e.g., `192.168.1.0-192.168.1.255`) into standard CIDR notation. Supports both space and dash delimiters. See also **`getip.py`** for a more versatile version.

* **`range2cidr2.py`**
  Performs the same IP-Range syntax conversion as `range2cidr.py`, but utilizes bulk text ingestion and bulk output buffering. 
  *Note: Faster execution but requires more memory.*

* **`revip.py`**
  Converts a list of IP addresses or CIDRs into their corresponding reverse DNS lookup names (`in-addr.arpa` for IPv4, and `ip6.arpa` for IPv6).

* **`revip2.py`**
  Performs the same reverse DNS lookup name generation as `revip.py`, but uses bulk memory chunking and optimized string slicing to dramatically reduce processing time on large datasets.
  *Note: Faster execution but requires more memory.*

### DNS Domain Tools

* **`clean-dom.py`**
  A comprehensive optimization script for DNS blocklists. It cross-references one or more blocklists against optional allowlists and Top-N lists, while simultaneously deduplicating subdomains across all provided files.
  
  **Advanced parsing and routing features:**
  * Accepts both local file paths and remote URLs (`http://` or `https://`).
  * Supports standard plain domain lists, HOSTS file syntax, and Adblock syntax.
  * Dynamically routes inline Adblock allowlist rules (`@@||domain.com^`) found inside blocklist files directly to the allowlist.
  * Fully parses and enforces Adblock `$denyallow` modifiers as strict exceptions to both block and allowlist rules.
  * Automatically normalizes inputs by lowercasing, trimming leading/trailing dots, and removing prefix wildcards (`*.domain.com` -> `domain.com`).
  * Optionally drops unused allowlist entries (`--optimize-allowlist`) to ensure exported allowlists are strictly utilized. 
  * Outputs dynamically to Plain Domain, HOSTS, or standard Adblock format.
  * Supports writing directly to dedicated blocklist and allowlist files.
  
  *(Note: This is the only tool that takes mandatory standard command-line arguments instead of just processing input from STDIN. It supports passing multiple files per argument. See [clean-dom-manual.md](https://github.com/cbuijs/aggrip/blob/master/clean-dom-manual.md) for advanced usage).*

* **`clean-dom2.py`**
  Performs the exact same DNS optimization, routing, and deduplication as `clean-dom.py`, but utilizes high-speed bulk memory reads and a reverse-string `O(N log N)` sorting algorithm.
  *Note: Significantly faster execution for massive blocklists, but consumes more RAM. Identical command-line arguments.*

* **`domsort.py`**
  Reads STDIN, identifies logical document sections based on non-domain text (such as comments or blank lines), and strictly validates and sorts domains from the root level down (tree-wise/TLD-first) *within* those sections. Perfectly preserves the original document layout. Supports a `-l` / `--less-strict` flag to permit underscores (`_`) and asterisks (`*`) in domains (e.g., wildcards or SRV records) without disrupting the alphabetical sort order. Additionally supports standard A-Z sorting via the `-a` / `--alphabetical` flag and descending sort order via the `-r` / `--reverse` flag.

* **`domsort2.py`**
  Performs the exact same segmented layout-preserving domain sort and optional parameter support (`-l` / `--less-strict`, `-a` / `--alphabetical`, `-r` / `--reverse`) as `domsort.py`, but utilizes high-speed bulk memory reads, fast-path text skipping, and segmented array sorting. 
  *Note: Faster execution but requires more memory.*

* **`getdom.py`**
  A powerful extraction tool that acts as a domain-aware `grep`. It reads text from standard input (plain lists, HOSTS formats, Adblock feeds, or URLs) and extracts valid DNS domains while discarding garbage text, IP addresses, and comments. Supports a `-a` / `--allow` flag to exclusively extract adblock/adguard "allowlisted" domains (e.g., rules starting with `@@` or isolated exceptions within `$denyallow` modifiers). Also supports a `-l` / `--less-strict` flag to permit underscores (`_`) and asterisks (`*`) for extracting wildcards or SRV records. Using the `-o` / `--output` parameter, the extracted domains can be formatted on the fly as `plain` (default), `adblock` (dynamically outputs `||domain^` or `@@||domain^` based on the `-a` flag), or `hosts` (prepends `0.0.0.0`). 

* **`getdom2.py`**
  Performs the exact same domain extraction, syntax routing, and customizable output formatting (`-o`) as `getdom.py`, but utilizes high-speed bulk memory ingestion and unified output buffering to dramatically speed up scanning across large datasets.
  *Note: Faster execution but requires more memory.*

* **`undup.py`**
  Deduplicates a DNS domain list by removing unnecessary subdomains if the parent domain already exists in the list (e.g., removes `sub.example.com` if `example.com` is present). Supports a `-l` / `--less-strict` flag to allow underscores (`_`) and asterisks (`*`) when deduplicating wildcards and SRV records.

* **`undup2.py`**
  Performs the same deduplication and optional less-strict validation (`-l` / `--less-strict`) as `undup.py`, but reads and filters data in raw binary/byte blocks. 
  *Note: Faster execution but requires more memory.*

---

## Usage Instructions

With the exception of `clean-dom.py`, these tools do NOT need mandatory command-line file parameters. They are designed to be chained together using standard input (`STDIN`) and standard output (`STDOUT`) based on common/best practices.

**NOTE:** You can fire up any of the scripts with `-h` or `--help` to get detailed information on available command-line parameters.

### Pipeline Examples:

    cat raw_ips.txt | ./aggrip.py > optimized_cidrs.txt
    cat ranges.txt | ./range2cidr.py | ./aggrip.py
    cat mixed_sources.txt | ./getdom2.py -l | ./undup2.py -l | ./domsort2.py > clean_domains.txt
    cat messy_adblock.txt | ./getdom2.py -a -o adblock > clean_allowlist.txt
    cat mixed_ips_and_comments.txt | ./ipsort.py -r > nicely_sorted_sections.txt
    cat messy_sections.txt | ./ipsort2.py -a > aggregated_sections.txt
    cat wildcard_zones.txt | ./domsort2.py -l -a -r > clean_zones.txt
    cat messy_dump_of_everything.log | ./categorize2.py -i > flagged_inventory.txt
    cat ips.list | ./ipsort.py -a | ./revip.py | ./categorize.py > neat_categorized_rev_ips.txt

### For `clean-dom.py`:

    ./clean-dom.py --blocklist bl1.txt https://example.com/bl2.txt \
                   [--allowlist al1.txt] \
                   [--topnlist top1.txt] \
                   [-o {domain,hosts,adblock}] \
                   [--out-blocklist out_bl.txt] \
                   [--out-allowlist out_al.txt] \
                   [--optimize-allowlist] \
                   [--suppress-comments] \
                   [-v | --verbose]

*Use the `-v` or `--verbose` flag to print loading progress, processing stages, and a final deduplication statistics summary to STDERR.*

---

## Dependencies & Installation

Some tools (`aggrip.py`, `aggrip-asn.py`) require the external `netaddr` library.
To install or upgrade the required dependencies, run:

    pip install -r requirements.txt


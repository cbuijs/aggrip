# Aggrip & DNS Domain Utilities

A collection of highly optimized Python 3 command-line utilities for processing, aggregating, and sorting IP addresses, CIDR networks, and DNS domain lists. These tools are designed for high-performance pipeline operations in Unix-like environments.

---

## Tool Overview

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

* **`undup.py`**
  Deduplicates a DNS domain list by removing unnecessary subdomains if the parent domain already exists in the list (e.g., removes `sub.example.com` if `example.com` is present).

* **`undup2.py`**
  Performs the same function as `undup.py` but reads data in raw binary/byte blocks. 
  *Note: Faster execution but requires more memory.*

* **`domsort.py`**
  Strictly validates and sorts a domain list from the root level down (tree-wise/TLD-first). Example: `com` -> `example` -> `sub`.

* **`domsort2.py`**
  Performs the same function as `domsort.py` but utilizes C-level regex filtering and bulk memory reads. 
  *Note: Faster execution but requires more memory.*

---

## Usage Instructions

With the exception of `clean-dom.py`, these tools do NOT need mandatory command-line file parameters. They are designed to be chained together using standard input (`STDIN`) and standard output (`STDOUT`) based on common/best practices.

### Pipeline Examples:

    cat raw_ips.txt | ./aggrip.py > optimized_cidrs.txt
    cat ranges.txt | ./range2cidr.py | ./aggrip.py
    cat domains.txt | ./undup.py | ./domsort.py > clean_domains.txt

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


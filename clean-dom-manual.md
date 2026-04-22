# CLEAN-DOM MANUAL

`clean-dom.py` is a highly efficient, multi-format DNS blocklist optimization and deduplication tool. It is designed to ingest massive blocklists, cross-reference them against allowlists, safely deduplicate redundant subdomains, optimize allowlists on the fly, and export the optimized results into formats compatible with systems like Pi-hole, AdGuard Home, Squid, or unbound.

## Table of Contents
1. [Core Features](#core-features)
2. [Command-Line Arguments](#command-line-arguments)
3. [Understanding the Logic](#understanding-the-logic)
4. [Usage Examples](#usage-examples)

---

## Core Features

* **Multi-Format Ingestion:** Seamlessly reads Plain Domain lists, RouteDNS rules, Squid proxy ACLs, standard HOSTS formats, and Adblock DNS syntaxes simultaneously. Can be strictly locked to a single format using `--input`. Automatically neutralizes leading wildcards (`*.`) or routing markers (`.`) effectively allowing explicit formats to be seamlessly compiled and merged with traditional inputs.
* **Strict Validation:** Automatically drops IPs, CIDR networks, URL paths, and invalid TLDs. Safely ignores Adblock Regex rules (`/regex/`) and explicitly protects Adblock element hiding rules (`##`, `#@#`) from being falsely interpreted as domains.
* **Dynamic Adblock Routing:** Automatically detects Adblock allowlist rules (`@@||`) inside blocklist feeds and routes them dynamically.
* **Strict Exception Handling:** Fully supports the Adblock `$denyallow` modifier, ensuring specific subdomains remain blocked or allowed regardless of their parent domain's status. Drops rules containing non-DNS modifiers (like `$ping` or `$third-party`).
* **Tree-Based Deduplication:** Sorts domains by depth (TLD -> Subdomain) to guarantee that if a parent domain is blocked, all redundant subdomains are stripped out to save memory.
* **Allowlist Optimization:** Optionally strips out allowlisted domains that do not actively match or neutralize any targeted blocklist items, keeping exported exception lists perfectly lean.
* **Multiple Output Formats & Sorting:** Export the final list as domains, HOSTS, Adblock, DNSMasq, Unbound, RPZ, RouteDNS, or Squid. Sort the output tree-wise (TLD-down), naturally alphabetically, or grouped by TLD. The engine guarantees output logs and line comments are glued directly above their relevant domain counterparts regardless of sort type. Supports an `-o all` parameter to auto-generate all formats simultaneously into an `--all-dir` directory. By combining `-o all` with `--topnlist`, the script dynamically triggers a dual-pass evaluation, building both the full variants and the `.top-n` restricted lists simultaneously.
* **Smart File Generation:** Outputs directly to dedicated files. Suppresses output file creation automatically if the final compiled payload is empty. Append `.top-n` naming conventions when Top-N lists are evaluated.
* **Hosts Formatter Logic Bypassing:** For `hosts` outputs, the tool intelligently bypasses subdomain deduplication, keeping all targeted subdomains fully intact since native `hosts` files do not process apex wildcarding or inherent inheritance.

### Performance Note: `clean-dom2.py`
For enterprise-scale blocklists, a memory-optimized alternative (`clean-dom2.py`) is included. It utilizes bulk memory reads and an `O(N log N)` reverse-string sort to instantly process Top-N filtering, Allowlist cross-referencing, and Deduplication in a single pass. Both scripts are functionally identical and share the exact same command-line syntax.

---

## Command-Line Arguments

| Argument | Requirement | Description |
| :--- | :--- | :--- |
| `--blocklist` | **Required** | One or more paths (or URLs) to DNS blocklists. Download/file retrieval errors are logged without stopping the compilation process. |
| `--allowlist` | Optional | One or more paths (or URLs) to DNS allowlists. |
| `--topnlist` | Optional | One or more paths (or URLs) to Top-N domain lists. If provided, *only* domains present in this list will be kept. Outputs are suffixed with `.top-n` automatically. |
| `-i`, `--input` | Optional | Strictly enforce an input format (`domain`, `hosts`, `adblock`, `routedns`, `squid`). Lines not matching this syntax are skipped. |
| `-o`, `--output` | Optional | Output format. Choices: `all`, `domain` (default), `hosts`, `adblock`, `dnsmasq`, `unbound`, `rpz`, `routedns`, `squid`. |
| `--all-dir` | Optional | **Mandatory** if `-o all` is used. Specifies the output directory to write all format files to. |
| `--sort` | Optional | Sorting algorithm. Choices: `domain` (default, TLD-down), `alphabetically` (natural A-Z), `tld` (grouped by TLD). |
| `-w`, `--work`| Optional | Directory path to save unmodified raw source files. Stored as `[SHA256].raw` with metadata headers. |
| `--out-blocklist` | Optional | File path to write the final blocklist to. If omitted, prints to STDOUT. |
| `--out-allowlist` | Optional | File path to write the parsed allowlist to. |
| `--optimize-allowlist` | Optional | Drops unused allowlist entries that do not match or neutralize any actively blocked targets. |
| `--suppress-comments`| Optional | Removes the audit log (lines starting with `#`) explaining why domains were removed. |
| `-v`, `--verbose` | Optional | Prints loading progress, routing events, and a final statistics summary to STDERR. |

---

## Understanding the Logic

### Normalization & Validation
When domains are ingested, `clean-dom.py` cleans and verifies the input:
* **Wildcards:** `*.example.com` becomes `example.com`
* **Dots:** Removes leading/trailing dots.
* **Syntax Checks:** Adblock syntaxes (`||` and `^`) are stripped. HOSTS entries (`0.0.0.0 domain.com`) are reduced to just the domain.
* **Rejection:** It immediately discards any parsed token that evaluates as a valid IPv4/IPv6 address, a CIDR block, an Adblock Regex (`/regex/`), or a URL containing slashes.

### Dynamic Routing & Adblock Modifiers
Because many maintained blocklists include inline exceptions, `clean-dom.py` parses these dynamically:
1. If `--blocklist list.txt` contains `@@||example.com^`, the script will automatically send `example.com` to the Allowlist.
2. If the tool encounters `||example.com^$denyallow=sub.example.com`, it will block `example.com` but generate a strict **Override** allowing `sub.example.com`. 
3. **Strict Modifiers:** If a rule contains a modifier that has nothing to do with DNS resolution (e.g., `||example.com^$ping,third-party`), the entire rule is discarded to prevent blocking infrastructure based on browser-specific tracking functions.

### The Deduplication Phase
To ensure efficiency, all rules are evaluated from the top-down:
1. If `example.com` is allowlisted, `sub.example.com` is safely removed from the blocklist.
2. If `example.com` is blocklisted, `sub.example.com` is removed from the blocklist because blocking the parent inherently blocks the child.

*Note on Flat Outputs (Domain/Adblock):* If an allowlist rule (`sub.example.com`) is protected, but its parent (`example.com`) is blocked, explicit formats will still block the subdomain depending on native implementations. The script will generate a specific warning comment (`# sub.example.com - Allowlisted but blocked by parent domain example.com`) to alert you of this limitation. (This warning is bypassed during native HOSTS output).

---

## Usage Examples

### 1. Basic Optimization
Read two local blocklists, apply an allowlist, and print the deduplicated plain domain list to the screen.
```bash
./clean-dom.py --blocklist ads.txt tracking.txt --allowlist whitelist.txt
```

### 2. Strict Exporting with Allowlist Optimization
Ingest URLs and local lists, explicitly enforce they are parsed as `adblock` format, drop unused exceptions from the allowlist, and output both targets to their own files sorted naturally.
```bash
./clean-dom.py --blocklist ads.txt https://example.com/malware.txt \
               --allowlist whitelist.txt \
               --input adblock \
               --sort alphabetically \
               --optimize-allowlist \
               --out-blocklist final_blocks.txt \
               --out-allowlist final_allows.txt
```

### 3. Caching Raw Files and Outputting RPZ
Download a large Top-N list and blocklist, save the original unparsed feeds to a `/tmp/raw` directory for auditing, and export the deduplicated results as a BIND RPZ zone file.
```bash
./clean-dom.py --blocklist https://example.com/huge-blocklist.txt \
               --topnlist https://example.com/top-1m.csv \
               --work /tmp/raw \
               --output rpz \
               --out-blocklist zone.rpz
```

### 4. Enterprise Generation: Build All Formats Instantly
Download lists, fully optimize the allowlist, and write every supported output format (Domains, HOSTS, Adblock, RPZ, RouteDNS, Squid, Unbound, and DNSMasq) into a central distribution directory. Both Full versions and Top-N filtered versions are dynamically generated across a dual-pass evaluation.
```bash
./clean-dom.py --blocklist https://example.com/huge-blocklist.txt \
               --allowlist whitelist.txt \
               --topnlist top-1m.csv \
               --optimize-allowlist \
               --output all \
               --all-dir /var/www/html/dns-exports/ \
               -v
```


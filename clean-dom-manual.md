# CLEAN-DOM MANUAL

`clean-dom.py` is a highly efficient, multi-format DNS blocklist optimization and deduplication tool. It is designed to ingest massive blocklists, cross-reference them against allowlists, safely deduplicate redundant subdomains, and export the optimized results into formats compatible with systems like Pi-hole, AdGuard Home, or unbound.

## Table of Contents
1. [Core Features](#core-features)
2. [Command-Line Arguments](#command-line-arguments)
3. [Understanding the Logic](#understanding-the-logic)
4. [Usage Examples](#usage-examples)

---

## Core Features

* **Multi-Format Ingestion:** Seamlessly reads Plain Domain lists, standard HOSTS formats, and Adblock DNS syntaxes simultaneously.
* **Dynamic Adblock Routing:** Automatically detects Adblock allowlist rules (`@@||`) inside blocklist feeds and routes them dynamically.
* **Strict Exception Handling:** Fully supports the Adblock `$denyallow` modifier, ensuring specific subdomains remain blocked or allowed regardless of their parent domain's status.
* **Tree-Based Deduplication:** Sorts domains by depth (TLD -> Subdomain) to guarantee that if a parent domain is blocked, all redundant subdomains are stripped out to save memory.
* **Multiple Output Formats:** Export the final, optimized list as plain domains, a valid HOSTS file, or a standard Adblock configuration file.
* **Direct File Exporting:** Natively write the final blocklist and the parsed allowlist into dedicated files, completely bypassing the need for shell redirects (`>`).

### Performance Note: `clean-dom2.py`
For enterprise-scale blocklists, a memory-optimized alternative (`clean-dom2.py`) is included. It utilizes bulk memory reads and an `O(N log N)` reverse-string sort to instantly process Top-N filtering, Allowlist cross-referencing, and Deduplication in a single pass. Both scripts are functionally identical and share the exact same command-line syntax; use `clean-dom2.py` when speed is critical and RAM overhead is not a concern.

---

## Command-Line Arguments

| Argument | Requirement | Description |
| :--- | :--- | :--- |
| `--blocklist` | **Required** | One or more paths (or URLs) to DNS blocklists. |
| `--allowlist` | Optional | One or more paths (or URLs) to DNS allowlists. |
| `--topnlist` | Optional | One or more paths (or URLs) to Top-N domain lists. If provided, *only* domains present in this list will be kept. |
| `-o`, `--output` | Optional | Output format. Choices: `domain` (default), `hosts`, `adblock`. |
| `--out-blocklist` | Optional | File path to write the final blocklist to. If omitted, prints to STDOUT. |
| `--out-allowlist` | Optional | File path to write the parsed allowlist to. |
| `--suppress-comments`| Optional | Removes the audit log (lines starting with `#`) explaining why domains were removed. |
| `-v`, `--verbose` | Optional | Prints loading progress, routing events, and a final statistics summary to STDERR. |

---

## Understanding the Logic

### Normalization
When domains are ingested, `clean-dom.py` strips unnecessary garbage:
* **Wildcards:** `*.example.com` becomes `example.com`
* **Dots:** Removes leading/trailing dots.
* **Syntax:** Adblock syntaxes (`||` and `^`) are stripped. HOSTS entries (`0.0.0.0 domain.com`) are reduced to just the domain.

### Dynamic Routing & `$denyallow`
Because many maintained blocklists include inline exceptions, `clean-dom.py` parses these dynamically:
1. If `--blocklist list.txt` contains `@@||example.com^`, the script will automatically send `example.com` to the Allowlist.
2. If the tool encounters `||example.com^$denyallow=sub.example.com`, it will block `example.com` but generate a strict **Override** allowing `sub.example.com`. 

### The Deduplication Phase
To ensure efficiency, all rules are evaluated from the top-down:
1. If `example.com` is allowlisted, `sub.example.com` is safely removed from the blocklist.
2. If `example.com` is blocklisted, `sub.example.com` is removed from the blocklist because blocking the parent inherently blocks the child.

*Note on Flat Outputs (Domain/HOSTS):* If an allowlist rule (`sub.example.com`) is protected, but its parent (`example.com`) is blocked, Pi-hole and HOSTS files will still block the subdomain. The script will generate a specific warning comment (`# sub.example.com - Allowlisted but blocked by parent domain example.com`) to alert you of this limitation.

---

## Usage Examples

### 1. Basic Optimization
Read two local blocklists, apply an allowlist, and print the deduplicated plain domain list to the screen.
```bash
./clean-dom.py --blocklist ads.txt tracking.txt --allowlist whitelist.txt


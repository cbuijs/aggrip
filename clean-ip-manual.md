# CLEAN-IP MANUAL

`clean-ip.py` (and its memory-optimized bulk-read counterpart `clean-ip2.py`) is an enterprise-grade IP blocklist optimization and aggregation tool. It is designed to ingest massive lists of IP addresses, subnets, and ranges, seamlessly cross-reference them against allowlists, and mathematically collapse and punch holes in routing blocks. Finally, it exports the optimized output directly into firewall-ready configurations.

## Table of Contents
1. [Core Features](#core-features)
2. [Command-Line Arguments](#command-line-arguments)
3. [Understanding the Logic](#understanding-the-logic)
4. [Supported Input & Output Formats](#supported-input--output-formats)
5. [Usage Examples](#usage-examples)

---

## Core Features

* **Multi-Format Ingestion:** Seamlessly reads plain IP addresses, standard CIDR notation (e.g., `192.168.1.0/24`), Netmask notation (e.g., `192.168.1.0/255.255.255.0`), IP-Ranges, **Cisco ACLs**, **iptables rules**, **MikroTik formats**, and **Padded IPs** (e.g., `010.000.000.000`). Automatically tokenizes ranges separated by dashes or spaces (`IP-IP`, `IP - IP`, or `IP IP`) and seamlessly converts Cisco wildcard masks on the fly.
* **Subnet Collapsing:** Automatically merges overlapping subnets and contiguous IP blocks into the most mathematically efficient CIDR supernets, natively supporting both IPv4 and IPv6 simultaneously.
* **Mathematical Hole-Punching:** If an allowlisted subnet falls completely inside a larger blocklisted subnet, the script mathematically fractures the larger blocklist to strictly exclude the allowlisted IP space without losing coverage of the rest of the block.
* **Allowlist Optimization:** Optionally strips out allowlisted entries that do not actively match or fracture any targeted blocklist items, keeping exported exception lists perfectly lean.
* **Multiple Output Formats:** Export the final optimized list as `cidr` (default), `netmask`, `range`, `cisco` (ACL), `iptables`, `mikrotik`, or `padded` (strictly formatted 3-digit octets for predictable string sorting). 
* **Custom Range Formatting:** When exporting to `range`, the `--range-sep` parameter dictates whether the output utilizes a `dash` (e.g., `192.168.1.10-192.168.1.20`) or a `space` separator.
* **Strict Validation:** Automatically truncates invalid host bits from CIDR blocks to save them, but can strictly reject dirty host bits using the `-s` / `--strict` flag.

### Performance Note: `clean-ip2.py`
For enterprise-scale blocklists, a memory-optimized alternative (`clean-ip2.py`) is included. It utilizes bulk memory reads and string buffers to maximize throughput. Both scripts are functionally identical and share the exact same command-line syntax.

---

## Command-Line Arguments

| Argument | Requirement | Description |
| :--- | :--- | :--- |
| `--blocklist` | **Required** | One or more paths (or URLs) to the IP blocklists. |
| `--allowlist` | Optional | One or more paths (or URLs) to the IP allowlists. |
| `-o`, `--output` | Optional | Output format. Choices: `cidr` (default), `netmask`, `range`, `cisco`, `iptables`, `mikrotik`, `padded`. |
| `--range-sep` | Optional | Separator used when exporting to `range` output. Choices: `dash` (default), `space`. |
| `--out-blocklist`| Optional | File path to write the blocklist output to. If omitted, prints to STDOUT. |
| `--out-allowlist`| Optional | File path to write the parsed allowlist to. |
| `--optimize-allowlist` | Optional | Drops unused allowlist entries that do not actively match or neutralize any blocked targets. |
| `--suppress-comments`| Optional | Removes the inline audit log (lines starting with `#`) explaining why IPs were removed or mathematically punched. |
| `-s`, `--strict` | Optional | Reject CIDRs with dirty host bits instead of automatically truncating them to the correct boundary. |
| `-v`, `--verbose`| Optional | Prints loading progress, processing stages, and a final deduplication statistics summary to STDERR. |

---

## Understanding the Logic

### Normalization & Aggregation
When IPs are ingested, `clean-ip.py` normalizes them into standard network objects:
1. `192.168.1.1` and `192.168.1.2` are merged.
2. Contiguous ranges like `10.0.0.0 - 10.0.0.255` are instantly converted to `10.0.0.0/24`.
3. If an input contains `192.168.1.10/24` (a dirty host bit), it auto-truncates it to `192.168.1.0/24` (unless `--strict` is enforced).
4. Cisco wildcard masks (`0.0.0.255`) are mathematically inverted and converted back to CIDR blocks.

### Hole-Punching (Exclusions)
Unlike domain names where blocking a parent inherently blocks the child, IP subnets work via routing calculations.
1. **Total Eclipse:** If `10.0.0.0/24` is blocklisted, but `10.0.0.0/16` is allowlisted, the blocklist rule is entirely removed because it is fully encompassed by the allowlist.
2. **Fracturing:** If `10.0.0.0/23` is blocklisted, but `10.0.0.0/24` is allowlisted, the engine mathematically "punches a hole" in the blocklist, outputting only `10.0.1.0/24` as the remaining blocked space. An inline comment is appended right above the rule to log this fracture.

---

## Supported Input & Output Formats

Both tools dynamically support various string inputs seamlessly without needing explicit format flags during ingestion. Output formats are specified using the `-o` argument.

| Format Type | Input Example | Output Example |
| :--- | :--- | :--- |
| **CIDR** (Default) | `192.168.1.0/24` or `10.0.0.1` | `192.168.1.0/24` |
| **Netmask** | `192.168.1.0/255.255.255.0` | `192.168.1.0/255.255.255.0` |
| **IP-Range** | `10.0.0.1 - 10.0.0.10` <br> `10.0.0.1 10.0.0.10` | `10.0.0.1-10.0.0.10` <br> *(Spacing adjustable via `--range-sep`)* |
| **Cisco ACL** | `deny ip 10.0.0.0 0.0.0.255 any` | `deny ip 10.0.0.0 0.0.0.255 any` <br> *(Outputs `permit` for allowlists)* |
| **iptables** | `-A INPUT -s 10.0.0.0/24 -j DROP` | `-A INPUT -s 10.0.0.0/24 -j DROP` <br> *(Outputs `ACCEPT` for allowlists)* |
| **MikroTik** | `add address=10.0.0.0/24 list=blocklist` | `add address=10.0.0.0/24 list=blocklist` <br> *(Outputs `allowlist` for allowlists)* |
| **Padded IP** | `010.000.000.000/24` | `010.000.000.000/24` |

---

## Usage Examples

### 1. Basic Aggregation & Outputting Netmasks
Read a raw list of IP addresses, aggregate them into efficient subnets, and output them in Netmask notation.
```bash
./clean-ip.py --blocklist raw_ips.txt -o netmask
```

### 2. Strict Exporting with IP-Ranges
Read blocklists and allowlists from URLs, drop unused exceptions from the allowlist, and export them as dash-separated IP ranges (`IP-IP`) without whitespaces.
```bash
./clean-ip.py --blocklist https://example.com/bad_ips.txt \
              --allowlist whitelist.txt \
              -o range \
              --range-sep dash \
              --optimize-allowlist \
              --out-blocklist final_blocks.txt \
              --out-allowlist final_allows.txt \
              -v
```

### 3. Firewall Direct Export
Download a massive drop list, apply local exceptions, and output directly into MikroTik RouterOS syntax.
```bash
./clean-ip.py --blocklist https://example.com/drop.txt \
              --allowlist my_exceptions.txt \
              -o mikrotik \
              --out-blocklist mikrotik_import.rsc
```


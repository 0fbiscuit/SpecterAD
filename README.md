# SpecterAD — In-Memory AD Attack Path Analyzer

> **Version**: 1.0.2 | **Author**: biscuit | **License**: MIT | **Python**: ≥ 3.12

SpecterAD is a CLI tool for analyzing Active Directory attack paths from SharpHound JSON data.
It operates entirely in-memory, requiring no Neo4j or BloodHound GUI.

---

## Installation

```bash
git clone https://github.com/0fbiscuit/SpecterAD.git
cd SpecterAD
python -m pip install -e .
```

### Dependencies

| Package | Version | Purpose |
| --------- | ----------- | ---------- |
| `networkx` | ≥ 3.3 | Graph construction and querying |
| `rich` | ≥ 13.0 | Beautiful console output (tables, trees, panels) |
| `orjson` | ≥ 3.10 | Extremely fast JSON parsing (bulk mode) |
| `ijson` | ≥ 3.2 | Streaming JSON for large files (>200MB) |
| `click` | ≥ 8.1 | CLI framework |
| `pyyaml` | ≥ 6.0 | Read edge weights config |

---

## Usage

### Run SpecterAD

```bash
# Method 1: --data (or -d) flag — used for all commands
specterad --data ./sharphound_data.zip <command>

# Method 2: 'load' command — only displays summary
specterad load ./sharphound_data.zip
```

> **Note**: SpecterAD accepts both `.zip` files and directories containing JSON files.

---

## Commands List

### 1. `load` — Load data and display overview

```bash
specterad load <path_to_zip_or_dir>
```

**Description**: Load SharpHound data, build graph in-memory, display number of nodes/edges/HVTs.

**Sample Output**:

```
[+] Data loaded successfully!
  Nodes: 1234  |  Edges: 5678  |  HVTs: 15  |  Domains: LAB.LOCAL
    > Users: 500
    > Computers: 200
    > Groups: 400
    > Domains: 1
```

---

### 2. `path` — Find attack paths

```bash
# Shortest path (BFS, fewest hops)
specterad -d data.zip path "D.QUAN" "Domain Admins" 

# Quietest path (Dijkstra, lowest detection risk)
specterad -d data.zip path "D.QUAN" "Domain Admins" -w 

# All shortest paths (max 10)
specterad -d data.zip path "D.QUAN" "Domain Admins" --all 

# All shortest paths (max 20)
specterad -d data.zip path "D.QUAN" "Domain Admins" --all --max 20 

# Find paths to ALL Domain Admins groups
specterad -d data.zip path "D.QUAN" --to-da 

# Find paths to ALL High-Value Targets
specterad -d data.zip path "D.QUAN" --to-hvt
```

**Options**:

| Flag | Description |
| ------ | -------- |
| `-w` / `--weighted` | Use Dijkstra (the "quietest" path, minimum detection risk) |
| `--to-da` | Find paths to all Domain Admins groups (SID ending -512) |
| `--to-hvt` | Find paths to all High-Value Targets |
| `--all` | Display all shortest paths (not just 1) |
| `--max N` | Limit the number of paths displayed (default: 10) |

**Weighted path explanation**: Each edge type has 3 risk dimensions:

- `detection_risk`: Probability of being detected (0=silent → 1=noisy)
- `failure_risk`: Probability of failure (0=certain → 1=hard to succeed)
- `complexity`: Technical complexity (0=easy → 1=expert)

Config at: `config/edge_weights.yaml`

---

### 3. `query` — Run security queries

```bash
specterad -d data.zip query <query_name>
```

**List of 22 built-in queries**:

| Query Name | Description |
| ------------ | -------- |
| `kerberoastable` | Users with SPN - vulnerable to Kerberoasting (offline TGS ticket crack) |
| `asreproast` | Users not requiring pre-auth - AS-REP Roasting |
| `unconstrained` | Computers with unconstrained delegation (cache TGT) |
| `constrained` | Accounts with constrained delegation (impersonate to specific services) |
| `s4u2self` | Accounts with TrustedToAuthForDelegation (S4U2Self abuse) |
| `dcsync` | Principals with DCSync rights (GetChanges + GetChangesAll) |
| `da-sessions` | Computers with Domain Admin session (credential dump target) |
| `hvt` | All High-Value Targets |
| `shadow-creds` | Principals that can set AddKeyCredentialLink (shadow credential) |
| `pwd-in-desc` | Users with password in description field |
| `pwd-never-expires` | Users with PasswordNeverExpires flag |
| `pwd-not-required` | Users with PASSWD_NOTREQD flag (can have blank password) |
| `priv-roast` | Users both roastable AND privileged (priority target) |
| `laps` | Computer LAPS status (has/doesn't have LAPS) |
| `gmsa` | Group Managed Service Accounts |
| `smartcard` | Users not requiring smartcard logon |
| `sensitive-not-delegated` | Privileged users missing NOT_DELEGATED flag |
| `domain-trusts` | All domain trust relationships |
| `rbcd-configurable` | Principals that can configure RBCD on computers |
| `all-users` | List all users |
| `all-groups` | List all groups |
| `all-computers` | List all computers |
| `all` | **Run ALL queries above** |

**Examples**:

```bash
# Find users vulnerable to Kerberoasting
specterad query kerberoastable -d data.zip

# Find DCSync principals
specterad query dcsync -d data.zip

# Run all queries
specterad query all -d data.zip
```

---

### 4. `stats` — Detailed statistics

```bash
specterad -d data.zip stats 
```

**Output**: Detailed panel including:

- Total nodes/edges/HVTs
- Nodes by type (User, Computer, Group, Domain, OU, GPO, ...)
- Edges by type (MemberOf, AdminTo, GenericAll, ...)
- Security posture: % Kerberoastable, % AS-REP Roastable, % PwdNeverExpires, % Unconstrained

---

### 5. `inventory` — Inventory analysis

```bash
specterad -d data.zip inventory <type>
```

| Type | Description |
| ------ | -------- |
| `pwd-age` | Password age distribution (buckets: <30d, 30-90d, 90-180d, 180-365d, >365d) |
| `stale` | Stale/inactive accounts (default >90 days no logon) |
| `groups` | Members of privileged groups (DA, EA, SA, Administrators) — direct + nested |
| `structural` | Domains, Domain Controllers, Trusts, OUs |
| `all` | Run all inventory analyses |

**Options**:

| Flag | Description |
|------|--------|
| `--days N` | Day threshold for stale detection (default: 90) |

**Examples**:

```bash
# Check stale accounts >180 days
specterad -d data.zip inventory stale --days 180

# View DA/EA/SA members
specterad -d data.zip inventory groups
```

---

### 6. `dossier` — Detailed report of 1 object

```bash
specterad -d data.zip dossier <identifier>
```

**Identifier** can be:

- Full name: `D.QUAN@LAB.LOCAL`
- Short name: `D.QUAN`
- SID: `S-1-5-21-1234-5678-512`

**Output includes**:

- Properties (enabled, admincount, lastlogon, hasspn, ...)
- Group memberships (direct + nested, by depth)
- Inbound edges (who has what rights over this object)
- Outbound edges (what rights this object has)
- AdminTo hosts (computers where the object is a local admin)
- Paths to HVTs (top 5 attack paths to important targets)

**Examples**:

```bash
specterad -d data.zip dossier ADMINISTRATOR 
specterad -d data.zip dossier "D.QUAN"
specterad -d data.zip dossier S-1-5-21-1234-5678-500
```

---

### 7. `remediate` — Analysis and remediation recommendations

```bash
specterad -d data.zip remediate
specterad -d data.zip remediate --top 20
```

**Description**: Analyze all shortest paths from all Users/Computers to all HVTs, count the occurrence frequency of each edge, rank the "busiest edges" (choke points). Each choke point comes with specific remediation recommendations.

**Options**:

| Flag | Description |
|------|--------|
| `--top N` | Number of choke points to display (default: 10) |

**Sample Output**:

```
  Remediation Analysis
  Paths analyzed: 1500  |  Unique edges: 300

  # | Source     | Edge        | Target        | Paths | Remediation
  1 | IT_ADMINS  | AdminTo     | DC01          | 450   | Remove local admin rights — use LAPS
  2 | D.QUAN     | MemberOf    | IT_ADMINS     | 380   | Review group membership
  3 | HELPDESK   | GenericAll  | HR_USERS      | 250   | Remove GenericAll ACE
```

---

### 8. `export` — Export data

```bash
specterad -d data.zip export <format> -o <output_path>
```

| Format | Description | Output |
| -------- | -------- | -------- |
| `dot` | Graphviz DOT format | `.dot` file — open with Graphviz |
| `csv` | Tabular edge list | `.csv` file — open with Excel |
| `json` | Structured JSON | `.json` file — for automation |
| `csv-pack` | PlumHound-style 12-file pack | Directory containing 12 CSV files |

**Examples**:

```bash
# Export DOT for visualization
specterad -d data.zip export dot -o graph.dot

# Export CSV for Excel/SIEM
specterad -d data.zip export csv -o edges.csv

# Export JSON for automation
specterad -d data.zip export json -o data.json

# Export CSV pack (12 files)
specterad -d data.zip export csv-pack -o ./csv_output
```

**CSV Pack includes 12 files**:

1. `01_domains.csv` — List of domains
2. `02_domain_admins.csv` — DA/EA/SA/Administrators members
3. `03_kerberoastable.csv` — Kerberoastable users
4. `04_asreproastable.csv` — AS-REP Roastable users
5. `05_laps_readers.csv` — LAPS password readers
6. `06_everyone_edges.csv` — Everyone/Authenticated Users edges
7. `07_overpriv_edges.csv` — GenericAll/WriteDacl/WriteOwner edges
8. `08_computer_admin_to_computer.csv` — Computer-to-Computer admin
9. `09_dual_priv_local_admin.csv` — DA members with AdminTo
10. `10_bulk_admin_to_hosts.csv` — All AdminTo relationships
11. `11_unconstrained.csv` — Unconstrained delegation computers
12. `12_dcsync.csv` — DCSync principals

---

## Global Options

| Flag | Description |
| ------ | -------- |
| `--data` / `-d` | Path to SharpHound ZIP or JSON directory |
| `--verbose` / `-v` | Enable verbose logging (DEBUG level) |
| `--version` | Show version |
| `--help` | Show help |

---

## Specific Use Cases

### Scenario 1: Quick audit of the entire AD environment

```bash
# Load + display overview
specterad load ./data.zip

# Run all security queries
specterad -d data.zip query all

# Run all inventory analyses
specterad -d data.zip inventory all

# Export csv-pack for reporting
specterad -d data.zip export csv-pack -o ./audit_results
```

### Scenario 2: Specific user risk assessment

```bash
# View user details
specterad -d data.zip dossier "JOHN.DOE" 

# Find attack paths from user to DA
specterad -d data.zip path "JOHN.DOE" --to-da 

# Find the "quietest" attack path
specterad -d data.zip path "JOHN.DOE" "Domain Admins" -w 
```

### Scenario 3: Find quick wins for remediation

```bash
# Top 20 choke points
specterad -d data.zip remediate --top 20 

# Kerberoastable privileged users (highest priority)
specterad -d data.zip query priv-roast 

# Privileged users missing NOT_DELEGATED
specterad -d data.zip query sensitive-not-delegated 
```

### Scenario 4: Analyze delegation risks

```bash
specterad -d data.zip query unconstrained 
specterad -d data.zip query constrained 
specterad -d data.zip query s4u2self 
specterad -d data.zip query rbcd-configurable 
```

### Scenario 5: Visualization with Graphviz

```bash
# Export DOT
specterad -d data.zip export dot -o graph.dot 

# Render to PNG (requires Graphviz)
dot -Tpng graph.dot -o graph.png

# Or render to SVG (interactive)
dot -Tsvg graph.dot -o graph.svg
```

---

## Important Notes

1. **SharpHound version**: SpecterAD supports SharpHound v2+ JSON format (with `meta.type` and `data` array).
2. **Large files**: Files >200MB automatically switch to streaming parser (ijson) to save RAM.
3. **Azure/Entra ID**: Azure module is currently a skeleton - needs AzureHound data for full testing.
4. **Windows console**: Output uses ASCII-safe characters (`safe_box=True`) for Windows cp1252 compatibility.
5. **Edge weights**: Can be customized in `config/edge_weights.yaml` - lower weight = more attractive path.

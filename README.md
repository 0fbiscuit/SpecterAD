# SpecterAD
**In-Memory Active Directory Attack Path Analyzer**
*Developed by biscuit*

---

**SpecterAD** is my take on a lightweight, terminal-first alternative. It’s an AD pathfinding engine built for speed and stealth. No database configuration. No heavy dependencies. You feed it SharpHound data, and it spits out the attack path right in your CLI.

But here is the real kicker: **Shortest path ≠ Best path**. 
Under the hood, SpecterAD doesn't just blindly run BFS. It features a custom **OpSec-weighted routing engine** (powered by Dijkstra). It calculates the risk of triggering SOC alerts, punishing noisy techniques (like RDP or Session hijacking) while favoring stealthy LDAP/ACL abuses. It tells you how to get to Domain Admins without waking up the Blue Team.

---

## Quick Start

### Installation
```bash
git clone https://github.com/0fbiscuit/SpecterAD.git
cd SpecterAD
python -m pip install -e .
```

### Usage

### 1. Ingest Data & Check Stats
Load data into memory:
```bash
specterad load /path/to/sharphound_data
```

### 2.Enumeration
List all users in the graph:
```bash
specterad -d /path/to/data query all-users
```

Find Kerberoastable accounts (Accounts with SPN set):
```bash
specterad -d /path/to/data query kerberoastable
```

Identify High-Value Targets (DA, Enterprise Admins, DCs, etc.):
```bash
specterad -d /path/to/data query hvt
```

### 3. Pathfinding
Find shortest attack path from source to target:
```bash
specterad -d /path/to/data path "Source" "Target"
```

Find "quietest" path (weighted Dijkstra):
```bash
specterad -d /path/to/data path "Source" "Target" -w
```

Find paths to all Domain Admins:
```bash
specterad -d /path/to/data path "Source" --to-da
```

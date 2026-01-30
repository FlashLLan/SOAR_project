# SOAR Project – Security Orchestration, Automation and Response (SOAR)

## Overview

This repository contains a **fully functional, end‑to‑end SOAR system** designed and implemented as a hands‑on security engineering project. The goal of the project is to demonstrate how **IDS/IPS detection, automated decision‑making, and firewall enforcement** can be combined into a single, cohesive defensive platform suitable for routers, gateways, or small perimeter networks.

The system integrates:

* **Suricata** as IDS/IPS (signature‑based + custom rules)
* **nftables** as the enforcement layer (dynamic sets, timeouts, rollback)
* **Python SOAR agent** (collector, decision engine, playbooks)
* **SQLite** for alert and action persistence
* **Systemd services** for production‑like operation
* **`soarctl` CLI** for human and machine (JSON) interaction

This is **not a toy IDS demo**. The project reaches the level where attacks are:

1. Detected in near‑real time
2. Parsed and classified
3. Automatically mitigated
4. Auditable and reversible

---

## Repository Structure

The project follows a **clear separation between runtime assets, Python logic, and examples**. This section reflects the **actual repository layout**.

```
SOAR_project/
├── agent/
│   ├── soar/
│   │   ├── assets/                 # Runtime assets installed on the system
│   │   │   ├── nftables/
│   │   │   │   └── soar.nft         # Active nftables ruleset (used by engine)
│   │   │   ├── suricata/
│   │   │   │   └── soar.rules       # Active Suricata rules
│   │   │   └── systemd/
│   │   │       └── soar-engine.service
│   │   │
│   │   ├── collector/               # Alert ingestion layer
│   │   │   ├── tailer.py             # Tails eve.json
│   │   │   ├── db.py                 # SQLite schema & queries
│   │   │   └── models.py             # Alert models
│   │   │
│   │   ├── decision/
│   │   │   └── engine.py             # Decision engine
│   │   │
│   │   ├── firewall/
│   │   │   └── nft.py                # nftables interaction layer
│   │   │
│   │   ├── playbooks/
│   │   │   └── playbooks.py          # Automated responses
│   │   │
│   │   ├── cli.py                    # soarctl CLI implementation
│   │   ├── config.py                 # Global configuration
│   │   ├── db.py                     # Shared DB helpers
│   │   └── __init__.py
│   │
│   └── pyproject.toml                # Python package definition
│
├── firewall/example_nft/             # Documentation-only examples
│   └── nftables.conf
│
├── ids/example_suricata/             # Documentation-only examples
│   ├── suricata.yaml
│   └── rules/
│       ├── local.rules
│       └── local.drop.rules
│
├── install.sh                        # Installer (supports dry-run)
├── uninstall.sh                      # Clean removal
└── README.md
```

### Important Distinction

* **Runtime assets** are installed from:

  * `agent/soar/assets/*`
* **Example directories**:

  * `firewall/example_nft/`
  * `ids/example_suricata/`

These examples are **not used by the running engine**. They exist strictly for:

* Documentation
* Testing
* Understanding rule design

---

## Architecture

### High-Level Flow (Decision logic path)

```
Attacker  ──►  Network Traffic
                │
                ▼
           Suricata (IDS / IPS)
                │  (EVE JSON alerts)
                ▼
        Python SOAR Collector
                │
        SQLite (alerts/actions)
                │
        Decision Engine
                │
          Playbooks
                │
        nftables (block / drop)
```

---

## Test Environment & Topology

### Virtual Machines

| Machine                 | Role                            | OS         |
| ----------------------- | ------------------------------- | ---------- |
| **SOAR_router**         | Router / Firewall / SOAR Engine | Debian     |
| **SOAR_dmz & SOAR_lan**            | DMZ / LAN server                | Debian     |
| **Kali_linux** | Attacker                        | Kali Linux | 

### IP Addressing

| Host        | Interface | IP              |
| ----------- | --------- | --------------- |
| SOAR_router | WAN       | 192.168.x.x     |
| SOAR_router | DMZ       | 10.10.10.1      |
| SOAR_router | LAN       | 10.20.20.1      |
| SOAR_dmz    | DMZ       | 10.10.10.10     |
| SOAR_lan    | LAN       | 10.20.20.10     |
| Kali        | WAN       | 192.168.x.x     |

### Network Design

* **WAN**: NAT‑backed interface simulating the Internet
* **DMZ**: Public‑facing services (SSH, HTTP, DNS testing)
* **LAN**: Internal protected network

Inter‑zone communication is strictly controlled via **nftables policies**, with additional inspection by Suricata.

---

## Firewall (nftables)

### Key Features

* Default‑deny policy
* Zone separation (WAN / DMZ / LAN)
* Anti‑spoofing rules
* Rate‑limiting and flood protection
* Dynamic blocklists using **nftables sets with timeouts**
* Port‑knocking for restricted SSH access

### Dynamic Sets

* `blocklist4` – inbound malicious IPs
* `egress_block4` – outbound abuse containment

Entries are added **automatically by SOAR playbooks** and expire unless refreshed.

### Why nftables?

* Atomic rule updates
* Native sets with timeouts
* Kernel‑level performance
* Clean integration with IPS workflows

---

## Setting up

### Prerequisites

On the router VM (Debian):

```
sudo apt install -y \
  python3 python3-venv python3-pip \
  nftables suricata jq sqlite3
```

### Install SOAR

From the repository root:

```
sudo ./install.sh
```

What `install.sh` is expected to do (high level):

* Install runtime assets from `agent/soar/assets/*` (nftables, suricata rules, systemd units)
* Install/enable systemd units (`soar-engine.service`)
* Make `soarctl` available system‑wide (via the Python package / entrypoint)


### Uninstall

To remove SOAR components from the system:

```
sudo ./uninstall.sh --yes
```

This will:

* Stop and disable SOAR systemd services
* Remove installed runtime assets
* Clean up SOAR-related files installed by `install.sh`


### Dry‑run mode

To preview what **would** be removed without making changes:

```
sudo ./uninstall.sh --dry-run
```

This is useful for verification and safety before a full uninstall.

---
## Interface Configuration (Important)

> **Interface Configuration Note**
> The provided nftables rules assume logical **WAN / LAN / DMZ** interfaces. While SOAR ships with its own nftables rules from `agent/soar/assets/nftables/`, **interface names are environment-specific** and must match your system.
>
> Before running SOAR, verify and configure the correct interfaces:
>
> ```
> soarctl ifaces show
> soarctl ifaces set --wan <iface> --lan <iface> --dmz <iface>
> ```
>
> Examples of interface names include `eth0`, `ens33`, `enp0s3`, etc. Incorrect interface mapping may result in traffic not being inspected or enforced.

---
## Running the System

### Start Services

SOAR can be started **in two ways**, depending on whether you want **manual/interactive control** or **system-managed (systemd) execution**.

#### Option A: Using `soarctl` (recommended for labs, demos, debugging)

This is the method that has been actively used.

```
soarctl engine start
```

* Runs the **decision engine in foreground mode**
* Useful for:

  * Live demos
  * Debugging
  * Watching logs/output directly

Silent/background mode:

```
soarctl engine start --silent
```

Stop the engine:

```
soarctl engine stop
```

---

#### Option B: Using systemd service (production-style)

SOAR is designed to run as a **single systemd service**. The alert collector (EVE JSON tailer) is **embedded inside the decision engine** and does **not** run as a separate service.

```
sudo systemctl restart nftables
sudo systemctl start soar-engine.service
```

* `soar-engine.service` runs:

  * the decision engine
  * the embedded Suricata EVE JSON collector
* This mode is intended for:

  * automatic startup on boot
  * unattended / appliance-style operation

> There is intentionally **no** `soar-collector.service`. The collector lifecycle is managed by the engine itself.


### Command Reference
The SOAR CLI is self-documented. All available commands and options can be discovered using:

```
soarctl -h
soarctl engine -h
soarctl alerts -h
soarctl blocklist -h
soarctl rollback -h
```


### Logs

```
tail -f /var/log/suricata/eve.json
```

---

## Attack Simulation (Examples)

Run attacks from the Kali VM toward the router target.

### 1) SYN Flood (simple)

```
hping3 -S --flood -V 192.168.x.x -p 22
# or against any port
hping3 -S --flood 192.168.x.x -p 80
```

### 2) SYN Scan / Port Scan

```
sudo nmap -sS 192.168.x.x
sudo nmap -A 192.168.x.x
sudo nmap -p- 192.168.x.x
```

### 3) ICMP Flood

```
hping3 192.168.x.x --icmp --flood
```

### 4) Ping flood (less aggressive)

```
ping -f -i 0.02 192.168.x.x
```

### 5) HTTP / URL scan

```
curl http://192.168.x.x/
```

### 6) SSH Brute Force

```
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.x.x:22
# smaller test
hydra -l test -p test ssh://192.168.x.x:22
```

### 7) UDP Flood

```
hping3 --udp --flood 192.168.x.x -p 53
```

### Verify enforcement

Blocked IPs should appear in nftables dynamic sets, for example:

```
soarctl blocklist show
sudo nft list set inet soar blocklist4
```

## Runtime vs Examples

* **Runtime files** are installed from `agent/soar/assets/*`
* `firewall/example_*` and `ids/example_*` are **documentation only**
* During development and testing, the example nftables and Suricata configurations were used to validate SOAR behavior in a controlled lab environment.
* They are **not used by the live engine**

---

## Project Status


- Core functionality complete
- IDS + IPS operational
- Automated blocking + rollback
- CLI with JSON output
- Systemd integration


This project is **feature‑complete** and ready for further expansion (UI, enrichment, distributed agents)

---

## Disclaimer

This project is for **educational and research purposes only**. Do not deploy in production environments without proper review, testing, and hardening.

---

## Author

Developed as a hands‑on SOAR / network security engineering project.

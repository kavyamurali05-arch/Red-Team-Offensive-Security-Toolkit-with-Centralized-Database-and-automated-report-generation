#  Red Team Offensive Security Toolkit (OSTK)

A lightweight, Python-based Red Team / VAPT (Vulnerability Assessment and Penetration Testing) toolkit that automates common offensive security workflows. It wraps industry-standard tools (Nmap, Whois, Nikto, SQLMap, Metasploit) behind a single menu-driven CLI, records every action in a centralized SQLite database, and automatically generates per-run and consolidated engagement reports (TXT / HTML / PDF).

>  **Disclaimer:** This toolkit is built strictly for **educational purposes and authorized penetration testing engagements only**. Do not use it against any system without explicit written permission. The author is not responsible for any misuse of this tool.

---

##  Project Overview

Penetration testers usually need to run several independent tools (Nmap, Nikto, SQLMap, Metasploit, etc.) and then manually collect the scattered outputs to write a report. This process is slow, error-prone, and hard to audit.

**OSTK (Offensive Security Toolkit)** solves this by acting as a single orchestration layer. It runs each tool, saves the raw output, records metadata (command, timestamp, exit code, SHA-256 checksum) in a database, and automatically builds both per-tool and final consolidated reports — reducing a multi-hour manual reporting task to a few clicks.

---

##  Problem Statement

- Running multiple security tools requires many separate commands, and their outputs get scattered across the terminal and different files.
- Manually preparing a penetration testing report (copy-pasting terminal output) is time-consuming and error-prone.
- There is usually no consistent audit trail of **who ran what command, when, and what the output checksum was**.
- Beginners in cybersecurity find it hard to maintain a clean, reproducible workflow that also preserves evidence.

---

## Objective

To build a single CLI-based toolkit that:
- Orchestrates common recon, scanning, and exploitation tools.
- Automatically logs every action with full traceability (command, output, SHA-256, exit code, timestamp).
- Auto-generates human-readable reports (per-run TXT and consolidated HTML/PDF) without manual effort.
- Provides a reproducible, auditable workflow suitable for lab coursework and authorized red team exercises.

---

##  Features

-  **Nmap Integration** — Quick, service version, aggressive, full-TCP, and custom scan profiles with XML output for automated parsing.
-  **Whois Lookup** — Domain registration and ownership information.
-  **Nikto Web Scanner** — Default, tuned, and custom web vulnerability scans.
-  **SQLMap Integration** — Batch, crawl, dump, and custom SQL injection testing modes.
-  **Metasploit Integration** — Interactive `msfconsole` sessions recorded to a log file using the `script` utility.
-  **Centralized SQLite Database** — Every tool run is logged with the command used, output file path, SHA-256 hash, exit code, and timestamp.
-  **Automated Report Generation** — Per-run TXT reports and a consolidated HTML/PDF engagement report, complete with auto-extracted findings and a heuristic risk rating (LOW / MEDIUM / HIGH / CRITICAL).
-  **Evidence Integrity** — SHA-256 checksums for every output file to preserve chain of custody.
-  **Per-Engagement Workspace** — Each engagement gets its own `logs/`, `exports/`, and `evidence/` folders.
-  **Simple Command-Line Interface** — Beginner-friendly, menu-driven navigation.

---

##  Project Architecture

```
 User (Operator)
      │
      ▼
 CLI Controller (ostk.py)
      │
      ▼
 Tool Wrappers  ──────► Nmap | Whois | Nikto | SQLMap | Metasploit
      │
      ▼
 Parsers / Normalizers (report_generator.py)
      │
      ▼
 Centralized Database (SQLite - ostk_logs.db)
      │
      ▼
 Report Generator
      │
      ▼
 Final Report (TXT / HTML / PDF)  ──►  Reviewer / Auditor / Grader
```

**Flow summary:**
1. The operator selects a tool from the CLI menu.
2. The CLI Controller executes the corresponding tool wrapper.
3. Raw output is streamed to the terminal and saved to a timestamped log file.
4. The output is parsed to auto-extract findings and generate a per-run TXT report.
5. The run metadata (command, output path, SHA-256, exit code) is stored in the SQLite database.
6. On request, the Report Generator pulls all logged runs and builds a consolidated HTML/PDF report.

---

##  Technologies & Tools Used

| Category            | Technology / Tool                                                   |
|----------------------|-----------------------------------------------------------------------|
| Programming Language | Python 3.10+                                                          |
| Database             | SQLite (via built-in `sqlite3`)                                       |
| Operating System     | Kali Linux (or any Debian-based Linux distribution)                   |
| Recon & Scanning     | Nmap, Whois                                                           |
| Web Vulnerability    | Nikto                                                                  |
| Exploitation         | SQLMap, Metasploit Framework                                           |
| Report Rendering     | HTML, WeasyPrint (optional, for PDF export)                            |
| Core Python Modules  | `subprocess`, `sqlite3`, `hashlib`, `pathlib`, `xml.etree.ElementTree`, `datetime`, `shlex` |

---

##  Folder Structure

```
Red-Team-Offensive-Security-Toolkit/
│
├── ostk.py                  # Main CLI - orchestrates tools, workspace, and DB logging
├── report_generator.py      # Parsers, risk heuristics, and report builders (TXT/HTML/PDF)
├── requirements.txt         # Optional Python dependencies (e.g. weasyprint)
├── README.md                # Project documentation (this file)
├── .gitignore                # Files/folders excluded from version control
├── LICENSE                  # Project license
│
├── docs/
│   └── MINI_PROJECT_DOCUMENTATION.pdf   # Full academic project report
│
├── screenshots/              # Sample terminal outputs and report previews
│
└── workspace/                # Auto-created at runtime (NOT uploaded to GitHub)
    └── <engagement_name>/
        ├── logs/
        ├── exports/
        └── evidence/
```

> Note: The `workspace/` folder and `ostk_logs.db` are generated automatically when the tool runs. They should **not** be committed to GitHub (see the `.gitignore` section below).

---

##  Installation Steps

### 1. Prerequisites
- Python 3.10 or higher
- Kali Linux (recommended) or any Debian-based Linux system
- The following tools installed and available in `PATH`:
  ```bash
  sudo apt update
  sudo apt install nmap whois nikto sqlmap metasploit-framework util-linux -y
  ```

### 2. Clone the repository
```bash
git clone https://github.com/<your-username>/Red-Team-Offensive-Security-Toolkit.git
cd Red-Team-Offensive-Security-Toolkit
```

### 3. (Optional) Create a virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Python dependencies
```bash
pip install -r requirements.txt
```
> `weasyprint` is optional — if it is not installed, the toolkit will still generate HTML reports, just without PDF export.

---

##  How to Run the Project

```bash
python3 ostk.py
```

You will be prompted to enter an engagement name (e.g. `CollegeMiniProject`). This creates a dedicated workspace folder for that engagement, and the main menu will appear:

```
=== Red Team Toolkit ===
1) Recon Flow (Nmap, Whois, Nikto)
2) Vulnerability Scanning (SQLMap)
3) Metasploit (Interactive, recorded)
4) Reporting (View recent runs / Generate report)
0) Exit
```

---

##  Sample Usage

**Example: Running an Nmap scan**
```
Select: 1.1
Target IP/Host: example.com
Profiles: 1) quick 2) sV 3) aggressive 4) full-tcp 5) custom
Choice: 2

[+] Running Nmap
$ nmap -sV --version-light --open example.com -oX workspace/.../nmap_example.com.xml
[+] Per-run TXT report written
[+] Nmap finished (exit=0) sha256=...
```

**Generating the final report**
```
Select: 4.2
[+] Report created:
   HTML: workspace/<engagement>/exports/<engagement>_report_<timestamp>.html
   PDF : workspace/<engagement>/exports/<engagement>_report_<timestamp>.pdf
```

---

##  Output / Results

- **Per-run TXT report** — Contains the command used, a trimmed log preview, auto-parsed findings, a heuristic risk rating, and proof-of-concept details.
- **Consolidated HTML/PDF report** — A chronological summary of every tool run in the engagement, including a summary table with tool name, exit code, timestamp, output path, and SHA-256 hash.
- **SQLite database (`ostk_logs.db`)** — Full audit trail of every command executed during the engagement.


---

##  Future Enhancements

- Extend SHA-256 evidence integrity checks to XML, SQLMap directories, and Metasploit logs, with an automated hash-verification routine.
- Normalize the single `logs` table into separate relational tables (`engagements`, `targets`, `scans`, `findings`, `evidence`).
- Add automated unit tests (using `pytest`) for the parsers to prevent regressions when tool output formats change.
- Add a `--lab-mode` flag to restrict scans to authorized/private network ranges only.
- Replace remaining `shell=True` subprocess calls with safer, structured argument handling.
- Migrate from SQLite to PostgreSQL to support concurrent multi-user usage.
- Build a Flask/FastAPI-based web dashboard for visualizing scans and findings.
- Integrate CVE/CVSS lookups to strengthen the risk-scoring engine beyond text heuristics.
- Improve credential-extraction regex patterns from SQLMap output to reduce false positives.

---

##  Author

**Name: Kavya Devi M.S.**

  Email: kavyadevimurali@gmail.com


---

##  References

- [Nmap](https://nmap.org)
- [SQLMap](https://sqlmap.org)
- [Nikto](https://cirt.net/Nikto2)
- [Metasploit](https://www.metasploit.com)
- [WeasyPrint](https://weasyprint.org)
- [Python](https://www.python.org)

---

##  License

This project is released under the [MIT License](./LICENSE). It is intended for educational use only.

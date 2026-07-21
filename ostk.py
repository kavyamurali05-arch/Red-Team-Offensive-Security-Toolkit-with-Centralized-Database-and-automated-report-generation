#!/usr/bin/env python3
"""
ostk.py - Clean Red Team Toolkit (educational)
Tools included: Nmap, Whois, Nikto, SQLMap, Metasploit (interactive recorded)
Behavior:
 - Each run streams output to terminal and saves a timestamped .txt log
 - Each run recorded in SQLite DB (ostk_logs.db)
 - Per-run TXT reports generated and final consolidated HTML+PDF via report_generator.py (WeasyPrint)
Note: Run only on targets you own or have written permission to test.
"""

import os
import shlex
import sqlite3
import hashlib
import datetime
import shutil
from pathlib import Path
from subprocess import Popen, PIPE, STDOUT, run

BASE = Path(__file__).resolve().parent
DB = BASE / "ostk_logs.db"
WORKSPACE = BASE / "workspace"

ENGAGEMENT = None
LOG_DIR = None
EXPORT_DIR = None
EVIDENCE_DIR = None  # kept for future use (not used now)

def now_ts():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def now_human():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sha256_of(path: Path):
    try:
        if not path or not path.exists(): return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1<<20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def which(bin_name: str) -> bool:
    return shutil.which(bin_name) is not None

# ---------------- DB ----------------
def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      engagement TEXT NOT NULL,
      tool TEXT NOT NULL,
      command TEXT NOT NULL,
      output_file TEXT,
      sha256 TEXT,
      exit_code INTEGER,
      timestamp TEXT NOT NULL
    )""")
    conn.commit(); conn.close()

def log_run(engagement, tool, command, output_file, sha256, exit_code):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""INSERT INTO logs
        (engagement, tool, command, output_file, sha256, exit_code, timestamp)
        VALUES (?,?,?,?,?,?,?)""",
        (engagement, tool, command, str(output_file) if output_file else None,
         sha256, exit_code, now_human()))
    conn.commit(); conn.close()

# ---------------- Workspace ----------------
def set_engagement(name: str):
    global ENGAGEMENT, LOG_DIR, EXPORT_DIR, EVIDENCE_DIR
    safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in (name or "Demo"))
    ENGAGEMENT = safe
    base = WORKSPACE / ENGAGEMENT
    (base / "logs").mkdir(parents=True, exist_ok=True)
    (base / "exports").mkdir(parents=True, exist_ok=True)
    (base / "evidence").mkdir(parents=True, exist_ok=True)
    LOG_DIR = base / "logs"
    EXPORT_DIR = base / "exports"
    EVIDENCE_DIR = base / "evidence"
    print(f"[+] Workspace ready: {base.resolve()}")

# ---------------- run & log ----------------
def run_and_save_text(tool_name: str, command: str, hint: str, use_shell: bool=False):
    safe_hint = hint.replace(" ", "_").replace("/", "_")
    log_path = LOG_DIR / f"{now_ts()}_{safe_hint}.txt"
    print(f"\n[+] Running {tool_name}\n$ {command}\n[+] Saving -> {log_path}\n")
    with open(log_path, "wb") as f:
        p = Popen(command if use_shell else shlex.split(command),
                  stdout=PIPE, stderr=STDOUT, shell=use_shell, text=True, bufsize=1)
        exit_code = 0
        try:
            for line in p.stdout:
                print(line, end="")
                f.write(line.encode("utf-8", "ignore"))
            p.wait(); exit_code = p.returncode
        except Exception as e:
            err = f"[EXCEPTION] {e}\n"
            print(err); f.write(err.encode()); exit_code = -1
    digest = sha256_of(log_path)
    log_run(ENGAGEMENT, tool_name, command, log_path, digest, exit_code)

    # attempt per-run report generation (TXT + registration)
    try:
        from report_generator import build_per_run_report
        build_per_run_report(DB, ENGAGEMENT, tool_name, command, log_path, digest, exit_code, EXPORT_DIR)
    except Exception as e:
        print("[!] Per-run report generation failed:", e)

    print(f"[+] {tool_name} finished (exit={exit_code}) sha256={digest}\n")
    return log_path, exit_code

# ---------------- Tools ----------------
def tool_nmap():
    if not which("nmap"):
        print("[!] nmap not found. Install (sudo apt install nmap).")
        return
    tgt = input("Target IP/Host (IP or domain): ").strip()
    if not tgt:
        print("No target.")
        return
    print("Profiles: 1) quick 2) sV 3) aggressive 4) full-tcp 5) custom")
    ch = input("Choice: ").strip()
    # default use --version-light and --open to avoid fingerprint dumps
    if ch == "1": cmd = f"nmap -sV --version-light --open {tgt}"
    elif ch == "2": cmd = f"nmap -sV --version-light --open {tgt}"
    elif ch == "3": cmd = f"nmap -A --version-light {tgt}"
    elif ch == "4": cmd = f"nmap -p- -sV --version-light {tgt}"
    elif ch == "5": cmd = input("Full nmap command: ").strip()
    else:
        cmd = f"nmap -sV --version-light --open {tgt}"
    # ensure XML output for parsing
    xml_path = LOG_DIR / f"{now_ts()}_nmap_{tgt.replace('/','_')}.xml"
    if "-oX" not in cmd and "--xml" not in cmd:
        cmd = cmd + f" -oX {xml_path}"
    run_and_save_text("Nmap", cmd, f"nmap_{tgt}")

def tool_whois():
    if not which("whois"):
        print("[!] whois not found. Install (sudo apt install whois).")
        return
    dom = input("Domain (example.com): ").strip()
    if not dom: return
    cmd = f"whois {dom}"
    run_and_save_text("Whois", cmd, f"whois_{dom}")

def tool_nikto():
    if not which("nikto"):
        print("[!] nikto not found. Install (sudo apt install nikto).")
        return
    url = input("Target URL (e.g., http://example.com): ").strip()
    if not url: return
    print("Nikto options: 1) default 2) tuning 3) custom")
    ch = input("Choice: ").strip()
    outf = LOG_DIR / f"{now_ts()}_nikto_{url.replace('://','_').replace('/','_')}.txt"
    if ch == "1":
        cmd = f"nikto -h {url} -output {outf}"
    elif ch == "2":
        tune = input("Tuning codes: ").strip()
        cmd = f"nikto -h {url} -Tuning {tune} -output {outf}"
    elif ch == "3":
        cmd = input("Full nikto command: ").strip()
    else:
        cmd = f"nikto -h {url} -output {outf}"
    run_and_save_text("Nikto", cmd, f"nikto_{outf.stem}")

def tool_sqlmap():
    if not which("sqlmap"):
        print("[!] sqlmap not found. Install (sudo apt install sqlmap).")
        return
    url = input("Target URL with param (e.g., http://site/?id=1): ").strip()
    if not url: return
    print("SQLMap modes: 1) batch 2) crawl2 3) dump 4) custom")
    ch = input("Choice: ").strip()
    outdir = LOG_DIR / f"{now_ts()}_sqlmap"
    outdir.mkdir(parents=True, exist_ok=True)
    if ch == "1":
        cmd = f'sqlmap -u "{url}" --batch --output-dir="{outdir}"'
    elif ch == "2":
        cmd = f'sqlmap -u "{url}" --crawl=2 --batch --output-dir="{outdir}"'
    elif ch == "3":
        cmd = f'sqlmap -u "{url}" --dump --batch --output-dir="{outdir}"'
    else:
        cmd = input("Full sqlmap command: ").strip()
    # run via shell to ensure sqlmap works with quotes
    run_and_save_text("SQLMap", cmd, "sqlmap", use_shell=True)
    # index output dir into DB (artifact)
    log_run(ENGAGEMENT, "SQLMap(output-dir)", cmd, outdir, None, 0)

def msf_interactive_recorded():
    if not which("msfconsole"):
        print("[!] msfconsole not found. Install metasploit-framework.")
        return
    if not which("script"):
        print("[!] 'script' utility not found. Install util-linux.")
        return
    logp = LOG_DIR / f"{now_ts()}_msf_session.txt"
    cmd = f'script -q -c "msfconsole -q" "{logp}"'
    print(f"[+] Launching interactive msfconsole (recorded -> {logp.name})")
    rc = run(cmd, shell=True).returncode
    sha = sha256_of(logp) if logp.exists() else None
    log_run(ENGAGEMENT, "Metasploit(interactive)", cmd, logp if logp.exists() else None, sha, rc)
    print(f"[+] msfconsole finished (exit={rc})")

# ---------------- view logs & report trigger ----------------
def view_recent():
    conn = sqlite3.connect(DB); c = conn.cursor()
    c.execute("SELECT id,tool,exit_code,timestamp,output_file FROM logs WHERE engagement=? ORDER BY id DESC LIMIT 50", (ENGAGEMENT,))
    rows = c.fetchall(); conn.close()
    print("\n=== Recent runs (latest 50) ===\n")
    for r in rows:
        print(f"[{r[0]}] {r[1]} | exit={r[2]} | {r[3]}\n   file: {r[4]}\n")

def generate_report():
    from report_generator import build_report
    h, p = build_report(DB, ENGAGEMENT, EXPORT_DIR, LOG_DIR)
    print(f"\n[+] Report created:\n  HTML: {h}\n  PDF : {p if p else 'PDF skipped'}\n")

# ---------------- Menu ----------------
def menu():
    while True:
        print(f"""
=== Red Team Toolkit ===
Engagement: {ENGAGEMENT}
Logs:      {LOG_DIR}
Exports:   {EXPORT_DIR}

1) Recon Flow 
1.1 Nmap
1.2 Whois
1.3 Nikto

2) Vulnerability Scanning
2.1 SQLMap

3) Metasploit
3.1 Interactive (recorded)

4) Reporting
4.1 View recent runs
4.2 Generate report 

0) Exit
""")
        ch = input("Select: ").strip()
        if ch in ("1","1.1"):
            if ch == "1":
                tool_nmap()
                nxt = input("Continue to WHOIS? (Enter=Yes / 'exit' to stop): ").strip().lower()
                if nxt == "exit": continue
                tool_whois()
                nxt = input("Continue to NIKTO? (Enter=Yes / 'exit' to stop): ").strip().lower()
                if nxt == "exit": continue
                tool_nikto()
            else:
                tool_nmap()
        elif ch == "1.2": tool_whois()
        elif ch == "1.3": tool_nikto()
        elif ch == "2.1": tool_sqlmap()
        elif ch == "3.1": msf_interactive_recorded()
        elif ch == "4.1": view_recent()
        elif ch == "4.2": generate_report()
        elif ch == "0":
            print("Exiting. Logs and DB preserved.")
            break
        else:
            print("Invalid option.")

# ---------------- Main ----------------
if __name__ == "__main__":
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    init_db()
    print("Authorized testing only. Obtain permission before scanning.")
    name = input("Engagement name (e.g., CollegeMiniProject): ").strip() or "Demo"
    set_engagement(name)
    menu()




#!/usr/bin/env python3
"""
report_generator.py
 - build_per_run_report(...) : create per-run TXT report (header, cmd, log preview, findings, risk, PoC)
 - build_report(...) : consolidated HTML + PDF (WeasyPrint) report for engagement
Parsing:
 - nmap XML -> ports/services
 - nikto text -> suspicious lines
 - sqlmap output-dir -> findings + attempt username/password extraction (best-effort)
 - metasploit recorded session -> key lines
"""

import sqlite3, datetime, re, os
from pathlib import Path
import xml.etree.ElementTree as ET

try:
    from weasyprint import HTML
    WEASY = True
except Exception:
    WEASY = False

def now_human(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# ---------- parsers ----------
def parse_nmap_xml(xmlp: Path):
    findings=[]
    try:
        tree = ET.parse(str(xmlp)); root = tree.getroot()
        for host in root.findall("host"):
            addr = host.find("address")
            ip = addr.get("addr","unknown") if addr is not None else "unknown"
            hn = host.find("hostnames")
            hostnames = []
            if hn is not None:
                hostnames = [h.get("name","") for h in hn.findall("hostname")]
            for port in host.findall(".//port"):
                pid = port.get("portid")
                proto = port.get("protocol")
                state = port.find("state").get("state") if port.find("state") is not None else "unknown"
                svc_el = port.find("service")
                svc = svc_el.get("name","") if svc_el is not None else ""
                prod = svc_el.get("product","") if svc_el is not None and "product" in svc_el.attrib else ""
                findings.append(f"{ip} {('('+','.join(hostnames)+') ' if hostnames else '')}{proto}/{pid} {state} service={svc} product={prod}")
    except Exception as e:
        findings.append(f"[nmap-parse-error] {e}")
    return findings

def parse_nikto(txtp: Path):
    findings=[]
    try:
        txt = txtp.read_text(errors="ignore")
        for ln in txt.splitlines():
            l = ln.strip()
            if not l: continue
            if any(k in l.lower() for k in ("osvdb","directory indexing","server:","vulnerab","found","cgi-bin","admin","warning")):
                findings.append(l)
    except Exception as e:
        findings.append(f"[nikto-parse-error] {e}")
    return findings[:200]

def parse_sqlmap_dir(dpath: Path):
    findings=[]
    creds=[]
    try:
        if not dpath.exists(): return findings, creds
        for f in sorted(dpath.rglob("*"), key=os.path.getmtime, reverse=False):
            if not f.is_file(): continue
            try:
                txt = f.read_text(errors="ignore")
            except Exception:
                continue
            lower = txt.lower()
            # simple heuristics
            if "is vulnerable" in lower or "sqlmap" in lower or "payload" in lower or "parameter" in lower:
                snippet = "\n".join([l.strip() for l in txt.splitlines() if l.strip()][:8])
                findings.append(f"{f.name}: {snippet}")
            # attempt credential extraction heuristics
            # look for lines like: username: admin   password: password
            for m in re.finditer(r"(?i)(user(name)?|login)[\s:=]{1,4}([^\s,;\"']+)", txt):
                u = m.group(3).strip()
                # search for a nearby password in the file (within next 200 chars)
                start = m.end()
                tail = txt[start:start+300]
                pm = re.search(r"(?i)(pass(word)?|pwd|passwd)[\s:=]{1,4}([^\s,;\"']+)", tail)
                if pm:
                    pval = pm.group(3).strip()
                    creds.append((u, pval))
            # also try generic user:pass patterns
            for mm in re.finditer(r"([^\s:,@]+)[:@]([^\s:,@]+)", txt):
                a,b = mm.group(1).strip(), mm.group(2).strip()
                # avoid matching obvious urls or hex strings; heuristic length check
                if 2 <= len(a) <= 40 and 2 <= len(b) <= 40:
                    creds.append((a,b))
    except Exception as e:
        findings.append(f"[sqlmap-parse-error] {e}")
    # dedupe
    uniq_f = []
    for it in findings:
        if it not in uniq_f: uniq_f.append(it)
    uniq_c = []
    for c in creds:
        if c not in uniq_c: uniq_c.append(c)
    return uniq_f[:120], uniq_c[:60]

def parse_msf_log(p: Path):
    findings=[]
    try:
        txt = p.read_text(errors="ignore")
        for ln in txt.splitlines():
            l = ln.strip()
            if not l: continue
            if any(k in l.lower() for k in ("meterpreter","session","command shell","vulnerable","success","opened","exploit","getuid")):
                findings.append(l)
    except Exception as e:
        findings.append(f"[msf-parse-error] {e}")
    return findings[:200]

# ---------- heuristic risk ----------
def risk_from_texts(texts):
    score = 0
    for t in texts:
        s = t.lower()
        if "cve-" in s or "remote code execution" in s or "unauthenticated" in s or "root" in s:
            score += 5
        if "is vulnerable" in s or "sql injection" in s or "directory traversal" in s or "command injection" in s:
            score += 4
        if "found" in s or "open" in s or "warning" in s or "exposed" in s:
            score += 2
        if "info" in s or "server" in s or "version" in s:
            score += 1
    if score >= 8: return "CRITICAL"
    if score >= 5: return "HIGH"
    if score >= 2: return "MEDIUM"
    return "LOW"

# ---------- per-run TXT report ----------
def build_per_run_report(db_path, engagement, tool, command, log_path: Path, sha, exit_code, export_dir: Path):
    export_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_tool = "".join(ch if ch.isalnum() else "_" for ch in tool)
    rpt = export_dir / f"{engagement}_{safe_tool}_{ts}.txt"
    # read log
    log_text = ""
    if log_path and Path(log_path).exists():
        try:
            log_text = Path(log_path).read_text(errors="ignore")
        except Exception:
            log_text = "[could not read log]"
    findings=[]
    creds=[]
    p = Path(log_path) if log_path else None
    if p and p.exists() and p.suffix.lower()==".xml" and "nmap" in p.name.lower():
        findings = parse_nmap_xml(p)
    elif p and p.exists() and "nikto" in p.name.lower():
        findings = parse_nikto(p)
    elif "sqlmap" in tool.lower() or (p and p.exists() and p.is_dir() and "sqlmap" in p.name.lower()):
        # try parse dir
        if p and p.exists() and p.is_dir():
            findings, creds = parse_sqlmap_dir(p)
        else:
            # fallback: search for nearest sqlmap dirs under log folder
            for d in log_path.parent.glob("*sqlmap*"):
                if d.is_dir():
                    f,c = parse_sqlmap_dir(d)
                    findings += f; creds += c
    elif p and p.exists() and ("msf" in p.name.lower() or "metasploit" in tool.lower()):
        findings = parse_msf_log(p)
    else:
        # generic keyword scan
        for ln in log_text.splitlines():
            l = ln.strip()
            if not l: continue
            if any(k in l.lower() for k in ("vulnerab","cve-","is vulnerable","sql injection","directory traversal","command injection","found","open")):
                findings.append(l)
    risk = risk_from_texts(findings if findings else [log_text[:2000]])
    description = findings[0] if findings else "No structured findings auto-extracted. Validate manually."
    with open(rpt, "w", encoding="utf-8") as r:
        r.write("──────────────────────────────────────────────\n")
        r.write("Per-run Vulnerability Report\n")
        r.write("──────────────────────────────────────────────\n")
        r.write(f"Engagement: {engagement}\n")
        r.write(f"Tool: {tool}\n")
        r.write(f"Date: {now_human()}\n\n")
        r.write("Command Executed:\n")
        r.write(f"{command}\n\n")
        r.write("Execution Log (trimmed preview):\n")
        r.write((log_text[:20000] + ("\n...[truncated]" if len(log_text)>20000 else "")) + "\n\n")
        r.write("Detailed Findings:\n")
        if findings:
            for it in findings:
                r.write(f"- {it}\n")
        else:
            r.write("- No auto-parsed findings.\n")
        r.write(f"\nRisk Rating: {risk}\n\n")
        r.write("Description:\n"); r.write(description + "\n\n")
        r.write("Proof of Concept (PoC):\n"); r.write(f"Command used: {command}\n\n")
        if creds:
            r.write("Captured credentials (auto-extracted from sqlmap outputs):\n")
            for u,pw in creds:
                r.write(f"- username: {u}  password: {pw}\n")
        r.write("\nNotes:\n- This report is auto-generated and heuristic. Validate findings manually.\n")
    print(f"[+] Per-run TXT report written: {rpt}")
    return rpt

# ---------- consolidated HTML + PDF ----------
def build_report(db_path, engagement, export_dir: Path, logs_dir: Path):
    export_dir.mkdir(parents=True, exist_ok=True)
    html_path = export_dir / f"{engagement}_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    pdf_path  = export_dir / f"{engagement}_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"

    conn = sqlite3.connect(db_path); cur = conn.cursor()
    cur.execute("SELECT id,tool,command,output_file,sha256,exit_code,timestamp FROM logs WHERE engagement=? ORDER BY id ASC", (engagement,))
    rows = cur.fetchall(); conn.close()

    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>{engagement} - Report</title>
    <style>
    body{{font-family:Arial,Helvetica,sans-serif;margin:18px}}
    h1{{color:#1b3b6f}} .section{{margin-top:18px;padding:12px;border:1px solid #ddd;background:#fff}}
    .mono{{font-family:monospace;font-size:12px}} ul{{margin:8px 0 8px 20px}}
    </style></head><body>
    <h1>Red Team Toolkit — Engagement Report</h1>
    <p><strong>Engagement:</strong> {engagement} &nbsp;&nbsp; <strong>Generated:</strong> {now}</p>
    """

    html += "<div class='section'><h2>Runs (chronological)</h2>"
    if not rows:
        html += "<p>No runs recorded.</p>"
    for r in rows:
        rid, tool, cmd, out, sha, exitc, ts = r
        html += f"<div style='margin-bottom:12px;padding:8px;border:1px solid #e5e5e5'><h3>Run #{rid} — {tool}</h3>"
        html += f"<p><strong>Timestamp:</strong> {ts} &nbsp; <strong>Exit:</strong> {exitc}</p>"
        html += f"<p class='mono'><strong>Command:</strong> {cmd}</p>"
        html += f"<p class='mono'><strong>Output artifact:</strong> {out or '-'}</p>"
        # try parse artifact for concise findings
        details=[]
        if out:
            p = Path(out)
            if p.exists():
                if p.suffix.lower()==".xml" and "nmap" in p.name.lower():
                    details = parse_nmap_xml(p)
                elif "nikto" in p.name.lower():
                    details = parse_nikto(p)
                elif p.is_dir() and "sqlmap" in p.name.lower():
                    f,c = parse_sqlmap_dir(p); details = f
                elif "msf" in p.name.lower() or "metasploit" in tool.lower():
                    details = parse_msf_log(p)
                else:
                    try:
                        txt = p.read_text(errors="ignore")
                        # show first interesting line if present
                        for ln in txt.splitlines():
                            if any(k in ln.lower() for k in ("vulnerab","cve-","sql injection","found","open","success")):
                                details.append(ln.strip()); break
                    except Exception:
                        pass
        if details:
            html += "<div><strong>Parsed findings / snippets:</strong><ul>"
            for d in details[:40]:
                html += f"<li class='mono'>{d}</li>"
            html += "</ul></div>"
            risk = risk_from_texts(details)
            html += f"<p><strong>Risk Rating:</strong> {risk}</p>"
        else:
            html += "<p><em>No parsed findings auto-extracted for this run.</em></p>"
        html += "</div>"

    html += "</div>"

    html += "<div class='section'><h2>Summary Table</h2>"
    html += "<table border='1' cellpadding='6' cellspacing='0' style='border-collapse:collapse;width:100%'><thead><tr><th>#</th><th>Tool</th><th>Exit</th><th>Timestamp</th><th>Output</th><th>SHA256</th><th>Command</th></tr></thead><tbody>"
    for r in rows[::-1]:
        rid, tool, cmd, out, sha, exitc, ts = r
        html += f"<tr><td>{rid}</td><td>{tool}</td><td>{exitc}</td><td>{ts}</td><td class='mono'>{out or '-'}</td><td class='mono'>{sha or '-'}</td><td class='mono'>{cmd}</td></tr>"
    html += "</tbody></table></div>"

    html += "<div class='section'><h2>Notes</h2><p>Automatic parsing is heuristic. Validate all findings manually. Per-run TXT reports are in the exports folder.</p></div>"
    html += "</body></html>"

    html_path.write_text(html, encoding="utf-8")

    pdf_out = None
    if WEASY:
        try:
            HTML(string=html).write_pdf(str(pdf_path))
            pdf_out = pdf_path
        except Exception as e:
            print("[!] PDF creation failed:", e)
            pdf_out = None

    return html_path, pdf_out


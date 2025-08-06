import json
import argparse
import os
import re
import time
import datetime
from collections import defaultdict, Counter
import functools

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm

import requests
from taxii2client.v20 import Server
from stix2 import Filter

console = Console()

CACHE_FILE = "mitre_techniques.json"
PROXIES = {
    "http": os.environ.get("HTTP_PROXY"),
    "https": os.environ.get("HTTPS_PROXY")
}

MITRE_FALSE_NEGATIVE_URI_PATTERNS = {
    "T1552.001": r"/\\.env",
    "T1552.002": r"/\\.git",
    "T1083": r"/\\.aws|\\.backup|\\.db|\\.credentials|\\.config|\\.docker|\\.dump|\\.s3|\\.ssh",
    "T1595": r"/\\.well-known/",
    "T1190": r"/wp-admin|/wp-content|/wp-login\\.php|/xmlrpc\\.php",
    "T1040": r"(sql|select|union|from|where)=.*",
    "T1203": r"\\.\\./|\\.\\.\\\\",
    "T1055": r"<script>|javascript:|onerror=",
    "T1566": r"/mail|email|login|webmail"
}

MITRE_ATTACK_TYPES = {
    "T1003": "Credential Dumping",
    "T1021": "Remote Services",
    "T1040": "SQL Injection",
    "T1055": "Cross Site Scripting (XSS)",
    "T1059": "Command and Scripting Interpreter",
    "T1083": "Sensitive File Discovery",
    "T1105": "Ingress Tool Transfer",
    "T1133": "External Remote Services",
    "T1190": "Exploit Public-Facing Application",
    "T1203": "Directory Traversal",
    "T1210": "Exploitation of Remote Services",
    "T1547": "Boot or Logon Autostart Execution",
    "T1552.001": "Credential Dump (.env)",
    "T1552.002": "Git Exposure",
    "T1566": "Phishing Attempt",
    "T1595": "Known Path Scanning",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1566.003": "Spearphishing via Service",
    "T1590": "Gather Victim Network Information",
    "T1583.001": "Acquire Infrastructure: Domains",
    "T1583.006": "Acquire Infrastructure: Web Services",
    "T1584.005": "Compromise Infrastructure: Botnet",
    "T1586.002": "Compromise Accounts: Email Accounts",
    "T1608.001": "Stage Capabilities: Upload Malware",
    "T1608.002": "Stage Capabilities: Tool",
    "T1608.003": "Stage Capabilities: Payloads",
    "T1587.001": "Develop Capabilities: Malware",
    "T1587.002": "Develop Capabilities: Tool",
    "T1587.003": "Develop Capabilities: Exploit"
    "T1505.003": "PHPUnit Remote Code Execution",
    "T1059.004": "Shellshock Bash Remote Code Execution (CVE-2014-6271)",
    "T1595.001": "Path Enumeration Attempt",
    "T1110.001": "Generic Login Bruteforce Attempt",
    "T1190.001": "Unauthenticated File Inclusion – LinkPreview Plugin Exploit",
    "T1110": "Fortinet SSL VPN Credential Stuffing",
    "T1595.002": "GlobalProtect Login Page Enumeration Attempt",
    "T1110.003": "WordPress Admin Brute Force Attack"
}


MITRE_SEVERITY_LEVEL = {
    "T1552.001": "CRITICAL",
    "T1552.002": "HIGH",
    "T1083": "MEDIUM",
    "T1595": "LOW",
    "T1190": "CRITICAL",
    "T1040": "HIGH",
    "T1203": "HIGH",
    "T1055": "MEDIUM",
    "T1566": "INFORMATION"
}

def get_severity_style(severity):
    return {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFORMATION": "cyan",
        "INFO": "cyan"
    }.get(severity.upper(), "white")

@functools.lru_cache(maxsize=128)
def get_mitre_technique_by_id_lazy(mitre_id):
    try:
        server = Server("https://cti-taxii.mitre.org/taxii/")
        api_root = server.api_roots[0]
        collection = next((c for c in api_root.collections if "enterprise" in c.title.lower()), None)

        if not collection:
            return {"name": "Unknown", "description": "No data."}

        filter_techniques = [Filter("type", "=", "attack-pattern")]
        for obj in collection.query(filter_techniques):
            for ref in obj.get("external_references", []):
                if ref.get("external_id") == mitre_id:
                    MITRE_ATTACK_TYPES[ref.get("external_id")] = obj.get("name", "Unknown")
                    return {
                        "name": obj.get("name", "Unknown"),
                        "description": obj.get("description", "No description.")
                    }

    except Exception:
        return {"name": "N/A", "description": "Connection failed."}

    return {"name": "N/A", "description": "Not found."}

MITRE_CACHE = {}

def get_mitre_technique_by_id(mitre_id):
    return MITRE_CACHE.get(mitre_id) or get_mitre_technique_by_id_lazy(mitre_id)

def analyze_uris(entries):
    mitre_summary = defaultdict(lambda: {"count": 0, "requests": 0, "uris": []})
    for entry in entries:
        uri = entry.get("URI", "")
        request_count = entry.get("request_count", 0)
        for mitre_id, pattern in MITRE_FALSE_NEGATIVE_URI_PATTERNS.items():
            if re.search(pattern, uri, re.IGNORECASE):
                mitre_summary[mitre_id]["count"] += 1
                mitre_summary[mitre_id]["requests"] += request_count
                mitre_summary[mitre_id]["uris"].append(uri)
    return mitre_summary

def fetch_all_techniques(mitre_ids):
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), BarColumn(), transient=True) as progress:
        task = progress.add_task("🔍 Mengambil data teknik MITRE...", total=len(mitre_ids))
        for mid in mitre_ids:
            get_mitre_technique_by_id(mid)
            time.sleep(0.2)
            progress.advance(task)

def display_summary(mitre_summary):
    total_uri = sum(item["count"] for item in mitre_summary.values())
    total_requests = sum(item["requests"] for item in mitre_summary.values())
    unique_uris = len(set(uri for item in mitre_summary.values() for uri in item["uris"]))
    total_attacks = sum(item["count"] for item in mitre_summary.values())
    total_ids = len(mitre_summary)

    severity_counter = Counter()
    for mitre_id, data in mitre_summary.items():
        severity = MITRE_SEVERITY_LEVEL.get(mitre_id, "INFO")
        severity_counter[severity.upper()] += data["count"]

    severity_summary = "\n".join(
        f"• Total {level.title():<11}: [{get_severity_style(level)}]{count}[/{get_severity_style(level)}]"
        for level, count in severity_counter.items()
    )

    console.print(Panel.fit(
        f"[bold cyan]📊 Ringkasan Akhir[/bold cyan]\n"
        f"• Total URI mencurigakan     : [yellow]{total_uri}[/yellow]\n"
        f"• Total Request Terlibat     : [yellow]{total_requests}[/yellow]\n"
        f"• URI Unik yang Mencurigakan : [magenta]{unique_uris}[/magenta]\n"
        f"• Total ID MITRE Dikenali    : [red]{total_ids}[/red]\n"
        f"• Total Serangan Keseluruhan : [bold red]{total_attacks}[/bold red]\n"
        f"\n[bold]📍 Rekap Berdasarkan Severity:[/bold]\n{severity_summary}",
        title="🛡️ False Negative Detected", border_style="cyan"))

    table = Table(title="📌 Statistik 5 Teratas per MITRE ATT&CK", show_lines=True)
    table.add_column("MITRE ID", style="bold red")
    table.add_column("Kategori", style="magenta")
    table.add_column("Severity")
    table.add_column("Jumlah URI", justify="right")
    table.add_column("Total Requests", justify="right")
    table.add_column("Contoh Payload URI", style="green", no_wrap=False, overflow="fold")

    top_5 = sorted(mitre_summary.items(), key=lambda item: item[1]["count"], reverse=True)[:5]

    for mitre_id, data in top_5:
        category = MITRE_ATTACK_TYPES.get(mitre_id, "Unknown")
        severity = MITRE_SEVERITY_LEVEL.get(mitre_id, "INFO")
        severity_colored = Text(severity, style=get_severity_style(severity))
        sample_uris = ", ".join(data["uris"][:3])
        table.add_row(
            mitre_id,
            category,
            severity_colored,
            str(data["count"]),
            str(data["requests"]),
            sample_uris
        )

    console.print(table, width=console.width)

def load_json(file_path):
    with open(file_path, "r") as f:
        return json.load(f)

def main():
    parser = argparse.ArgumentParser(description="🔍 URI Summary + MITRE ATT&CK Hybrid Sync")
    parser.add_argument("json_file", help="Path ke file JSON dari OCI Firewall")
    args = parser.parse_args()

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        progress.add_task(description="📂 Membaca dan menganalisis data JSON...", total=None)
        data = load_json(args.json_file)
        mitre_summary = analyze_uris(data)

    fetch_all_techniques(mitre_summary.keys())
    display_summary(mitre_summary)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
osintbot - Advanced OSINT Aggregator
Aggregates: WHOIS, DNS, SSL Certs, Subdomains, HTTP Headers,
            Shodan (if key provided), Email harvesting, Pastebin leaks,
            Social media presence, IP geolocation, ASN info,
            Wayback Machine, GitHub dorking, Technology stack

Usage:
    python3 osintbot.py -t example.com
    python3 osintbot.py -t example.com --deep
    python3 osintbot.py -t example.com --shodan-key YOUR_KEY
    python3 osintbot.py --ip 8.8.8.8
    python3 osintbot.py -t example.com --output ./results

No API keys required for basic scan.
Optional: Shodan API key for extended intel.
"""

import argparse
import sys
import os
import re
import json
import socket
import ssl
import urllib.request
import urllib.parse
import urllib.error
import datetime
import time
import hashlib
import base64
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.rule import Rule
    from rich.tree import Tree
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.columns import Columns
    from rich.text import Text
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None
    print("[!] pip3 install rich  for better output\n")

OUTPUT_DIR = Path("osintbot_output")

BANNER = r"""
   ___  ____  _____  _   _ _____     ____  ___  ______ 
  / _ \/ ___||_   _|| \ | |_   _|   | __ )/ _ \|_   _|
 | | | \___ \  | |  |  \| | | |     |  _ \ | | | | |  
 | |_| |___) | | |  | |\  | | |     | |_) | |_| | | |  
  \___/|____/  |_|  |_| \_| |_|     |____/ \___/  |_|  

  Advanced OSINT Aggregator — No API keys required
  WHOIS · DNS · SSL · Subdomains · Geo · ASN · Leaks
"""

UA = "Mozilla/5.0 (compatible; osintbot/1.0; research)"

# ──────────────────────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def print_banner():
    if RICH:
        console.print(Panel(BANNER, style="bold magenta", border_style="magenta"))
    else:
        print(BANNER)

def info(msg):
    if RICH: console.print(f"[cyan]→[/cyan]  {msg}")
    else: print(f"[.] {msg}")

def success(msg):
    if RICH: console.print(f"[bold green]✔[/bold green]  {msg}")
    else: print(f"[+] {msg}")

def warn(msg):
    if RICH: console.print(f"[yellow]⚠[/yellow]  {msg}")
    else: print(f"[!] {msg}")

def error(msg):
    if RICH: console.print(f"[bold red]✘[/bold red]  {msg}")
    else: print(f"[-] {msg}")

def section(title):
    if RICH: console.print(Rule(f"[bold white] {title} [/bold white]", style="dim magenta"))
    else: print(f"\n{'='*60}\n  {title}\n{'='*60}")

def fetch(url, timeout=10, headers=None):
    """Simple HTTP GET, returns text or None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="replace")
    except Exception:
        return None

def run_cmd(cmd, timeout=30):
    import subprocess
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except Exception as e:
        return "", str(e), 1

def save(out_dir, filename, content):
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / filename
    with open(path, "w") as f:
        f.write(content if isinstance(content, str) else json.dumps(content, indent=2))
    return path

def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ──────────────────────────────────────────────────────────────────────────────
# MODULE 1 — WHOIS
# ──────────────────────────────────────────────────────────────────────────────

def module_whois(target):
    section("WHOIS LOOKUP")
    result = {}

    out, _, rc = run_cmd(f"whois {target} 2>/dev/null", timeout=15)
    if not out:
        warn("whois returned no data")
        return result

    save_raw = out
    patterns = {
        "Registrar":        r"Registrar:\s*(.+)",
        "Registered On":    r"(?:Creation Date|Created(?:On)?|Registered):\s*(.+)",
        "Expires On":       r"(?:Expir(?:y|ation|es) Date?|Expiry):\s*(.+)",
        "Updated On":       r"(?:Updated Date|Last Modified):\s*(.+)",
        "Name Servers":     r"Name Server:\s*(.+)",
        "Registrant Org":   r"Registrant\s*Org(?:anization)?:\s*(.+)",
        "Registrant Email": r"Registrant\s*Email:\s*(.+)",
        "Registrant Country":r"Registrant\s*Country:\s*(.+)",
        "Admin Email":      r"Admin\s*Email:\s*(.+)",
        "Tech Email":       r"Tech\s*Email:\s*(.+)",
        "Status":           r"(?:Domain\s*)?Status:\s*(.+)",
        "DNSSEC":           r"DNSSEC:\s*(.+)",
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, out, re.IGNORECASE)
        if matches:
            unique = list(dict.fromkeys([m.strip() for m in matches]))
            result[key] = unique[0] if len(unique) == 1 else unique

    if RICH:
        table = Table(title="WHOIS Data", border_style="dim", show_lines=False)
        table.add_column("Field", style="bold cyan", width=22)
        table.add_column("Value")
        for k, v in result.items():
            val = ", ".join(v) if isinstance(v, list) else str(v)
            table.add_row(k, val[:80])
        console.print(table)
    else:
        for k, v in result.items():
            print(f"  {k:<22} {v}")

    if result:
        success(f"WHOIS data collected — {len(result)} fields")

        # Privacy check
        if not result.get("Registrant Email") or "privacy" in str(result.get("Registrant Email","")).lower():
            warn("Registrant details hidden (WHOIS privacy enabled)")
        else:
            warn(f"Registrant email exposed: {result.get('Registrant Email')}")

    return result


# ──────────────────────────────────────────────────────────────────────────────
# MODULE 2 — DNS ENUMERATION
# ──────────────────────────────────────────────────────────────────────────────

def module_dns(target):
    section("DNS ENUMERATION")
    result = {"records": {}, "zone_transfer": False, "ipv4": [], "ipv6": []}

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR", "DMARC"]
    for rtype in record_types:
        query = f"_dmarc.{target}" if rtype == "DMARC" else target
        out, _, _ = run_cmd(f"dig +short {rtype} {query} 2>/dev/null", timeout=8)
        if out:
            records = [l.strip() for l in out.splitlines() if l.strip()]
            result["records"][rtype] = records
            if rtype == "A":
                result["ipv4"] = records
            elif rtype == "AAAA":
                result["ipv6"] = records

    # Zone transfer attempt
    ns_records = result["records"].get("NS", [])
    for ns in ns_records[:3]:
        ns = ns.rstrip(".")
        out, _, rc = run_cmd(f"dig axfr {target} @{ns} 2>/dev/null", timeout=10)
        if out and "Transfer failed" not in out and "connection refused" not in out.lower():
            if len(out.splitlines()) > 5:
                result["zone_transfer"] = True
                result["zone_transfer_data"] = out
                warn(f"ZONE TRANSFER SUCCESSFUL via {ns} — critical misconfiguration!")
                save(OUTPUT_DIR / target, "zone_transfer.txt", out)
                break

    if not result["zone_transfer"]:
        success("Zone transfer blocked (expected)")

    # SPF/DMARC analysis
    txt_records = result["records"].get("TXT", [])
    spf = [r for r in txt_records if "v=spf1" in r.lower()]
    dmarc = result["records"].get("DMARC", [])

    if spf:
        success(f"SPF record found: {spf[0][:80]}")
        if "+all" in spf[0]:
            warn("SPF uses +all — ANYONE can send email as this domain!")
        elif "~all" in spf[0]:
            warn("SPF uses ~all (softfail) — consider -all for strict mode")
    else:
        warn("No SPF record — domain vulnerable to email spoofing")

    if dmarc:
        success(f"DMARC record found")
    else:
        warn("No DMARC record — phishing/spoofing risk")

    if RICH:
        table = Table(title="DNS Records", border_style="dim")
        table.add_column("Type", style="bold cyan", width=8)
        table.add_column("Records")
        for rtype, records in result["records"].items():
            table.add_row(rtype, "\n".join(records[:3]))
        console.print(table)
    else:
        for rtype, records in result["records"].items():
            for r in records:
                print(f"  {rtype:<8} {r}")

    return result


# ──────────────────────────────────────────────────────────────────────────────
# MODULE 3 — SSL CERTIFICATE INTELLIGENCE
# ──────────────────────────────────────────────────────────────────────────────

def module_ssl(target):
    section("SSL CERTIFICATE INTELLIGENCE")
    result = {}

    # OpenSSL raw cert info
    out, _, _ = run_cmd(
        f"echo | openssl s_client -connect {target}:443 -servername {target} 2>/dev/null | "
        f"openssl x509 -noout -text 2>/dev/null",
        timeout=15
    )

    if out:
        # Extract fields
        patterns = {
            "Subject":      r"Subject:\s*(.+)",
            "Issuer":       r"Issuer:\s*(.+)",
            "Valid From":   r"Not Before:\s*(.+)",
            "Valid Until":  r"Not After\s*:\s*(.+)",
            "Serial":       r"Serial Number:\s*[\n\s]*([0-9a-f:]+)",
            "Signature":    r"Signature Algorithm:\s*(.+)",
            "SANs":         r"DNS:([^\s,]+)",
        }
        for key, pattern in patterns.items():
            matches = re.findall(pattern, out, re.IGNORECASE)
            if matches:
                result[key] = matches if key == "SANs" else matches[0].strip()

        # Check expiry
        if result.get("Valid Until"):
            try:
                exp_str = result["Valid Until"].strip()
                exp = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (exp - datetime.datetime.utcnow()).days
                result["Days Until Expiry"] = days_left
                if days_left < 0:
                    warn(f"Certificate EXPIRED {abs(days_left)} days ago!")
                elif days_left < 30:
                    warn(f"Certificate expires in {days_left} days — renew soon!")
                else:
                    success(f"Certificate valid for {days_left} more days")
            except Exception:
                pass

        # SANs = additional domains on same cert (goldmine for recon)
        sans = result.get("SANs", [])
        if sans:
            success(f"Found {len(sans)} Subject Alternative Names (SANs)")
            if RICH:
                console.print(f"[dim]SANs: {', '.join(sans[:15])}[/dim]")
            else:
                print(f"  SANs: {', '.join(sans[:10])}")
            result["related_domains"] = sans

    # crt.sh — certificate transparency logs (goldmine)
    info("Querying certificate transparency logs (crt.sh) ...")
    ct_data = fetch(f"https://crt.sh/?q={target}&output=json", timeout=15)
    ct_domains = []
    if ct_data:
        try:
            certs = json.loads(ct_data)
            for cert in certs:
                name = cert.get("name_value", "")
                for domain in name.split("\n"):
                    domain = domain.strip().lstrip("*.")
                    if domain and domain not in ct_domains:
                        ct_domains.append(domain)
            result["ct_domains"] = ct_domains[:50]
            success(f"Certificate transparency: {len(ct_domains)} unique domains found")
            if RICH:
                console.print(f"[dim]{', '.join(ct_domains[:20])}[/dim]")
        except Exception:
            warn("Could not parse crt.sh response")

    if RICH and result:
        table = Table(title="SSL Certificate", border_style="dim")
        table.add_column("Field", style="bold cyan", width=20)
        table.add_column("Value")
        skip = {"SANs", "ct_domains", "related_domains"}
        for k, v in result.items():
            if k not in skip:
                table.add_row(k, str(v)[:80])
        console.print(table)

    return result


# ──────────────────────────────────────────────────────────────────────────────
# MODULE 4 — SUBDOMAIN ENUMERATION
# ──────────────────────────────────────────────────────────────────────────────

def module_subdomains(target, deep=False):
    section("SUBDOMAIN ENUMERATION")
    result = {"subdomains": [], "alive": []}
    all_subs = set()

    # subfinder
    out, _, _ = run_cmd(f"subfinder -d {target} -silent 2>/dev/null", timeout=60)
    if out:
        for s in out.splitlines():
            all_subs.add(s.strip())
        success(f"subfinder: {len(all_subs)} subdomains")

    # crt.sh subdomains
    ct_data = fetch(f"https://crt.sh/?q=%.{target}&output=json", timeout=15)
    if ct_data:
        try:
            for cert in json.loads(ct_data):
                for name in cert.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{target}") or name == target:
                        all_subs.add(name)
        except Exception:
            pass
        success(f"After crt.sh: {len(all_subs)} subdomains")

    # HackerTarget API
    ht = fetch(f"https://api.hackertarget.com/hostsearch/?q={target}", timeout=10)
    if ht and "error" not in ht.lower():
        for line in ht.splitlines():
            parts = line.split(",")
            if parts:
                all_subs.add(parts[0].strip())
        success(f"After HackerTarget: {len(all_subs)} subdomains")

    # AlienVault OTX
    otx = fetch(f"https://otx.alienvault.com/api/v1/indicators/domain/{target}/passive_dns", timeout=10)
    if otx:
        try:
            data = json.loads(otx)
            for entry in data.get("passive_dns", []):
                hostname = entry.get("hostname", "")
                if hostname.endswith(f".{target}"):
                    all_subs.add(hostname)
        except Exception:
            pass

    result["subdomains"] = sorted(all_subs)

    # Check which are alive
    if result["subdomains"]:
        info(f"Checking which of {len(result['subdomains'])} subdomains are alive ...")
        alive = []

        def check_alive(sub):
            try:
                socket.setdefaulttimeout(3)
                socket.gethostbyname(sub)
                return sub
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=30) as ex:
            futures = {ex.submit(check_alive, s): s for s in result["subdomains"]}
            for fut in as_completed(futures):
                res = fut.result()
                if res:
                    alive.append(res)

        result["alive"] = sorted(alive)
        success(f"{len(alive)} subdomains alive out of {len(result['subdomains'])}")

        if RICH:
            table = Table(title=f"Live Subdomains ({len(alive)})", border_style="dim")
            table.add_column("Subdomain", style="green")
            for s in alive[:30]:
                table.add_row(s)
            if len(alive) > 30:
                table.add_row(f"[dim]... {len(alive)-30} more[/dim]")
            console.print(table)
        else:
            for s in alive[:20]:
                print(f"  {s}")

    save(OUTPUT_DIR / target, "subdomains.txt", "\n".join(result["subdomains"]))
    save(OUTPUT_DIR / target, "subdomains_alive.txt", "\n".join(result["alive"]))
    return result


# ──────────────────────────────────────────────────────────────────────────────
# MODULE 5 — IP GEOLOCATION & ASN
# ──────────────────────────────────────────────────────────────────────────────

def module_geo(target):
    section("IP GEOLOCATION & ASN INTELLIGENCE")
    result = {}

    # Resolve to IP first
    try:
        ip = socket.gethostbyname(target)
        result["resolved_ip"] = ip
        success(f"Resolved: {target} → {ip}")
    except Exception:
        ip = target
        result["resolved_ip"] = ip

    # ip-api.com (free, no key)
    geo = fetch(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,mobile,proxy,hosting,query", timeout=10)
    if geo:
        try:
            data = json.loads(geo)
            if data.get("status") == "success":
                fields = ["country", "regionName", "city", "zip", "lat", "lon",
                         "timezone", "isp", "org", "as", "asname", "reverse",
                         "mobile", "proxy", "hosting"]
                for f in fields:
                    if data.get(f):
                        result[f] = data[f]

                if RICH:
                    table = Table(title=f"Geolocation & ASN — {ip}", border_style="dim")
                    table.add_column("Field", style="bold cyan", width=16)
                    table.add_column("Value")
                    display = {
                        "Location": f"{data.get('city')}, {data.get('regionName')}, {data.get('country')}",
                        "Coordinates": f"{data.get('lat')}, {data.get('lon')}",
                        "Timezone": data.get("timezone", ""),
                        "ISP": data.get("isp", ""),
                        "Organization": data.get("org", ""),
                        "ASN": data.get("as", ""),
                        "AS Name": data.get("asname", ""),
                        "Reverse DNS": data.get("reverse", ""),
                        "Is Proxy/VPN": str(data.get("proxy", False)),
                        "Is Hosting/DC": str(data.get("hosting", False)),
                        "Is Mobile": str(data.get("mobile", False)),
                    }
                    for k, v in display.items():
                        if v and v != "None":
                            table.add_row(k, str(v))
                    console.print(table)
                else:
                    for k, v in result.items():
                        print(f"  {k:<16} {v}")

                if data.get("proxy"):
                    warn("IP is behind a proxy/VPN")
                if data.get("hosting"):
                    warn("IP is a hosting/datacenter IP")
        except Exception:
            pass

    # BGP/ASN info via bgpview
    asn_data = fetch(f"https://api.bgpview.io/ip/{ip}", timeout=10)
    if asn_data:
        try:
            data = json.loads(asn_data)
            prefixes = data.get("data", {}).get("prefixes", [])
            if prefixes:
                asn_info = []
                for p in prefixes[:3]:
                    asn_info.append({
                        "prefix": p.get("prefix"),
                        "asn": p.get("asn", {}).get("asn"),
                        "name": p.get("asn", {}).get("name"),
                        "description": p.get("asn", {}).get("description"),
                    })
                result["bgp_prefixes"] = asn_info
                success(f"BGP prefix info found: {asn_info[0].get('prefix')}")
        except Exception:
            pass

    # Shodan internetdb (free, no key needed)
    shodan_free = fetch(f"https://internetdb.shodan.io/{ip}", timeout=10)
    if shodan_free:
        try:
            data = json.loads(shodan_free)
            result["shodan_free"] = {
                "open_ports": data.get("ports", []),
                "hostnames":  data.get("hostnames", []),
                "cpes":       data.get("cpes", []),
                "vulns":      data.get("vulns", []),
                "tags":       data.get("tags", []),
            }
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            if ports:
                success(f"Shodan (free): open ports {ports}")
            if vulns:
                warn(f"Shodan CVEs found: {', '.join(vulns[:5])}")
                result["cves"] = vulns
        except Exception:
            pass

    return result


# ──────────────────────────────────────────────────────────────────────────────
# MODULE 6 — EMAIL & BREACH INTELLIGENCE
# ──────────────────────────────────────────────────────────────────────────────

def module_email_intel(target):
    section("EMAIL & BREACH INTELLIGENCE")
    result = {"emails": [], "breach_hints": [], "paste_hits": []}

    # Hunter.io free (basic)
    info("Searching for email patterns ...")
    # Derive common email patterns from domain
    common_patterns = [
        f"admin@{target}", f"info@{target}", f"contact@{target}",
        f"security@{target}", f"support@{target}", f"abuse@{target}",
        f"webmaster@{target}", f"postmaster@{target}", f"noreply@{target}",
    ]
    result["common_emails"] = common_patterns

    # Check MX records to confirm mail is active
    out, _, _ = run_cmd(f"dig +short MX {target}", timeout=8)
    if out:
        result["mail_active"] = True
        success(f"Mail server active: {out.splitlines()[0] if out.splitlines() else ''}")
    else:
        result["mail_active"] = False
        warn("No MX records — domain may not accept email")

    # DMARC/SPF already covered in DNS but flag here
    dmarc = fetch(f"https://emailrep.io/{target}", timeout=8)
    if dmarc:
        try:
            data = json.loads(dmarc)
            result["email_reputation"] = {
                "reputation": data.get("reputation"),
                "suspicious":  data.get("suspicious"),
                "references":  data.get("references"),
                "details":     data.get("details", {}),
            }
            rep = data.get("reputation", "unknown")
            susp = data.get("suspicious", False)
            if susp:
                warn(f"Domain flagged as suspicious by emailrep.io")
            else:
                success(f"Email reputation: {rep}")
        except Exception:
            pass

    # Pastebin/paste search via PasteHunter-style search
    info("Checking public paste sites for leaks ...")
    paste_sources = [
        f"https://psbdmp.ws/api/search/{target}",
    ]
    for url in paste_sources:
        data = fetch(url, timeout=10)
        if data and len(data) > 10:
            try:
                parsed = json.loads(data)
                if parsed:
                    result["paste_hits"].append({"source": url, "count": len(parsed) if isinstance(parsed, list) else 1})
                    warn(f"Paste site hit found for {target}!")
            except Exception:
                pass

    # GitHub dork search (public API)
    info("Searching GitHub for exposed secrets/code ...")
    gh_dorks = [
        f"https://api.github.com/search/code?q={target}+password&type=code",
        f"https://api.github.com/search/code?q={target}+api_key&type=code",
        f"https://api.github.com/search/code?q={target}+secret&type=code",
    ]
    gh_hits = []
    for url in gh_dorks:
        data = fetch(url, timeout=10, headers={"Accept": "application/vnd.github.v3+json"})
        if data:
            try:
                parsed = json.loads(data)
                count = parsed.get("total_count", 0)
                if count > 0:
                    keyword = re.search(r"q=.+\+(\w+)", url)
                    kw = keyword.group(1) if keyword else "unknown"
                    gh_hits.append({"keyword": kw, "count": count})
                    warn(f"GitHub: {count} results for '{target} {kw}'")
            except Exception:
                pass
        time.sleep(0.5)  # respect rate limits

    result["github_hits"] = gh_hits
    if gh_hits:
        if RICH:
            table = Table(title="GitHub Exposure", border_style="dim")
            table.add_column("Keyword", style="bold yellow")
            table.add_column("Results", justify="right")
            for h in gh_hits:
                table.add_row(h["keyword"], str(h["count"]))
            console.print(table)
    else:
        success("No obvious GitHub exposure found")

    return result


# ──────────────────────────────────────────────────────────────────────────────
# MODULE 7 — WEB INTELLIGENCE
# ──────────────────────────────────────────────────────────────────────────────

def module_web_intel(target):
    section("WEB INTELLIGENCE")
    result = {}

    # HTTP headers & tech stack
    info("Analysing HTTP headers & technology stack ...")
    for scheme in ["https", "http"]:
        out, _, rc = run_cmd(f"curl -sIL --max-time 10 {scheme}://{target} 2>/dev/null", timeout=12)
        if out and rc == 0:
            result["headers"] = out
            result["scheme"] = scheme

            # Tech detection
            tech_sigs = {
                "nginx":       "Nginx",
                "apache":      "Apache",
                "iis":         "Microsoft IIS",
                "cloudflare":  "Cloudflare CDN",
                "cloudfront":  "AWS CloudFront",
                "fastly":      "Fastly CDN",
                "akamai":      "Akamai CDN",
                "php":         "PHP",
                "asp.net":     "ASP.NET",
                "x-powered-by":"(see header)",
                "wordpress":   "WordPress",
                "drupal":      "Drupal",
                "joomla":      "Joomla",
                "django":      "Django",
                "express":     "Express.js",
                "laravel":     "Laravel",
                "rails":       "Ruby on Rails",
                "tomcat":      "Apache Tomcat",
            }
            techs = []
            for sig, label in tech_sigs.items():
                if sig.lower() in out.lower():
                    techs.append(label)

            # Extract X-Powered-By value
            xpb = re.search(r"X-Powered-By:\s*(.+)", out, re.IGNORECASE)
            if xpb:
                techs.append(f"X-Powered-By: {xpb.group(1).strip()}")

            result["technologies"] = techs
            if techs:
                success(f"Technologies: {', '.join(techs)}")
            break

    # Robots.txt
    info("Checking robots.txt ...")
    robots = fetch(f"https://{target}/robots.txt", timeout=8)
    if not robots:
        robots = fetch(f"http://{target}/robots.txt", timeout=8)
    if robots and len(robots) > 10:
        result["robots_txt"] = robots[:2000]
        disallowed = re.findall(r"Disallow:\s*(.+)", robots, re.IGNORECASE)
        result["disallowed_paths"] = [d.strip() for d in disallowed if d.strip()]
        success(f"robots.txt found — {len(result['disallowed_paths'])} disallowed paths")
        if result["disallowed_paths"]:
            interesting = [p for p in result["disallowed_paths"] if any(
                kw in p.lower() for kw in ["admin", "api", "backup", "config", "internal", "secret", "private"]
            )]
            if interesting:
                warn(f"Interesting disallowed paths: {', '.join(interesting[:5])}")

    # Sitemap
    sitemap = fetch(f"https://{target}/sitemap.xml", timeout=8)
    if sitemap and "<url>" in sitemap:
        urls = re.findall(r"<loc>(.+?)</loc>", sitemap)
        result["sitemap_urls"] = len(urls)
        success(f"Sitemap found — {len(urls)} URLs")

    # Security.txt
    sectxt = fetch(f"https://{target}/.well-known/security.txt", timeout=8)
    if sectxt and len(sectxt) > 10:
        result["security_txt"] = sectxt[:500]
        success("security.txt found — bug bounty / disclosure policy present")
        if RICH:
            console.print(Panel(sectxt[:300], title="security.txt", border_style="dim green"))

    # Wayback Machine — historical snapshots
    info("Checking Wayback Machine ...")
    wb = fetch(f"http://archive.org/wayback/available?url={target}", timeout=10)
    if wb:
        try:
            data = json.loads(wb)
            snap = data.get("archived_snapshots", {}).get("closest", {})
            if snap.get("available"):
                result["wayback"] = {
                    "url": snap.get("url"),
                    "timestamp": snap.get("timestamp"),
                    "status": snap.get("status"),
                }
                success(f"Wayback Machine: last snapshot {snap.get('timestamp', '')[:8]}")
        except Exception:
            pass

    # Page title
    page = fetch(f"https://{target}", timeout=10)
    if not page:
        page = fetch(f"http://{target}", timeout=10)
    if page:
        title = re.search(r"<title[^>]*>(.+?)</title>", page, re.IGNORECASE | re.DOTALL)
        if title:
            result["page_title"] = title.group(1).strip()[:100]
            success(f"Page title: {result['page_title']}")

        # Meta description
        desc = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']+)', page, re.IGNORECASE)
        if desc:
            result["meta_description"] = desc.group(1)[:200]

        # Check for login pages
        login_indicators = ["login", "signin", "sign-in", "authenticate", "password"]
        if any(kw in page.lower() for kw in login_indicators):
            result["has_login"] = True
            warn("Login page detected")

    return result


# ──────────────────────────────────────────────────────────────────────────────
# MODULE 8 — SHODAN (if API key provided)
# ──────────────────────────────────────────────────────────────────────────────

def module_shodan(ip, api_key):
    section("SHODAN INTELLIGENCE")
    result = {}

    if not api_key:
        info("No Shodan API key provided — using free internetdb instead")
        data = fetch(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if data:
            try:
                parsed = json.loads(data)
                result = parsed
                ports = parsed.get("ports", [])
                vulns = parsed.get("vulns", [])
                if RICH:
                    table = Table(title=f"Shodan Free — {ip}", border_style="dim")
                    table.add_column("Field", style="bold cyan")
                    table.add_column("Value")
                    table.add_row("Open Ports", str(ports))
                    table.add_row("Hostnames", str(parsed.get("hostnames", [])))
                    table.add_row("CPEs", str(parsed.get("cpes", []))[:80])
                    table.add_row("CVEs", f"[red]{', '.join(vulns[:5])}[/red]" if vulns else "None")
                    table.add_row("Tags", str(parsed.get("tags", [])))
                    console.print(table)
                if vulns:
                    warn(f"Known CVEs: {', '.join(vulns)}")
            except Exception:
                pass
        return result

    # Full Shodan API
    data = fetch(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}", timeout=15)
    if data:
        try:
            parsed = json.loads(data)
            result = {
                "ip": parsed.get("ip_str"),
                "org": parsed.get("org"),
                "isp": parsed.get("isp"),
                "asn": parsed.get("asn"),
                "country": parsed.get("country_name"),
                "city": parsed.get("city"),
                "ports": parsed.get("ports", []),
                "vulns": list(parsed.get("vulns", {}).keys()),
                "hostnames": parsed.get("hostnames", []),
                "tags": parsed.get("tags", []),
                "os": parsed.get("os"),
                "last_update": parsed.get("last_update"),
            }

            services = []
            for item in parsed.get("data", []):
                services.append({
                    "port": item.get("port"),
                    "transport": item.get("transport"),
                    "product": item.get("product", ""),
                    "version": item.get("version", ""),
                    "banner": item.get("data", "")[:100],
                })
            result["services"] = services

            if RICH:
                table = Table(title=f"Shodan — {ip}", border_style="dim")
                table.add_column("Field", style="bold cyan", width=18)
                table.add_column("Value")
                for k in ["ip", "org", "isp", "asn", "country", "city", "os", "ports", "tags"]:
                    if result.get(k):
                        table.add_row(k.title(), str(result[k])[:80])
                if result["vulns"]:
                    table.add_row("CVEs", f"[red]{', '.join(result['vulns'][:5])}[/red]")
                console.print(table)

            if result["vulns"]:
                warn(f"Shodan CVEs found: {', '.join(result['vulns'])}")
            success(f"Shodan: {len(result['ports'])} ports, {len(result['services'])} services")
        except Exception as e:
            error(f"Shodan API error: {e}")

    return result


# ──────────────────────────────────────────────────────────────────────────────
# FINAL REPORT
# ──────────────────────────────────────────────────────────────────────────────

def generate_report(target, out_dir, all_results):
    section("OSINT REPORT")
    now = timestamp()

    whois_r   = all_results.get("whois",    {})
    dns_r     = all_results.get("dns",      {})
    ssl_r     = all_results.get("ssl",      {})
    subs_r    = all_results.get("subs",     {})
    geo_r     = all_results.get("geo",      {})
    email_r   = all_results.get("email",    {})
    web_r     = all_results.get("web",      {})
    shodan_r  = all_results.get("shodan",   {})

    # Risk indicators
    risks = []
    if dns_r.get("zone_transfer"):
        risks.append("🔴 CRITICAL — DNS Zone Transfer allowed")
    if not [r for r in dns_r.get("records", {}).get("TXT", []) if "v=spf1" in r.lower()]:
        risks.append("🟠 HIGH — No SPF record (email spoofing risk)")
    if not dns_r.get("records", {}).get("DMARC"):
        risks.append("🟠 HIGH — No DMARC record")
    if ssl_r.get("Days Until Expiry", 999) < 30:
        risks.append(f"🟠 HIGH — SSL expires in {ssl_r.get('Days Until Expiry')} days")
    if email_r.get("github_hits"):
        risks.append(f"🟡 MEDIUM — GitHub exposure: {len(email_r['github_hits'])} keyword hits")
    if geo_r.get("shodan_free", {}).get("vulns"):
        risks.append(f"🔴 CRITICAL — Known CVEs: {', '.join(geo_r['shodan_free']['vulns'][:3])}")
    if web_r.get("disallowed_paths"):
        interesting = [p for p in web_r["disallowed_paths"] if any(
            kw in p.lower() for kw in ["admin", "api", "backup", "config"])]
        if interesting:
            risks.append(f"🟡 MEDIUM — Interesting paths in robots.txt: {', '.join(interesting[:3])}")

    # Terminal summary
    if RICH:
        console.print(Panel(
            f"[bold]Target:[/bold]         {target}\n"
            f"[bold]Scan Date:[/bold]      {now}\n"
            f"[bold]IP Address:[/bold]     {geo_r.get('resolved_ip', 'unknown')}\n"
            f"[bold]Location:[/bold]       {geo_r.get('city','?')}, {geo_r.get('country','?')}\n"
            f"[bold]ISP/Org:[/bold]        {geo_r.get('isp','unknown')}\n"
            f"[bold]ASN:[/bold]            {geo_r.get('as','unknown')}\n\n"
            f"[bold]Registrar:[/bold]      {whois_r.get('Registrar','unknown')}\n"
            f"[bold]Expires:[/bold]        {whois_r.get('Expires On','unknown')}\n\n"
            f"[bold]Subdomains:[/bold]     {len(subs_r.get('subdomains',[]))} found / {len(subs_r.get('alive',[]))} alive\n"
            f"[bold]CT Domains:[/bold]     {len(ssl_r.get('ct_domains',[]))}\n"
            f"[bold]Technologies:[/bold]   {', '.join(web_r.get('technologies',[]))[:60] or 'unknown'}\n\n"
            f"[bold]Risk Indicators:[/bold]\n" +
            "\n".join(f"  {r}" for r in risks) if risks else "  ✅ No major risks detected",
            title="[bold white]🔍 OSINT SUMMARY",
            border_style="magenta"
        ))
    else:
        print(f"\nOSINT REPORT — {target} — {now}")
        print(f"IP: {geo_r.get('resolved_ip')} | {geo_r.get('city')}, {geo_r.get('country')}")
        print(f"Subdomains: {len(subs_r.get('subdomains',[]))} | Alive: {len(subs_r.get('alive',[]))}")
        for r in risks:
            print(f"  {r}")

    # Markdown report
    lines = [
        f"# OSINTbot Report — {target}",
        f"\n**Date:** {now}  ",
        f"**Target:** `{target}`  ",
        f"**IP:** {geo_r.get('resolved_ip','unknown')}  ",
        f"**Location:** {geo_r.get('city','?')}, {geo_r.get('regionName','?')}, {geo_r.get('country','?')}\n",
        "---\n",
        "## Risk Summary\n",
    ]
    if risks:
        for r in risks:
            lines.append(f"- {r}")
    else:
        lines.append("- ✅ No major risks detected")

    lines += ["\n---\n", "## WHOIS\n"]
    for k, v in whois_r.items():
        lines.append(f"- **{k}:** {v}")

    lines += ["\n---\n", "## DNS Records\n"]
    for rtype, records in dns_r.get("records", {}).items():
        lines.append(f"- **{rtype}:** {', '.join(records[:5])}")
    lines.append(f"\n- **Zone Transfer:** {'⚠ VULNERABLE' if dns_r.get('zone_transfer') else 'Blocked'}")

    lines += ["\n---\n", "## SSL Certificate\n"]
    for k, v in ssl_r.items():
        if k not in ("SANs", "ct_domains", "related_domains"):
            lines.append(f"- **{k}:** {v}")
    if ssl_r.get("ct_domains"):
        lines.append(f"\n**CT Domains ({len(ssl_r['ct_domains'])}):**")
        for d in ssl_r["ct_domains"][:20]:
            lines.append(f"- `{d}`")

    lines += ["\n---\n", "## Subdomains\n"]
    lines.append(f"**Total:** {len(subs_r.get('subdomains',[]))} | **Alive:** {len(subs_r.get('alive',[]))}\n")
    for s in subs_r.get("alive", [])[:30]:
        lines.append(f"- `{s}`")

    lines += ["\n---\n", "## Geolocation & ASN\n"]
    for k in ["resolved_ip","country","regionName","city","isp","org","as","asname","reverse","proxy","hosting"]:
        if geo_r.get(k):
            lines.append(f"- **{k}:** {geo_r[k]}")
    if geo_r.get("shodan_free", {}).get("vulns"):
        lines.append(f"\n**CVEs:** {', '.join(geo_r['shodan_free']['vulns'])}")

    lines += ["\n---\n", "## Web Intelligence\n"]
    lines.append(f"- **Technologies:** {', '.join(web_r.get('technologies',[]))}")
    lines.append(f"- **Page Title:** {web_r.get('page_title','N/A')}")
    lines.append(f"- **security.txt:** {'Present' if web_r.get('security_txt') else 'Not found'}")
    lines.append(f"- **Wayback Machine:** {web_r.get('wayback',{}).get('timestamp','N/A')}")
    if web_r.get("disallowed_paths"):
        lines.append(f"\n**robots.txt disallowed paths:**")
        for p in web_r["disallowed_paths"][:20]:
            lines.append(f"- `{p}`")

    lines += ["\n---\n", "## Email & Leak Intelligence\n"]
    lines.append(f"- **Mail Active:** {email_r.get('mail_active', False)}")
    if email_r.get("github_hits"):
        lines.append(f"\n**GitHub Exposure:**")
        for h in email_r["github_hits"]:
            lines.append(f"- Keyword `{h['keyword']}`: {h['count']} results")

    lines += [f"\n---\n*Generated by osintbot — {now}*"]

    report_path = save(out_dir, "OSINT_REPORT.md", "\n".join(lines))
    save(out_dir, "osint_full.json", all_results)
    success(f"Report saved → {report_path}")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="osintbot — Advanced OSINT Aggregator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
EXAMPLES:
  Full OSINT on a domain:
    python3 osintbot.py -t example.com

  Deep scan (all modules):
    python3 osintbot.py -t example.com --deep

  IP address lookup:
    python3 osintbot.py --ip 8.8.8.8

  With Shodan API key:
    python3 osintbot.py -t example.com --shodan-key YOUR_KEY

  Custom output directory:
    python3 osintbot.py -t example.com --output ./intel

NOTE: No API keys required for basic scan.
      Optional: Shodan key at https://account.shodan.io
        """
    )
    parser.add_argument("-t", "--target",     help="Target domain (e.g. example.com)")
    parser.add_argument("--ip",               help="Target IP address for geo/ASN lookup")
    parser.add_argument("--deep",             action="store_true", help="Deep scan (all modules, slower)")
    parser.add_argument("--shodan-key",       help="Shodan API key for extended intel")
    parser.add_argument("--output",           help="Custom output directory")
    parser.add_argument("--no-subdomains",    action="store_true", help="Skip subdomain enumeration")

    args = parser.parse_args()
    print_banner()

    if not args.target and not args.ip:
        parser.print_help()
        sys.exit(0)

    target  = (args.target or args.ip or "").replace("https://", "").replace("http://", "").rstrip("/")
    out_dir = Path(args.output) if args.output else OUTPUT_DIR / target.replace("/", "_")
    out_dir.mkdir(parents=True, exist_ok=True)

    if RICH:
        console.print(f"[bold]Target:[/bold]  [magenta]{target}[/magenta]")
        console.print(f"[bold]Output:[/bold]  [dim]{out_dir}[/dim]")
        console.print(f"[bold]Mode:  [/bold]  {'[yellow]Deep[/yellow]' if args.deep else '[cyan]Standard[/cyan]'}\n")
        console.print(Panel(
            "[yellow]Only perform OSINT on targets you are authorized to investigate.\n"
            "Respect privacy laws (GDPR, etc.) in your jurisdiction.[/yellow]",
            title="⚠  Legal & Ethics Notice", border_style="yellow"
        ))
    else:
        print(f"Target: {target}\nOutput: {out_dir}\n")
        print("⚠  Only investigate targets you are authorized to research.\n")

    all_results = {}

    try:
        if args.target:
            all_results["whois"]  = module_whois(target)
            all_results["dns"]    = module_dns(target)
            all_results["ssl"]    = module_ssl(target)
            if not args.no_subdomains:
                all_results["subs"] = module_subdomains(target, args.deep)
            all_results["web"]    = module_web_intel(target)
            all_results["email"]  = module_email_intel(target)

        all_results["geo"]    = module_geo(args.ip or target)
        all_results["shodan"] = module_shodan(
            all_results["geo"].get("resolved_ip", target),
            args.shodan_key
        )

        generate_report(target, out_dir, all_results)

        section("COMPLETE")
        success(f"All intel saved to: {out_dir}/")
        if RICH:
            console.print("\n[bold]Output files:[/bold]")
            for f in sorted(out_dir.glob("*")):
                console.print(f"  [dim]📄[/dim] {f.name}")

    except KeyboardInterrupt:
        warn("\nScan interrupted.")
        sys.exit(0)


if __name__ == "__main__":
    main()

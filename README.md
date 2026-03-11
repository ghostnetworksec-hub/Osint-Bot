# osintbot 🔍
### Advanced OSINT Aggregator — No API Keys Required

---

## ⚡ Setup

```bash
# Only one optional dependency
pip3 install rich

# Run it
python3 osintbot.py -t example.com
```

**Zero API keys needed for full basic scan.**

---

## 🚀 Commands

```bash
# Full OSINT on a domain
python3 osintbot.py -t example.com

# Deep scan (all modules)
python3 osintbot.py -t example.com --deep

# IP address intel
python3 osintbot.py --ip 8.8.8.8

# With Shodan API key (more port/vuln data)
python3 osintbot.py -t example.com --shodan-key YOUR_KEY

# Skip subdomain enum (faster)
python3 osintbot.py -t example.com --no-subdomains

# Custom output folder
python3 osintbot.py -t example.com --output ./intel
```

---

## 🧠 What It Collects

| Module | What It Finds |
|---|---|
| **WHOIS** | Registrar, dates, registrant email, nameservers, DNSSEC |
| **DNS** | A/MX/NS/TXT/SOA/CAA/SRV records, zone transfer test, SPF/DMARC audit |
| **SSL** | Certificate details, expiry, SANs, CT log domains via crt.sh |
| **Subdomains** | subfinder + crt.sh + HackerTarget + AlienVault OTX — alive check |
| **Geolocation** | Country, city, ISP, ASN, BGP prefix, proxy/VPN/datacenter detection |
| **Shodan** | Open ports, CVEs, hostnames, CPEs (free internetdb or full API) |
| **Web Intel** | Tech stack, robots.txt, sitemap, security.txt, Wayback Machine |
| **Email Intel** | SPF/DMARC audit, email reputation, GitHub secret exposure |

---

## 📁 Output Files

```
osintbot_output/example.com/
├── subdomains.txt          ← All discovered subdomains
├── subdomains_alive.txt    ← Live subdomains only
├── zone_transfer.txt       ← Zone transfer data (if vulnerable)
├── osint_full.json         ← Complete raw data (JSON)
└── OSINT_REPORT.md         ← Full formatted report
```

---

## Optional: Shodan API Key

Get a free key at https://account.shodan.io — unlocks:
- Full port/service data
- CVE mapping per host
- Historical scan data
- Banner grabbing

```bash
python3 osintbot.py -t example.com --shodan-key abc123xyz
```

---

## ⚠️ Legal & Ethics

Only investigate targets you are **authorized** to research.
Respect privacy laws (GDPR, IT Act 2000, etc.) in your jurisdiction.

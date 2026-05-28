"""
scanner.py  –  SecLite Security Scanner
10 real-world pre-go-live security checks using free public APIs + socket/SSL
No paid API keys required.

pip install requests dnspython
"""

import socket, ssl, json, re, time
from datetime import datetime
from urllib.parse import urlparse
import requests

# ── helpers ────────────────────────────────────────────────────────────────────
def parse_host(target: str) -> dict:
    if not target.startswith("http"):
        target = "https://" + target
    p = urlparse(target)
    return {"hostname": p.hostname, "scheme": p.scheme, "port": p.port or (443 if p.scheme=="https" else 80), "url": target}

def severity(score: int) -> str:
    if score >= 80: return "Safe"
    if score >= 60: return "Low"
    if score >= 40: return "Medium"
    if score >= 20: return "High"
    return "Critical"

def safe_get(url, timeout=10, headers=None):
    try:
        r = requests.get(url, timeout=timeout, headers=headers or {}, allow_redirects=True)
        return r
    except Exception:
        return None

def google_dns(name: str, rtype: str):
    try:
        r = requests.get(f"https://dns.google/resolve?name={name}&type={rtype}", timeout=8)
        return r.json() if r.ok else {}
    except Exception:
        return {}

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK 1: DNS Security Analysis
# ══════════════════════════════════════════════════════════════════════════════
def check_dns(hostname: str) -> dict:
    a_rec   = google_dns(hostname, "A")
    mx_rec  = google_dns(hostname, "MX")
    txt_rec = google_dns(hostname, "TXT")
    ns_rec  = google_dns(hostname, "NS")

    has_a      = bool(a_rec.get("Answer"))
    has_mx     = bool(mx_rec.get("Answer"))
    has_ns     = bool(ns_rec.get("Answer"))
    has_dnssec = bool(a_rec.get("AD"))
    ips        = [r["data"] for r in a_rec.get("Answer", [])]
    txt_recs   = [r["data"] for r in txt_rec.get("Answer", [])]

    score = 10
    if has_a:      score += 20
    if has_mx:     score += 10
    if has_ns:     score += 15
    if has_dnssec: score += 40
    if txt_recs:   score += 5

    return {
        "id": "dns", "name": "DNS Security Analysis",
        "score": min(score, 100),
        "findings": [
            f"A records: {', '.join(ips[:3]) if ips else '✗ NONE FOUND'}",
            f"MX records: {'✓ Present' if has_mx else '✗ Missing – email not configured'}",
            f"NS records: {'✓ Present' if has_ns else '✗ Missing'}",
            f"DNSSEC: {'✓ Enabled' if has_dnssec else '✗ NOT enabled – DNS spoofing possible'}",
            f"TXT records: {len(txt_recs)} found",
        ],
        "recommendations": [
            "🔴 Enable DNSSEC immediately" if not has_dnssec else "✓ DNSSEC active",
            "Regularly audit DNS records",
            "Use DDoS-protected DNS (Cloudflare/Google)",
        ],
        "how_to_fix": [
            "Log in to DNS provider → Enable DNSSEC (usually 1-click)",
            "Publish DS record at your domain registrar",
            "Verify: dnssec-debugger.verisignlabs.com",
        ],
        "threat_impact": "Without DNSSEC, DNS cache poisoning silently redirects all users to attacker servers — enabling mass credential theft.",
        "references": [
            {"title": "ICANN DNSSEC Guide", "url": "https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en"},
        ]
    }

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK 2: SSL/TLS Certificate (SSL Labs API)
# ══════════════════════════════════════════════════════════════════════════════
def check_ssl(hostname: str, scheme: str, progress_cb=None) -> dict:
    if scheme != "https":
        return {
            "id": "ssl", "name": "SSL/TLS Certificate", "score": 2,
            "findings": ["✗ HTTP – NO encryption", "✗ All traffic (passwords, cookies) sent in plaintext", "✗ Man-in-the-middle trivially easy"],
            "recommendations": ["🔴 CRITICAL: Install SSL certificate NOW (free via Let's Encrypt)"],
            "how_to_fix": ["certbot certonly --standalone -d yourdomain.com", "Redirect HTTP → HTTPS (301)", "Add HSTS header"],
            "threat_impact": "HTTP exposes every user to credential theft and session hijacking. This is a critical pre-go-live blocker.",
            "references": [{"title": "Let's Encrypt", "url": "https://letsencrypt.org"}]
        }

    if progress_cb: progress_cb("Starting SSL Labs analysis (may take 60–90s for cold scan)...")

    # Try cached first
    try:
        r = requests.get(f"https://api.ssllabs.com/api/v3/analyze?host={hostname}&fromCache=on&all=done", timeout=15)
        data = r.json()
        if data.get("status") == "READY" and data.get("endpoints"):
            return _parse_ssl_labs(data, hostname)
    except Exception:
        pass

    # Start fresh
    try:
        requests.get(f"https://api.ssllabs.com/api/v3/analyze?host={hostname}&startNew=on", timeout=10)
        for i in range(18):
            time.sleep(5)
            if progress_cb: progress_cb(f"SSL Labs scanning... ({(i+1)*5}s)")
            r = requests.get(f"https://api.ssllabs.com/api/v3/analyze?host={hostname}&all=done", timeout=10)
            data = r.json()
            if data.get("status") == "READY":
                return _parse_ssl_labs(data, hostname)
            if data.get("status") == "ERROR":
                break
    except Exception:
        pass

    # Fallback: use Python ssl module
    return _check_ssl_python(hostname)

def _parse_ssl_labs(data, hostname):
    ep    = data["endpoints"][0]
    grade = ep.get("grade", "Unknown")
    det   = ep.get("details", {})
    protos = [f"{p['name']} {p['version']}" for p in det.get("protocols", [])]
    vulns  = []
    if det.get("heartbleed"): vulns.append("HEARTBLEED")
    if det.get("poodle"):     vulns.append("POODLE")
    if det.get("freak"):      vulns.append("FREAK")
    if det.get("logjam"):     vulns.append("LOGJAM")

    certs    = data.get("certs") or [det.get("cert", {})]
    cert     = certs[0] if certs else {}
    expiry   = datetime.fromtimestamp(cert.get("notAfter",0)/1000) if cert.get("notAfter") else None
    days_left = (expiry - datetime.now()).days if expiry else None

    g_score  = {"A+":100,"A":88,"B":65,"C":45,"D":28,"E":15,"F":5,"T":10,"M":12}
    score    = g_score.get(grade, 40)

    return {
        "id": "ssl", "name": "SSL/TLS Certificate",
        "score": score,
        "findings": [
            f"SSL Labs Grade: {grade}",
            f"Protocols: {', '.join(protos) or 'Unknown'}",
            f"Certificate expires: {expiry.strftime('%Y-%m-%d') if expiry else 'Unknown'} ({days_left} days)" if days_left else "Expiry unknown",
            f"HSTS: {'✓ Enabled' if det.get('hstsPolicy',{}).get('status')=='present' else '✗ NOT configured'}",
            f"Vulnerabilities: {', '.join(vulns) if vulns else '✓ None found'}",
        ],
        "recommendations": [
            f"Improve grade from {grade} to A+" if grade not in ("A","A+") else "✓ Good SSL grade",
            "Enable HSTS with preload directive" if det.get("hstsPolicy",{}).get("status") != "present" else "✓ HSTS active",
            f"URGENT: Renew certificate – {days_left} days left" if days_left and days_left < 60 else "✓ Certificate valid",
            "Patch SSL vulnerabilities: " + ", ".join(vulns) if vulns else "✓ No SSL CVEs",
        ],
        "how_to_fix": [
            f"Full report: https://www.ssllabs.com/ssltest/analyze.html?d={hostname}",
            "Config generator: ssl-config.mozilla.org",
            "Nginx HSTS: add_header Strict-Transport-Security \"max-age=63072000; includeSubDomains; preload\";",
        ],
        "threat_impact": f"Grade {grade} SSL configuration {'has active vulnerabilities. ' if vulns else ''}Weak TLS enables downgrade attacks and session interception.",
        "references": [{"title": f"SSL Labs Report for {hostname}", "url": f"https://www.ssllabs.com/ssltest/analyze.html?d={hostname}"}]
    }

def _check_ssl_python(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(8)
            s.connect((hostname, 443))
            cert = s.getpeercert()
            not_after = cert.get('notAfter') if cert else None
            expiry = None
            if isinstance(not_after, str):
                try:
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                except ValueError:
                    expiry = None
            days_left = (expiry - datetime.now()).days if expiry else None
            tls_ver = s.version()
        return {
            "id": "ssl", "name": "SSL/TLS Certificate", "score": 65,
            "findings": [
                "✓ SSL/TLS certificate valid",
                f"Protocol: {tls_ver}",
                f"Expires: {expiry.strftime('%Y-%m-%d')} ({days_left} days)" if expiry else "Expires: Unknown",
                "SSL Labs analysis timed out – run manually for full grade",
            ],
            "recommendations": ["Run SSL Labs test for full grade: ssllabs.com/ssltest", "Enable HSTS"],
            "how_to_fix": ["Visit ssllabs.com/ssltest for complete analysis"],
            "threat_impact": "Without full SSL Labs analysis, weak ciphers or vulnerabilities may be present.",
            "references": [{"title": "SSL Labs Test", "url": "https://www.ssllabs.com/ssltest/"}]
        }
    except ssl.SSLError as e:
        return {
            "id": "ssl", "name": "SSL/TLS Certificate", "score": 5,
            "findings": [f"✗ SSL Error: {str(e)}", "Certificate may be invalid, expired, or self-signed"],
            "recommendations": ["Fix SSL certificate immediately – pre-go-live blocker"],
            "how_to_fix": ["Check certificate at ssllabs.com/ssltest", "Replace with valid CA-signed certificate"],
            "threat_impact": "Invalid SSL certificates trigger browser security warnings, blocking all users and destroying trust.",
            "references": [{"title": "SSL Labs", "url": "https://www.ssllabs.com/ssltest/"}]
        }
    except Exception:
        return {
            "id": "ssl", "name": "SSL/TLS Certificate", "score": 30,
            "findings": ["Could not connect to port 443", "SSL analysis unavailable"],
            "recommendations": ["Verify HTTPS is properly configured", "Run: openssl s_client -connect hostname:443"],
            "how_to_fix": ["Check server is listening on port 443", "Verify firewall allows 443"],
            "threat_impact": "SSL verification failure is a critical pre-go-live blocker.",
            "references": []
        }

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK 3: HTTP Security Headers
# ══════════════════════════════════════════════════════════════════════════════
def check_headers(url: str) -> dict:
    r = safe_get(url, timeout=10)
    if not r:
        return {
            "id": "headers", "name": "HTTP Security Headers", "score": 5,
            "findings": ["✗ Could not fetch URL to inspect headers"],
            "recommendations": ["Verify site is accessible", "Check security headers at securityheaders.com"],
            "how_to_fix": ["Ensure site is publicly accessible", "Add all security headers in Nginx/Apache config"],
            "threat_impact": "Missing security headers are the #1 exploited misconfiguration category.",
            "references": [{"title": "SecurityHeaders.com", "url": "https://securityheaders.com"}]
        }

    headers = {k.lower(): v for k, v in r.headers.items()}
    checks = [
        ("content-security-policy",     "Content-Security-Policy (CSP)",     20),
        ("x-frame-options",              "X-Frame-Options",                   15),
        ("x-content-type-options",       "X-Content-Type-Options",            10),
        ("strict-transport-security",    "HSTS",                              20),
        ("referrer-policy",              "Referrer-Policy",                   10),
        ("permissions-policy",           "Permissions-Policy",                10),
        ("x-xss-protection",             "X-XSS-Protection",                   5),
    ]

    score    = 0
    found    = []
    missing  = []
    warnings = []

    for key, label, pts in checks:
        if key in headers:
            score += pts
            found.append(f"✓ {label}: {headers[key][:60]}")
            # Quality checks
            if key == "content-security-policy" and "unsafe-inline" in headers[key]:
                warnings.append(f"⚠ CSP contains 'unsafe-inline' — weakens XSS protection")
                score -= 8
            if key == "strict-transport-security" and "preload" not in headers[key]:
                warnings.append("⚠ HSTS missing 'preload' directive")
        else:
            missing.append(f"✗ {label} — MISSING")

    server = headers.get("server", "")
    if server:
        warnings.append(f"⚠ Server header exposes version: {server}")
        score -= 5
    x_powered = headers.get("x-powered-by", "")
    if x_powered:
        warnings.append(f"⚠ X-Powered-By exposes tech: {x_powered}")
        score -= 5

    return {
        "id": "headers", "name": "HTTP Security Headers",
        "score": max(0, min(score, 100)),
        "findings": missing[:5] + found[:4] + warnings[:3],
        "recommendations": [
            f"Add {len(missing)} missing security headers" if missing else "✓ All key headers present",
            "Remove Server and X-Powered-By headers to prevent fingerprinting",
            "Test final config at securityheaders.com",
        ],
        "how_to_fix": [
            "Nginx: add_header X-Frame-Options \"DENY\";",
            "Nginx: add_header X-Content-Type-Options \"nosniff\";",
            "Nginx: add_header Content-Security-Policy \"default-src 'self'\";",
            "Nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\";",
            "Nginx: server_tokens off;  # hides version",
        ],
        "threat_impact": "Missing security headers enable clickjacking, XSS, MIME sniffing, and referrer leakage — all trivially exploitable.",
        "references": [{"title": "Security Headers Scanner", "url": f"https://securityheaders.com/?q={url}"}]
    }

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK 4: Email Security (SPF / DKIM / DMARC)
# ══════════════════════════════════════════════════════════════════════════════
def check_email_security(hostname: str) -> dict:
    spf_data   = google_dns(hostname, "TXT")
    dmarc_data = google_dns(f"_dmarc.{hostname}", "TXT")
    dkim_data  = google_dns(f"default._domainkey.{hostname}", "TXT")

    spf_recs   = [r["data"] for r in spf_data.get("Answer", [])]
    dmarc_recs = [r["data"] for r in dmarc_data.get("Answer", [])]
    dkim_recs  = [r["data"] for r in dkim_data.get("Answer", [])]

    spf    = next((r for r in spf_recs   if r.startswith("v=spf1")), None)
    dmarc  = next((r for r in dmarc_recs if "v=DMARC1" in r), None)
    dkim   = bool(dkim_recs)
    p_val  = re.search(r"p=(\w+)", dmarc or "")
    policy = p_val.group(1) if p_val else "none"
    strong = policy in ("reject", "quarantine")

    score = 0
    if spf:    score += 30
    if dmarc:  score += 25
    if strong: score += 25
    if dkim:   score += 20

    return {
        "id": "email", "name": "Email Security (SPF/DKIM/DMARC)",
        "score": score,
        "findings": [
            f"SPF: {'✓ ' + spf[:60] if spf else '✗ MISSING — domain open to email spoofing'}",
            f"DMARC: {'✓ ' + dmarc[:60] if dmarc else '✗ MISSING — no email auth policy'}",
            f"DMARC enforcement: p={policy} {'✓ Strong' if strong else '⚠ Weak — upgrade to reject/quarantine'}" if dmarc else "✗ No DMARC policy",
            f"DKIM: {'✓ Detected at default selector' if dkim else '✗ Not found at default._domainkey'}",
        ],
        "recommendations": [
            "🔴 Add SPF record" if not spf else "✓ SPF present",
            "🔴 Add DMARC record" if not dmarc else f"{'✓' if strong else '⚠'} Upgrade DMARC to p=reject" if not strong else "✓ DMARC strong",
            "Configure DKIM via your email provider" if not dkim else "✓ DKIM detected",
        ],
        "how_to_fix": [
            f"SPF TXT: \"v=spf1 include:_spf.google.com ~all\"",
            f"DMARC TXT at _dmarc.{hostname}: \"v=DMARC1; p=quarantine; rua=mailto:dmarc@{hostname}\"",
            "DKIM: Enable in Google Workspace / Microsoft 365 settings",
            "Monitor at dmarcanalyzer.com",
        ],
        "threat_impact": "Without email auth records, anyone can send email appearing to come from your domain — enabling phishing attacks against your customers with zero technical barriers.",
        "references": [{"title": "MXToolbox Email Health", "url": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{hostname}&run=toolpage"}]
    }

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK 5: WHOIS / Domain Registration
# ══════════════════════════════════════════════════════════════════════════════
def check_whois(hostname: str) -> dict:
    domain = ".".join(hostname.split(".")[-2:])
    try:
        r = requests.get(f"https://rdap.org/domain/{domain}", timeout=10)
        data = r.json()
    except Exception:
        data = {}

    if not data or data.get("errorCode"):
        return {
            "id": "whois", "name": "WHOIS / Domain Registration", "score": 35,
            "findings": ["RDAP data unavailable or domain uses privacy protection", "Verify registration status manually"],
            "recommendations": ["Enable domain lock", "Set auto-renewal"],
            "how_to_fix": ["Log in to registrar → enable Transfer Lock", "Enable auto-renewal"],
            "threat_impact": "Expired or unlocked domains can be hijacked, redirecting all traffic to malicious sites.",
            "references": [{"title": "ICANN WHOIS", "url": f"https://lookup.icann.org/en/lookup?name={domain}"}]
        }

    events   = data.get("events", [])
    status   = data.get("status", [])
    reg_date = next((e["eventDate"] for e in events if e.get("eventAction") == "registration"), None)
    exp_date = next((e["eventDate"] for e in events if e.get("eventAction") == "expiration"), None)
    locked   = any("transfer-prohibited" in s for s in status)
    registrar_ent = next((e for e in data.get("entities", []) if "registrar" in e.get("roles", [])), None)
    registrar = "Unknown"
    if registrar_ent:
        vcard = registrar_ent.get("vcardArray", [None, []])[1]
        fn = next((v[3] for v in vcard if v[0] == "fn"), "Unknown")
        registrar = fn

    expiry     = datetime.fromisoformat(exp_date.replace("Z","")) if exp_date else None
    days_left  = (expiry - datetime.now()).days if expiry else None
    age_years  = round((datetime.now() - datetime.fromisoformat(reg_date.replace("Z",""))).days / 365, 1) if reg_date else None

    score = 15
    if locked:                           score += 35
    if days_left and days_left > 90:     score += 25
    elif days_left and days_left > 30:   score += 10
    if age_years and age_years > 2:      score += 15
    if reg_date:                         score += 10

    return {
        "id": "whois", "name": "WHOIS / Domain Registration",
        "score": min(score, 100),
        "findings": [
            f"Registrar: {registrar}",
            f"Registered: {reg_date[:10] if reg_date else 'Unknown'} ({age_years} years ago)" if age_years else "Registration date unknown",
            f"Expires: {expiry.strftime('%Y-%m-%d') if expiry else 'Unknown'} — {days_left} days remaining" if days_left else "Expiry unknown",
            f"Transfer Lock: {'✓ Active' if locked else '✗ INACTIVE — domain vulnerable to hijacking'}",
            f"Status: {', '.join(status[:3]) or 'unknown'}",
        ],
        "recommendations": [
            "🔴 Enable client-transfer-prohibited NOW" if not locked else "✓ Transfer lock active",
            f"🔴 URGENT: Renew domain — only {days_left} days left" if days_left and days_left < 60 else "✓ Domain not expiring soon",
            "Enable WHOIS privacy protection",
        ],
        "how_to_fix": [
            "Registrar dashboard → Domain Settings → Enable Transfer Lock",
            "Enable WHOIS Privacy / ID Protection",
            "Set up auto-renewal",
        ],
        "threat_impact": "Domain hijacking silently redirects all web and email traffic. Expiring domains are instantly snatched and monetized by squatters.",
        "references": [{"title": "RDAP WHOIS", "url": f"https://rdap.org/domain/{domain}"}]
    }

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK 6: URL / Domain Reputation (URLScan.io)
# ══════════════════════════════════════════════════════════════════════════════
def check_reputation(hostname: str) -> dict:
    try:
        r = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{hostname}&size=1", timeout=10)
        data = r.json()
        scan = data.get("results", [{}])[0] if data.get("results") else None
    except Exception:
        scan = None

    if not scan:
        return {
            "id": "reputation", "name": "URL / Domain Reputation", "score": 45,
            "findings": ["No URLScan.io data found", "Submit a scan at urlscan.io", "Check manually at virustotal.com"],
            "recommendations": ["Submit domain to URLScan.io", "Check VirusTotal and Google Safe Browsing"],
            "how_to_fix": ["Submit at urlscan.io/scan", "Register with Google Search Console"],
            "threat_impact": "Without reputation monitoring, malware injection or blacklisting may go undetected for weeks.",
            "references": [{"title": "URLScan.io", "url": f"https://urlscan.io/search/#domain:{hostname}"}]
        }

    malicious  = scan.get("verdicts", {}).get("overall", {}).get("malicious", False)
    rep_score  = scan.get("verdicts", {}).get("overall", {}).get("score", 0)
    tags       = scan.get("verdicts", {}).get("overall", {}).get("tags", [])
    scan_date  = scan.get("task", {}).get("time", "")[:10]

    score = 5 if malicious else max(50, 100 - rep_score)

    return {
        "id": "reputation", "name": "URL / Domain Reputation",
        "score": score,
        "findings": [
            f"URLScan.io: {'🔴 MALICIOUS CONTENT DETECTED' if malicious else '✓ No malicious verdict'}",
            f"Reputation score: {rep_score}/100",
            f"Tags: {', '.join(tags) if tags else 'None'}",
            f"Last scanned: {scan_date}",
        ],
        "recommendations": [
            "🔴 IMMEDIATE ACTION: Clean malware and submit blacklist removal requests" if malicious else "✓ No reputation issues",
            "Monitor at virustotal.com and urlvoid.com",
            "Deploy WAF (Cloudflare free tier)",
        ],
        "how_to_fix": (
            ["Scan: sitecheck.sucuri.net", "Remove malicious files", "Submit blacklist removal"] if malicious
            else ["Schedule monthly VirusTotal checks", "Set up Google Search Console alerts"]
        ),
        "threat_impact": "Blacklisted domains trigger browser red-screen warnings for ALL visitors, instantly destroying trust and organic traffic.",
        "references": [
            {"title": "URLScan.io Results", "url": f"https://urlscan.io/search/#domain:{hostname}"},
            {"title": "VirusTotal", "url": f"https://www.virustotal.com/gui/domain/{hostname}"},
        ]
    }

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK 7: Open Ports & Services
# ══════════════════════════════════════════════════════════════════════════════
def check_ports(hostname: str) -> dict:
    common_ports = [21, 22, 23, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 27017, 3389, 9200]
    port_names   = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",80:"HTTP",443:"HTTPS",3306:"MySQL",
                    5432:"PostgreSQL",6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",27017:"MongoDB",
                    3389:"RDP",9200:"Elasticsearch"}
    dangerous    = {21,23,3306,5432,6379,27017,3389,9200}

    open_ports  = []
    closed_count = 0

    for port in common_ports:
        try:
            s = socket.socket()
            s.settimeout(2)
            result = s.connect_ex((hostname, port))
            s.close()
            if result == 0:
                open_ports.append(port)
            else:
                closed_count += 1
        except Exception:
            closed_count += 1

    exposed_dangerous = [p for p in open_ports if p in dangerous]
    score = 85
    score -= len(exposed_dangerous) * 20
    score -= max(0, len(open_ports) - 2) * 5
    score = max(5, score)

    findings = []
    for p in open_ports:
        name = port_names.get(p, "Unknown")
        warn = " 🔴 DANGEROUS — should NOT be publicly exposed" if p in dangerous else " ✓"
        findings.append(f"Port {p} ({name}): OPEN{warn}")
    if not open_ports:
        findings.append("✓ No common dangerous ports found open")
    findings.append(f"Scanned {len(common_ports)} ports — {len(open_ports)} open, {closed_count} closed/filtered")

    return {
        "id": "ports", "name": "Open Ports & Network Exposure",
        "score": score,
        "findings": findings,
        "recommendations": [
            f"🔴 CLOSE DANGEROUS PORTS IMMEDIATELY: {', '.join(str(p)+'/'+port_names.get(p,'?') for p in exposed_dangerous)}" if exposed_dangerous else "✓ No dangerous ports exposed",
            "Firewall rule: allow only 80 and 443 from internet",
            "Restrict SSH to specific IP addresses only",
            "Use fail2ban to block brute-force attempts",
        ],
        "how_to_fix": [
            "sudo ufw default deny incoming && sudo ufw allow 443/tcp && sudo ufw allow 80/tcp",
            "sudo ufw allow from YOUR_OFFICE_IP to any port 22",
            "Block databases: sudo ufw deny 3306 && sudo ufw deny 5432 && sudo ufw deny 27017",
        ],
        "threat_impact": f"{'Exposed database/admin ports (' + ', '.join(str(p) for p in exposed_dangerous) + ') allow direct data exfiltration without going through application layer controls. ' if exposed_dangerous else ''}Each open port is a potential attack vector.",
        "references": [{"title": "Shodan Search", "url": f"https://www.shodan.io/search?query={hostname}"}]
    }

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK 8: Mixed Content & Redirect Chain
# ══════════════════════════════════════════════════════════════════════════════
def check_mixed_content(url: str, hostname: str) -> dict:
    try:
        r = requests.get(url, timeout=12, allow_redirects=True)
        content      = r.text[:30000]
        final_url    = r.url
        redirect_chain = len(r.history)
    except Exception:
        return {
            "id": "mixed", "name": "Mixed Content & Redirect Chain", "score": 35,
            "findings": ["Could not fetch page for analysis"],
            "recommendations": ["Ensure site is publicly accessible"],
            "how_to_fix": ["Check server logs for errors"],
            "threat_impact": "Mixed content and redirect issues compromise security and SEO.",
            "references": []
        }

    issues  = []
    score   = 80

    # Mixed content detection
    http_srcs = re.findall(r'src=["\']http://[^"\']+["\']', content)
    http_hrefs = re.findall(r'href=["\']http://[^"\']+["\']', content)
    if http_srcs:
        issues.append(f"🔴 Mixed content: {len(http_srcs)} HTTP src= attributes found — loads insecure resources")
        score -= min(30, len(http_srcs) * 8)
    if http_hrefs:
        issues.append(f"⚠ {len(http_hrefs)} HTTP href= links found — potential mixed content")
        score -= min(10, len(http_hrefs) * 3)

    # Redirect chain
    if redirect_chain > 3:
        issues.append(f"⚠ Long redirect chain: {redirect_chain} redirects — performance and SEO impact")
        score -= 10
    elif redirect_chain > 0:
        issues.append(f"✓ Redirect chain: {redirect_chain} step(s) — acceptable")

    # HTTP → HTTPS redirect check
    if url.startswith("https://") and final_url.startswith("https://"):
        issues.append("✓ Stays on HTTPS throughout")
    elif final_url.startswith("http://"):
        issues.append("🔴 Ends on HTTP — HTTPS redirect not working correctly")
        score -= 30

    # Cookie security
    set_cookie = r.headers.get("set-cookie", "")
    if set_cookie:
        if "secure" not in set_cookie.lower():
            issues.append("🔴 Session cookie missing 'Secure' flag — cookie sent over HTTP")
            score -= 20
        if "httponly" not in set_cookie.lower():
            issues.append("🔴 Session cookie missing 'HttpOnly' flag — accessible via JavaScript")
            score -= 15
        if "samesite" not in set_cookie.lower():
            issues.append("⚠ Cookie missing 'SameSite' attribute — CSRF risk")
            score -= 5
        if "secure" in set_cookie.lower() and "httponly" in set_cookie.lower():
            issues.append("✓ Cookie flags: Secure + HttpOnly present")

    if not issues:
        issues.append("✓ No mixed content detected")
        issues.append("✓ Redirect chain acceptable")

    return {
        "id": "mixed", "name": "Mixed Content & Cookie Security",
        "score": max(0, score),
        "findings": issues,
        "recommendations": [
            "Fix all mixed content — use protocol-relative URLs (//)",
            "Add Secure + HttpOnly + SameSite=Strict to all cookies",
            "Keep redirect chains to maximum 2 hops",
        ],
        "how_to_fix": [
            "Replace all http:// asset URLs with https:// or //",
            "Nginx cookie: add_header Set-Cookie \"...; Secure; HttpOnly; SameSite=Strict\"",
            "Or in app code: resp.set_cookie('name','val', secure=True, httponly=True, samesite='Strict')",
        ],
        "threat_impact": "Mixed content breaks HTTPS security entirely. Insecure cookies allow session hijacking over HTTP and via XSS.",
        "references": [{"title": "MDN Mixed Content", "url": "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content"}]
    }

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK 9: Content Security Policy Analysis
# ══════════════════════════════════════════════════════════════════════════════
def check_csp(url: str) -> dict:
    r = safe_get(url)
    if not r:
        return {
            "id": "csp", "name": "Content Security Policy (CSP)", "score": 5,
            "findings": ["✗ Could not fetch URL"], "recommendations": ["Add CSP header"],
            "how_to_fix": ["Add Content-Security-Policy header"], "threat_impact": "No CSP = full XSS exposure.",
            "references": []
        }

    headers  = {k.lower(): v for k, v in r.headers.items()}
    csp_hdr  = headers.get("content-security-policy", "")
    csp_ro   = headers.get("content-security-policy-report-only", "")
    csp      = csp_hdr or csp_ro

    score    = 0
    findings = []

    if not csp:
        findings.append("✗ NO Content-Security-Policy header — full XSS exposure")
        score = 5
    else:
        score += 40
        mode = "Report-Only mode ⚠" if not csp_hdr else "Enforcement mode ✓"
        findings.append(f"CSP present ({mode})")

        if "unsafe-inline" in csp:
            findings.append("⚠ 'unsafe-inline' present — significantly weakens XSS protection")
            score -= 15
        else:
            findings.append("✓ No 'unsafe-inline'")
            score += 15

        if "nonce-" in csp or "sha256-" in csp:
            findings.append("✓ Nonce/hash-based script whitelisting")
            score += 20
        if "'strict-dynamic'" in csp:
            findings.append("✓ 'strict-dynamic' enabled")
            score += 10
        if "report-uri" in csp or "report-to" in csp:
            findings.append("✓ CSP violation reporting configured")
            score += 10
        if "upgrade-insecure-requests" in csp:
            findings.append("✓ upgrade-insecure-requests directive")
            score += 5

    # Check for iframe embedding
    xfo = headers.get("x-frame-options", "")
    if not xfo and (not csp or "frame-ancestors" not in csp):
        findings.append("✗ No clickjacking protection (X-Frame-Options or frame-ancestors missing)")
        score -= 10

    return {
        "id": "csp", "name": "Content Security Policy (CSP)",
        "score": max(5, min(score, 100)),
        "findings": findings,
        "recommendations": [
            "Add strict CSP without unsafe-inline" if "unsafe-inline" in csp else ("✓ CSP is strict" if csp else "🔴 Add Content-Security-Policy header"),
            "Use nonce-based scripts instead of unsafe-inline",
            "Add report-uri to monitor CSP violations in production",
            "Add frame-ancestors 'none' to prevent clickjacking",
        ],
        "how_to_fix": [
            "Start: Content-Security-Policy-Report-Only: default-src 'self'",
            "Monitor violations at report-uri.com (free)",
            "Progress to: script-src 'nonce-{SERVER_RANDOM}' 'strict-dynamic'",
            "Test: csp-evaluator.withgoogle.com",
        ],
        "threat_impact": "Without CSP, any XSS vulnerability (in your code or third-party scripts) allows full account takeover, credential harvesting, and malware injection.",
        "references": [{"title": "CSP Evaluator", "url": "https://csp-evaluator.withgoogle.com"}]
    }

# ══════════════════════════════════════════════════════════════════════════════
#  CHECK 10: Technology Stack & Vulnerability Exposure
# ══════════════════════════════════════════════════════════════════════════════
def check_vulnerability_exposure(url: str, hostname: str) -> dict:
    r      = safe_get(url)
    score  = 55
    issues = []

    if r:
        headers   = {k.lower(): v for k, v in r.headers.items()}
        content   = r.text[:20000]
        status    = r.status_code

        # Server fingerprinting
        server = headers.get("server", "")
        if server:
            issues.append(f"⚠ Server version exposed: {server}")
            score -= 10
        x_powered = headers.get("x-powered-by", "")
        if x_powered:
            issues.append(f"⚠ Technology exposed: X-Powered-By: {x_powered}")
            score -= 10

        # Technology detection
        tech_patterns = [
            (r"wp-content|wp-includes|wordpress",    "WordPress detected",                    -5),
            (r"Drupal\.settings|drupal",             "Drupal detected",                       -5),
            (r"<meta[^>]+generator[^>]+Joomla",      "Joomla detected",                       -5),
            (r"laravel_session|X-Laravel",           "Laravel framework detected",              0),
            (r"ASP\.NET|__VIEWSTATE",                "ASP.NET detected",                       -5),
            (r"phpMyAdmin",                           "🔴 phpMyAdmin accessible — high risk!",  -35),
            (r"wp-login\.php",                       "⚠ WordPress login page accessible",      -15),
            (r"\.git/HEAD|git-sha",                   "🔴 .git directory EXPOSED!",             -40),
            (r"\.env\b",                              "🔴 .env file potentially accessible!",   -40),
            (r"/admin/|/administrator/",              "⚠ Admin panel accessible via crawl",    -10),
        ]
        for pattern, label, penalty in tech_patterns:
            if re.search(pattern, content, re.I):
                issues.append(label)
                score += penalty

        # Directory listing
        if re.search(r"Index of /|Parent Directory", content, re.I):
            issues.append("🔴 Directory listing ENABLED — exposes file structure")
            score -= 20

        # Detailed error pages
        if re.search(r"stack trace|sql syntax|ORA-[0-9]+|mysql_fetch|pg_query", content, re.I):
            issues.append("🔴 Detailed error messages exposed — reveals tech stack and query structure")
            score -= 20

        # Check common sensitive paths
        paths_to_check = ["/robots.txt", "/.well-known/security.txt"]
        has_security_txt = False
        for path in paths_to_check:
            try:
                tr = requests.get(f"https://{hostname}{path}", timeout=5)
                if tr.ok:
                    if "security.txt" in path:
                        has_security_txt = True
                        issues.append("✓ security.txt found — responsible disclosure policy present")
                        score += 5
            except Exception:
                pass
        if not has_security_txt:
            issues.append("⚠ No security.txt — consider adding responsible disclosure policy")
    else:
        issues.append("⚠ Could not fetch page — manual audit required")

    if not issues:
        issues.append("✓ No obvious technology fingerprints or vulnerabilities in surface scan")

    issues.append("⚠ Full assessment requires authenticated scan: Nikto, OWASP ZAP, OpenVAS")

    return {
        "id": "vulnerability", "name": "Technology Stack & Vulnerability Exposure",
        "score": max(5, min(score, 100)),
        "findings": issues,
        "recommendations": [
            "Remove server version from HTTP headers",
            "Protect all admin interfaces behind VPN or IP allowlist",
            "Remove .git, .env, and all debug paths from web root",
            "Disable directory listing",
            "Run: nikto -h " + url,
        ],
        "how_to_fix": [
            "Nginx: server_tokens off;  Apache: ServerTokens Prod",
            "Block paths: location ~ /\\.(git|env|htaccess) { deny all; return 404; }",
            "Disable directory listing: autoindex off;",
            "Full scan: nikto -h " + url,
            "OWASP ZAP: zaproxy.org (free, comprehensive)",
        ],
        "threat_impact": "Exposed tech stack lets attackers instantly look up known CVEs. Exposed .git or .env files leak source code, credentials, and database passwords. Admin panel exposure enables targeted brute-force attacks.",
        "references": [
            {"title": "OWASP Top 10", "url": "https://owasp.org/www-project-top-ten/"},
            {"title": "NIST CVE Database", "url": "https://nvd.nist.gov/vuln/search"},
        ]
    }

# ══════════════════════════════════════════════════════════════════════════════
#  NEWS FEED  — rotates fresh articles each call
# ══════════════════════════════════════════════════════════════════════════════
def fetch_cyber_news() -> list:
    import xml.etree.ElementTree as ET
    feeds = [
        ("https://feeds.feedburner.com/TheHackersNews",        "The Hacker News"),
        ("https://krebsonsecurity.com/feed/",                   "Krebs on Security"),
        ("https://www.darkreading.com/rss.xml",                 "Dark Reading"),
        ("https://securityaffairs.com/feed",                    "Security Affairs"),
        ("https://threatpost.com/feed/",                        "Threatpost"),
        ("https://www.schneier.com/blog/atom.xml",              "Schneier on Security"),
        ("https://isc.sans.edu/rssfeed_full.xml",               "SANS Internet Storm Center"),
        ("https://www.bleepingcomputer.com/feed/",              "BleepingComputer"),
    ]

    articles = []
    for feed_url, source in feeds:
        try:
            r = requests.get(feed_url, timeout=8, headers={"User-Agent": "SecLite/1.0"})
            if not r.ok:
                continue
            root = ET.fromstring(r.content)
            ns   = {"atom": "http://www.w3.org/2005/Atom"}
            # RSS
            for item in root.findall(".//item")[:2]:
                title   = item.findtext("title", "").strip()
                link    = item.findtext("link", "").strip()
                desc    = re.sub(r"<[^>]+>", "", item.findtext("description", "") or "").strip()[:200]
                pub     = item.findtext("pubDate", "")
                if title and link:
                    articles.append({
                        "title": title, "url": link, "summary": desc,
                        "source": source, "published": pub,
                        "category": _detect_cat(title),
                        "image": "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400&h=200&fit=crop"
                    })
            # Atom
            for entry in root.findall("atom:entry", ns)[:2]:
                title  = entry.findtext("atom:title", "", ns).strip()
                link_el = entry.find("atom:link", ns)
                link   = link_el.get("href","") if link_el is not None else ""
                summ   = re.sub(r"<[^>]+>","", entry.findtext("atom:summary","",ns) or "").strip()[:200]
                pub    = entry.findtext("atom:published","",ns)
                if title and link:
                    articles.append({
                        "title": title, "url": link, "summary": summ,
                        "source": source, "published": pub,
                        "category": _detect_cat(title),
                        "image": "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400&h=200&fit=crop"
                    })
        except Exception:
            continue

    # Shuffle so each refresh shows different order
    import random
    random.shuffle(articles)
    return articles[:20] if articles else _fallback_news()

def _detect_cat(title: str) -> str:
    t = title.lower()
    if "ransomware" in t:                          return "Ransomware"
    if "breach" in t or "leak" in t:               return "Breach"
    if "cve" in t or "vulnerabilit" in t or "zero-day" in t: return "Vulnerability"
    if "malware" in t or "phishing" in t:          return "Malware"
    if "patch" in t or "advisory" in t:            return "Advisory"
    return "Security"

def _fallback_news() -> list:
    return [
        {"title": "CISA Warns of Actively Exploited Enterprise Software Vulnerabilities", "url": "https://www.cisa.gov/news-events/cybersecurity-advisories", "summary": "CISA urges immediate patching of critical vulnerabilities being exploited in the wild.", "source": "CISA", "published": "", "category": "Advisory", "image": "https://images.unsplash.com/photo-1550751827-4bd374c3f58b?w=400&h=200&fit=crop"},
        {"title": "New Ransomware Group Targets Healthcare Organizations", "url": "https://www.darkreading.com", "summary": "A new RaaS operation demands millions from healthcare targets across multiple countries.", "source": "Dark Reading", "published": "", "category": "Ransomware", "image": "https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=400&h=200&fit=crop"},
        {"title": "Critical Zero-Day in VPN Software — Patch Immediately", "url": "https://thehackernews.com", "summary": "Emergency patch released for critical zero-day affecting millions of enterprise VPN users.", "source": "The Hacker News", "published": "", "category": "Vulnerability", "image": "https://images.unsplash.com/photo-1563013544-824ae1b704d3?w=400&h=200&fit=crop"},
        {"title": "State-Sponsored APT Group Breaches Government Networks", "url": "https://securityaffairs.com", "summary": "Nation-state actor compromises ministries across multiple countries in coordinated campaign.", "source": "Security Affairs", "published": "", "category": "Breach", "image": "https://images.unsplash.com/photo-1614064641938-3bbee52942c7?w=400&h=200&fit=crop"},
        {"title": "FBI: BEC Attacks Surge — $3B Lost in 2025", "url": "https://krebsonsecurity.com", "summary": "Business Email Compromise attacks at record levels, targeting CFOs and finance teams.", "source": "Krebs on Security", "published": "", "category": "Advisory", "image": "https://images.unsplash.com/photo-1516321318423-f06f85e504b3?w=400&h=200&fit=crop"},
        {"title": "50M Records Exposed in Social Platform Data Breach", "url": "https://threatpost.com", "summary": "Emails, phone numbers and hashed passwords leaked. Credential stuffing attacks expected.", "source": "Threatpost", "published": "", "category": "Breach", "image": "https://images.unsplash.com/photo-1504639725590-34d0984388bd?w=400&h=200&fit=crop"},
    ]

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN SCAN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════════════════════
def run_full_scan(target: str, progress_cb=None) -> dict:
    info = parse_host(target)
    hostname = info["hostname"]
    scheme   = info["scheme"]
    url      = info["url"]

    steps = [
        ("Resolving DNS records...",             lambda: check_dns(hostname)),
        ("Analysing SSL/TLS certificate...",     lambda: check_ssl(hostname, scheme, progress_cb)),
        ("Inspecting HTTP security headers...",  lambda: check_headers(url)),
        ("Checking email security (SPF/DKIM/DMARC)...", lambda: check_email_security(hostname)),
        ("Fetching WHOIS/RDAP data...",          lambda: check_whois(hostname)),
        ("Checking domain reputation...",         lambda: check_reputation(hostname)),
        ("Scanning open ports...",               lambda: check_ports(hostname)),
        ("Checking mixed content & cookies...",  lambda: check_mixed_content(url, hostname)),
        ("Analysing Content Security Policy...", lambda: check_csp(url)),
        ("Assessing vulnerability exposure...",  lambda: check_vulnerability_exposure(url, hostname)),
    ]

    modules = []
    for i, (step_msg, fn) in enumerate(steps):
        if progress_cb:
            pct = int((i / len(steps)) * 90) + 5
            progress_cb(step_msg, pct)
        result = fn()
        result["score"]    = max(2, min(100, result["score"]))
        result["severity"] = severity(result["score"])
        modules.append(result)

    overall = round(sum(m["score"] for m in modules) / len(modules))
    if progress_cb: progress_cb("Scan complete!", 100)

    return {
        "modules": modules,
        "overall_score": overall,
        "overall_severity": severity(overall),
        "target_url": url,
        "hostname": hostname,
        "scanned_at": datetime.now().isoformat(),
    }
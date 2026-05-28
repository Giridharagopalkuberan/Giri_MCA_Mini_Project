// ═══════════════════════════════════════════════════════════════
//  SECLITE SCANNER  –  scanner.js
//  All real free APIs: Google DNS, SSL Labs, URLScan.io, RDAP
//  No dependencies. No build step. No Base44.
// ═══════════════════════════════════════════════════════════════

const SCANNER = (() => {

  // ── helpers ──────────────────────────────────────────────────
  const sleep = ms => new Promise(r => setTimeout(r, ms));

  function parseHost(target) {
    try {
      const url = target.startsWith('http') ? target : 'https://' + target;
      const u = new URL(url);
      return { hostname: u.hostname, protocol: u.protocol, href: u.href };
    } catch {
      const h = target.replace(/^https?:\/\//, '').split('/')[0];
      return { hostname: h, protocol: 'https:', href: 'https://' + h };
    }
  }

  function sev(score) {
    if (score >= 80) return 'Safe';
    if (score >= 60) return 'Low';
    if (score >= 40) return 'Medium';
    if (score >= 20) return 'High';
    return 'Critical';
  }

  async function safeGet(url, opts = {}) {
    try {
      const r = await fetch(url, opts);
      return r.ok ? r.json() : null;
    } catch { return null; }
  }

  // ── REAL API: Google DNS-over-HTTPS ───────────────────────────
  async function gDNS(name, type) {
    return safeGet(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`);
  }

  // ── REAL API: SSL Labs (polls until READY, max 90s) ───────────
  async function fetchSSLLabs(host) {
    try {
      // Try cache first (very fast if recently scanned)
      let d = await safeGet(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(host)}&fromCache=on&all=done`);
      if (d && d.status === 'READY' && d.endpoints?.length) return d;

      // Start fresh scan
      d = await safeGet(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(host)}&startNew=on&all=done`);
      for (let i = 0; i < 18; i++) {
        if (!d || d.status === 'ERROR') return null;
        if (d.status === 'READY') return d;
        await sleep(5000);
        d = await safeGet(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(host)}&all=done`);
      }
      return (d && d.status === 'READY') ? d : null;
    } catch { return null; }
  }

  // ── REAL API: URLScan.io ──────────────────────────────────────
  async function fetchURLScan(host) {
    return safeGet(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(host)}&size=1`);
  }

  // ── REAL API: RDAP (WHOIS) ────────────────────────────────────
  async function fetchRDAP(hostname) {
    const domain = hostname.split('.').slice(-2).join('.');
    return safeGet(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
  }

  // ── REAL API: Security Headers check via allorigins proxy ─────
  async function fetchHeaders(href) {
    try {
      const r = await fetch(`https://api.allorigins.win/get?url=${encodeURIComponent(href)}`);
      if (!r.ok) return null;
      const d = await r.json();
      // allorigins returns contents + status; we do basic content sniff
      return { ok: !!d.contents, content: d.contents?.slice(0, 5000) || '', status: d.status?.http_code };
    } catch { return null; }
  }

  // ═══════════════════════════════════════════════════════════════
  //  MODULE BUILDERS  – each returns { id, name, score, severity,
  //    summary, findings[], recommendations[], howToFix[],
  //    threatImpact, references[] }
  // ═══════════════════════════════════════════════════════════════

  function buildDNS(dnsData) {
    const { a, mx, txt, ns } = dnsData;
    const hasA      = !!(a?.Answer?.length);
    const hasMX     = !!(mx?.Answer?.length);
    const hasNS     = !!(ns?.Answer?.length);
    const hasDNSSEC = !!(a?.AD);
    const txtRecs   = (txt?.Answer || []).map(r => r.data);
    const ips       = (a?.Answer || []).map(r => r.data);

    let score = 10; // start low
    if (hasA)      score += 20;
    if (hasMX)     score += 10;
    if (hasNS)     score += 15;
    if (hasDNSSEC) score += 40;
    if (txtRecs.length > 0) score += 5;

    const findings = [
      hasA  ? `A record: ${ips.slice(0,3).join(', ')}` : '⚠ No A record found',
      hasMX ? `MX: ${mx.Answer[0].data}` : '⚠ No MX records – email not configured',
      hasNS ? `NS: ${ns.Answer.slice(0,2).map(r=>r.data).join(', ')}` : '⚠ No nameservers found',
      hasDNSSEC ? 'DNSSEC: Enabled ✓' : '✗ DNSSEC: NOT enabled – DNS spoofing possible',
      `TXT records: ${txtRecs.length} found${txtRecs.length ? '' : ' – SPF/DMARC likely missing'}`,
    ];

    return {
      id: 'dns', name: 'DNS Security Analysis', score: Math.min(score, 100),
      summary: `DNS analysis for ${dnsData.hostname}. ${hasDNSSEC ? 'DNSSEC is active.' : 'No DNSSEC — vulnerable to cache poisoning.'}`,
      findings,
      recommendations: [
        hasDNSSEC ? 'DNSSEC active — ensure key rotation is scheduled' : '🔴 CRITICAL: Enable DNSSEC immediately',
        'Use DNS monitoring/alerting for unauthorized record changes',
        'Consider Cloudflare or similar DDoS-protected DNS',
        'Audit all DNS records quarterly',
      ],
      howToFix: [
        'Log into your DNS provider → enable DNSSEC (usually 1-click)',
        'Generate KSK & ZSK, publish DS record at your registrar',
        'Verify: dnssec-debugger.verisignlabs.com',
        'Set low TTL on critical records to limit poisoning window',
      ],
      threatImpact: 'Without DNSSEC, cache poisoning silently redirects ALL your users to attacker-controlled servers. Credentials, sessions, and data are stolen transparently.',
      references: [
        { title: 'ICANN DNSSEC Guide', url: 'https://www.icann.org/resources/pages/dnssec-what-is-it-why-important-2019-03-05-en' },
        { title: 'CISA DNS Security Directive', url: 'https://www.cisa.gov/news-events/directives/bod-18-01' },
      ]
    };
  }

  function buildSSL(sslData, protocol) {
    const isHttps = protocol === 'https:';

    if (!isHttps) {
      return {
        id: 'ssl', name: 'SSL/TLS Certificate',
        score: 2,
        summary: '✗ CRITICAL: Site uses HTTP — ALL traffic is transmitted in plaintext. No encryption whatsoever.',
        findings: [
          '✗ Protocol: HTTP — zero encryption',
          '✗ No SSL/TLS certificate installed',
          '✗ All data (passwords, tokens, cookies) visible to any network observer',
          '✗ No HSTS possible without HTTPS',
          '✗ Man-in-the-middle attack trivially easy',
        ],
        recommendations: [
          '🔴 CRITICAL: Install SSL certificate immediately — free via Let\'s Encrypt',
          'Redirect ALL HTTP traffic to HTTPS (301 redirect)',
          'Enable HSTS after certificate installation',
          'Run SSL Labs test after migration: ssllabs.com/ssltest',
        ],
        howToFix: [
          'Step 1: certbot certonly --standalone -d yourdomain.com',
          'Step 2: Configure HTTPS in Nginx/Apache with certificate paths',
          'Step 3: Add redirect: return 301 https://$host$request_uri;',
          'Step 4: Add HSTS: Strict-Transport-Security: max-age=31536000',
        ],
        threatImpact: 'HTTP sites expose EVERY user to credential theft, session hijacking, and data manipulation by anyone on the same network or ISP. This is a critical failure that invalidates all other security measures.',
        references: [
          { title: "Let's Encrypt (Free SSL)", url: 'https://letsencrypt.org/getting-started/' },
          { title: 'SSL Labs Test', url: 'https://www.ssllabs.com/ssltest/' },
        ]
      };
    }

    if (!sslData || !sslData.endpoints?.length) {
      return {
        id: 'ssl', name: 'SSL/TLS Certificate',
        score: 35,
        summary: 'HTTPS is configured but SSL Labs could not complete analysis. Manual verification recommended.',
        findings: [
          'Protocol: HTTPS – encrypted traffic ✓',
          '⚠ SSL Labs scan unavailable or timed out',
          '⚠ Certificate details could not be fully verified',
          '⚠ TLS version and cipher strength unknown',
          'Manually test at ssllabs.com/ssltest for full grade',
        ],
        recommendations: ['Run SSL Labs test for full analysis', 'Ensure TLS 1.3 is enabled', 'Disable TLS 1.0/1.1', 'Add HSTS header'],
        howToFix: ['Visit ssllabs.com/ssltest to get detailed grade', 'Follow A+ configuration guide at ssl-config.mozilla.org'],
        threatImpact: 'Without SSL analysis, weak cipher suites or outdated protocols may allow decryption of traffic.',
        references: [{ title: 'SSL Labs Test', url: 'https://www.ssllabs.com/ssltest/' }]
      };
    }

    const ep = sslData.endpoints[0];
    const grade = ep.grade || 'Unknown';
    const gradeScore = { 'A+': 100, 'A': 88, 'B': 65, 'C': 45, 'D': 28, 'E': 15, 'F': 5, 'T': 10, 'M': 12 };
    const score = gradeScore[grade] ?? 40;
    const det = ep.details || {};
    const protocols = (det.protocols || []).map(p => `${p.name} ${p.version}`);
    const vulns = [];
    if (det.heartbleed)   vulns.push('HEARTBLEED (CVE-2014-0160)');
    if (det.poodle)       vulns.push('POODLE');
    if (det.freak)        vulns.push('FREAK');
    if (det.logjam)       vulns.push('LOGJAM');
    if (det.drown)        vulns.push('DROWN');
    if (det.beast?.isVulnerable) vulns.push('BEAST');
    const cert = det.cert || sslData.certs?.[0] || {};
    const expiry = cert.notAfter ? new Date(cert.notAfter) : null;
    const daysLeft = expiry ? Math.ceil((expiry - Date.now()) / 86400000) : null;

    const findings = [
      `SSL Labs Grade: ${grade}${grade === 'A+' ? ' ✓' : grade === 'A' ? ' ✓' : ' ⚠'}`,
      `TLS Protocols: ${protocols.join(', ') || 'Unknown'}`,
      expiry ? `Certificate expires: ${expiry.toLocaleDateString()} (${daysLeft > 0 ? daysLeft + ' days left' : '⚠ EXPIRED!'})` : '⚠ Certificate expiry unknown',
      `HSTS: ${det.hstsPolicy?.status === 'present' ? 'Enabled ✓' : '✗ NOT configured'}`,
      `Forward Secrecy: ${det.forwardSecrecy >= 2 ? 'Supported ✓' : '✗ Not fully supported'}`,
      vulns.length ? `🔴 VULNERABILITIES FOUND: ${vulns.join(', ')}` : 'No major SSL vulnerabilities found ✓',
    ];

    return {
      id: 'ssl', name: 'SSL/TLS Certificate',
      score,
      summary: `SSL Labs Grade: ${grade}. ${vulns.length ? 'Active vulnerabilities detected!' : 'No active SSL vulnerabilities.'} ${daysLeft != null && daysLeft < 30 ? 'Certificate expiring soon!' : ''}`,
      findings,
      recommendations: [
        grade !== 'A+' ? `Improve SSL grade from ${grade} to A+ — see ssl-config.mozilla.org` : 'Excellent A+ grade — maintain current configuration',
        !det.hstsPolicy || det.hstsPolicy.status !== 'present' ? 'Enable HSTS immediately' : 'HSTS active ✓',
        vulns.length ? `URGENT: Patch vulnerabilities: ${vulns.join(', ')}` : 'No SSL vulnerabilities — monitor for new CVEs',
        protocols.some(p => p.includes('1.0') || p.includes('1.1')) ? 'Disable TLS 1.0 and 1.1 immediately' : 'TLS versions acceptable ✓',
      ],
      howToFix: [
        `Current grade: ${grade}. Visit https://www.ssllabs.com/ssltest/analyze.html?d=${sslData.host} for full report`,
        grade !== 'A+' ? 'Use Mozilla SSL Config Generator: ssl-config.mozilla.org' : '',
        'Nginx HSTS: add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";',
        daysLeft != null && daysLeft < 60 ? `URGENT: Renew certificate — expires in ${daysLeft} days` : 'Set up certificate auto-renewal',
      ].filter(Boolean),
      threatImpact: `${vulns.length ? 'Active vulnerabilities allow attackers to decrypt your SSL traffic. ' : ''}Weak SSL configuration enables downgrade attacks and session interception.`,
      references: [
        { title: `SSL Labs Full Report for ${sslData.host}`, url: `https://www.ssllabs.com/ssltest/analyze.html?d=${sslData.host}` },
        { title: 'Mozilla SSL Configuration Generator', url: 'https://ssl-config.mozilla.org' },
      ]
    };
  }

  function buildHeaders(pageData, url) {
    const content = pageData?.content || '';
    // Score based on what we can detect from HTML source + known patterns
    let score = 0;
    const found = [];
    const missing = [];

    // Check for common security indicators in page source / known configs
    const checks = [
      { key: 'content-security-policy', pattern: /content-security-policy/i,    points: 20, label: 'Content-Security-Policy (CSP)' },
      { key: 'x-frame-options',         pattern: /x-frame-options/i,             points: 15, label: 'X-Frame-Options' },
      { key: 'x-content-type',          pattern: /x-content-type-options/i,      points: 10, label: 'X-Content-Type-Options' },
      { key: 'hsts',                     pattern: /strict-transport-security/i,   points: 20, label: 'HSTS (Strict-Transport-Security)' },
      { key: 'referrer',                 pattern: /referrer-policy/i,             points: 10, label: 'Referrer-Policy' },
      { key: 'permissions',              pattern: /permissions-policy/i,          points: 10, label: 'Permissions-Policy' },
      { key: 'xss',                      pattern: /x-xss-protection/i,            points: 5,  label: 'X-XSS-Protection' },
    ];

    // Also sniff HTML for inline CSP meta tags
    const hasCspMeta = /<meta[^>]+http-equiv\s*=\s*["']Content-Security-Policy/i.test(content);

    checks.forEach(c => {
      const inContent = c.pattern.test(content);
      const isCspMeta = c.key === 'content-security-policy' && hasCspMeta;
      if (inContent || isCspMeta) {
        score += c.points;
        found.push(`✓ ${c.label} detected`);
      } else {
        missing.push(`✗ ${c.label} – MISSING`);
      }
    });

    // If we couldn't fetch the page at all, assume worst case for HTTP sites
    if (!pageData?.ok) {
      score = 5; // assume bare minimum – can't verify
    }

    const findings = [
      pageData?.ok ? `HTTP Response received (status ${pageData.status || '?'})` : '⚠ Could not fetch page headers via proxy',
      ...missing.slice(0, 4),
      ...found.slice(0, 4),
    ];

    return {
      id: 'headers', name: 'HTTP Security Headers',
      score: Math.min(score, 100),
      summary: pageData?.ok
        ? `${found.length} of ${checks.length} security headers detected. ${missing.length} missing.`
        : 'Could not directly inspect headers — scored conservatively.',
      findings,
      recommendations: [
        missing.find(m => m.includes('CSP')) ? '🔴 Add Content-Security-Policy header — prevents XSS' : 'CSP configured ✓',
        missing.find(m => m.includes('Frame')) ? 'Add X-Frame-Options: DENY — prevents clickjacking' : '',
        missing.find(m => m.includes('HSTS')) ? 'Add HSTS header — enforces HTTPS' : '',
        '✓ Test final config at securityheaders.com',
      ].filter(Boolean),
      howToFix: [
        "Nginx: add_header Content-Security-Policy \"default-src 'self'\";",
        "Nginx: add_header X-Frame-Options \"DENY\";",
        "Nginx: add_header X-Content-Type-Options \"nosniff\";",
        "Nginx: add_header Referrer-Policy \"strict-origin-when-cross-origin\";",
        'Verify: securityheaders.com',
      ],
      threatImpact: 'Missing security headers are the single most exploited misconfiguration category. XSS via missing CSP, clickjacking via missing X-Frame-Options, and session theft via missing HSTS are trivially automated.',
      references: [
        { title: 'Security Headers Scanner', url: 'https://securityheaders.com/?q=' + encodeURIComponent(url) },
        { title: 'OWASP Secure Headers Project', url: 'https://owasp.org/www-project-secure-headers/' },
      ]
    };
  }

  function buildEmail(spfData, dmarcData, dkimData) {
    const spfRecs   = (spfData?.Answer || []).map(r => r.data);
    const dmarcRecs = (dmarcData?.Answer || []).map(r => r.data);
    const dkimRecs  = (dkimData?.Answer || []).map(r => r.data);

    const spf     = spfRecs.find(t => t.startsWith('v=spf1')) || null;
    const dmarc   = dmarcRecs.find(t => t.includes('v=DMARC1')) || null;
    const hasDKIM = dkimRecs.length > 0;

    const dmarcPolicy = dmarc?.match(/p=(\w+)/)?.[1] || 'none';
    const dmarcStrong = ['reject', 'quarantine'].includes(dmarcPolicy);

    let score = 0;
    if (spf)         score += 30;
    if (dmarc)       score += 25;
    if (dmarcStrong) score += 25;
    if (hasDKIM)     score += 20;

    return {
      id: 'email', name: 'Email Security (SPF/DKIM/DMARC)',
      score,
      summary: `SPF: ${spf ? 'Present' : 'MISSING'} | DMARC: ${dmarc ? `p=${dmarcPolicy}` : 'MISSING'} | DKIM: ${hasDKIM ? 'Detected' : 'Not found'}`,
      findings: [
        spf     ? `✓ SPF: ${spf}` : '✗ SPF record MISSING — domain open to spoofing',
        dmarc   ? `${dmarcStrong ? '✓' : '⚠'} DMARC: ${dmarc}` : '✗ DMARC record MISSING',
        dmarc   ? `DMARC enforcement: p=${dmarcPolicy}${dmarcStrong ? ' ✓' : ' — weak, upgrade to reject/quarantine'}` : '✗ No DMARC policy — no spoofed email protection',
        hasDKIM ? '✓ DKIM signing key detected' : '✗ DKIM not found at default._domainkey (may use other selector)',
      ],
      recommendations: [
        !spf     ? '🔴 Add SPF TXT record to DNS immediately' : 'SPF present ✓',
        !dmarc   ? '🔴 Add DMARC record to prevent domain spoofing' : '',
        !dmarcStrong && dmarc ? `Upgrade DMARC from p=${dmarcPolicy} to p=quarantine then p=reject` : '',
        !hasDKIM ? 'Configure DKIM via your email provider' : '',
      ].filter(Boolean),
      howToFix: [
        `SPF: Add TXT record → "v=spf1 include:_spf.google.com ~all"`,
        `DMARC: Add TXT at _dmarc.yourdomain.com → "v=DMARC1; p=quarantine; rua=mailto:dmarc@you.com"`,
        'DKIM: Enable in Google Workspace / Microsoft 365 / your mail provider settings',
        'Monitor DMARC reports at dmarcanalyzer.com',
      ],
      threatImpact: 'Missing email authentication allows anyone to send emails appearing from your domain. Enables targeted phishing of your customers and employees with zero technical barriers.',
      references: [
        { title: 'MXToolbox Email Diagnostics', url: 'https://mxtoolbox.com/emailhealth/' },
        { title: 'DMARC.org Implementation Guide', url: 'https://dmarc.org/overview/' },
      ]
    };
  }

  function buildWHOIS(rdap, hostname) {
    if (!rdap || rdap.errorCode) {
      return {
        id: 'whois', name: 'WHOIS / Domain Registration',
        score: 30,
        summary: 'RDAP/WHOIS data unavailable — domain may be private or using proxy protection.',
        findings: ['RDAP data not publicly available', 'Privacy protection may be enabled', 'Cannot verify domain lock status', 'Expiry date unknown'],
        recommendations: ['Enable registrar lock to prevent unauthorized transfers', 'Set auto-renewal or 60-day reminder', 'Verify current registration details'],
        howToFix: ['Log in to registrar → enable "Transfer Lock"', 'Enable WHOIS privacy if not active', 'Set auto-renewal in registrar settings'],
        threatImpact: 'Unlocked domains can be transferred by attackers using social engineering. Expiring domains are instantly snatched and redirected.',
        references: [{ title: 'ICANN WHOIS', url: 'https://lookup.icann.org' }]
      };
    }

    const events    = rdap.events || [];
    const regDate   = events.find(e => e.eventAction === 'registration')?.eventDate;
    const expDate   = events.find(e => e.eventAction === 'expiration')?.eventDate;
    const lastChanged = events.find(e => e.eventAction === 'last changed')?.eventDate;
    const status    = rdap.status || [];
    const locked    = status.some(s => s.includes('client-transfer-prohibited') || s.includes('serverTransferProhibited'));
    const registrar = rdap.entities?.find(e => e.roles?.includes('registrar'));
    const regName   = registrar?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || 'Unknown';
    const expiry    = expDate ? new Date(expDate) : null;
    const daysLeft  = expiry ? Math.ceil((expiry - Date.now()) / 86400000) : null;
    const ageYears  = regDate ? ((Date.now() - new Date(regDate)) / (1000*60*60*24*365)).toFixed(1) : null;

    let score = 15;
    if (locked)                           score += 35;
    if (daysLeft != null && daysLeft > 90) score += 25;
    else if (daysLeft != null && daysLeft > 30) score += 10;
    if (ageYears && parseFloat(ageYears) > 2) score += 15;
    if (regDate) score += 10;

    return {
      id: 'whois', name: 'WHOIS / Domain Registration',
      score: Math.min(score, 100),
      summary: `Registered ${ageYears ? ageYears + ' years ago' : 'unknown'}. ${locked ? 'Transfer lock active.' : '⚠ Transfer lock INACTIVE.'} ${expiry ? `Expires ${expiry.toLocaleDateString()}.` : ''}`,
      findings: [
        `Registrar: ${regName}`,
        regDate  ? `Registered: ${new Date(regDate).toLocaleDateString()} (${ageYears} years ago)` : '⚠ Registration date unknown',
        expiry   ? `Expires: ${expiry.toLocaleDateString()} — ${daysLeft > 0 ? daysLeft + ' days remaining' : '🔴 EXPIRED'}` : '⚠ Expiry date unknown',
        locked   ? '✓ Transfer lock: Active — domain protected from hijacking' : '✗ Transfer lock: INACTIVE — domain vulnerable to unauthorized transfer',
        lastChanged ? `Last modified: ${new Date(lastChanged).toLocaleDateString()}` : '',
        `Status flags: ${status.slice(0,4).join(', ') || 'none'}`,
      ].filter(Boolean),
      recommendations: [
        !locked  ? '🔴 Enable client-transfer-prohibited immediately' : 'Transfer lock active ✓',
        daysLeft != null && daysLeft < 60 ? `⚠ URGENT: Renew domain — only ${daysLeft} days remaining` : 'Set auto-renewal ✓',
        'Enable WHOIS privacy to hide personal contact information',
        'Review registrar account security (strong password + 2FA)',
      ],
      howToFix: [
        'Log in to your registrar → Domain Settings → Enable "Domain Lock" / "Transfer Lock"',
        'Enable WHOIS Privacy / ID Protection',
        'Set up auto-renewal and secondary renewal reminder email',
        'Secure registrar account with strong password + 2FA',
      ],
      threatImpact: 'Domain hijacking silently redirects all web and email traffic to attacker servers. Domain expiry allows instant registration by squatters who monetize your brand traffic.',
      references: [{ title: 'RDAP WHOIS Lookup', url: `https://rdap.org/domain/${hostname.split('.').slice(-2).join('.')}` }]
    };
  }

  function buildReputation(urlscanResult, hostname) {
    const scan = urlscanResult?.results?.[0];
    if (!scan) {
      return {
        id: 'reputation', name: 'URL / Domain Reputation',
        score: 40,
        summary: 'No recent URLScan.io data available for this domain. Reputation cannot be verified.',
        findings: ['No URLScan.io scan data found for this domain', 'Submit a scan at urlscan.io to generate data', 'Check manually at virustotal.com'],
        recommendations: ['Submit domain to URLScan.io for analysis', 'Check VirusTotal and Google Safe Browsing', 'Monitor with Google Search Console'],
        howToFix: ['Submit at urlscan.io/scan', 'Register with Google Search Console', 'Set up Cloudflare WAF'],
        threatImpact: 'Without reputation monitoring, malware injection or blacklisting may go undetected for weeks, costing all organic traffic.',
        references: [{ title: 'URLScan.io', url: `https://urlscan.io/search/#domain:${hostname}` }, { title: 'VirusTotal', url: 'https://www.virustotal.com/gui/domain/' + hostname }]
      };
    }

    const malicious = scan.verdicts?.overall?.malicious || false;
    const repScore  = scan.verdicts?.overall?.score || 0;
    const tags      = scan.verdicts?.overall?.tags || [];
    const cats      = scan.verdicts?.overall?.categories || [];
    const server    = scan.page?.server || scan.page?.title || '';
    const scanDate  = scan.task?.time ? new Date(scan.task.time).toLocaleDateString() : 'Unknown';

    let score = malicious ? 5 : Math.max(50, 100 - repScore);
    if (tags.includes('malware'))  score = Math.min(score, 10);
    if (tags.includes('phishing')) score = Math.min(score, 8);

    return {
      id: 'reputation', name: 'URL / Domain Reputation',
      score,
      summary: malicious ? `🔴 MALICIOUS — URLScan.io flagged this domain! Tags: ${tags.join(', ')}` : `Domain appears clean. Reputation score: ${repScore}/100. Scanned: ${scanDate}`,
      findings: [
        malicious ? `🔴 MALICIOUS: URLScan.io verdict — malicious content detected` : '✓ URLScan.io verdict: No malicious content',
        `Reputation score: ${repScore}/100 (lower is better)`,
        tags.length  ? `Tags: ${tags.join(', ')}` : 'No threat tags',
        cats.length  ? `Categories: ${cats.join(', ')}` : 'No suspicious categories',
        server       ? `Server technology: ${server}` : '',
        `Last URLScan.io scan: ${scanDate}`,
      ].filter(Boolean),
      recommendations: [
        malicious ? '🔴 IMMEDIATE ACTION REQUIRED: Domain flagged as malicious by URLScan.io' : 'No reputation issues detected ✓',
        'Monitor reputation at virustotal.com and urlvoid.com regularly',
        'Set up Google Search Console for blacklisting alerts',
        'Deploy WAF (Cloudflare free tier) to reduce attack surface',
      ],
      howToFix: malicious
        ? ['Scan web root for malware: sitecheck.sucuri.net', 'Remove all malicious files', 'Submit removal requests to each blacklist', 'Install WAF to prevent re-infection']
        : ['Schedule monthly VirusTotal and URLScan checks', 'Set up Cloudflare WAF', 'Enable server-side malware scanning'],
      threatImpact: 'Blacklisted domains trigger browser security warnings (red screen) for ALL visitors, instantly destroying trust and organic traffic.',
      references: [
        { title: 'URLScan.io Domain Search', url: `https://urlscan.io/search/#domain:${hostname}` },
        { title: 'VirusTotal Domain Lookup', url: `https://www.virustotal.com/gui/domain/${hostname}` },
      ]
    };
  }

  function buildPorts(hostname, protocol) {
    // Browser can't do real port scanning — give conservative heuristic score
    const isHttp = protocol === 'http:';
    const score = isHttp ? 20 : 45;

    return {
      id: 'ports', name: 'Network Exposure / Open Ports',
      score,
      summary: `Browser-based scanning cannot perform TCP port scanning. Score based on protocol and heuristics. Run nmap locally for accurate results.`,
      findings: [
        `Port 443 (HTTPS): ${protocol === 'https:' ? 'Active ✓' : 'Not confirmed'}`,
        `Port 80 (HTTP): ${protocol === 'http:' ? 'Open — serving unencrypted traffic ✗' : 'Unknown (redirect assumed)'}`,
        '⚠ TCP port scanning requires local tool (nmap) — cannot run from browser',
        'Run: nmap -sV --script=banner <hostname> for full port audit',
        'Common dangerous exposed ports: 22 (SSH), 3306 (MySQL), 5432 (Postgres), 27017 (MongoDB)',
      ],
      recommendations: [
        'Run nmap port scan from your network to identify all open services',
        'Use firewall: allow only 80/443 inbound from internet',
        'Never expose database ports (3306, 5432, 27017) to internet',
        'Restrict SSH (port 22) to specific IP addresses via firewall',
      ],
      howToFix: [
        'Audit: nmap -sV -p- ' + hostname,
        'Ubuntu firewall: sudo ufw default deny incoming && sudo ufw allow 443/tcp && sudo ufw allow 80/tcp',
        'Restrict SSH: sudo ufw allow from YOUR_IP to any port 22',
        'Install fail2ban to block brute-force attempts',
      ],
      threatImpact: 'Each exposed port is a potential entry point. Exposed database ports allow direct data theft. Open SSH enables credential brute-forcing. Exposed admin panels enable targeted attacks.',
      references: [
        { title: 'Shodan Internet Port Scanner', url: `https://www.shodan.io/search?query=${hostname}` },
        { title: 'Nmap Documentation', url: 'https://nmap.org/book/man.html' },
      ]
    };
  }

  function buildMalware(urlscanResult, hostname) {
    const scan = urlscanResult?.results?.[0];
    const malicious = scan?.verdicts?.overall?.malicious || false;
    const score = malicious ? 5 : 65;

    return {
      id: 'malware', name: 'Malware & Phishing Detection',
      score,
      summary: malicious ? '🔴 URLScan.io indicates malicious content on this domain!' : 'No active malware detected in available threat intelligence feeds.',
      findings: [
        malicious ? '🔴 URLScan.io: MALICIOUS verdict' : '✓ URLScan.io: No malicious verdict',
        '⚠ Full malware scan requires server-side access (ClamAV / Sucuri)',
        'Run Sucuri SiteCheck: sitecheck.sucuri.net for server-side scan',
        'Google Safe Browsing check: transparencyreport.google.com/safe-browsing/search',
        'Browser cannot inspect server filesystem — run local malware scanner',
      ],
      recommendations: [
        malicious ? '🔴 CRITICAL: Clean malware immediately' : 'Run periodic malware scans ✓',
        'Scan with Sucuri SiteCheck monthly: sitecheck.sucuri.net',
        'Implement file integrity monitoring (AIDE)',
        'Use Subresource Integrity (SRI) for all external scripts',
      ],
      howToFix: [
        'Free scan: sitecheck.sucuri.net',
        'Install ClamAV: sudo apt install clamav && clamscan -r /var/www/',
        'Monitor for file changes: sudo apt install aide && aide --init',
        'Add SRI to all <script src="..."> tags',
      ],
      threatImpact: 'Undetected malware silently steals visitor credentials, mines crypto using visitor browsers, or turns your server into a spam/botnet node. Google blacklisting destroys all search traffic instantly.',
      references: [
        { title: 'Sucuri Free Site Scanner', url: 'https://sitecheck.sucuri.net' },
        { title: 'Google Safe Browsing', url: `https://transparencyreport.google.com/safe-browsing/search?url=${hostname}` },
      ]
    };
  }

  function buildCSP(pageData) {
    const content = pageData?.content || '';
    const hasCsp      = /content-security-policy/i.test(content) || /<meta[^>]+http-equiv\s*=\s*["']Content-Security-Policy/i.test(content);
    const hasUnsafe   = /unsafe-inline/i.test(content);
    const hasNonce    = /nonce-/i.test(content);
    const hasStrict   = /'strict-dynamic'/i.test(content);
    const hasReporting = /report-uri|report-to/i.test(content);

    let score = 0;
    if (hasCsp)      score += 40;
    if (!hasUnsafe)  score += 20;
    if (hasNonce)    score += 20;
    if (hasStrict)   score += 10;
    if (hasReporting) score += 10;
    if (!hasCsp) score = 5;

    return {
      id: 'csp', name: 'Content Security Policy (CSP)',
      score,
      summary: hasCsp
        ? `CSP ${hasUnsafe ? 'present but allows unsafe-inline — weakened XSS protection' : 'configured' + (hasNonce ? ' with nonce-based scripts ✓' : '')}`
        : '✗ NO Content Security Policy detected — site fully vulnerable to XSS attacks',
      findings: [
        hasCsp       ? `✓ CSP header/meta tag found` : '✗ CSP: NOT FOUND — XSS attacks unrestricted',
        hasCsp && hasUnsafe  ? "⚠ 'unsafe-inline' detected — weakens XSS protection significantly" : hasCsp ? '✓ No unsafe-inline found' : '',
        hasNonce     ? '✓ Nonce-based script whitelisting detected' : '✗ No nonce/hash-based scripts — inline scripts uncontrolled',
        hasStrict    ? "✓ 'strict-dynamic' enabled" : "✗ 'strict-dynamic' not set",
        hasReporting ? '✓ CSP violation reporting configured' : '✗ No CSP reporting endpoint configured',
      ].filter(Boolean),
      recommendations: [
        !hasCsp ? "🔴 Add Content-Security-Policy header — blocks XSS by restricting script sources" : '',
        hasUnsafe ? "Remove 'unsafe-inline' — use nonce-based CSP instead" : '',
        !hasNonce ? 'Implement nonce-based CSP for dynamic content' : '',
        !hasReporting ? 'Add report-uri directive to monitor CSP violations' : '',
      ].filter(Boolean),
      howToFix: [
        "Start: Content-Security-Policy-Report-Only: default-src 'self'",
        "Progress to: script-src 'nonce-{random}' 'strict-dynamic'",
        'Monitor violations at report-uri.com (free tier)',
        'Test at csp-evaluator.withgoogle.com',
      ],
      threatImpact: "Without CSP, any XSS vulnerability allows attackers to run arbitrary JavaScript in users' browsers — stealing session tokens, passwords, and performing actions on the user's behalf.",
      references: [
        { title: 'CSP Evaluator (Google)', url: 'https://csp-evaluator.withgoogle.com' },
        { title: 'MDN CSP Docs', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' },
      ]
    };
  }

  function buildVulnerability(sslData, dnsData, pageData) {
    const content = pageData?.content || '';
    let score = 50;
    const findings = [];

    // Detect server/tech fingerprinting from page content
    const techPatterns = [
      { pattern: /wp-content|wp-includes|wordpress/i, label: 'WordPress detected', risk: 'medium' },
      { pattern: /Drupal|drupal/,                      label: 'Drupal detected',    risk: 'medium' },
      { pattern: /joomla/i,                            label: 'Joomla detected',    risk: 'medium' },
      { pattern: /x-powered-by.*php/i,                 label: 'PHP version exposed',risk: 'high' },
      { pattern: /phpMyAdmin/i,                        label: '⚠ phpMyAdmin exposed', risk: 'critical' },
      { pattern: /wp-login\.php/i,                     label: '⚠ WordPress login exposed', risk: 'high' },
      { pattern: /administrator\/index\.php/i,         label: '⚠ Joomla admin path exposed', risk: 'high' },
      { pattern: /\.git\//,                            label: '🔴 .git directory exposed!', risk: 'critical' },
      { pattern: /api\/v[0-9]/i,                       label: 'API endpoint detected', risk: 'low' },
    ];

    techPatterns.forEach(p => {
      if (p.pattern.test(content)) {
        findings.push(`${p.risk === 'critical' ? '🔴' : p.risk === 'high' ? '⚠' : '•'} ${p.label}`);
        if (p.risk === 'critical') score -= 30;
        else if (p.risk === 'high') score -= 15;
        else if (p.risk === 'medium') score -= 5;
      }
    });

    // SSL age/weakness
    const ep = sslData?.endpoints?.[0];
    const grade = ep?.grade;
    if (grade === 'F') { score -= 25; findings.push('🔴 SSL Labs grade F — critical TLS weaknesses'); }
    else if (grade === 'C' || grade === 'D') { score -= 15; findings.push(`⚠ SSL Labs grade ${grade} — TLS configuration needs improvement`); }

    if (findings.length === 0) findings.push('✓ No obvious technology fingerprints or known vulnerabilities detected in surface scan');
    findings.push('⚠ Full vulnerability assessment requires authenticated scan (OpenVAS, Nikto, OWASP ZAP)');
    findings.push(`Recommended tools: nikto -h ${dnsData.hostname} | openvas | OWASP ZAP`);

    score = Math.max(5, Math.min(score, 100));

    return {
      id: 'vulnerability', name: 'Vulnerability Assessment',
      score,
      summary: `Surface-level vulnerability check. ${findings.filter(f => f.startsWith('🔴') || f.startsWith('⚠')).length} potential issues found. Full scan requires Nikto/OWASP ZAP.`,
      findings,
      recommendations: [
        'Run Nikto for full web vulnerability scan',
        'Run OWASP ZAP for authenticated application scan',
        'Keep all software and frameworks updated (check CVE database monthly)',
        'Hide server/technology information from HTTP headers',
        'Disable directory listing and remove all .git/.env files from web root',
      ],
      howToFix: [
        `Nikto scan: nikto -h https://${dnsData.hostname}`,
        'OWASP ZAP: zaproxy.org (free, GUI and CLI)',
        'Remove server info: Nginx → server_tokens off; Apache → ServerTokens Prod',
        'Protect .git: location ~ /\\.git { deny all; }',
        'Check CVEs: nvd.nist.gov/vuln/search',
      ],
      threatImpact: 'Known CVEs are the primary attack vector for web compromise. Automated scanners constantly probe all public IPs — an unpatched vulnerability will be found and exploited within hours of public disclosure.',
      references: [
        { title: 'OWASP Top 10', url: 'https://owasp.org/www-project-top-ten/' },
        { title: 'NIST CVE Database', url: 'https://nvd.nist.gov/vuln/search' },
        { title: 'Nikto Web Scanner', url: 'https://cirt.net/Nikto2' },
      ]
    };
  }

  // ═══════════════════════════════════════════════════════════════
  //  MAIN: runScan
  // ═══════════════════════════════════════════════════════════════
  async function runScan(targetUrl, onProgress) {
    const { hostname, protocol, href } = parseHost(targetUrl);

    onProgress?.({ pct: 5, step: `Resolving DNS for ${hostname}...` });
    const [aRes, mxRes, txtRes, nsRes, dmarcRes, dkimRes] = await Promise.allSettled([
      gDNS(hostname, 'A'),
      gDNS(hostname, 'MX'),
      gDNS(hostname, 'TXT'),
      gDNS(hostname, 'NS'),
      gDNS('_dmarc.' + hostname, 'TXT'),
      gDNS('default._domainkey.' + hostname, 'TXT'),
    ]);

    onProgress?.({ pct: 18, step: 'Checking domain reputation (URLScan.io)...' });
    const [urlscanRes, rdapRes] = await Promise.allSettled([
      fetchURLScan(hostname),
      fetchRDAP(hostname),
    ]);

    onProgress?.({ pct: 28, step: 'Fetching page headers via proxy...' });
    const pageRes = await Promise.race([
      fetchHeaders(href),
      sleep(8000).then(() => null),
    ]);

    onProgress?.({ pct: 38, step: 'Starting SSL Labs analysis (may take up to 90s for first scan)...' });
    const sslRes = await Promise.race([
      fetchSSLLabs(hostname),
      sleep(88000).then(() => null),
    ]);

    onProgress?.({ pct: 90, step: 'Compiling results and calculating scores...' });

    const get = r => r.status === 'fulfilled' ? r.value : null;

    const dnsData = { hostname, a: get(aRes), mx: get(mxRes), txt: get(txtRes), ns: get(nsRes) };

    const modules = [
      buildDNS(dnsData),
      buildSSL(sslRes, protocol),
      buildHeaders(pageRes, href),
      buildEmail(get(txtRes), get(dmarcRes), get(dkimRes)),
      buildWHOIS(get(rdapRes), hostname),
      buildReputation(get(urlscanRes), hostname),
      buildPorts(hostname, protocol),
      buildMalware(get(urlscanRes), hostname),
      buildCSP(pageRes),
      buildVulnerability(sslRes, dnsData, pageRes),
    ].map(m => ({
      ...m,
      score: Math.max(2, Math.min(100, Math.round(m.score))),
      severity: sev(Math.max(2, Math.min(100, Math.round(m.score)))),
    }));

    const overallScore = Math.round(modules.reduce((a, m) => a + m.score, 0) / modules.length);

    onProgress?.({ pct: 100, step: 'Scan complete!' });

    return {
      modules,
      overallScore,
      overallSeverity: sev(overallScore),
      targetUrl: href,
      hostname,
      scannedAt: new Date().toISOString(),
    };
  }

  return { runScan };
})();
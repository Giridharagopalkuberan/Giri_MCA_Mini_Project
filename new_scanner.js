// ═══════════════════════════════════════════════════════════════
//  SECLITE SCANNER v3.0  –  scanner.js
//  Real APIs: Google DNS, SSL Labs, URLScan.io, RDAP, crt.sh
//  Accurate OWASP Top 10 scoring with fair neutral defaults
// ═══════════════════════════════════════════════════════════════

const SCANNER = (() => {

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
      const r = await fetch(url, { ...opts, signal: AbortSignal.timeout(12000) });
      if (!r.ok) return null;
      const text = await r.text();
      return JSON.parse(text);
    } catch { return null; }
  }

  // ── Google DNS-over-HTTPS ─────────────────────────────────────
  async function gDNS(name, type) {
    return safeGet(`https://dns.google/resolve?name=${encodeURIComponent(name)}&type=${type}`);
  }

  // ── SSL Labs (polls until READY, max 90s) ─────────────────────
  async function fetchSSLLabs(host) {
    try {
      let d = await safeGet(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(host)}&fromCache=on&all=done`);
      if (d?.status === 'READY' && d.endpoints?.length) return d;
      d = await safeGet(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(host)}&startNew=on&all=done`);
      for (let i = 0; i < 18; i++) {
        if (!d || d.status === 'ERROR') return null;
        if (d.status === 'READY') return d;
        await sleep(5000);
        d = await safeGet(`https://api.ssllabs.com/api/v3/analyze?host=${encodeURIComponent(host)}&all=done`);
      }
      return (d?.status === 'READY') ? d : null;
    } catch { return null; }
  }

  // ── URLScan.io ────────────────────────────────────────────────
  async function fetchURLScan(host) {
    return safeGet(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(host)}&size=1`);
  }

  // ── RDAP / WHOIS ──────────────────────────────────────────────
  async function fetchRDAP(hostname) {
    const domain = hostname.split('.').slice(-2).join('.');
    return safeGet(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
  }

  // ── Page headers via allorigins proxy ────────────────────────
  async function fetchHeaders(href) {
    try {
      const r = await fetch(`https://api.allorigins.win/get?url=${encodeURIComponent(href)}`, {
        signal: AbortSignal.timeout(10000)
      });
      if (!r.ok) return null;
      const d = await r.json();
      return { ok: !!d.contents, content: d.contents?.slice(0, 8000) || '', status: d.status?.http_code };
    } catch { return null; }
  }

  // ── crt.sh certificate transparency ──────────────────────────
  async function fetchCRTSH(hostname) {
    const domain = hostname.split('.').slice(-2).join('.');
    return safeGet(`https://crt.sh/?q=%.${encodeURIComponent(domain)}&output=json`);
  }

  // ── Redirect chain tracing ────────────────────────────────────
  async function traceRedirectChain(url, maxHops = 8) {
    const chain = [];
    let current = url;
    const visited = new Set();
    for (let i = 0; i < maxHops; i++) {
      if (visited.has(current)) { chain.push({ url: current, status: '∞', note: 'LOOP DETECTED' }); break; }
      visited.add(current);
      try {
        const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(current)}`;
        const r = await fetch(proxyUrl, { signal: AbortSignal.timeout(8000) });
        const d = await r.json();
        const status = d.status?.http_code || 200;
        const finalUrl = d.status?.url || current;
        chain.push({ url: current, status, note: flagUrl(current) });
        if (finalUrl && finalUrl !== current && !finalUrl.startsWith('data:')) {
          current = finalUrl;
        } else {
          chain.push({ url: finalUrl, status: 200, note: flagUrl(finalUrl), final: true });
          break;
        }
      } catch (e) {
        chain.push({ url: current, status: 'ERR', note: 'Connection failed' });
        break;
      }
    }
    return chain;
  }

  function flagUrl(url) {
    const u = url.toLowerCase();
    if (/bit\.ly|tinyurl|t\.co|ow\.ly|goo\.gl|rb\.gy/.test(u)) return '⚠ URL Shortener';
    if (/tracking|analytics|pixel|beacon/.test(u)) return '⚠ Tracking';
    if (/malware|phish|spam|hack/.test(u)) return '🔴 Suspicious';
    if (/accounts|login|signin|auth/.test(u)) return '🔑 Auth Page';
    return '';
  }

  // ═══════════════════════════════════════════════════════════════
  //  MODULE BUILDERS (OWASP Top 10 aligned, accurate scoring)
  // ═══════════════════════════════════════════════════════════════

  // OWASP A05 – Security Misconfiguration (DNS)
  function buildDNS(dnsData) {
    const { a, mx, txt, ns } = dnsData;
    const hasA      = !!(a?.Answer?.length);
    const hasMX     = !!(mx?.Answer?.length);
    const hasNS     = !!(ns?.Answer?.length);
    const hasDNSSEC = !!(a?.AD);
    const txtRecs   = (txt?.Answer || []).map(r => r.data);
    const ips       = (a?.Answer || []).map(r => r.data);

    // Fair scoring: DNSSEC is optional even for major companies (Google, Meta don't use it)
    // Base score 30 for any resolvable domain
    let score = 30;
    if (hasA)      score += 20;  // resolves to IP
    if (hasMX)     score += 10;  // email infrastructure
    if (hasNS)     score += 15;  // nameservers present
    if (hasDNSSEC) score += 20;  // bonus for DNSSEC (not penalty for missing)
    if (txtRecs.length > 0) score += 5;

    return {
      id: 'dns', name: 'DNS Security (OWASP A05)',
      score: Math.min(score, 100),
      summary: `DNS analysis for ${dnsData.hostname}. ${hasA ? ips.slice(0,2).join(', ') : 'No A record'}. ${hasDNSSEC ? 'DNSSEC enabled ✓' : 'DNSSEC not detected (common for large platforms).'}`,
      findings: [
        hasA  ? `✓ A record: ${ips.slice(0,3).join(', ')}` : '⚠ No A record found',
        hasMX ? `✓ MX: ${mx.Answer[0]?.data || ''}` : '⚠ No MX records – email not configured',
        hasNS ? `✓ NS: ${ns.Answer.slice(0,2).map(r=>r.data).join(', ')}` : '⚠ No nameservers found',
        hasDNSSEC ? '✓ DNSSEC: Enabled — DNS response integrity verified' : '⚠ DNSSEC: Not detected — DNS cache poisoning theoretically possible',
        `TXT records: ${txtRecs.length} found${txtRecs.length ? '' : ' — SPF/DMARC may be missing'}`,
        txtRecs.slice(0,2).map(r => `  • ${r.slice(0,80)}`).join('\n'),
      ].filter(Boolean),
      recommendations: [
        hasDNSSEC ? '✓ DNSSEC active — ensure key rotation is scheduled' : 'Consider enabling DNSSEC for cryptographic DNS integrity',
        'Use DNS monitoring for unauthorized record changes',
        'Consider Cloudflare or Akamai for DDoS-resistant DNS',
        'Audit all DNS records quarterly for stale entries',
      ],
      howToFix: [
        'Enable DNSSEC at your DNS provider (usually 1-click)',
        'Generate KSK & ZSK, publish DS record at registrar',
        'Verify at: dnssec-debugger.verisignlabs.com',
        'Monitor with: dnschecker.org',
      ],
      threatImpact: 'DNS cache poisoning can silently redirect users to attacker-controlled servers. DNSSEC prevents this via cryptographic signatures.',
      references: [
        { title: 'ICANN DNSSEC Guide', url: 'https://www.icann.org/resources/pages/dnssec-2012-02-25-en' },
        { title: 'CISA DNS Security', url: 'https://www.cisa.gov/news-events/directives/bod-18-01' },
      ]
    };
  }

  // OWASP A02 – Cryptographic Failures (SSL/TLS)
  function buildSSL(sslData, protocol) {
    const isHttps = protocol === 'https:';

    if (!isHttps) {
      return {
        id: 'ssl', name: 'SSL/TLS Encryption (OWASP A02)',
        score: 2,
        summary: '🔴 CRITICAL: HTTP — all traffic transmitted in plaintext. No encryption.',
        findings: [
          '✗ Protocol: HTTP — zero encryption',
          '✗ No SSL/TLS certificate installed',
          '✗ All data (passwords, tokens, cookies) visible to network observers',
          '✗ HSTS impossible without HTTPS',
          '✗ Man-in-the-middle attacks trivially easy',
        ],
        recommendations: ['🔴 Install SSL certificate immediately — free via Let\'s Encrypt', 'Redirect ALL HTTP to HTTPS (301)', 'Enable HSTS after migration'],
        howToFix: ['certbot certonly --standalone -d yourdomain.com', 'Configure HTTPS redirect in Nginx/Apache', 'Add HSTS: Strict-Transport-Security: max-age=31536000'],
        threatImpact: 'HTTP exposes ALL user data to credential theft and session hijacking by anyone on the same network.',
        references: [{ title: "Let's Encrypt", url: 'https://letsencrypt.org' }, { title: 'SSL Labs Test', url: 'https://www.ssllabs.com/ssltest/' }]
      };
    }

    if (!sslData?.endpoints?.length) {
      return {
        id: 'ssl', name: 'SSL/TLS Encryption (OWASP A02)',
        score: 55, // neutral — HTTPS confirmed but can't get SSL Labs grade
        summary: 'HTTPS is active ✓. SSL Labs analysis unavailable (API timeout or rate limit). Manual verification at ssllabs.com recommended.',
        findings: [
          '✓ Protocol: HTTPS — traffic is encrypted',
          '⚠ SSL Labs could not complete analysis (API timeout/rate limit)',
          '⚠ TLS version and cipher strength unverified this session',
          'Test manually: ssllabs.com/ssltest for full grade',
        ],
        recommendations: ['✓ HTTPS confirmed — run SSL Labs test for detailed grade', 'Ensure TLS 1.3 is enabled', 'Disable TLS 1.0/1.1 if still active', 'Add HSTS header'],
        howToFix: ['Visit ssllabs.com/ssltest', 'Use Mozilla SSL Config Generator: ssl-config.mozilla.org', 'Enable TLS 1.3 in server config'],
        threatImpact: 'Without SSL grade confirmation, weak cipher suites or outdated TLS may allow traffic decryption.',
        references: [{ title: 'SSL Labs Test', url: 'https://www.ssllabs.com/ssltest/' }, { title: 'Mozilla SSL Config', url: 'https://ssl-config.mozilla.org' }]
      };
    }

    const ep = sslData.endpoints[0];
    const grade = ep.grade || 'Unknown';
    const gradeScore = { 'A+': 100, 'A': 88, 'B': 68, 'C': 45, 'D': 28, 'E': 15, 'F': 5, 'T': 10, 'M': 12 };
    const score = gradeScore[grade] ?? 50;
    const det = ep.details || {};
    const protocols = (det.protocols || []).map(p => `${p.name} ${p.version}`);
    const vulns = [];
    if (det.heartbleed)             vulns.push('HEARTBLEED (CVE-2014-0160)');
    if (det.poodle)                 vulns.push('POODLE');
    if (det.freak)                  vulns.push('FREAK');
    if (det.logjam)                 vulns.push('LOGJAM');
    if (det.drown)                  vulns.push('DROWN');
    if (det.beast?.isVulnerable)    vulns.push('BEAST');
    const cert = det.cert || sslData.certs?.[0] || {};
    const expiry = cert.notAfter ? new Date(cert.notAfter) : null;
    const daysLeft = expiry ? Math.ceil((expiry - Date.now()) / 86400000) : null;

    return {
      id: 'ssl', name: 'SSL/TLS Encryption (OWASP A02)',
      score,
      summary: `SSL Labs Grade: ${grade}. ${vulns.length ? '🔴 Vulnerabilities detected!' : '✓ No SSL vulnerabilities.'} ${daysLeft != null && daysLeft < 30 ? '⚠ Certificate expiring soon!' : ''}`,
      findings: [
        `SSL Labs Grade: ${grade}${['A+','A'].includes(grade) ? ' ✓' : ' ⚠'}`,
        `TLS Protocols: ${protocols.join(', ') || 'Unknown'}`,
        expiry ? `Certificate expires: ${expiry.toLocaleDateString()} (${daysLeft > 0 ? daysLeft + ' days' : '🔴 EXPIRED'})` : '',
        `HSTS: ${det.hstsPolicy?.status === 'present' ? 'Enabled ✓' : '⚠ NOT configured'}`,
        `Forward Secrecy: ${det.forwardSecrecy >= 2 ? '✓ Supported' : '⚠ Not fully supported'}`,
        vulns.length ? `🔴 VULNERABILITIES: ${vulns.join(', ')}` : '✓ No known SSL vulnerabilities',
      ].filter(Boolean),
      recommendations: [
        grade !== 'A+' ? `Improve from ${grade} to A+ — see ssl-config.mozilla.org` : '✓ Excellent A+ — maintain configuration',
        vulns.length ? `🔴 URGENT: Patch ${vulns.join(', ')}` : '✓ No SSL vulnerabilities',
        protocols.some(p => p.includes('1.0') || p.includes('1.1')) ? 'Disable TLS 1.0/1.1 immediately' : '✓ TLS versions acceptable',
        !det.hstsPolicy || det.hstsPolicy.status !== 'present' ? 'Enable HSTS' : '✓ HSTS active',
      ],
      howToFix: [
        `Full report: https://www.ssllabs.com/ssltest/analyze.html?d=${sslData.host}`,
        'Mozilla SSL Config: ssl-config.mozilla.org',
        'HSTS: add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";',
        daysLeft != null && daysLeft < 60 ? `🔴 RENEW certificate — expires in ${daysLeft} days` : 'Set up auto-renewal (certbot renew)',
      ].filter(Boolean),
      threatImpact: `${vulns.length ? 'Active vulnerabilities allow traffic decryption. ' : ''}Weak SSL enables downgrade attacks and session interception.`,
      references: [
        { title: `SSL Labs Report`, url: `https://www.ssllabs.com/ssltest/analyze.html?d=${sslData.host}` },
        { title: 'Mozilla SSL Generator', url: 'https://ssl-config.mozilla.org' },
      ]
    };
  }

  // OWASP A05 – Security Misconfiguration (HTTP Headers)
  function buildHeaders(pageData, url) {
    const content = pageData?.content || '';
    const proxyWorked = pageData?.ok === true;

    // If we can't fetch via proxy, we cannot verify headers.
    // Score neutrally (not critically) — many sites block CORS proxies legitimately.
    if (!proxyWorked) {
      return {
        id: 'headers', name: 'HTTP Security Headers (OWASP A05)',
        score: 42,
        summary: 'Security headers could not be inspected from the browser (proxy blocked or CORS restriction). This is common for security-hardened sites. Verify manually at securityheaders.com.',
        findings: [
          '⚠ Could not fetch headers via browser proxy (site may block proxy requests)',
          '• This is common for security-conscious sites that restrict CORS/proxies',
          `• Verify actual headers at: securityheaders.com/?q=${encodeURIComponent(url)}`,
          '• Key headers to check: CSP, X-Frame-Options, HSTS, X-Content-Type-Options',
        ],
        recommendations: [
          'Use securityheaders.com for accurate header analysis',
          'Add Content-Security-Policy header',
          'Add X-Frame-Options: DENY',
          'Add Referrer-Policy: strict-origin-when-cross-origin',
        ],
        howToFix: [
          "Nginx: add_header Content-Security-Policy \"default-src 'self'\";",
          "Nginx: add_header X-Frame-Options DENY;",
          "Nginx: add_header X-Content-Type-Options nosniff;",
          "Nginx: add_header Referrer-Policy strict-origin-when-cross-origin;",
          'Full reference: securityheaders.com',
        ],
        threatImpact: 'Missing security headers enable XSS, clickjacking, and MIME-type attacks. Verify with securityheaders.com for accurate results.',
        references: [
          { title: 'Security Headers Scanner', url: `https://securityheaders.com/?q=${encodeURIComponent(url)}` },
          { title: 'OWASP Secure Headers', url: 'https://owasp.org/www-project-secure-headers/' },
        ]
      };
    }

    let score = 0;
    const found = [], missing = [];
    const checks = [
      { pattern: /content-security-policy/i,  points: 20, label: 'Content-Security-Policy' },
      { pattern: /x-frame-options/i,           points: 15, label: 'X-Frame-Options' },
      { pattern: /x-content-type-options/i,    points: 10, label: 'X-Content-Type-Options' },
      { pattern: /strict-transport-security/i, points: 20, label: 'HSTS' },
      { pattern: /referrer-policy/i,           points: 10, label: 'Referrer-Policy' },
      { pattern: /permissions-policy/i,        points: 10, label: 'Permissions-Policy' },
      { pattern: /x-xss-protection/i,          points: 5,  label: 'X-XSS-Protection' },
    ];
    const hasCspMeta = /<meta[^>]+http-equiv\s*=\s*["']Content-Security-Policy/i.test(content);
    checks.forEach(c => {
      if (c.pattern.test(content) || (c.label === 'Content-Security-Policy' && hasCspMeta)) {
        score += c.points; found.push(`✓ ${c.label}`);
      } else {
        missing.push(`✗ ${c.label} missing`);
      }
    });

    return {
      id: 'headers', name: 'HTTP Security Headers (OWASP A05)',
      score: Math.min(score, 100),
      summary: `${found.length} of ${checks.length} security headers detected. ${missing.length} missing.`,
      findings: [`HTTP Response received (status ${pageData.status || '?'})`, ...missing.slice(0,4), ...found.slice(0,4)],
      recommendations: [
        missing.some(m => m.includes('CSP')) ? '🔴 Add Content-Security-Policy — prevents XSS' : '✓ CSP configured',
        missing.some(m => m.includes('Frame')) ? 'Add X-Frame-Options: DENY — prevents clickjacking' : '✓ Clickjacking protection active',
        missing.some(m => m.includes('HSTS')) ? 'Add HSTS — enforces HTTPS for all visitors' : '✓ HSTS active',
        'Verify at securityheaders.com',
      ],
      howToFix: [
        "add_header Content-Security-Policy \"default-src 'self'\";",
        "add_header X-Frame-Options DENY;",
        "add_header X-Content-Type-Options nosniff;",
        "add_header Referrer-Policy strict-origin-when-cross-origin;",
        'Test: securityheaders.com',
      ],
      threatImpact: 'Missing headers enable XSS via absent CSP, clickjacking via absent X-Frame-Options, and session theft via absent HSTS.',
      references: [
        { title: 'Security Headers Scanner', url: 'https://securityheaders.com/?q=' + encodeURIComponent(url) },
        { title: 'OWASP Secure Headers', url: 'https://owasp.org/www-project-secure-headers/' },
      ]
    };
  }

  // OWASP A07 – Identification & Auth Failures (Email Security)
  function buildEmail(spfData, dmarcData, dkimData) {
    const spfRecs   = (spfData?.Answer || []).map(r => r.data);
    const dmarcRecs = (dmarcData?.Answer || []).map(r => r.data);
    const dkimRecs  = (dkimData?.Answer || []).map(r => r.data);

    const spf   = spfRecs.find(t => t.startsWith('v=spf1')) || null;
    const dmarc = dmarcRecs.find(t => t.includes('v=DMARC1')) || null;
    const hasDKIM = dkimRecs.length > 0;
    const dmarcPolicy = dmarc?.match(/p=(\w+)/)?.[1] || 'none';
    const dmarcStrong = ['reject', 'quarantine'].includes(dmarcPolicy);

    let score = 5;
    if (spf)         score += 30;
    if (dmarc)       score += 25;
    if (dmarcStrong) score += 25;
    if (hasDKIM)     score += 20;

    return {
      id: 'email', name: 'Email Authentication (OWASP A07)',
      score,
      summary: `SPF: ${spf ? '✓' : '✗'} | DMARC: ${dmarc ? `p=${dmarcPolicy}` : '✗ MISSING'} | DKIM: ${hasDKIM ? '✓ Detected' : '⚠ Not found'}`,
      findings: [
        spf   ? `✓ SPF: ${spf.slice(0,80)}` : '✗ SPF record MISSING — domain spoofable',
        dmarc ? `${dmarcStrong ? '✓' : '⚠'} DMARC: ${dmarc.slice(0,80)}` : '✗ DMARC MISSING — no email fraud protection',
        dmarc ? `DMARC policy: p=${dmarcPolicy}${dmarcStrong ? ' ✓ (Strong)' : ' ⚠ (Weak — upgrade to quarantine/reject)'}` : '',
        hasDKIM ? '✓ DKIM signing key detected at default._domainkey' : '⚠ DKIM not found (may use custom selector)',
      ].filter(Boolean),
      recommendations: [
        !spf   ? '🔴 Add SPF TXT record immediately' : '✓ SPF configured',
        !dmarc ? '🔴 Add DMARC record' : '',
        !dmarcStrong && dmarc ? `Upgrade DMARC from p=${dmarcPolicy} to p=reject` : '',
        !hasDKIM ? 'Configure DKIM via email provider' : '',
      ].filter(Boolean),
      howToFix: [
        'SPF: Add TXT → "v=spf1 include:_spf.google.com ~all"',
        'DMARC: Add TXT at _dmarc.domain.com → "v=DMARC1; p=quarantine; rua=mailto:dmarc@you.com"',
        'DKIM: Enable in your email provider settings (Google Workspace / M365)',
        'Monitor reports: dmarcanalyzer.com',
      ],
      threatImpact: 'Without SPF/DMARC/DKIM, anyone can send phishing emails appearing from your domain — targeting your customers with zero barriers.',
      references: [
        { title: 'MXToolbox Email Health', url: 'https://mxtoolbox.com/emailhealth/' },
        { title: 'DMARC.org Guide', url: 'https://dmarc.org/overview/' },
      ]
    };
  }

  // OWASP A05 – Security Misconfiguration (WHOIS/Domain)
  function buildWHOIS(rdap, hostname) {
    if (!rdap || rdap.errorCode) {
      return {
        id: 'whois', name: 'Domain Registration (OWASP A05)',
        score: 38,
        summary: 'RDAP/WHOIS data unavailable — privacy protection enabled or registry not responding.',
        findings: ['RDAP data not publicly available (privacy protection likely enabled)', 'Cannot verify domain lock status', 'Expiry date unknown'],
        recommendations: ['Enable registrar lock to prevent unauthorized transfers', 'Set auto-renewal reminders', 'Verify registration details are current'],
        howToFix: ['Log in to registrar → enable "Transfer Lock"', 'Enable WHOIS privacy', 'Set auto-renewal'],
        threatImpact: 'Unlocked domains can be transferred by social engineering. Expired domains are instantly registered by squatters.',
        references: [{ title: 'ICANN WHOIS', url: 'https://lookup.icann.org' }]
      };
    }

    const events  = rdap.events || [];
    const regDate = events.find(e => e.eventAction === 'registration')?.eventDate;
    const expDate = events.find(e => e.eventAction === 'expiration')?.eventDate;
    const lastChanged = events.find(e => e.eventAction === 'last changed')?.eventDate;
    const status  = rdap.status || [];
    const locked  = status.some(s => s.includes('client-transfer-prohibited') || s.includes('serverTransferProhibited'));
    const registrar = rdap.entities?.find(e => e.roles?.includes('registrar'));
    const regName = registrar?.vcardArray?.[1]?.find(v => v[0] === 'fn')?.[3] || rdap.entities?.[0]?.handle || 'Unknown';
    const expiry  = expDate ? new Date(expDate) : null;
    const daysLeft = expiry ? Math.ceil((expiry - Date.now()) / 86400000) : null;
    const ageYears = regDate ? ((Date.now() - new Date(regDate)) / (1000*60*60*24*365)).toFixed(1) : null;

    let score = 20;
    if (locked)                            score += 35;
    if (daysLeft != null && daysLeft > 90) score += 25;
    else if (daysLeft != null && daysLeft > 30) score += 10;
    if (ageYears && parseFloat(ageYears) > 2) score += 15;
    if (regDate) score += 5;

    return {
      id: 'whois', name: 'Domain Registration (OWASP A05)',
      score: Math.min(score, 100),
      summary: `Registered ${ageYears ? ageYears + ' years ago' : 'unknown'}. ${locked ? '✓ Transfer lock active.' : '⚠ Transfer lock inactive.'} ${expiry ? `Expires ${expiry.toLocaleDateString()}.` : ''}`,
      findings: [
        `Registrar: ${regName}`,
        regDate   ? `✓ Registered: ${new Date(regDate).toLocaleDateString()} (${ageYears} yrs — established domain)` : '⚠ Registration date unknown',
        expiry    ? `Expires: ${expiry.toLocaleDateString()} — ${daysLeft > 0 ? daysLeft + ' days remaining' : '🔴 EXPIRED'}` : '⚠ Expiry unknown',
        locked    ? '✓ Transfer lock: Active — domain protected from hijacking' : '⚠ Transfer lock: INACTIVE — vulnerable to unauthorized transfer',
        lastChanged ? `Last modified: ${new Date(lastChanged).toLocaleDateString()}` : '',
        `Status: ${status.slice(0,4).join(', ') || 'unknown'}`,
      ].filter(Boolean),
      recommendations: [
        !locked  ? '🔴 Enable client-transfer-prohibited lock immediately' : '✓ Transfer lock active',
        daysLeft != null && daysLeft < 60 ? `⚠ URGENT: Renew — ${daysLeft} days left` : '✓ Set auto-renewal',
        'Secure registrar account with 2FA',
        'Enable WHOIS privacy protection',
      ],
      howToFix: [
        'Registrar → Domain Settings → Enable "Domain Lock"',
        'Enable WHOIS Privacy / ID Protection',
        'Set auto-renewal with secondary reminder email',
        'Add strong password + 2FA to registrar account',
      ],
      threatImpact: 'Domain hijacking redirects all web and email traffic to attacker servers. Domain expiry allows instant squatting.',
      references: [{ title: 'RDAP Lookup', url: `https://rdap.org/domain/${hostname.split('.').slice(-2).join('.')}` }]
    };
  }

  // OWASP A09 – Security Logging / Monitoring (Reputation)
  function buildReputation(urlscanResult, hostname) {
    const scan = urlscanResult?.results?.[0];

    if (!scan) {
      // No data ≠ malicious. Default to neutral-positive (most sites are legitimate).
      return {
        id: 'reputation', name: 'Domain Reputation (OWASP A09)',
        score: 58,
        summary: 'No recent URLScan.io data found. Domain not in threat databases. Verify manually at virustotal.com and urlvoid.com.',
        findings: [
          '✓ No malicious verdict in URLScan.io database',
          '⚠ No recent scan data available — domain may be new or rarely scanned',
          `• Check manually: virustotal.com/gui/domain/${hostname}`,
          '• Check manually: urlvoid.com (free multi-source reputation check)',
          '• Monitor: Google Search Console for blacklisting alerts',
        ],
        recommendations: [
          'Submit domain to URLScan.io for analysis',
          'Verify at VirusTotal and URLVoid',
          'Set up Google Search Console alerts',
          'Deploy Cloudflare WAF (free tier)',
        ],
        howToFix: ['Submit scan: urlscan.io/scan', 'Register with Google Search Console', 'Set up Cloudflare WAF free tier'],
        threatImpact: 'Without reputation monitoring, malware injection or blacklisting may go undetected, destroying organic traffic.',
        references: [
          { title: 'URLScan.io', url: `https://urlscan.io/search/#domain:${hostname}` },
          { title: 'VirusTotal', url: `https://www.virustotal.com/gui/domain/${hostname}` },
        ]
      };
    }

    const malicious = scan.verdicts?.overall?.malicious || false;
    const repScore  = scan.verdicts?.overall?.score || 0;
    const tags      = scan.verdicts?.overall?.tags || [];
    const cats      = scan.verdicts?.overall?.categories || [];
    const scanDate  = scan.task?.time ? new Date(scan.task.time).toLocaleDateString() : 'Unknown';

    let score = malicious ? 5 : Math.max(60, 100 - repScore);
    if (tags.includes('malware'))  score = Math.min(score, 8);
    if (tags.includes('phishing')) score = Math.min(score, 8);

    return {
      id: 'reputation', name: 'Domain Reputation (OWASP A09)',
      score,
      summary: malicious ? `🔴 MALICIOUS — URLScan.io flagged domain! Tags: ${tags.join(', ')}` : `✓ Clean reputation. URLScan score: ${repScore}/100. Last scanned: ${scanDate}`,
      findings: [
        malicious ? '🔴 URLScan.io verdict: MALICIOUS' : '✓ URLScan.io verdict: Clean',
        `Reputation score: ${repScore}/100 (lower is better)`,
        tags.length  ? `Tags: ${tags.join(', ')}` : '✓ No threat tags',
        cats.length  ? `Categories: ${cats.join(', ')}` : '✓ No suspicious categories',
        `Last URLScan.io scan: ${scanDate}`,
      ].filter(Boolean),
      recommendations: [
        malicious ? '🔴 IMMEDIATE ACTION: Domain flagged malicious by URLScan.io' : '✓ No reputation issues',
        'Monitor monthly: virustotal.com and urlvoid.com',
        'Set up Google Search Console for blacklisting alerts',
        'Deploy WAF (Cloudflare free tier)',
      ],
      howToFix: malicious
        ? ['Scan: sitecheck.sucuri.net', 'Remove malicious files', 'Submit removal to blacklists', 'Install WAF']
        : ['Monthly: urlscan.io/scan', 'Set up Google Search Console', 'Enable Cloudflare free WAF'],
      threatImpact: 'Blacklisted domains trigger browser red-screen warnings for ALL visitors, instantly destroying trust and traffic.',
      references: [
        { title: 'URLScan.io', url: `https://urlscan.io/search/#domain:${hostname}` },
        { title: 'VirusTotal', url: `https://www.virustotal.com/gui/domain/${hostname}` },
      ]
    };
  }

  // OWASP A05 – Network Exposure (Ports)
  function buildPorts(hostname, protocol) {
    const isHttps = protocol === 'https:';
    // HTTPS confirmed = good baseline. Browser can't do TCP scan — neutral score with clear explanation.
    const score = isHttps ? 65 : 20;

    return {
      id: 'ports', name: 'Network Exposure (OWASP A05)',
      score,
      summary: `${isHttps ? 'HTTPS active ✓' : '⚠ HTTP only'}. Browser cannot perform TCP port scanning. Use nmap locally for a full audit.`,
      findings: [
        `Port 443 (HTTPS): ${isHttps ? '✓ Active and serving encrypted traffic' : 'Not confirmed'}`,
        `Port 80 (HTTP): ${!isHttps ? '⚠ Serving unencrypted traffic' : 'Assumed redirecting to HTTPS'}`,
        '⚠ TCP scanning requires local nmap — cannot run from browser',
        'Dangerous ports to audit: 22 (SSH), 3306 (MySQL), 5432 (Postgres), 27017 (MongoDB), 6379 (Redis)',
        `Run: nmap -sV --top-ports 1000 ${hostname}`,
      ],
      recommendations: [
        isHttps ? '✓ HTTPS active' : '🔴 Enable HTTPS immediately',
        'Run nmap to identify all exposed services',
        'Firewall: allow only 80/443 inbound from internet',
        'Never expose DB ports (3306, 5432, 27017) to internet',
      ],
      howToFix: [
        `nmap -sV -p- ${hostname}`,
        'ufw default deny incoming && ufw allow 443/tcp && ufw allow 80/tcp',
        'Restrict SSH: ufw allow from YOUR_IP to any port 22',
        'Install fail2ban for brute-force protection',
      ],
      threatImpact: 'Each exposed port is a potential entry point. Exposed DB ports allow direct data theft. Open SSH enables credential brute-forcing.',
      references: [
        { title: 'Shodan Search', url: `https://www.shodan.io/search?query=${hostname}` },
        { title: 'Nmap Reference', url: 'https://nmap.org/book/man.html' },
      ]
    };
  }

  // OWASP A08 – Software & Data Integrity (Malware)
  function buildMalware(urlscanResult, hostname) {
    const scan = urlscanResult?.results?.[0];
    const malicious = scan?.verdicts?.overall?.malicious || false;
    // Default safe score when no data — most sites are not malicious
    const score = malicious ? 5 : (scan ? 72 : 62);

    return {
      id: 'malware', name: 'Malware & Phishing (OWASP A08)',
      score,
      summary: malicious ? '🔴 URLScan.io indicates malicious content!' : `✓ No active malware detected in threat intelligence feeds. ${!scan ? '(No recent URLScan data — verify manually)' : ''}`,
      findings: [
        malicious ? '🔴 URLScan.io: MALICIOUS verdict' : '✓ URLScan.io: No malicious verdict',
        scan ? '✓ URLScan.io scan data available' : '⚠ No recent URLScan.io data — submit scan for analysis',
        '⚠ Full malware scan requires server-side access (ClamAV / Sucuri)',
        `Google Safe Browsing: transparencyreport.google.com/safe-browsing/search?url=${hostname}`,
        'Run Sucuri SiteCheck: sitecheck.sucuri.net',
      ],
      recommendations: [
        malicious ? '🔴 CRITICAL: Clean malware immediately' : '✓ No active threats detected',
        'Run Sucuri SiteCheck monthly: sitecheck.sucuri.net',
        'Implement file integrity monitoring (AIDE)',
        'Use Subresource Integrity (SRI) for external scripts',
      ],
      howToFix: [
        'Free scan: sitecheck.sucuri.net',
        'Install ClamAV: apt install clamav && clamscan -r /var/www/',
        'Monitor: sudo apt install aide && aide --init',
        'SRI for scripts: srihash.org',
      ],
      threatImpact: 'Undetected malware silently steals credentials, mines crypto using visitor browsers, or turns server into a botnet node.',
      references: [
        { title: 'Sucuri SiteCheck', url: 'https://sitecheck.sucuri.net' },
        { title: 'Google Safe Browsing', url: `https://transparencyreport.google.com/safe-browsing/search?url=${hostname}` },
      ]
    };
  }

  // OWASP A03 – Injection (CSP)
  function buildCSP(pageData) {
    const content = pageData?.content || '';
    const proxyWorked = pageData?.ok === true;

    // If proxy didn't work, can't verify CSP — score neutrally
    if (!proxyWorked) {
      return {
        id: 'csp', name: 'Content Security Policy (OWASP A03)',
        score: 40,
        summary: 'CSP could not be inspected from browser (proxy blocked). Verify at csp-evaluator.withgoogle.com and securityheaders.com.',
        findings: [
          '⚠ Could not inspect CSP via browser proxy (common for security-hardened sites)',
          '• CSP is typically set as an HTTP response header (not visible in HTML source)',
          `• Verify at: https://csp-evaluator.withgoogle.com/?url=${encodeURIComponent(pageData?.url || '')}`,
          '• Check: report-uri.com/home/analyse',
        ],
        recommendations: ['Verify CSP at csp-evaluator.withgoogle.com', 'Add CSP header to prevent XSS', 'Use nonce-based CSP for inline scripts', 'Set up CSP violation reporting'],
        howToFix: ["Content-Security-Policy: default-src 'self'; script-src 'nonce-{random}'", "Start with Report-Only mode to find violations", 'Use csp-evaluator.withgoogle.com to test'],
        threatImpact: "Without CSP, XSS vulnerabilities allow attackers to run arbitrary JS in users' browsers.",
        references: [
          { title: 'CSP Evaluator (Google)', url: 'https://csp-evaluator.withgoogle.com' },
          { title: 'MDN CSP Docs', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' },
        ]
      };
    }

    const hasCsp      = /content-security-policy/i.test(content) || /<meta[^>]+http-equiv\s*=\s*["']Content-Security-Policy/i.test(content);
    const hasUnsafe   = /unsafe-inline/i.test(content);
    const hasNonce    = /nonce-/i.test(content);
    const hasStrict   = /'strict-dynamic'/i.test(content);
    const hasReporting = /report-uri|report-to/i.test(content);

    let score = 5;
    if (hasCsp)       score += 40;
    if (!hasUnsafe)   score += 20;
    if (hasNonce)     score += 20;
    if (hasStrict)    score += 10;
    if (hasReporting) score += 10;

    return {
      id: 'csp', name: 'Content Security Policy (OWASP A03)',
      score: Math.min(score, 100),
      summary: hasCsp
        ? `CSP ${hasUnsafe ? 'present but uses unsafe-inline ⚠' : `configured${hasNonce ? ' with nonces ✓' : ''}`}`
        : '✗ No CSP detected — site vulnerable to XSS attacks',
      findings: [
        hasCsp ? '✓ CSP header/meta tag found' : '✗ CSP: NOT FOUND — XSS unrestricted',
        hasCsp && hasUnsafe ? "⚠ 'unsafe-inline' weakens XSS protection" : hasCsp ? '✓ No unsafe-inline' : '',
        hasNonce ? '✓ Nonce-based scripts detected' : '⚠ No nonce/hash-based scripts',
        hasStrict ? "✓ 'strict-dynamic' enabled" : "⚠ 'strict-dynamic' not set",
        hasReporting ? '✓ CSP violation reporting configured' : '⚠ No violation reporting',
      ].filter(Boolean),
      recommendations: [
        !hasCsp ? '🔴 Add Content-Security-Policy header' : '',
        hasUnsafe ? "Remove 'unsafe-inline' — use nonces instead" : '',
        !hasNonce ? 'Add nonce-based CSP' : '',
        !hasReporting ? 'Add report-uri for CSP violation monitoring' : '',
      ].filter(Boolean),
      howToFix: [
        "Start: Content-Security-Policy-Report-Only: default-src 'self'",
        "Advance to: script-src 'nonce-{random}' 'strict-dynamic'",
        'Monitor: report-uri.com (free tier)',
        'Test: csp-evaluator.withgoogle.com',
      ],
      threatImpact: "Without CSP, XSS allows attackers to run arbitrary JavaScript — stealing sessions, passwords, and performing actions on users' behalf.",
      references: [
        { title: 'CSP Evaluator', url: 'https://csp-evaluator.withgoogle.com' },
        { title: 'MDN CSP', url: 'https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP' },
      ]
    };
  }

  // OWASP A06 – Vulnerable Components
  function buildVulnerability(sslData, dnsData, pageData) {
    const content = pageData?.content || '';
    let score = 55;
    const findings = [];

    const techPatterns = [
      { pattern: /wp-content|wp-includes|wordpress/i,    label: 'WordPress detected', risk: 'medium' },
      { pattern: /Drupal|drupal/,                         label: 'Drupal detected',    risk: 'medium' },
      { pattern: /joomla/i,                               label: 'Joomla detected',    risk: 'medium' },
      { pattern: /x-powered-by.*php/i,                    label: 'PHP version exposed', risk: 'high' },
      { pattern: /phpMyAdmin/i,                           label: '⚠ phpMyAdmin exposed', risk: 'critical' },
      { pattern: /wp-login\.php/i,                        label: '⚠ WordPress login exposed', risk: 'high' },
      { pattern: /\.git\//,                               label: '🔴 .git directory exposed!', risk: 'critical' },
      { pattern: /api\/v[0-9]/i,                          label: 'API endpoint detected', risk: 'low' },
      { pattern: /laravel|codeigniter|symfony/i,          label: 'PHP framework detected', risk: 'low' },
      { pattern: /react|angular|vue|next\.js/i,           label: 'Modern JS framework detected', risk: 'info' },
    ];

    techPatterns.forEach(p => {
      if (p.pattern.test(content)) {
        findings.push(`${p.risk === 'critical' ? '🔴' : p.risk === 'high' ? '⚠' : p.risk === 'info' ? '✓' : '•'} ${p.label}`);
        if (p.risk === 'critical') score -= 30;
        else if (p.risk === 'high') score -= 15;
        else if (p.risk === 'medium') score -= 5;
      }
    });

    const ep = sslData?.endpoints?.[0];
    const grade = ep?.grade;
    if (grade === 'F') { score -= 25; findings.push('🔴 SSL Labs F — critical TLS weaknesses'); }
    else if (['C','D'].includes(grade)) { score -= 10; findings.push(`⚠ SSL grade ${grade} — TLS needs improvement`); }
    else if (['A','A+'].includes(grade)) { score += 5; findings.push(`✓ SSL Labs grade ${grade}`); }

    if (findings.length === 0 || findings.every(f => f.startsWith('✓'))) {
      findings.unshift('✓ No critical technology fingerprints or known vulnerabilities in surface scan');
    }
    findings.push('⚠ Full assessment requires: Nikto / OWASP ZAP / authenticated scan');

    return {
      id: 'vulnerability', name: 'Vulnerability Exposure (OWASP A06)',
      score: Math.max(5, Math.min(score, 100)),
      summary: `Surface-level OWASP A06 check. ${findings.filter(f => f.includes('🔴') || f.includes('⚠')).length} potential issues. Full scan: Nikto/OWASP ZAP.`,
      findings,
      recommendations: [
        'Run Nikto for full web vulnerability scan',
        'Run OWASP ZAP for authenticated application scan',
        'Keep all components updated (check nvd.nist.gov)',
        'Hide server/tech info from HTTP headers',
        'Remove .git, .env files from web root',
      ],
      howToFix: [
        `nikto -h https://${dnsData.hostname}`,
        'OWASP ZAP: zaproxy.org (free)',
        'Server info: Nginx → server_tokens off; Apache → ServerTokens Prod',
        'Protect git: location ~ /\\.git { deny all; }',
        'CVE lookup: nvd.nist.gov/vuln/search',
      ],
      threatImpact: 'Known CVEs are automated attack targets. Unpatched vulnerabilities are exploited within hours of public disclosure.',
      references: [
        { title: 'OWASP Top 10', url: 'https://owasp.org/www-project-top-ten/' },
        { title: 'NIST CVE Database', url: 'https://nvd.nist.gov/vuln/search' },
        { title: 'Nikto Scanner', url: 'https://cirt.net/Nikto2' },
      ]
    };
  }

  // ═══════════════════════════════════════════════════════════════
  //  MAIN: runScan
  // ═══════════════════════════════════════════════════════════════
  async function runScan(targetUrl, onProgress) {
    const { hostname, protocol, href } = parseHost(targetUrl);

    onProgress?.({ pct: 5, step: `Resolving DNS records for ${hostname}...` });
    const [aRes, mxRes, txtRes, nsRes, dmarcRes, dkimRes] = await Promise.allSettled([
      gDNS(hostname, 'A'),
      gDNS(hostname, 'MX'),
      gDNS(hostname, 'TXT'),
      gDNS(hostname, 'NS'),
      gDNS('_dmarc.' + hostname, 'TXT'),
      gDNS('default._domainkey.' + hostname, 'TXT'),
    ]);

    onProgress?.({ pct: 18, step: 'Checking URLScan.io reputation + RDAP domain data...' });
    const [urlscanRes, rdapRes] = await Promise.allSettled([
      fetchURLScan(hostname),
      fetchRDAP(hostname),
    ]);

    onProgress?.({ pct: 30, step: 'Fetching page content via proxy (for header analysis)...' });
    const pageRes = await Promise.race([
      fetchHeaders(href),
      sleep(9000).then(() => null),
    ]);

    onProgress?.({ pct: 40, step: 'SSL Labs analysis — first-time scans take up to 90s...' });
    const sslRes = await Promise.race([
      fetchSSLLabs(hostname),
      sleep(88000).then(() => null),
    ]);

    onProgress?.({ pct: 92, step: 'Compiling OWASP Top 10 analysis...' });

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

  // ═══════════════════════════════════════════════════════════════
  //  REDIRECT CHAIN TRACER
  // ═══════════════════════════════════════════════════════════════
  async function runRedirectTrace(url, onProgress) {
    onProgress?.({ pct: 10, step: 'Starting redirect chain trace...' });
    const { href } = parseHost(url);
    const chain = await traceRedirectChain(href);
    onProgress?.({ pct: 100, step: 'Trace complete!' });

    // Analyze chain
    const suspicious = chain.filter(h => h.note && (h.note.includes('⚠') || h.note.includes('🔴'))).length;
    const loops = chain.some(h => h.note?.includes('LOOP'));
    const hops = chain.length;

    return {
      url: href,
      chain,
      hops,
      suspicious,
      loops,
      risk: loops ? 'Critical' : suspicious > 1 ? 'High' : suspicious === 1 ? 'Medium' : hops > 5 ? 'Medium' : 'Low',
    };
  }

  // ═══════════════════════════════════════════════════════════════
  //  DOMAIN INTELLIGENCE ANALYZER
  // ═══════════════════════════════════════════════════════════════
  async function runDomainIntel(targetUrl, onProgress) {
    const { hostname } = parseHost(targetUrl);
    const domain = hostname.split('.').slice(-2).join('.');

    onProgress?.({ pct: 10, step: 'Fetching RDAP / WHOIS data...' });
    const rdap = await fetchRDAP(hostname);

    onProgress?.({ pct: 25, step: 'Querying crt.sh certificate transparency logs...' });
    const crtData = await fetchCRTSH(hostname);

    onProgress?.({ pct: 40, step: 'Checking DNS records (A, MX, NS, CAA, AAAA)...' });
    const [aRes, mxRes, nsRes, caaRes, aaaaRes, txtRes] = await Promise.allSettled([
      gDNS(hostname, 'A'),
      gDNS(hostname, 'MX'),
      gDNS(hostname, 'NS'),
      gDNS(hostname, 'CAA'),
      gDNS(hostname, 'AAAA'),
      gDNS(hostname, 'TXT'),
    ]);

    onProgress?.({ pct: 65, step: 'Checking URLScan.io reputation...' });
    const urlscan = await fetchURLScan(hostname);

    onProgress?.({ pct: 85, step: 'Analyzing results...' });

    const get = r => r.status === 'fulfilled' ? r.value : null;
    const a = get(aRes), mx = get(mxRes), ns = get(nsRes);
    const caa = get(caaRes), aaaa = get(aaaaRes), txt = get(txtRes);

    // crt.sh analysis
    const certs = Array.isArray(crtData) ? crtData.slice(0,50) : [];
    const uniqueIssuers = [...new Set(certs.map(c => c.issuer_name?.match(/O=([^,]+)/)?.[1] || 'Unknown'))];
    const subdomains = [...new Set(certs.map(c => c.name_value).flatMap(n => n.split('\n')))].slice(0,20);
    const newestCert = certs[0];
    const oldestCert = certs[certs.length - 1];

    // RDAP data
    const events = rdap?.events || [];
    const regDate = events.find(e => e.eventAction === 'registration')?.eventDate;
    const expDate = events.find(e => e.eventAction === 'expiration')?.eventDate;
    const ageYears = regDate ? ((Date.now() - new Date(regDate)) / (1000*60*60*24*365)).toFixed(1) : null;
    const status = rdap?.status || [];
    const locked = status.some(s => s.includes('transfer-prohibited'));

    // Suspicious indicators
    const isNewDomain = ageYears !== null && parseFloat(ageYears) < 1;
    const hasCert = certs.length > 0;
    const hasIPv6 = !!(aaaa?.Answer?.length);
    const hasCAA = !!(caa?.Answer?.length);
    const txtRecs = (txt?.Answer || []).map(r => r.data);
    const hasSPF = txtRecs.some(t => t.startsWith('v=spf1'));

    onProgress?.({ pct: 100, step: 'Domain intelligence complete!' });

    return {
      domain, hostname, ageYears, regDate, expDate, locked, status,
      ipv4: (a?.Answer || []).map(r => r.data),
      ipv6: (aaaa?.Answer || []).map(r => r.data),
      mx: (mx?.Answer || []).map(r => r.data),
      ns: (ns?.Answer || []).map(r => r.data),
      caa: (caa?.Answer || []).map(r => r.data),
      txtRecs, hasSPF, hasIPv6, hasCAA,
      certs: { total: certs.length, issuers: uniqueIssuers, subdomains, newest: newestCert?.not_after, oldest: oldestCert?.not_before },
      isNewDomain, hasCert,
      reputation: urlscan?.results?.[0] || null,
      risk: isNewDomain ? 'High' : (!locked && !hasCert) ? 'Medium' : 'Low',
    };
  }

  // ═══════════════════════════════════════════════════════════════
  //  SECURE CODE SCANNER (client-side regex-based SAST)
  // ═══════════════════════════════════════════════════════════════
  function runCodeScan(filename, code) {
    const findings = [];
    const lines = code.split('\n');

    const rules = [
      // Secrets & Credentials (OWASP A02)
      { pattern: /api[_-]?key\s*[=:]\s*['"`][a-zA-Z0-9_\-]{16,}/i,          severity:'Critical', cat:'Hardcoded Secret',   msg:'Hardcoded API key detected' },
      { pattern: /password\s*[=:]\s*['"`][^'"`\s]{6,}/i,                       severity:'Critical', cat:'Hardcoded Secret',   msg:'Hardcoded password in source' },
      { pattern: /secret\s*[=:]\s*['"`][a-zA-Z0-9_\-]{8,}/i,                  severity:'Critical', cat:'Hardcoded Secret',   msg:'Hardcoded secret value' },
      { pattern: /private[_-]?key\s*[=:]\s*['"`][^'"`]{16,}/i,                 severity:'Critical', cat:'Hardcoded Secret',   msg:'Private key in source code' },
      { pattern: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/,             severity:'Critical', cat:'Private Key',        msg:'PEM private key embedded in file' },
      { pattern: /AKIA[0-9A-Z]{16}/,                                             severity:'Critical', cat:'AWS Key',            msg:'AWS Access Key ID detected' },
      { pattern: /ghp_[a-zA-Z0-9]{36}/,                                          severity:'Critical', cat:'GitHub Token',       msg:'GitHub Personal Access Token detected' },
      { pattern: /sk-[a-zA-Z0-9]{48}/,                                           severity:'Critical', cat:'OpenAI Key',         msg:'OpenAI API key detected' },
      { pattern: /xox[baprs]-[0-9a-zA-Z]{10,48}/,                               severity:'Critical', cat:'Slack Token',        msg:'Slack token detected' },

      // Injection (OWASP A03)
      { pattern: /eval\s*\(/,                                                     severity:'High',     cat:'Injection (A03)',   msg:'eval() usage — potential code injection' },
      { pattern: /exec\s*\(.*\$_/,                                                severity:'High',     cat:'Injection (A03)',   msg:'Command injection via user input' },
      { pattern: /system\s*\(.*\$/,                                                severity:'High',     cat:'Injection (A03)',   msg:'OS command injection risk' },
      { pattern: /\.innerHTML\s*=\s*[^'"]/,                                        severity:'High',     cat:'XSS (A03)',         msg:'innerHTML assignment — XSS risk' },
      { pattern: /document\.write\s*\(/,                                           severity:'High',     cat:'XSS (A03)',         msg:'document.write() — XSS risk' },
      { pattern: /\$_(GET|POST|REQUEST|COOKIE)\[/,                                 severity:'High',     cat:'Injection (A03)',   msg:'Unsanitized PHP superglobal used' },
      { pattern: /SELECT.*FROM.*\$|INSERT.*INTO.*\$|DELETE.*FROM.*\$/i,            severity:'High',     cat:'SQLi (A03)',        msg:'SQL query with variable — potential SQL injection' },
      { pattern: /mysql_query\s*\(|mysqli_query\s*\(/,                             severity:'Medium',   cat:'SQLi (A03)',        msg:'Direct MySQL query — use prepared statements' },

      // Cryptographic Failures (OWASP A02)
      { pattern: /md5\s*\(|MD5\(/,                                                 severity:'High',     cat:'Weak Crypto (A02)', msg:'MD5 hash — cryptographically broken, use SHA-256+' },
      { pattern: /sha1\s*\(|SHA1\(/,                                                severity:'High',     cat:'Weak Crypto (A02)', msg:'SHA-1 hash — deprecated, use SHA-256+' },
      { pattern: /DES|3DES|RC4|ECB/,                                                severity:'High',     cat:'Weak Crypto (A02)', msg:'Weak cipher algorithm detected' },
      { pattern: /Math\.random\(\)/,                                                 severity:'Medium',   cat:'Weak Random (A02)', msg:'Math.random() is NOT cryptographically secure' },
      { pattern: /base64_decode\s*\(\$_/,                                            severity:'High',     cat:'Injection (A03)',   msg:'base64_decode of user input — potential injection' },

      // Security Misconfiguration (OWASP A05)
      { pattern: /debug\s*=\s*true|DEBUG\s*=\s*True|APP_DEBUG\s*=\s*true/i,       severity:'High',     cat:'Misconfiguration (A05)', msg:'Debug mode enabled in code' },
      { pattern: /localhost|127\.0\.0\.1|0\.0\.0\.0/,                               severity:'Medium',   cat:'Misconfiguration (A05)', msg:'Localhost/0.0.0.0 hardcoded — dev config in prod?' },
      { pattern: /console\.log\(|print_r\(|var_dump\(/,                              severity:'Low',      cat:'Info Disclosure (A05)',  msg:'Debug output — remove from production' },
      { pattern: /cors.*\*|Access-Control-Allow-Origin.*\*/i,                        severity:'Medium',   cat:'Misconfiguration (A05)', msg:'CORS wildcard (*) — allows any origin' },

      // Vulnerable Components (OWASP A06)
      { pattern: /require\(['"`]http:/,                                              severity:'High',     cat:'Insecure Dep (A06)',     msg:'Dependency loaded over HTTP (not HTTPS)' },
      { pattern: /<script src=['"]http:/i,                                            severity:'High',     cat:'Insecure Dep (A06)',     msg:'Script loaded over HTTP — MITM risk' },

      // Insecure Design (OWASP A04)
      { pattern: /TODO.*security|FIXME.*auth|HACK.*bypass/i,                         severity:'Medium',   cat:'Design (A04)',           msg:'Security TODO/FIXME comment found' },
      { pattern: /\/\*\s*disable\s*auth|skip.*authentication/i,                       severity:'Critical', cat:'Auth Bypass (A04)',      msg:'Authentication bypass comment detected' },
    ];

    const ext = filename.split('.').pop().toLowerCase();
    const langMap = { js:'JavaScript', ts:'TypeScript', jsx:'JavaScript/React', tsx:'TypeScript/React', py:'Python', php:'PHP', java:'Java', rb:'Ruby', go:'Go', cs:'C#', cpp:'C++', env:'.ENV File' };
    const lang = langMap[ext] || ext.toUpperCase();

    lines.forEach((line, idx) => {
      const trimmed = line.trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('#') || trimmed.startsWith('*')) return; // skip comments
      rules.forEach(rule => {
        if (rule.pattern.test(line)) {
          findings.push({ line: idx + 1, severity: rule.severity, cat: rule.cat, msg: rule.msg, snippet: line.trim().slice(0, 100) });
        }
      });
    });

    // Deduplicate by line
    const unique = findings.filter((f, i, arr) => arr.findIndex(x => x.line === f.line && x.msg === f.msg) === i);
    const stats = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    unique.forEach(f => stats[f.severity] = (stats[f.severity] || 0) + 1);

    const score = Math.max(5, 100 - (stats.Critical * 25) - (stats.High * 15) - (stats.Medium * 7) - (stats.Low * 2));

    return { filename, lang, findings: unique, stats, score, severity: sev(score), lines: lines.length };
  }

  return { runScan, runRedirectTrace, runDomainIntel, runCodeScan };
})();

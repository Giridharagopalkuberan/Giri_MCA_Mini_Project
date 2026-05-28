"""
index.py  –  SecLite Security Scanner  (Streamlit UI)
Run:  streamlit run index.py
Requires: pip install streamlit requests dnspython fpdf2
"""

import streamlit as st
import json, time
from datetime import datetime
import importlib, os, sys

# ── page config ────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecLite – Security Scanner",
    page_icon="🛡",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Global CSS  (cyberpunk theme) ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@400;600;700&family=Share+Tech+Mono&display=swap');

html, body, [class*="css"] {
    background-color: #050A0F !important;
    color: #C8E6FF !important;
    font-family: 'Rajdhani', sans-serif !important;
}
.stApp { background: #050A0F !important; }
.block-container { padding: 1.5rem 2rem !important; max-width: 1100px !important; }

/* Nav */
.seclite-nav { display:flex; align-items:center; justify-content:space-between; padding:10px 0 18px; border-bottom:1px solid rgba(0,180,255,0.15); margin-bottom:24px; }
.seclite-logo { font-family:'Orbitron',sans-serif; font-size:1.3rem; font-weight:900; color:#00B4FF; text-shadow:0 0 15px rgba(0,180,255,0.6); letter-spacing:3px; }
.nav-user { font-family:'Share Tech Mono',monospace; font-size:0.85rem; color:#5A8FA8; }
.admin-badge { background:rgba(255,0,60,0.15); border:1px solid rgba(255,0,60,0.4); color:#FF6080; padding:3px 10px; border-radius:4px; font-family:'Share Tech Mono',monospace; font-size:0.68rem; letter-spacing:1px; margin-right:8px; }

/* Panels */
.scan-panel { background:rgba(8,16,28,0.85); border:1px solid rgba(0,180,255,0.2); border-radius:10px; padding:22px; margin-bottom:16px; }
.panel-title { font-family:'Orbitron',sans-serif; font-size:0.85rem; color:#00B4FF; letter-spacing:2px; margin-bottom:16px; }

/* Score ring */
.score-ring-wrap { text-align:center; }
.score-number { font-family:'Orbitron',sans-serif; font-weight:900; line-height:1; }
.score-label  { font-family:'Share Tech Mono',monospace; font-size:0.58rem; letter-spacing:2px; color:#3A5A6A; margin-top:3px; }
.score-sev    { font-family:'Orbitron',sans-serif; font-size:0.72rem; letter-spacing:2px; font-weight:700; margin-top:6px; }

/* Module expander */
.mod-header { display:flex; align-items:center; gap:12px; padding:12px 16px; border-radius:6px; cursor:pointer; border:1px solid; margin-bottom:5px; }
.mod-name   { font-family:'Orbitron',sans-serif; font-size:0.72rem; letter-spacing:1px; font-weight:700; flex:1; color:#C8E6FF; }
.mod-score  { font-family:'Orbitron',sans-serif; font-size:1rem; font-weight:900; }
.mod-sev    { padding:2px 10px; border-radius:4px; font-family:'Share Tech Mono',monospace; font-size:0.63rem; letter-spacing:1px; border:1px solid; }

/* Stat badge */
.stat-card  { background:rgba(10,20,35,0.8); border-radius:8px; padding:12px; text-align:center; }
.stat-val   { font-family:'Orbitron',sans-serif; font-size:1.5rem; font-weight:900; line-height:1; }
.stat-lbl   { font-family:'Share Tech Mono',monospace; font-size:0.6rem; letter-spacing:1px; color:#3A5A6A; margin-top:4px; }

/* API tags */
.api-tag { display:inline-block; background:rgba(0,180,255,0.08); border:1px solid rgba(0,180,255,0.18); color:#3A7A9A; padding:3px 10px; border-radius:12px; font-family:'Share Tech Mono',monospace; font-size:0.63rem; letter-spacing:1px; margin:2px; }

/* Findings / recs */
.finding { padding:4px 0; border-bottom:1px solid rgba(0,180,255,0.06); font-family:'Rajdhani',sans-serif; font-size:0.92rem; }
.section-head { font-family:'Share Tech Mono',monospace; font-size:0.7rem; letter-spacing:2px; margin:12px 0 6px; }

/* Ticker */
.ticker { background:rgba(255,60,0,0.06); border:1px solid rgba(255,60,0,0.18); border-radius:6px; padding:8px 16px; margin-bottom:20px; font-family:'Share Tech Mono',monospace; font-size:0.72rem; color:#CC5040; letter-spacing:1px; }

/* News card */
.news-card { background:rgba(8,16,28,0.85); border:1px solid rgba(0,180,255,0.15); border-radius:10px; padding:16px; margin-bottom:12px; transition:all 0.2s; }
.news-title { font-family:'Rajdhani',sans-serif; font-size:1.05rem; font-weight:700; color:#C8E6FF; margin-bottom:6px; }
.news-meta  { display:flex; justify-content:space-between; font-family:'Share Tech Mono',monospace; font-size:0.68rem; margin-top:10px; }
.news-src   { color:#00B4FF; }
.news-date  { color:#3A5A6A; }

/* History row */
.hist-row   { background:rgba(8,16,28,0.85); border:1px solid rgba(0,180,255,0.12); border-radius:8px; padding:14px 18px; margin-bottom:8px; }

/* Streamlit widget overrides */
div[data-testid="stTextInput"] input {
    background: rgba(0,180,255,0.04) !important; border: 1px solid rgba(0,180,255,0.25) !important;
    color: #C8E6FF !important; font-family: 'Share Tech Mono', monospace !important; border-radius: 6px !important;
}
div[data-testid="stTextInput"] input:focus { border-color: #00B4FF !important; box-shadow: 0 0 10px rgba(0,180,255,0.2) !important; }
div[data-testid="stPasswordInput"] input {
    background: rgba(255,0,60,0.04) !important; border: 1px solid rgba(255,0,60,0.2) !important;
    color: #C8E6FF !important; font-family: 'Share Tech Mono', monospace !important; border-radius: 6px !important;
}
.stButton > button {
    background: linear-gradient(135deg, rgba(0,180,255,0.2), rgba(0,90,180,0.3)) !important;
    border: 1px solid rgba(0,180,255,0.45) !important; color: #00B4FF !important;
    font-family: 'Orbitron', sans-serif !important; font-size: 0.78rem !important;
    letter-spacing: 2px !important; border-radius: 6px !important; padding: 0.5rem 1.5rem !important;
}
.stButton > button:hover { box-shadow: 0 0 15px rgba(0,180,255,0.3) !important; }
.stExpander { border: 1px solid rgba(0,180,255,0.18) !important; border-radius: 8px !important; background: rgba(8,16,28,0.8) !important; }
.stExpander > details > summary { font-family: 'Orbitron', sans-serif !important; font-size: 0.75rem !important; letter-spacing: 1px !important; }
div[data-testid="stProgress"] > div { background: rgba(0,180,255,0.1) !important; }
div[data-testid="stProgress"] > div > div { background: linear-gradient(90deg, #00B4FF, #0060CC) !important; }
.stAlert { border-radius: 6px !important; }
h1, h2, h3 { font-family: 'Orbitron', sans-serif !important; color: #00B4FF !important; }
.stTabs [data-baseweb="tab"] { font-family: 'Orbitron', sans-serif !important; font-size: 0.72rem !important; letter-spacing: 2px !important; color: #5A8FA8 !important; }
.stTabs [data-baseweb="tab"][aria-selected="true"] { color: #00B4FF !important; border-bottom: 2px solid #00B4FF !important; }
footer { display: none !important; }
#MainMenu { display: none !important; }
header[data-testid="stHeader"] { display: none !important; }
</style>
""", unsafe_allow_html=True)

# ── session state init ─────────────────────────────────────────────────────────
def init_state():
    for k, v in {
        "logged_in": False, "user": None, "page": "scan",
        "scan_results": None, "scan_history": [], "news_cache": None, "news_ts": 0,
    }.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()


def get_scanner_module():
    root = os.path.dirname(os.path.abspath(__file__))
    if root not in sys.path:
        sys.path.insert(0, root)
    try:
        return importlib.import_module("scanner")
    except ImportError:
        return None

# ── severity helpers ──────────────────────────────────────────────────────────
SEV_COLOR = {"Critical":"#FF003C","High":"#FF6030","Medium":"#FFD700","Low":"#00E676","Safe":"#00FF88"}
SEV_ICON  = {"Critical":"🔴","High":"🟠","Medium":"🟡","Low":"🟢","Safe":"✅"}
CAT_COLOR = {"Ransomware":"#FF6030","Breach":"#FF003C","Vulnerability":"#FFD700","Malware":"#FF4080","Advisory":"#00B4FF","Security":"#00B4FF"}

def sc(sev): return SEV_COLOR.get(sev,"#00B4FF")

def score_gauge_svg(score, sev, size=110):
    c    = sc(sev)
    r    = 44
    circ = 2 * 3.14159 * r
    dash = (score/100) * circ
    return f"""
    <div style="text-align:center">
      <svg width="{size}" height="{size}" style="transform:rotate(-90deg)">
        <circle cx="{size//2}" cy="{size//2}" r="{r}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="9"/>
        <circle cx="{size//2}" cy="{size//2}" r="{r}" fill="none" stroke="{c}" stroke-width="9"
          stroke-dasharray="{dash:.1f} {circ:.1f}" stroke-linecap="round"
          style="filter:drop-shadow(0 0 6px {c})"/>
      </svg>
      <div style="margin-top:-{size//2+8}px;text-align:center">
        <div style="font-family:'Orbitron',sans-serif;font-size:1.6rem;font-weight:900;color:{c};text-shadow:0 0 16px {c};line-height:1">{score}</div>
        <div style="font-family:'Share Tech Mono',monospace;font-size:0.5rem;letter-spacing:2px;color:#3A5A6A;margin-top:2px">SCORE</div>
      </div>
      <div style="margin-top:10px;font-family:'Orbitron',sans-serif;font-size:0.72rem;letter-spacing:2px;font-weight:700;color:{c}">{sev.upper()}</div>
    </div>"""

def stat_card(val, label, color):
    return f"""
    <div class="stat-card" style="border:1px solid {color}30">
      <div class="stat-val" style="color:{color};text-shadow:0 0 8px {color}">{val}</div>
      <div class="stat-lbl">{label}</div>
    </div>"""

# ══════════════════════════════════════════════════════════════════════════════
#  LOGIN PAGE  (with particles.js background)
# ══════════════════════════════════════════════════════════════════════════════
def render_login():
    import streamlit.components.v1 as components
    components.html("""
<!DOCTYPE html>
<html>
<head>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#050A0F; font-family:'Orbitron',sans-serif; overflow:hidden; }
  #particles-js { position:fixed; width:100%; height:100%; top:0; left:0; z-index:0; }
  .content { position:relative; z-index:10; display:flex; flex-direction:column; align-items:center; justify-content:center; height:100vh; }
  .logo-wrap { text-align:center; margin-bottom:20px; }
  .logo-title { font-size:2.5rem; font-weight:900; color:#00B4FF; text-shadow:0 0 25px rgba(0,180,255,0.8); letter-spacing:5px; }
  .logo-sub   { color:#3A6A80; font-family:'Share Tech Mono',monospace; font-size:0.82rem; letter-spacing:3px; margin-top:8px; }
  .tag-line   { color:#1A4A60; font-family:'Share Tech Mono',monospace; font-size:0.68rem; letter-spacing:2px; margin-top:14px; }
  .stat-row   { display:flex; gap:30px; margin-top:24px; }
  .stat-box   { text-align:center; }
  .stat-num   { font-size:1.5rem; font-weight:900; color:#00B4FF; }
  .stat-lbl   { font-size:0.6rem; color:#2A5A70; letter-spacing:2px; font-family:'Share Tech Mono',monospace; }
</style>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Share+Tech+Mono&display=swap" rel="stylesheet"/>
</head>
<body>
<div id="particles-js"></div>
<div class="content">
  <div class="logo-wrap">
    <div style="font-size:3rem;margin-bottom:10px">🛡</div>
    <div class="logo-title">SECLITE</div>
    <div class="logo-sub">UNIFIED SECURITY SCANNER</div>
    <div class="tag-line">► Pre-Go-Live Security Assessment Platform ◄</div>
  </div>
  <div class="stat-row">
    <div class="stat-box"><div class="stat-num">10</div><div class="stat-lbl">SCAN MODULES</div></div>
    <div class="stat-box"><div class="stat-num">5</div><div class="stat-lbl">LIVE APIs</div></div>
    <div class="stat-box"><div class="stat-num">100%</div><div class="stat-lbl">FREE</div></div>
  </div>
</div>
<script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
<script>
particlesJS('particles-js', {
  particles: {
    number: { value: 80, density: { enable: true, value_area: 900 } },
    color: { value: ["#00B4FF","#0060CC","#00E676","#FF6030"] },
    shape: { type: "circle" },
    opacity: { value: 0.5, random: true, anim: { enable: true, speed: 0.8, opacity_min: 0.1 } },
    size: { value: 2.5, random: true, anim: { enable: true, speed: 2, size_min: 0.5 } },
    line_linked: { enable: true, distance: 140, color: "#003A5A", opacity: 0.25, width: 1 },
    move: { enable: true, speed: 1.2, direction: "none", random: true, straight: false, out_mode: "out" }
  },
  interactivity: {
    detect_on: "canvas",
    events: { onhover: { enable: true, mode: "repulse" }, onclick: { enable: true, mode: "push" } },
    modes: { repulse: { distance: 80, duration: 0.4 }, push: { particles_nb: 3 } }
  },
  retina_detect: true
});
</script>
</body>
</html>
""", height=420)

    st.markdown("<br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 1.4, 1])
    with col2:
        st.markdown('<div style="background:rgba(8,16,28,0.95);border:1px solid rgba(0,180,255,0.25);border-radius:12px;padding:28px;box-shadow:0 0 50px rgba(0,180,255,0.1)">', unsafe_allow_html=True)
        
        tab_user, tab_admin = st.tabs(["👤  USER LOGIN", "⚡  ADMIN ACCESS"])

        with tab_user:
            st.markdown('<div style="margin-top:12px"></div>', unsafe_allow_html=True)
            email = st.text_input("EMAIL ADDRESS", placeholder="you@example.com", key="login_email", label_visibility="visible")
            if st.button("▶ ENTER SYSTEM", key="btn_user_login", use_container_width=True):
                if email and "@" in email:
                    st.session_state.logged_in = True
                    st.session_state.user = {"email": email, "name": email.split("@")[0], "is_admin": False}
                    st.rerun()
                else:
                    st.error("Enter a valid email address")

        with tab_admin:
            st.markdown('<div style="margin-top:12px"></div>', unsafe_allow_html=True)
            uname = st.text_input("USERNAME", placeholder="admin", key="admin_uname")
            passwd = st.text_input("PASSWORD", type="password", placeholder="••••••••", key="admin_pass")
            if st.button("🔒 AUTHENTICATE", key="btn_admin_login", use_container_width=True):
                if uname == "admin" and passwd == "admin@123":
                    st.session_state.logged_in = True
                    st.session_state.user = {"email": "admin@seclite.local", "name": "Administrator", "is_admin": True}
                    st.rerun()
                else:
                    st.error("ACCESS DENIED: Invalid credentials")

        st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown('<p style="text-align:center;color:#1A2A30;font-family:Share Tech Mono,monospace;font-size:0.72rem;margin-top:16px">SecLite v2.0 · Standalone · No cloud required</p>', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  MODULE DISPLAY
# ══════════════════════════════════════════════════════════════════════════════
def render_module(mod, default_open=False):
    c       = sc(mod["severity"])
    icon    = SEV_ICON.get(mod["severity"], "•")
    label   = f"{icon} {mod['name']}  —  Score: {mod['score']}  |  {mod['severity'].upper()}"

    with st.expander(label, expanded=default_open):
        st.markdown(f"""
        <div style="background:{c}10;border-left:3px solid {c}60;padding:10px 14px;border-radius:4px;margin-bottom:14px;font-family:'Rajdhani',sans-serif;font-size:0.95rem;color:#8AAFC0;line-height:1.6">
          {mod.get('summary','') or ''}
        </div>""", unsafe_allow_html=True)

        # Progress bar
        bar_w = mod["score"]
        st.markdown(f"""
        <div style="margin-bottom:14px">
          <div style="display:flex;justify-content:space-between;margin-bottom:4px">
            <span style="font-family:'Share Tech Mono',monospace;font-size:0.68rem;color:#3A5A6A">SECURITY SCORE</span>
            <span style="font-family:'Orbitron',sans-serif;font-size:0.85rem;font-weight:900;color:{c}">{mod['score']}/100</span>
          </div>
          <div style="background:rgba(255,255,255,0.06);border-radius:4px;height:6px;overflow:hidden">
            <div style="width:{bar_w}%;height:100%;background:{c};border-radius:4px;box-shadow:0 0 8px {c}"></div>
          </div>
        </div>""", unsafe_allow_html=True)

        col1, col2 = st.columns(2)

        with col1:
            if mod.get("findings"):
                st.markdown(f'<div class="section-head" style="color:{c}">⚠ FINDINGS</div>', unsafe_allow_html=True)
                for f in mod["findings"]:
                    color = "#FF6080" if f.startswith("✗") or "🔴" in f else ("#FFD700" if "⚠" in f else "#C8E6FF")
                    st.markdown(f'<div class="finding" style="color:{color}">{f}</div>', unsafe_allow_html=True)

        with col2:
            if mod.get("recommendations"):
                st.markdown('<div class="section-head" style="color:#00FF88">✓ RECOMMENDATIONS</div>', unsafe_allow_html=True)
                for r in mod["recommendations"]:
                    if r:
                        st.markdown(f'<div class="finding">{r}</div>', unsafe_allow_html=True)

        if mod.get("how_to_fix"):
            st.markdown('<div class="section-head" style="color:#00B4FF">🔧 HOW TO FIX</div>', unsafe_allow_html=True)
            for i, step in enumerate(mod["how_to_fix"]):
                st.markdown(f"""
                <div style="display:flex;gap:10px;margin-bottom:8px;align-items:flex-start">
                  <div style="background:rgba(0,180,255,0.2);border:1px solid rgba(0,180,255,0.4);border-radius:50%;width:22px;height:22px;display:flex;align-items:center;justify-content:center;font-family:'Orbitron',sans-serif;font-size:0.6rem;color:#00B4FF;flex-shrink:0">{i+1}</div>
                  <code style="background:rgba(0,0,0,0.4);padding:4px 8px;border-radius:4px;font-family:'Share Tech Mono',monospace;font-size:0.82rem;color:#C8E6FF;border:1px solid rgba(0,180,255,0.15);flex:1">{step}</code>
                </div>""", unsafe_allow_html=True)

        if mod.get("threat_impact"):
            st.markdown(f"""
            <div style="background:rgba(255,140,0,0.05);border:1px solid rgba(255,140,0,0.2);border-radius:6px;padding:12px 14px;margin-top:12px">
              <div style="color:#FF8C00;font-family:'Share Tech Mono',monospace;font-size:0.68rem;letter-spacing:2px;margin-bottom:8px">⚡ THREAT IMPACT</div>
              <div style="color:#E0C080;font-family:'Rajdhani',sans-serif;font-size:0.92rem;line-height:1.6">{mod['threat_impact']}</div>
            </div>""", unsafe_allow_html=True)

        if mod.get("references"):
            st.markdown('<div style="margin-top:12px;display:flex;flex-wrap:wrap;gap:6px">', unsafe_allow_html=True)
            for ref in mod["references"]:
                st.markdown(f'📚 [{ref["title"]}]({ref["url"]})', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  SCAN RESULTS  
# ══════════════════════════════════════════════════════════════════════════════
def render_scan_results(results):
    oc        = sc(results["overall_severity"])
    modules   = results["modules"]
    sorted_m  = sorted(modules, key=lambda m: {"Critical":0,"High":1,"Medium":2,"Low":3,"Safe":4}.get(m["severity"],5))
    criticals = sum(1 for m in modules if m["severity"] in ("Critical","High"))
    mediums   = sum(1 for m in modules if m["severity"] == "Medium")
    safes     = sum(1 for m in modules if m["severity"] in ("Low","Safe"))

    # Summary card
    st.markdown(f'<div style="background:{oc}0d;border:1px solid {oc}35;border-radius:10px;padding:20px 24px;margin-bottom:16px;box-shadow:0 0 20px {oc}12">', unsafe_allow_html=True)
    col_gauge, col_info, col_btn = st.columns([1.2, 3.5, 1.3])

    with col_gauge:
        st.markdown(score_gauge_svg(results["overall_score"], results["overall_severity"], 120), unsafe_allow_html=True)

    with col_info:
        st.markdown(f"""
        <div>
          <div style="font-family:'Orbitron',sans-serif;font-size:1.1rem;font-weight:700;color:{oc};letter-spacing:2px;margin-bottom:6px">
            {results['overall_severity'].upper()} RISK
          </div>
          <div style="color:#8AAFC0;font-family:'Rajdhani',sans-serif;font-size:0.95rem;margin-bottom:14px">
            Assessment complete for <span style="color:#00B4FF;font-family:'Share Tech Mono',monospace">{results['hostname']}</span>
            &nbsp;·&nbsp; {datetime.fromisoformat(results['scanned_at']).strftime('%Y-%m-%d %H:%M')}
          </div>
        </div>""", unsafe_allow_html=True)

        c1, c2, c3, c4 = st.columns(4)
        with c1: st.markdown(stat_card(criticals, "CRITICAL/HIGH", "#FF003C"), unsafe_allow_html=True)
        with c2: st.markdown(stat_card(mediums,   "MEDIUM",        "#FFD700"), unsafe_allow_html=True)
        with c3: st.markdown(stat_card(safes,     "LOW/SAFE",      "#00E676"), unsafe_allow_html=True)
        with c4: st.markdown(stat_card(len(modules),"MODULES",     "#00B4FF"), unsafe_allow_html=True)

    with col_btn:
        if st.button("📄 PDF REPORT", key="pdf_top"):
            _generate_pdf(results)

    st.markdown("</div>", unsafe_allow_html=True)

    # API tags
    st.markdown("""
    <div style="margin-bottom:14px">
      <span class="api-tag">Google DNS API</span>
      <span class="api-tag">SSL Labs API</span>
      <span class="api-tag">URLScan.io API</span>
      <span class="api-tag">RDAP/WHOIS API</span>
      <span class="api-tag">Real Socket Port Scan</span>
      <span class="api-tag">Header Inspection</span>
    </div>""", unsafe_allow_html=True)

    st.markdown('<p style="color:#2A4A5A;font-family:Share Tech Mono,monospace;font-size:0.7rem;margin-bottom:12px">Click any row to expand full details. Critical issues auto-expanded.</p>', unsafe_allow_html=True)

    # Module list
    for mod in sorted_m:
        render_module(mod, default_open=(mod["severity"] == "Critical"))

    st.markdown("<br>", unsafe_allow_html=True)
    col_c, col_d, _ = st.columns([1, 1, 2])
    with col_c:
        if st.button("📄 DOWNLOAD PDF REPORT", key="pdf_bottom"):
            _generate_pdf(results)
    with col_d:
        if st.button("🔄 NEW SCAN", key="new_scan"):
            st.session_state.scan_results = None
            st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
#  PDF GENERATION
# ══════════════════════════════════════════════════════════════════════════════
def _generate_pdf(results):
    try:
        from fpdf import FPDF
    except ImportError:
        st.error("fpdf2 not installed. Run: pip install fpdf2")
        return

    SEV_C = {"Critical":(255,0,60),"High":(255,96,48),"Medium":(255,215,0),"Low":(0,230,118),"Safe":(0,255,136)}

    pdf = FPDF()
    pdf.add_page()
    pdf.set_fill_color(5,10,15); pdf.rect(0,0,210,297,'F')
    pdf.set_fill_color(0,100,180); pdf.rect(0,0,210,4,'F')

    pdf.set_font("Helvetica","B",26); pdf.set_text_color(0,180,255)
    pdf.set_xy(0,20); pdf.cell(210,12,"SECLITE – SECURITY SCAN REPORT",align="C",ln=True)
    pdf.set_font("Helvetica","",10); pdf.set_text_color(150,200,255)
    pdf.cell(210,7,f"Target: {results['target_url']}",align="C",ln=True)
    pdf.cell(210,7,f"Scanned: {results['scanned_at'][:19]}  |  Overall: {results['overall_score']}/100  [{results['overall_severity']}]",align="C",ln=True)
    pdf.set_draw_color(0,100,180); pdf.line(15,52,195,52)

    for mod in results["modules"]:
        pdf.add_page()
        pdf.set_fill_color(5,10,15); pdf.rect(0,0,210,297,'F')
        mc = SEV_C.get(mod["severity"],(0,180,255))
        pdf.set_fill_color(*mc); pdf.rect(0,0,4,297,'F')

        pdf.set_xy(8,10); pdf.set_font("Helvetica","B",14); pdf.set_text_color(*mc)
        pdf.cell(190,8,mod["name"].upper(),ln=True)

        pdf.set_xy(8,22); pdf.set_font("Helvetica","",9); pdf.set_text_color(180,220,255)
        pdf.cell(50,7,f"Score: {mod['score']}/100",)
        pdf.cell(50,7,f"Severity: {mod['severity']}",ln=True)

        def section(title, items, color=(0,180,255)):
            if not items: return
            cy = pdf.get_y() + 4
            pdf.set_fill_color(18,32,46); pdf.rect(8,cy,192,7,'F')
            pdf.set_xy(10,cy); pdf.set_font("Helvetica","B",8); pdf.set_text_color(*color)
            pdf.cell(0,7,title,ln=True)
            pdf.set_font("Helvetica","",8); pdf.set_text_color(180,220,255)
            for i,item in enumerate(items or []):
                if item:
                    pdf.set_x(12)
                    pdf.multi_cell(185,5,f"{i+1}. {item}")
            pdf.ln(2)

        section("FINDINGS",          mod.get("findings",[]),          mc)
        section("RECOMMENDATIONS",   mod.get("recommendations",[]),   (0,200,100))
        section("HOW TO FIX",        mod.get("how_to_fix",[]),        (0,180,255))
        if mod.get("threat_impact"):
            pdf.ln(2); pdf.set_x(8); pdf.set_font("Helvetica","B",8); pdf.set_text_color(255,140,0)
            pdf.cell(0,6,"THREAT IMPACT",ln=True)
            pdf.set_font("Helvetica","",8); pdf.set_text_color(200,180,100); pdf.set_x(12)
            pdf.multi_cell(185,5,mod["threat_impact"])

    import io
    buf = io.BytesIO(bytes(pdf.output()))
    fname = f"SecLite_{results['hostname'].replace('.','_')}_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    st.download_button("⬇ Download PDF", data=buf, file_name=fname, mime="application/pdf", key=f"pdf_dl_{time.time()}")

# ══════════════════════════════════════════════════════════════════════════════
#  SCAN PAGE
# ══════════════════════════════════════════════════════════════════════════════
def render_scan_page():
    st.markdown('<h1 style="font-size:1.35rem;letter-spacing:3px;margin-bottom:6px">🔍 SECURITY SCANNER</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color:#3A5A6A;font-family:Share Tech Mono,monospace;font-size:0.72rem;letter-spacing:1px;margin-bottom:20px">10 real-world pre-go-live checks · Google DNS · SSL Labs · URLScan.io · RDAP · Socket Port Scan</p>', unsafe_allow_html=True)

    with st.container():
        st.markdown('<div class="scan-panel">', unsafe_allow_html=True)
        col_input, col_btn = st.columns([5, 1])
        with col_input:
            target = st.text_input("TARGET URL", placeholder="https://example.com  or  example.com", label_visibility="visible", key="scan_target")
        with col_btn:
            st.markdown("<br>", unsafe_allow_html=True)
            scan_clicked = st.button("▶ SCAN", key="scan_go", use_container_width=True)
        st.markdown("""
        <div style="margin-top:10px">
          <span class="api-tag">1. DNS Security</span><span class="api-tag">2. SSL/TLS</span>
          <span class="api-tag">3. HTTP Headers</span><span class="api-tag">4. Email Auth</span>
          <span class="api-tag">5. WHOIS</span><span class="api-tag">6. Reputation</span>
          <span class="api-tag">7. Port Scan</span><span class="api-tag">8. Mixed Content</span>
          <span class="api-tag">9. CSP</span><span class="api-tag">10. Vuln Exposure</span>
        </div>""", unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    if scan_clicked and target:
        scanner_mod = get_scanner_module()
        if scanner_mod is None:
            st.error("Scanner module not found. Ensure scanner.py exists in the app directory.")
            return
        run_full_scan = getattr(scanner_mod, "run_full_scan", None)
        if not callable(run_full_scan):
            st.error("Scanner entry point not found in scanner.py.")
            return

        prog_bar  = st.progress(0)
        prog_text = st.empty()

        def on_progress(step, pct):
            prog_bar.progress(pct)
            prog_text.markdown(f'<p style="color:#00B4FF;font-family:Share Tech Mono,monospace;font-size:0.8rem">⚙ {step}</p>', unsafe_allow_html=True)

        try:
            results = run_full_scan(target.strip(), on_progress)
            st.session_state.scan_results = results
            st.session_state.scan_history.insert(0, results)
            prog_bar.empty(); prog_text.empty()
        except Exception as e:
            prog_bar.empty(); prog_text.empty()
            st.error(f"Scan failed: {e}")
            return

    if st.session_state.scan_results:
        render_scan_results(st.session_state.scan_results)
    else:
        st.markdown("""
        <div style="text-align:center;padding:60px 0;color:#1A2A35">
          <div style="font-size:4rem;margin-bottom:14px">🛡</div>
          <p style="font-family:'Share Tech Mono',monospace;font-size:0.85rem;color:#2A3A45;letter-spacing:1px">Enter a target URL above to begin the 10-module pre-go-live security assessment</p>
        </div>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  HISTORY PAGE
# ══════════════════════════════════════════════════════════════════════════════
def render_history_page():
    user = st.session_state.user
    history = st.session_state.scan_history
    if user.get("is_admin"):
        st.markdown('<h1 style="font-size:1.35rem;letter-spacing:3px;margin-bottom:6px">📁 SCAN HISTORY (Admin — All Scans)</h1>', unsafe_allow_html=True)
    else:
        st.markdown(f'<h1 style="font-size:1.35rem;letter-spacing:3px;margin-bottom:6px">📁 SCAN HISTORY</h1><p style="color:#3A5A6A;font-family:Share Tech Mono,monospace;font-size:0.72rem">Showing scans for {user["email"]}</p>', unsafe_allow_html=True)

    if not history:
        st.info("No scan history yet. Run your first scan!")
        return

    st.markdown(f'<p style="color:#00B4FF;font-family:Share Tech Mono,monospace;font-size:0.75rem;margin-bottom:16px">{len(history)} scans in session</p>', unsafe_allow_html=True)

    for idx, res in enumerate(history):
        oc = sc(res["overall_severity"])
        col_a, col_score, col_sev, col_btn = st.columns([4, 1, 1, 1.5])
        with col_a:
            st.markdown(f"""
            <div style="padding:4px 0">
              <div style="font-family:'Share Tech Mono',monospace;font-size:0.88rem;color:#C8E6FF">{res['target_url']}</div>
              <div style="font-family:'Rajdhani',sans-serif;font-size:0.8rem;color:#3A5A6A;margin-top:2px">{res['scanned_at'][:19]}</div>
            </div>""", unsafe_allow_html=True)
        with col_score:
            st.markdown(f'<div style="font-family:Orbitron,sans-serif;font-size:1.4rem;font-weight:900;color:{oc};text-shadow:0 0 10px {oc};padding-top:4px">{res["overall_score"]}</div>', unsafe_allow_html=True)
        with col_sev:
            st.markdown(f'<div style="color:{oc};font-family:Share Tech Mono,monospace;font-size:0.72rem;padding-top:8px">{res["overall_severity"]}</div>', unsafe_allow_html=True)
        with col_btn:
            if st.button("📄 PDF", key=f"hist_pdf_{idx}"):
                _generate_pdf(res)
            if st.button("▶ View", key=f"hist_view_{idx}"):
                st.session_state.scan_results = res
                st.session_state.page = "scan"
                st.rerun()
        st.divider()

# ══════════════════════════════════════════════════════════════════════════════
#  BLOGS PAGE  (live RSS, refreshes on each visit)
# ══════════════════════════════════════════════════════════════════════════════
def render_blogs_page():
    st.markdown('<h1 style="font-size:1.35rem;letter-spacing:3px;margin-bottom:6px">📡 CYBER THREAT INTEL</h1>', unsafe_allow_html=True)
    st.markdown('<p style="color:#3A5A6A;font-family:Share Tech Mono,monospace;font-size:0.72rem;margin-bottom:16px">Krebs · Schneier · Bleeping Computer · SANS ISC · Security Affairs · Dark Reading — refreshed on every visit</p>', unsafe_allow_html=True)
    st.markdown('<div class="ticker">⚠ LIVE THREAT FEED — Latest cybersecurity incidents, vulnerability disclosures &amp; advisories</div>', unsafe_allow_html=True)

    col_h, col_btn = st.columns([4,1])
    with col_btn:
        force_refresh = st.button("🔄 REFRESH NOW", key="news_refresh")

    now = time.time()
    if force_refresh or not st.session_state.news_cache or (now - st.session_state.news_ts) > 3600:
        with st.spinner("Fetching latest threat intelligence..."):
            from scanner import fetch_cyber_news
            st.session_state.news_cache = fetch_cyber_news()
            st.session_state.news_ts    = now

    articles = st.session_state.news_cache or []
    if not articles:
        st.info("Could not fetch news — check internet connection")
        return

    st.markdown(f'<p style="color:#2A4A5A;font-family:Share Tech Mono,monospace;font-size:0.68rem;margin-bottom:16px">⚡ {len(articles)} articles loaded · Fetched: {datetime.fromtimestamp(st.session_state.news_ts).strftime("%H:%M:%S")}</p>', unsafe_allow_html=True)

    # 3-column grid
    cols = st.columns(3)
    for i, art in enumerate(articles):
        cat_color = CAT_COLOR.get(art.get("category","Security"), "#00B4FF")
        pub = art.get("published","")
        pub_str = pub[:10] if len(pub) >= 10 else "Recent"
        with cols[i % 3]:
            st.markdown(f"""
            <a href="{art['url']}" target="_blank" style="text-decoration:none">
              <div class="news-card" onmouseover="this.style.borderColor='rgba(0,180,255,0.4)'" onmouseout="this.style.borderColor='rgba(0,180,255,0.15)'">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
                  <span style="background:{cat_color}20;border:1px solid {cat_color}60;color:{cat_color};padding:2px 8px;border-radius:4px;font-family:Share Tech Mono,monospace;font-size:0.62rem;letter-spacing:1px">{art.get('category','Security')}</span>
                  <span style="color:#3A5A6A;font-family:Share Tech Mono,monospace;font-size:0.65rem">{art['source']}</span>
                </div>
                <div class="news-title">{art['title'][:90]}{'...' if len(art['title'])>90 else ''}</div>
                <div style="color:#5A8FA8;font-family:Rajdhani,sans-serif;font-size:0.85rem;line-height:1.5;margin-bottom:8px">{art.get('summary','')[:140]}{'...' if len(art.get('summary',''))>140 else ''}</div>
                <div class="news-meta">
                  <span class="news-date">📅 {pub_str}</span>
                  <span class="news-src">↗ Read More</span>
                </div>
              </div>
            </a>""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  NAV
# ══════════════════════════════════════════════════════════════════════════════
def render_nav():
    user = st.session_state.user
    col_logo, col_nav, col_user = st.columns([2, 3, 2])
    with col_logo:
        st.markdown('<div class="seclite-logo">🛡 SECLITE</div>', unsafe_allow_html=True)
    with col_nav:
        c1, c2, c3 = st.columns(3)
        with c1:
            if st.button("SCAN",        key="nav_scan"):    st.session_state.page = "scan";    st.rerun()
        with c2:
            if st.button("HISTORY",     key="nav_hist"):    st.session_state.page = "history"; st.rerun()
        with c3:
            if st.button("DAILY BLOGS", key="nav_blogs"):   st.session_state.page = "blogs";   st.rerun()
    with col_user:
        badge = '<span class="admin-badge">ADMIN</span>' if user.get("is_admin") else ""
        st.markdown(f'<div style="text-align:right;padding-top:4px">{badge}<span class="nav-user">{user["name"]}</span></div>', unsafe_allow_html=True)
        if st.button("↩ LOGOUT", key="nav_logout"):
            for k in ["logged_in","user","scan_results","scan_history","news_cache","news_ts"]:
                del st.session_state[k]
            st.rerun()
    st.markdown('<hr style="border:none;border-top:1px solid rgba(0,180,255,0.15);margin:8px 0 20px">', unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
if not st.session_state.logged_in:
    render_login()
else:
    render_nav()
    page = st.session_state.page
    if   page == "scan":    render_scan_page()
    elif page == "history": render_history_page()
    elif page == "blogs":   render_blogs_page()
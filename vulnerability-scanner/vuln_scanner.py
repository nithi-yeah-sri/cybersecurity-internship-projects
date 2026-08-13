import streamlit as st
import requests
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------
st.set_page_config(page_title="Vulnerability Scanner", page_icon="🛰️", layout="centered")

# ---------------------------------------------------------
# REFERENCE DATA
# ---------------------------------------------------------

# Security headers every modern site should send, and why they matter
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "risk": "Medium",
        "explanation": "Without this header, browsers may connect over insecure HTTP, exposing traffic to interception.",
        "fix": "Add 'Strict-Transport-Security: max-age=31536000' to force HTTPS connections."
    },
    "X-Frame-Options": {
        "risk": "Medium",
        "explanation": "Without this header, your site can be embedded in a hidden iframe on a malicious site (clickjacking attack).",
        "fix": "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' to prevent embedding."
    },
    "X-Content-Type-Options": {
        "risk": "Low",
        "explanation": "Without this header, browsers may 'guess' file types, which can lead to malicious file execution.",
        "fix": "Add 'X-Content-Type-Options: nosniff'."
    },
    "Content-Security-Policy": {
        "risk": "High",
        "explanation": "Without this header, the site has no defense against malicious scripts being injected (XSS attacks).",
        "fix": "Add a 'Content-Security-Policy' header restricting where scripts/styles can load from."
    },
    "Referrer-Policy": {
        "risk": "Low",
        "explanation": "Without this header, full URLs (which may contain sensitive info) may leak to third-party sites via the referrer.",
        "fix": "Add 'Referrer-Policy: strict-origin-when-cross-origin'."
    },
    "Permissions-Policy": {
        "risk": "Low",
        "explanation": "Without this header, browser features (camera, mic, location) aren't restricted for embedded content.",
        "fix": "Add a 'Permissions-Policy' header to restrict sensitive browser features."
    },
}

# Common ports that are worth checking for a basic scan (safe, non-intrusive set)
COMMON_PORTS = {
    21: "FTP (file transfer — often insecure, avoid exposing)",
    22: "SSH (remote access — should be firewalled/restricted)",
    23: "Telnet (very insecure, should never be open)",
    25: "SMTP (email — should be restricted)",
    80: "HTTP (normal web traffic)",
    443: "HTTPS (normal secure web traffic)",
    3306: "MySQL (database — should NEVER be open to the public)",
    3389: "RDP (remote desktop — high risk if open to public)",
    8080: "Alternate HTTP (often used for dev/admin panels)",
}


# ---------------------------------------------------------
# SCAN LOGIC
# ---------------------------------------------------------
def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    return raw_url


def check_headers(url: str):
    """Check response headers against the security header checklist."""
    findings = []
    try:
        resp = requests.get(url, timeout=8, allow_redirects=True)
        headers = resp.headers

        for header, info in SECURITY_HEADERS.items():
            if header not in headers:
                findings.append({
                    "type": "Missing Security Header",
                    "name": header,
                    "risk": info["risk"],
                    "explanation": info["explanation"],
                    "fix": info["fix"]
                })

        # Server / software version disclosure
        server_header = headers.get("Server")
        if server_header:
            findings.append({
                "type": "Information Disclosure",
                "name": f"Server header reveals: {server_header}",
                "risk": "Low",
                "explanation": "Exposing server software/version helps attackers look up known vulnerabilities for that exact version.",
                "fix": "Configure your server to hide or generalize the 'Server' header."
            })

        x_powered_by = headers.get("X-Powered-By")
        if x_powered_by:
            findings.append({
                "type": "Information Disclosure",
                "name": f"X-Powered-By header reveals: {x_powered_by}",
                "risk": "Low",
                "explanation": "This reveals the backend framework/language in use, aiding targeted attacks.",
                "fix": "Disable or remove the 'X-Powered-By' header in your server configuration."
            })

        # Check cookie security flags (if any cookies set)
        if resp.cookies:
            for cookie in resp.cookies:
                if not cookie.secure:
                    findings.append({
                        "type": "Insecure Cookie",
                        "name": f"Cookie '{cookie.name}' missing Secure flag",
                        "risk": "Medium",
                        "explanation": "Cookies without the Secure flag can be transmitted over unencrypted HTTP connections.",
                        "fix": "Set the 'Secure' and 'HttpOnly' flags on all cookies."
                    })

        return findings, resp.status_code, None
    except requests.exceptions.SSLError:
        return [], None, "SSL certificate error — the site's HTTPS certificate may be invalid or self-signed."
    except requests.exceptions.ConnectionError:
        return [], None, "Could not connect to this site. Check the URL and make sure the site/server is running."
    except requests.exceptions.Timeout:
        return [], None, "Connection timed out. The site may be slow, offline, or blocking automated requests."
    except Exception as e:
        return [], None, f"Unexpected error: {e}"


def check_https(url: str):
    """Check whether the site enforces HTTPS."""
    findings = []
    if url.startswith("http://"):
        findings.append({
            "type": "Insecure Protocol",
            "name": "Site does not use HTTPS",
            "risk": "High",
            "explanation": "Data sent to/from this site (including passwords) can be intercepted by attackers on the network.",
            "fix": "Install an SSL/TLS certificate and redirect all HTTP traffic to HTTPS."
        })
    return findings


def scan_ports(hostname: str):
    """Lightweight, non-intrusive check of a small set of common ports."""
    # Resolve hostname first — fail cleanly if it doesn't exist
    try:
        socket.gethostbyname(hostname)
    except socket.gaierror:
        return None

    results = []
    for port, description in COMMON_PORTS.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.2)
            result = sock.connect_ex((hostname, port))
            sock.close()
            if result == 0:
                risky = port in [21, 23, 3306, 3389]
                results.append({
                    "port": port,
                    "description": description,
                    "risk": "High" if risky else "Info"
                })
        except Exception:
            continue
    return results


def risk_sort_key(risk):
    order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    return order.get(risk, 4)


# ---------------------------------------------------------
# THEME: dark terminal / matrix aesthetic (matches phishing detector)
# ---------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=JetBrains+Mono:wght@400;600;800&display=swap');

@import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=Inter:wght@400;500;600&family=IBM+Plex+Mono:wght@400;600&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }
.stApp {
    background:
        radial-gradient(circle at 50% -10%, rgba(0,212,255,0.10) 0%, transparent 55%),
        linear-gradient(180deg, #0b1220 0%, #0a0f1a 100%);
    color: #dce6f0;
}
#MainMenu, footer, header {visibility: hidden;}

/* ---- radar header ---- */
.radar-wrap {
    display: flex; align-items: center; gap: 22px;
    background: #101a2e; border: 1px solid #1e3a5f; border-radius: 12px;
    padding: 24px 28px; margin-bottom: 24px;
    box-shadow: 0 0 40px rgba(0,212,255,0.06), inset 0 0 60px rgba(0,212,255,0.02);
}
.radar {
    position: relative; width: 64px; height: 64px; border-radius: 50%;
    background: radial-gradient(circle, #0e1b30 0%, #0b1424 100%);
    border: 2px solid #1e3a5f; flex-shrink: 0; overflow: hidden;
}
.radar::before {
    content: ''; position: absolute; top: 50%; left: 50%; width: 50%; height: 2px;
    background: linear-gradient(90deg, rgba(0,212,255,0.9), transparent);
    transform-origin: left center; animation: sweep 2.4s linear infinite;
}
.radar::after {
    content: ''; position: absolute; inset: 8px; border-radius: 50%; border: 1px solid rgba(0,212,255,0.25);
}
@keyframes sweep { from { transform: translateY(-50%) rotate(0deg); } to { transform: translateY(-50%) rotate(360deg); } }

.hero-title {
    font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 26px; color: #eaf6ff;
    margin: 0 0 5px 0; letter-spacing: 0.2px;
}
.hero-title span { color: #00d4ff; }
.hero-sub { font-family: 'Inter', sans-serif; color: #7d93ad; font-size: 14px; margin: 0; line-height: 1.5; }

div[data-testid="stWidgetLabel"] p {
    color: #00d4ff !important; font-family: 'Space Grotesk', sans-serif !important;
    font-size: 12.5px !important; letter-spacing: 1.5px !important; font-weight: 700 !important; opacity: 0.9;
    text-transform: uppercase;
}
.stTextInput input {
    background: #0d1729 !important; border: 1px solid #234669 !important; color: #dce6f0 !important;
    font-family: 'IBM Plex Mono', monospace !important; border-radius: 8px !important;
    box-shadow: 0 0 6px rgba(0,212,255,0.08) !important;
}
.stTextInput input:focus { border: 1px solid #00d4ff !important; box-shadow: 0 0 16px rgba(0,212,255,0.45) !important; }
.stTextInput input::placeholder { color: #3f5878 !important; }

.stButton button {
    background: linear-gradient(135deg, #00d4ff, #0091d5) !important; color: #04101c !important; font-weight: 700 !important;
    font-family: 'Space Grotesk', sans-serif !important;
    border: none !important; border-radius: 8px !important; padding: 10px 26px !important;
    box-shadow: 0 0 18px rgba(0,212,255,0.35); transition: all 0.15s ease;
}
.stButton button:hover { box-shadow: 0 0 30px rgba(0,212,255,0.7); transform: translateY(-1px); }

.finding-card {
    border-radius: 10px; padding: 16px 20px; margin: 12px 0; border: 1px solid;
    font-family: 'Inter', sans-serif; background: #0d1729;
}
.risk-high { border-color: #ff4757; box-shadow: inset 3px 0 0 #ff4757; }
.risk-medium { border-color: #ffa502; box-shadow: inset 3px 0 0 #ffa502; }
.risk-low { border-color: #00d4ff; box-shadow: inset 3px 0 0 #00d4ff; }
.risk-info { border-color: #2c4562; box-shadow: inset 3px 0 0 #2c4562; }

.finding-title { font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 15px; margin-bottom: 5px; color: #eaf6ff; }
.finding-body { color: #a7bcd4; font-size: 13.5px; line-height: 1.55; }
.finding-fix { color: #6fd3ff; font-size: 13px; margin-top: 8px; font-family: 'IBM Plex Mono', monospace; }

.badge {
    display: inline-block; padding: 3px 11px; border-radius: 20px; font-size: 10.5px;
    font-family: 'Space Grotesk', sans-serif; font-weight: 700; letter-spacing: 1px; margin-right: 9px;
}
.badge-high { background: #ff4757; color: #0a0f1a; }
.badge-medium { background: #ffa502; color: #0a0f1a; }
.badge-low { background: #00d4ff; color: #0a0f1a; }
.badge-info { background: #2c4562; color: #dce6f0; }

.section-label {
    font-family: 'Space Grotesk', sans-serif; color: #00d4ff; font-size: 12.5px;
    letter-spacing: 2.5px; margin: 26px 0 12px 0; opacity: 0.9; text-transform: uppercase;
}
.summary-strip { display: flex; gap: 14px; margin: 18px 0 4px 0; flex-wrap: wrap; }
.summary-box {
    flex: 1; min-width: 110px; text-align: center; padding: 16px 8px; border-radius: 10px;
    border: 1px solid #1e3a5f; background: #0d1729; font-family: 'Space Grotesk', sans-serif;
}
.summary-num { font-size: 26px; font-weight: 700; }
.summary-label { font-size: 10.5px; color: #7d93ad; letter-spacing: 1.5px; margin-top: 3px; }

hr { border-color: #1e3a5f !important; }
.stExpander { background: #0d1729 !important; border: 1px solid #1e3a5f !important; border-radius: 10px !important; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# UI — HEADER
# ---------------------------------------------------------
st.markdown("""
<div class="radar-wrap">
    <div class="radar"></div>
    <div>
        <div class="hero-title">Basic <span>Vulnerability</span> Scanner</div>
        <p class="hero-sub">Enter a website URL you own or are authorized to test. The scanner checks HTTPS enforcement, security headers, information disclosure, and common open ports.</p>
    </div>
</div>
""", unsafe_allow_html=True)

st.markdown('<div class="finding-card risk-info"><b>⚠ Scope reminder:</b> Only scan websites/servers you own or have explicit permission to test. Scanning systems without authorization is illegal in most countries.</div>', unsafe_allow_html=True)

target_url = st.text_input("Target URL", placeholder="e.g. https://cyberguardaiapp.netlify.app")

scan = st.button("⦿  Run Scan", type="primary")

if scan:
    if not target_url.strip():
        st.warning("⚠ Enter a URL to scan.")
    else:
        url = normalize_url(target_url)
        hostname = urlparse(url).hostname

        with st.spinner("Scanning target..."):
            header_findings, status_code, error = check_headers(url)
            https_findings = check_https(url)
            port_results = scan_ports(hostname) if hostname else None

        if error:
            st.markdown(f'<div class="finding-card risk-high"><div class="finding-title">Scan Failed</div><div class="finding-body">{error}</div></div>', unsafe_allow_html=True)
        else:
            all_findings = https_findings + header_findings

            port_findings = []
            if port_results:
                for p in port_results:
                    port_findings.append({
                        "type": "Open Port",
                        "name": f"Port {p['port']} open — {p['description']}",
                        "risk": p["risk"] if p["risk"] != "Info" else "Low",
                        "explanation": "This port responded to a connection attempt, meaning a service is publicly reachable on it.",
                        "fix": "Close this port via your firewall/hosting settings unless it is intentionally required to be public."
                    })
            elif port_results is None:
                st.markdown('<div class="finding-card risk-medium"><div class="finding-title">Port scan skipped</div><div class="finding-body">Could not resolve the hostname for port scanning. Header/HTTPS checks still ran normally above.</div></div>', unsafe_allow_html=True)

            all_findings += port_findings
            all_findings.sort(key=lambda f: risk_sort_key(f["risk"]))

            high = len([f for f in all_findings if f["risk"] == "High"])
            medium = len([f for f in all_findings if f["risk"] == "Medium"])
            low = len([f for f in all_findings if f["risk"] == "Low"])

            st.markdown(f"""
            <div class="summary-strip">
                <div class="summary-box"><div class="summary-num" style="color:#ff4757">{high}</div><div class="summary-label">HIGH RISK</div></div>
                <div class="summary-box"><div class="summary-num" style="color:#ffa502">{medium}</div><div class="summary-label">MEDIUM RISK</div></div>
                <div class="summary-box"><div class="summary-num" style="color:#00d4ff">{low}</div><div class="summary-label">LOW RISK</div></div>
                <div class="summary-box"><div class="summary-num" style="color:#eaf6ff">{status_code}</div><div class="summary-label">HTTP STATUS</div></div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown('<div class="section-label">Scan Report</div>', unsafe_allow_html=True)

            if not all_findings:
                st.markdown('<div class="finding-card risk-info"><div class="finding-title">No issues detected</div><div class="finding-body">All checked security headers are present and no risky open ports were found in the scanned set.</div></div>', unsafe_allow_html=True)
            else:
                for f in all_findings:
                    risk_class = f"risk-{f['risk'].lower()}"
                    badge_class = f"badge-{f['risk'].lower()}"
                    st.markdown(f"""
                    <div class="finding-card {risk_class}">
                        <span class="badge {badge_class}">{f['risk'].upper()}</span>
                        <span class="finding-title">{f['type']}: {f['name']}</span>
                        <div class="finding-body">{f['explanation']}</div>
                        <div class="finding-fix">→ Fix: {f['fix']}</div>
                    </div>
                    """, unsafe_allow_html=True)

            st.caption(f"Scan completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}. This is a basic educational scanner — not a substitute for professional penetration testing tools.")

st.divider()
with st.expander("ℹ️  About this tool"):
    st.write("""
    This scanner checks for common, non-intrusive security weaknesses:
    - **HTTPS enforcement** — whether the site forces encrypted connections
    - **Security headers** — protections like Content-Security-Policy, X-Frame-Options, etc.
    - **Information disclosure** — server/software details exposed in response headers
    - **Cookie security flags** — whether cookies are marked Secure/HttpOnly
    - **Common open ports** — a small, safe set of frequently-targeted ports

    Each finding is labeled by risk level (High / Medium / Low) with a plain-English explanation
    and a suggested fix, similar to how real vulnerability scanning tools (like Nikto or OWASP ZAP)
    report their results — just simplified for learning purposes.
    """)

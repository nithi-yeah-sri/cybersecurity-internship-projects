import streamlit as st
import re
from urllib.parse import urlparse

# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------
st.set_page_config(page_title="Phishing Detection System", page_icon="🛡️", layout="centered")

# ---------------------------------------------------------
# REFERENCE DATA (used by the checks below)
# ---------------------------------------------------------

# Common brand names that phishers love to impersonate
TRUSTED_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "facebook",
    "netflix", "bankofamerica", "chase", "wellsfargo", "instagram",
    "linkedin", "ebay", "dropbox", "icloud", "outlook", "hdfc", "sbi",
    "icici", "axis", "irs", "whatsapp"
]

# Keywords commonly found in phishing URLs / emails
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account", "confirm",
    "banking", "signin", "sign-in", "webscr", "password", "suspend",
    "urgent", "click here", "limited time", "reactivate", "unlock",
    "security-alert", "billing", "invoice"
]

# Known URL-shortening services (they hide the real destination)
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "shorte.st", "rb.gy"
]

# Suspicious / free top-level domains often abused for phishing
SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".gq", ".tk", ".ml", ".cf", ".ga",
    ".loan", ".work", ".click", ".link", ".rest"
]

# Urgency / social-engineering phrases common in phishing emails
URGENCY_PHRASES = [
    "act now", "verify your account", "account suspended", "urgent action required",
    "confirm your identity", "your account will be closed", "unusual activity detected",
    "click below to verify", "limited time offer", "immediate action required",
    "your account has been locked", "update your payment", "win a prize",
    "you have won", "claim your reward", "failure to comply"
]

GENERIC_GREETINGS = ["dear customer", "dear user", "dear valued customer", "dear member", "dear sir/madam"]

SENSITIVE_INFO_REQUESTS = [
    "enter your password", "provide your ssn", "social security number",
    "credit card number", "cvv", "one time password", "otp", "pin number",
    "confirm your password", "banking details", "enter your pin"
]


# ---------------------------------------------------------
# URL ANALYSIS LOGIC
# ---------------------------------------------------------
def analyze_url(url: str):
    reasons = []
    score = 0

    original_url = url.strip()
    # Ensure URL has a scheme so urlparse works properly
    check_url = original_url
    if not re.match(r'^https?://', check_url, re.IGNORECASE):
        check_url = "http://" + check_url

    parsed = urlparse(check_url)
    domain = parsed.netloc.lower()
    full_url_lower = original_url.lower()

    # 1. Uses HTTPS or not
    if not original_url.lower().startswith("https://"):
        reasons.append("Does not use HTTPS (no secure connection)")
        score += 1

    # 2. IP address used instead of a domain name
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}'
    if re.match(ip_pattern, domain.replace(":", ".").split(".")[0] + "." + ".".join(domain.split(".")[1:])) or re.match(ip_pattern, domain):
        reasons.append("Uses a raw IP address instead of a domain name")
        score += 3

    # 3. '@' symbol trick (browsers ignore everything before '@')
    if "@" in original_url:
        reasons.append("Contains '@' symbol (used to disguise the real destination)")
        score += 3

    # 4. Known URL shortener
    for shortener in URL_SHORTENERS:
        if shortener in domain:
            reasons.append(f"Uses a URL shortening service ({shortener}) which hides the real destination")
            score += 2
            break

    # 5. Excessive hyphens in domain (common in fake lookalike domains)
    if domain.count("-") >= 2:
        reasons.append("Domain contains multiple hyphens (common in fake lookalike domains)")
        score += 2

    # 6. Excessive subdomains
    domain_parts = domain.split(".")
    if len(domain_parts) > 3:
        reasons.append("Unusually high number of subdomains")
        score += 2

    # 7. Very long URL
    if len(original_url) > 75:
        reasons.append("URL is unusually long (phishing links are often long to hide the real domain)")
        score += 1

    # 8. Suspicious keywords anywhere in the URL
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    if found_keywords:
        reasons.append(f"Contains suspicious keyword(s): {', '.join(found_keywords[:5])}")
        score += min(len(found_keywords), 3)

    # 9. Suspicious / free TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            reasons.append(f"Uses a top-level domain often linked to phishing ({tld})")
            score += 2
            break

    # 10. Brand name impersonation (brand mentioned but not the real domain)
    for brand in TRUSTED_BRANDS:
        if brand in full_url_lower and brand not in domain.replace("-", ""):
            reasons.append(f"Mentions brand '{brand}' but the domain doesn't actually belong to {brand}")
            score += 3
            break
        elif brand in domain:
            # brand appears as part of a longer suspicious domain, e.g. paypal-secure-login.com
            core_domain = domain.split(".")[0] if domain.split(".") else domain
            if core_domain != brand and brand in core_domain:
                reasons.append(f"Domain imitates brand '{brand}' with extra text (typosquatting pattern)")
                score += 3
            break

    # Determine verdict
    if score >= 6:
        verdict = "Likely Phishing"
    elif score >= 3:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return verdict, score, reasons


# ---------------------------------------------------------
# EMAIL TEXT ANALYSIS LOGIC
# ---------------------------------------------------------
def analyze_email(text: str):
    reasons = []
    score = 0
    text_lower = text.lower()

    # 1. Urgency / social engineering phrases
    found_urgency = [p for p in URGENCY_PHRASES if p in text_lower]
    if found_urgency:
        reasons.append(f"Contains urgency/pressure language: \"{found_urgency[0]}\"")
        score += min(len(found_urgency), 3)

    # 2. Generic greeting instead of a real name
    for greeting in GENERIC_GREETINGS:
        if greeting in text_lower:
            reasons.append("Uses a generic greeting instead of your actual name")
            score += 1
            break

    # 3. Requests for sensitive information
    found_sensitive = [p for p in SENSITIVE_INFO_REQUESTS if p in text_lower]
    if found_sensitive:
        reasons.append(f"Asks for sensitive information: \"{found_sensitive[0]}\"")
        score += 3

    # 4. Brand mentioned in text
    mentioned_brands = [b for b in TRUSTED_BRANDS if b in text_lower]
    if mentioned_brands:
        reasons.append(f"References well-known brand(s): {', '.join(mentioned_brands[:3])} (common impersonation target)")
        score += 1

    # 5. Extract any URLs inside the email and analyze them too
    urls_found = re.findall(r'(https?://[^\s]+|www\.[^\s]+)', text)
    url_flag_added = False
    for u in urls_found:
        u_verdict, u_score, u_reasons = analyze_url(u)
        if u_score >= 3:
            reasons.append(f"Contains a suspicious link ({u}) — flagged as {u_verdict}")
            score += 2
            url_flag_added = True

    # 6. Poor grammar / excessive exclamation marks (simple heuristic)
    if text.count("!") >= 3:
        reasons.append("Excessive use of exclamation marks (common in scam emails)")
        score += 1

    # 7. Mentions of prize / lottery / free money
    money_words = ["free money", "you have won", "lottery", "claim your prize", "cash prize"]
    if any(w in text_lower for w in money_words):
        reasons.append("Mentions winning money/prizes unexpectedly")
        score += 2

    if score >= 6:
        verdict = "Likely Phishing"
    elif score >= 3:
        verdict = "Suspicious"
    else:
        verdict = "Safe"

    return verdict, score, reasons


# ---------------------------------------------------------
# THEME: dark terminal / matrix aesthetic
# ---------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=JetBrains+Mono:wght@400;600;800&display=swap');

/* ---- base ---- */
html, body, [class*="css"] {
    font-family: 'JetBrains Mono', monospace !important;
}
.stApp {
    background:
        radial-gradient(circle at 15% 0%, rgba(0,255,65,0.06) 0%, transparent 45%),
        radial-gradient(circle at 85% 100%, rgba(0,255,65,0.05) 0%, transparent 45%),
        #0a0e0a;
    color: #c8f7d4;
}
#MainMenu, footer, header {visibility: hidden;}

/* ---- terminal header ---- */
.term-bar {
    background: #0f1a10;
    border: 1px solid #1c3a20;
    border-radius: 8px 8px 0 0;
    padding: 8px 14px;
    display: flex;
    gap: 7px;
    align-items: center;
}
.term-dot { width: 11px; height: 11px; border-radius: 50%; }
.dot-red { background:#ff5f56; } .dot-yellow { background:#ffbd2e; } .dot-green { background:#27c93f; }
.term-title { margin-left: 10px; color:#5f8a68; font-size: 12px; letter-spacing: 1px; }

.term-body {
    background: #0d150e;
    border: 1px solid #1c3a20;
    border-top: none;
    border-radius: 0 0 8px 8px;
    padding: 26px 28px 22px 28px;
    margin-bottom: 26px;
    box-shadow: 0 0 40px rgba(0,255,65,0.05), inset 0 0 60px rgba(0,255,65,0.02);
}

.hero-title {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 800;
    font-size: 30px;
    color: #00ff41;
    text-shadow: 0 0 8px rgba(0,255,65,0.55), 0 0 22px rgba(0,255,65,0.25);
    margin: 0 0 4px 0;
    letter-spacing: 0.5px;
}
.hero-sub {
    font-family: 'Share Tech Mono', monospace;
    color: #6fae7a;
    font-size: 14.5px;
    margin: 0;
}
.blink-cursor {
    display: inline-block;
    width: 9px; height: 18px;
    background: #00ff41;
    margin-left: 6px;
    vertical-align: -3px;
    animation: blink 1.1s steps(1) infinite;
    box-shadow: 0 0 8px #00ff41;
}
@keyframes blink { 50% { opacity: 0; } }

/* ---- labels / inputs ---- */
.stRadio label, .stTextInput label, .stTextArea label, p, .stMarkdown, span {
    color: #a9d8b3 !important;
}
.stRadio > div { gap: 4px; }
.stTextInput input, .stTextArea textarea {
    background: #0a120b !important;
    border: 1px solid #245c30 !important;
    color: #c8f7d4 !important;
    font-family: 'Share Tech Mono', monospace !important;
    border-radius: 6px !important;
}
.stTextInput input:focus, .stTextArea textarea:focus {
    border: 1px solid #00ff41 !important;
    box-shadow: 0 0 10px rgba(0,255,65,0.35) !important;
}
.stTextInput input::placeholder, .stTextArea textarea::placeholder { color: #3d5c43 !important; }

/* ---- button ---- */
.stButton button {
    background: #00ff41 !important;
    color: #06120a !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-weight: 800 !important;
    border: none !important;
    border-radius: 6px !important;
    padding: 10px 26px !important;
    letter-spacing: 0.5px;
    box-shadow: 0 0 16px rgba(0,255,65,0.4);
    transition: all 0.15s ease;
}
.stButton button:hover {
    box-shadow: 0 0 26px rgba(0,255,65,0.75);
    transform: translateY(-1px);
}

/* ---- result cards ---- */
.result-card {
    border-radius: 8px;
    padding: 18px 22px;
    margin: 18px 0 6px 0;
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700;
    font-size: 17px;
    border: 1px solid;
}
.card-safe {
    background: rgba(0,255,65,0.07);
    border-color: #00ff41;
    color: #6dffa0;
    box-shadow: 0 0 20px rgba(0,255,65,0.15);
}
.card-suspicious {
    background: rgba(255,184,0,0.08);
    border-color: #ffb800;
    color: #ffd166;
    box-shadow: 0 0 20px rgba(255,184,0,0.15);
}
.card-danger {
    background: rgba(255,51,51,0.08);
    border-color: #ff3333;
    color: #ff8080;
    box-shadow: 0 0 20px rgba(255,51,51,0.18);
}

.reason-item {
    font-family: 'Share Tech Mono', monospace;
    color: #b7d9bf;
    font-size: 14.5px;
    padding: 5px 0 5px 4px;
    border-left: 2px solid #245c30;
    padding-left: 12px;
    margin-bottom: 6px;
}

.section-label {
    font-family: 'JetBrains Mono', monospace;
    color: #00ff41;
    font-size: 13px;
    letter-spacing: 2px;
    margin: 22px 0 10px 0;
    opacity: 0.8;
}

hr { border-color: #1c3a20 !important; }

.stExpander {
    background: #0d150e !important;
    border: 1px solid #1c3a20 !important;
    border-radius: 8px !important;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# UI — TERMINAL HEADER
# ---------------------------------------------------------
st.markdown("""
<div class="term-bar">
    <div class="term-dot dot-red"></div>
    <div class="term-dot dot-yellow"></div>
    <div class="term-dot dot-green"></div>
    <span class="term-title">phishing_detector.exe — running</span>
</div>
<div class="term-body">
    <div class="hero-title">&gt; PHISHING_DETECTION_SYSTEM<span class="blink-cursor"></span></div>
    <p class="hero-sub">Paste a URL or email text below. The system scans it for known phishing indicators and returns a risk verdict.</p>
</div>
""", unsafe_allow_html=True)

input_type = st.radio("SCAN TARGET:", ["URL", "Email Text"], horizontal=True)

if input_type == "URL":
    user_input = st.text_input("TARGET URL:", placeholder="e.g. http://paypal-secure-login.xyz/verify")
else:
    user_input = st.text_area("TARGET EMAIL CONTENT:", height=200, placeholder="Paste the full email content here...")

check = st.button("▶ RUN SCAN", type="primary")

if check:
    if not user_input.strip():
        st.warning("⚠ No input detected. Enter a URL or email text to scan.")
    else:
        if input_type == "URL":
            verdict, score, reasons = analyze_url(user_input)
        else:
            verdict, score, reasons = analyze_email(user_input)

        # Result banner
        if verdict == "Safe":
            st.markdown(f'<div class="result-card card-safe">✅ VERDICT: {verdict.upper()} &nbsp;|&nbsp; RISK SCORE: {score}</div>', unsafe_allow_html=True)
        elif verdict == "Suspicious":
            st.markdown(f'<div class="result-card card-suspicious">⚠ VERDICT: {verdict.upper()} &nbsp;|&nbsp; RISK SCORE: {score}</div>', unsafe_allow_html=True)
        else:
            st.markdown(f'<div class="result-card card-danger">🚨 VERDICT: {verdict.upper()} &nbsp;|&nbsp; RISK SCORE: {score}</div>', unsafe_allow_html=True)

        # Reasons
        st.markdown('<div class="section-label">// DETECTED INDICATORS</div>', unsafe_allow_html=True)
        if reasons:
            for r in reasons:
                st.markdown(f'<div class="reason-item">$ {r}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="reason-item">$ No suspicious indicators found.</div>', unsafe_allow_html=True)

        st.caption("Note: This is a rule-based educational tool and not a substitute for professional security software.")

st.divider()
with st.expander("ℹ️  ABOUT THIS TOOL"):
    st.write("""
    This system checks for common phishing red flags such as:
    - Suspicious keywords (login, verify, urgent, etc.)
    - Fake or lookalike domains impersonating trusted brands
    - IP addresses used instead of proper domain names
    - URL shorteners hiding real destinations
    - Urgency and pressure language in emails
    - Requests for sensitive information (passwords, OTPs, card numbers)

    Each indicator adds to a risk score, which determines whether the input is classified as
    **Safe**, **Suspicious**, or **Likely Phishing**.
    """)

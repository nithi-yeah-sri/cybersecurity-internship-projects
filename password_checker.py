import streamlit as st
import re

# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------
st.set_page_config(page_title="Password Strength Checker", page_icon="🔐", layout="centered")

# ---------------------------------------------------------
# REFERENCE DATA
# ---------------------------------------------------------
COMMON_WEAK_PASSWORDS = [
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "password1", "111111", "iloveyou", "admin", "welcome", "monkey",
    "letmein", "dragon", "master", "login", "princess", "qwerty123",
    "solo", "passw0rd", "starwars", "football", "shadow"
]

KEYBOARD_PATTERNS = ["qwerty", "asdf", "zxcv", "1234", "0987", "9876"]


# ---------------------------------------------------------
# ANALYSIS LOGIC
# ---------------------------------------------------------
def analyze_password(pw: str):
    checks = []
    score = 0
    pw_lower = pw.lower()

    # 1. Length
    length = len(pw)
    if length >= 12:
        checks.append({"label": "Length (12+ characters)", "passed": True, "detail": f"{length} characters — strong length."})
        score += 2
    elif length >= 8:
        checks.append({"label": "Length (8+ characters)", "passed": True, "detail": f"{length} characters — acceptable, but 12+ is safer."})
        score += 1
    else:
        checks.append({"label": "Length (8+ characters)", "passed": False, "detail": f"Only {length} characters — too short. Aim for 12+."})

    # 2. Uppercase
    has_upper = bool(re.search(r'[A-Z]', pw))
    checks.append({"label": "Contains uppercase letter", "passed": has_upper, "detail": "Found at least one A-Z." if has_upper else "No uppercase letters found."})
    if has_upper: score += 1

    # 3. Lowercase
    has_lower = bool(re.search(r'[a-z]', pw))
    checks.append({"label": "Contains lowercase letter", "passed": has_lower, "detail": "Found at least one a-z." if has_lower else "No lowercase letters found."})
    if has_lower: score += 1

    # 4. Numbers
    has_digit = bool(re.search(r'[0-9]', pw))
    checks.append({"label": "Contains a number", "passed": has_digit, "detail": "Found at least one digit." if has_digit else "No numbers found."})
    if has_digit: score += 1

    # 5. Special characters
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?~`]', pw))
    checks.append({"label": "Contains special character", "passed": has_special, "detail": "Found at least one symbol (!@#$ etc.)." if has_special else "No special characters found."})
    if has_special: score += 1

    # 6. Not a common weak password
    is_common = pw_lower in COMMON_WEAK_PASSWORDS
    checks.append({"label": "Not a commonly used password", "passed": not is_common, "detail": "This exact password appears on common breach/weak-password lists!" if is_common else "Not found in common weak-password list."})
    if is_common: score -= 3

    # 7. No obvious keyboard pattern
    has_pattern = any(pattern in pw_lower for pattern in KEYBOARD_PATTERNS)
    checks.append({"label": "No obvious keyboard pattern", "passed": not has_pattern, "detail": "Contains a predictable pattern like 'qwerty' or '1234'." if has_pattern else "No obvious keyboard patterns detected."})
    if has_pattern: score -= 1

    # 8. No excessive repeated characters
    has_repeats = bool(re.search(r'(.)\1{2,}', pw))
    checks.append({"label": "No repeated character runs", "passed": not has_repeats, "detail": "Contains 3+ repeated characters in a row (e.g. 'aaa')." if has_repeats else "No excessive character repetition."})
    if has_repeats: score -= 1

    score = max(0, score)

    # Verdict
    if score >= 6:
        verdict = "Strong"
    elif score >= 3:
        verdict = "Medium"
    else:
        verdict = "Weak"

    # Suggestions based on failed checks
    suggestions = []
    for c in checks:
        if not c["passed"]:
            if "Length" in c["label"]:
                suggestions.append("Make your password at least 12 characters long.")
            elif "uppercase" in c["label"]:
                suggestions.append("Add at least one uppercase letter (A-Z).")
            elif "lowercase" in c["label"]:
                suggestions.append("Add at least one lowercase letter (a-z).")
            elif "number" in c["label"]:
                suggestions.append("Add at least one number (0-9).")
            elif "special" in c["label"]:
                suggestions.append("Add at least one special character (e.g. ! @ # $ %).")
            elif "commonly used" in c["label"]:
                suggestions.append("Avoid using well-known passwords — pick something unique.")
            elif "keyboard pattern" in c["label"]:
                suggestions.append("Avoid predictable sequences like 'qwerty' or '1234'.")
            elif "repeated character" in c["label"]:
                suggestions.append("Avoid repeating the same character multiple times in a row.")

    if not suggestions:
        suggestions.append("Great password! Consider using a password manager to keep it unique per account.")

    return verdict, score, checks, suggestions


def suggest_strong_password(pw: str):
    """Strengthen the user's own password by keeping it recognizable and
    adding only what's missing (capital, digit, symbol, extra length),
    instead of generating something fully random."""
    suggestion = pw

    # Ensure at least one uppercase letter — capitalize the first letter found
    if not re.search(r'[A-Z]', suggestion):
        idx = next((i for i, c in enumerate(suggestion) if c.isalpha()), None)
        if idx is not None:
            suggestion = suggestion[:idx] + suggestion[idx].upper() + suggestion[idx+1:]
        else:
            suggestion = "X" + suggestion

    # Ensure at least one lowercase letter (rare edge case)
    if not re.search(r'[a-z]', suggestion):
        suggestion += "x"

    # Ensure at least one digit
    if not re.search(r'[0-9]', suggestion):
        suggestion += "7"

    # Ensure at least one special character
    if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?~`]', suggestion):
        suggestion += "#"

    # Extend length to 12+ using a repeating symbol+digit pattern
    # (keeps it non-random/deterministic, easy to remember the "formula")
    suffix_pool = [":", "!", "$", "%", "&"]
    i = 0
    while len(suggestion) < 12:
        suggestion += suffix_pool[i % len(suffix_pool)]
        if len(suggestion) < 12:
            suggestion += str((i * 3 + 7) % 10)
        i += 1

    return suggestion


# ---------------------------------------------------------
# THEME: vault / deep purple & gold aesthetic
# ---------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@600;700&family=Manrope:wght@400;500;600;700&display=swap');

html, body, [class*="css"] { font-family: 'Manrope', sans-serif !important; }
.stApp {
    background:
        radial-gradient(circle at 50% -10%, rgba(212,175,55,0.10) 0%, transparent 55%),
        linear-gradient(180deg, #1a0f2e 0%, #140a24 100%);
    color: #e8dff5;
}
#MainMenu, footer, header {visibility: hidden;}

.vault-wrap {
    display: flex; align-items: center; gap: 22px;
    background: #22163a; border: 1px solid #3d2a5c; border-radius: 12px;
    padding: 24px 28px; margin-bottom: 22px;
    box-shadow: 0 0 40px rgba(212,175,55,0.06), inset 0 0 60px rgba(212,175,55,0.02);
}
.vault-icon {
    width: 60px; height: 60px; border-radius: 50%; flex-shrink: 0;
    background: radial-gradient(circle, #2c1d47 0%, #1c1230 100%);
    border: 2px solid #d4af37; display: flex; align-items: center; justify-content: center;
    font-size: 26px; box-shadow: 0 0 18px rgba(212,175,55,0.35);
}
.hero-title {
    font-family: 'Cormorant Garamond', serif; font-weight: 700; font-size: 30px; color: #f3ecff;
    margin: 0 0 5px 0; letter-spacing: 0.3px;
}
.hero-title span { color: #d4af37; }
.hero-sub { color: #b3a1cc; font-size: 14px; margin: 0; line-height: 1.5; }

div[data-testid="stWidgetLabel"] p {
    color: #d4af37 !important; font-family: 'Manrope', sans-serif !important;
    font-size: 12.5px !important; letter-spacing: 1.5px !important; font-weight: 700 !important; opacity: 0.9;
    text-transform: uppercase;
}
.stTextInput input {
    background: #1c1230 !important; border: 1px solid #3d2a5c !important; color: #e8dff5 !important;
    font-family: 'Manrope', sans-serif !important; border-radius: 8px !important;
    box-shadow: 0 0 6px rgba(212,175,55,0.08) !important;
}
.stTextInput input:focus { border: 1px solid #d4af37 !important; box-shadow: 0 0 16px rgba(212,175,55,0.4) !important; }
.stTextInput input::placeholder { color: #5c4a7a !important; }

/* meter */
.meter-track {
    width: 100%; height: 12px; background: #1c1230; border-radius: 20px; overflow: hidden;
    border: 1px solid #3d2a5c; margin: 14px 0 4px 0;
}
.meter-fill { height: 100%; border-radius: 20px; transition: width 0.4s ease; }
.fill-weak { background: linear-gradient(90deg, #ff4757, #ff6b81); }
.fill-medium { background: linear-gradient(90deg, #ffa502, #ffd166); }
.fill-strong { background: linear-gradient(90deg, #2ed573, #7bed9f); }

.verdict-label {
    font-family: 'Cormorant Garamond', serif; font-weight: 700; font-size: 22px; margin: 6px 0 18px 0;
}
.verdict-weak { color: #ff6b81; }
.verdict-medium { color: #ffd166; }
.verdict-strong { color: #7bed9f; }

/* vault door */
.vault-door-scene {
    position: relative; width: 100%; max-width: 320px; height: 90px; margin: 4px auto 22px auto;
    background: #0f0a1c; border-radius: 10px; border: 1px solid #3d2a5c; overflow: hidden;
    box-shadow: inset 0 0 30px rgba(0,0,0,0.5);
}
.vault-interior {
    position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
    background: radial-gradient(circle, #1c1230 0%, #0f0a1c 100%);
}
.vault-lock-icon { font-size: 28px; z-index: 3; position: relative; transition: all 0.4s ease; }
.vault-lock-glow-strong { filter: drop-shadow(0 0 12px #d4af37); }
.door-panel {
    position: absolute; top: 0; bottom: 0; z-index: 2;
    background: repeating-linear-gradient(135deg, #4a3568, #4a3568 8px, #3d2a5c 8px, #3d2a5c 16px);
    border: 1px solid #d4af37; transition: width 0.5s cubic-bezier(.4,0,.2,1);
    box-shadow: 0 0 14px rgba(212,175,55,0.15);
}
.door-left { left: 0; border-right: 2px solid #d4af37; }
.door-right { right: 0; border-left: 2px solid #d4af37; }
.vault-caption {
    text-align: center; font-size: 12px; color: #9c88b8; margin-top: -14px; margin-bottom: 16px;
    letter-spacing: 0.5px;
}


.check-item {
    display: flex; align-items: flex-start; gap: 10px; padding: 9px 4px; border-bottom: 1px solid #2c1d47;
}
.check-icon { font-size: 14px; margin-top: 1px; }
.check-pass { color: #7bed9f; } .check-fail { color: #ff6b81; }
.check-label { font-weight: 600; font-size: 13.5px; color: #e8dff5; }
.check-detail { font-size: 12.5px; color: #9c88b8; margin-top: 1px; }

.suggestion-card {
    background: #22163a; border: 1px solid #3d2a5c; border-left: 3px solid #d4af37;
    border-radius: 8px; padding: 12px 16px; margin: 8px 0; font-size: 13.5px; color: #d9cdee;
}

.password-suggest-box {
    background: #1c1230; border: 1px solid #d4af37; border-radius: 10px;
    padding: 16px 20px; margin: 14px 0; box-shadow: 0 0 20px rgba(212,175,55,0.15);
}
.password-suggest-label {
    font-size: 11.5px; color: #9c88b8; letter-spacing: 1.5px; text-transform: uppercase; margin-bottom: 8px;
}
.password-suggest-value {
    font-family: 'Courier New', monospace; font-size: 19px; font-weight: 700; color: #f3ecff;
    letter-spacing: 1px; word-break: break-all;
}
.password-suggest-note {
    font-size: 12px; color: #9c88b8; margin-top: 8px; line-height: 1.5;
}

.section-label {
    font-family: 'Manrope', sans-serif; color: #d4af37; font-size: 12.5px;
    letter-spacing: 2.5px; margin: 24px 0 10px 0; opacity: 0.9; text-transform: uppercase;
}

hr { border-color: #3d2a5c !important; }
.stExpander { background: #22163a !important; border: 1px solid #3d2a5c !important; border-radius: 10px !important; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# UI — HEADER
# ---------------------------------------------------------
st.markdown("""
<div class="vault-wrap">
    <div class="vault-icon">🔐</div>
    <div>
        <div class="hero-title">Password <span>Strength</span> Checker</div>
        <p class="hero-sub">Type a password below to see how strong it is, with specific suggestions to improve it. Nothing you type is saved or sent anywhere.</p>
    </div>
</div>
""", unsafe_allow_html=True)

password = st.text_input("Enter a password to check", type="password", placeholder="Type here...")

if password:
    verdict, score, checks, suggestions = analyze_password(password)

    fill_class = f"fill-{verdict.lower()}"
    verdict_class = f"verdict-{verdict.lower()}"
    fill_pct = min(100, max(8, (score / 8) * 100))
    door_width = fill_pct / 2  # each door panel covers half the closing distance

    # Lock icon + glow state based on verdict
    if verdict == "Strong":
        lock_icon, glow_class = "🔒", "vault-lock-glow-strong"
    elif verdict == "Medium":
        lock_icon, glow_class = "🔐", ""
    else:
        lock_icon, glow_class = "🔓", ""

    # ---- animated vault door ----
    st.markdown(f"""
    <div class="vault-door-scene">
        <div class="vault-interior"><span class="vault-lock-icon {glow_class}">{lock_icon}</span></div>
        <div class="door-panel door-left" style="width:{door_width}%;"></div>
        <div class="door-panel door-right" style="width:{door_width}%;"></div>
    </div>
    <div class="vault-caption">{"Vault sealed" if verdict == "Strong" else "Vault door closing..." if verdict == "Medium" else "Vault wide open — unsafe"}</div>
    """, unsafe_allow_html=True)

    st.markdown(f"""
    <div class="meter-track"><div class="meter-fill {fill_class}" style="width:{fill_pct}%;"></div></div>
    <div class="verdict-label {verdict_class}">{verdict} Password</div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="section-label">Checklist</div>', unsafe_allow_html=True)
    for c in checks:
        icon = "✓" if c["passed"] else "✕"
        icon_class = "check-pass" if c["passed"] else "check-fail"
        st.markdown(f"""
        <div class="check-item">
            <span class="check-icon {icon_class}">{icon}</span>
            <div>
                <div class="check-label">{c['label']}</div>
                <div class="check-detail">{c['detail']}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="section-label">Suggestions</div>', unsafe_allow_html=True)
    for s in suggestions:
        st.markdown(f'<div class="suggestion-card">💡 {s}</div>', unsafe_allow_html=True)

    # ---- smart strengthened suggestion (only if not already strong) ----
    if verdict != "Strong":
        smart_suggestion = suggest_strong_password(password)
        st.markdown('<div class="section-label">Strengthened Version</div>', unsafe_allow_html=True)
        st.markdown(f"""
        <div class="password-suggest-box">
            <div class="password-suggest-label">Based on what you typed</div>
            <div class="password-suggest-value">{smart_suggestion}</div>
            <div class="password-suggest-note">This keeps your original password recognizable but adds what's missing (capital letter, symbol, digits, length) to make it significantly stronger.</div>
        </div>
        """, unsafe_allow_html=True)

else:
    st.caption("Start typing above to see your password strength analysis.")

st.divider()
with st.expander("ℹ️  About this tool"):
    st.write("""
    This checker evaluates password strength using common security criteria:
    - **Length** — longer passwords are exponentially harder to brute-force
    - **Character variety** — uppercase, lowercase, numbers, and symbols increase the possible combinations an attacker must try
    - **Common password detection** — flags passwords found on well-known weak/breached password lists
    - **Pattern detection** — flags predictable sequences (like 'qwerty' or '1234') and repeated characters

    Your password is classified as **Weak**, **Medium**, or **Strong** based on a scoring system, with
    specific suggestions to improve it. Nothing typed here is stored, logged, or transmitted anywhere —
    all analysis happens instantly in this session only.
    """)

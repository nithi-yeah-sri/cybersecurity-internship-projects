import streamlit as st
import sqlite3
import hashlib
import secrets
import hmac
import time
import os
from datetime import datetime

# ---------------------------------------------------------
# PAGE CONFIG
# ---------------------------------------------------------
st.set_page_config(page_title="Secure Login System", page_icon="🛡️", layout="centered")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "secure_login_users.db")

MAX_ATTEMPTS = 3          # failed attempts allowed before lockout
LOCKOUT_SECONDS = 30      # how long the account stays locked (kept short for demo purposes)
PBKDF2_ITERATIONS = 200_000


# ---------------------------------------------------------
# DATABASE SETUP
# ---------------------------------------------------------
def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            failed_attempts INTEGER DEFAULT 0,
            lock_until REAL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


# ---------------------------------------------------------
# HASHING LOGIC
# ---------------------------------------------------------
def hash_password(password: str, salt: bytes = None):
    """Hash a password with PBKDF2-SHA256 and a random salt.
    Returns (salt_hex, hash_hex)."""
    if salt is None:
        salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, PBKDF2_ITERATIONS)
    return salt.hex(), pwd_hash.hex()


def verify_password(password: str, salt_hex: str, stored_hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    _, computed_hash = hash_password(password, salt)
    # constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed_hash, stored_hash_hex)


# ---------------------------------------------------------
# USER OPERATIONS
# ---------------------------------------------------------
def register_user(username: str, password: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username FROM users WHERE username = ?", (username,))
    if cur.fetchone():
        conn.close()
        return False, "Username already exists. Try logging in instead."

    salt_hex, hash_hex = hash_password(password)
    cur.execute(
        "INSERT INTO users (username, salt, password_hash, failed_attempts, lock_until, created_at) VALUES (?, ?, ?, 0, 0, ?)",
        (username, salt_hex, hash_hex, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()
    return True, "Account created successfully. You can now log in."


def attempt_login(username: str, password: str):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT salt, password_hash, failed_attempts, lock_until FROM users WHERE username = ?", (username,))
    row = cur.fetchone()

    if not row:
        conn.close()
        return False, "No account found with that username.", None

    salt_hex, stored_hash, failed_attempts, lock_until = row
    now = time.time()

    # Check lockout
    if lock_until and now < lock_until:
        remaining = int(lock_until - now)
        conn.close()
        return False, f"Account temporarily locked due to too many failed attempts. Try again in {remaining} seconds.", remaining

    if verify_password(password, salt_hex, stored_hash):
        # success — reset attempts
        cur.execute("UPDATE users SET failed_attempts = 0, lock_until = 0 WHERE username = ?", (username,))
        conn.commit()
        conn.close()
        return True, "Login successful!", None
    else:
        failed_attempts += 1
        if failed_attempts >= MAX_ATTEMPTS:
            new_lock_until = now + LOCKOUT_SECONDS
            cur.execute("UPDATE users SET failed_attempts = 0, lock_until = ? WHERE username = ?", (new_lock_until, username))
            conn.commit()
            conn.close()
            return False, f"Incorrect password. Too many failed attempts — account locked for {LOCKOUT_SECONDS} seconds.", LOCKOUT_SECONDS
        else:
            cur.execute("UPDATE users SET failed_attempts = ? WHERE username = ?", (failed_attempts, username))
            conn.commit()
            conn.close()
            remaining_tries = MAX_ATTEMPTS - failed_attempts
            return False, f"Incorrect password. {remaining_tries} attempt(s) remaining before lockout.", None


def get_all_users_demo():
    """For the educational 'admin view' panel only — shows stored (hashed) data."""
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, salt, password_hash, created_at FROM users ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()
    return rows


# ---------------------------------------------------------
# THEME: crimson / charcoal "fortress" aesthetic
# ---------------------------------------------------------
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Oswald:wght@500;700&family=Inter:wght@400;500;600&display=swap');

html, body, [class*="css"] { font-family: 'Inter', sans-serif !important; }
.stApp {
    background:
        radial-gradient(circle at 50% -10%, rgba(220,38,38,0.08) 0%, transparent 55%),
        linear-gradient(180deg, #1a1a1a 0%, #141414 100%);
    color: #e8e6e3;
}
#MainMenu, footer, header {visibility: hidden;}

.fortress-wrap {
    display: flex; align-items: center; gap: 22px;
    background: #1f1f1f; border: 1px solid #3a3a3a; border-radius: 4px;
    padding: 24px 28px; margin-bottom: 22px; border-left: 4px solid #dc2626;
    box-shadow: 0 0 40px rgba(220,38,38,0.06);
}
.fortress-icon {
    width: 58px; height: 58px; flex-shrink: 0; display: flex; align-items: center; justify-content: center;
    background: #262626; border: 2px solid #dc2626; border-radius: 50%; font-size: 26px;
    box-shadow: 0 0 16px rgba(220,38,38,0.3);
}
.hero-title {
    font-family: 'Oswald', sans-serif; font-weight: 700; font-size: 27px; color: #f2f2f2;
    margin: 0 0 5px 0; letter-spacing: 0.5px; text-transform: uppercase;
}
.hero-title span { color: #dc2626; }
.hero-sub { color: #9c9c9c; font-size: 14px; margin: 0; line-height: 1.5; }

div[data-testid="stWidgetLabel"] p {
    color: #dc2626 !important; font-family: 'Oswald', sans-serif !important;
    font-size: 12.5px !important; letter-spacing: 1.5px !important; font-weight: 700 !important; opacity: 0.9;
    text-transform: uppercase;
}
.stTextInput input {
    background: #1f1f1f !important; border: 1px solid #3a3a3a !important; color: #e8e6e3 !important;
    font-family: 'Inter', sans-serif !important; border-radius: 4px !important;
}
.stTextInput input:focus { border: 1px solid #dc2626 !important; box-shadow: 0 0 14px rgba(220,38,38,0.35) !important; }
.stTextInput input::placeholder { color: #5c5c5c !important; }

.stButton button {
    background: #dc2626 !important; color: #fff !important; font-weight: 700 !important;
    font-family: 'Oswald', sans-serif !important; text-transform: uppercase; letter-spacing: 1px;
    border: none !important; border-radius: 4px !important; padding: 10px 26px !important;
    box-shadow: 0 0 16px rgba(220,38,38,0.3); transition: all 0.15s ease;
}
.stButton button:hover { box-shadow: 0 0 26px rgba(220,38,38,0.6); transform: translateY(-1px); }

.status-card {
    border-radius: 4px; padding: 14px 18px; margin: 14px 0; border-left: 4px solid; font-size: 14px;
}
.status-success { background: rgba(34,197,94,0.08); border-color: #22c55e; color: #86efac; }
.status-error { background: rgba(220,38,38,0.08); border-color: #dc2626; color: #fca5a5; }
.status-lock { background: rgba(234,179,8,0.08); border-color: #eab308; color: #fde68a; }

.section-label {
    font-family: 'Oswald', sans-serif; color: #dc2626; font-size: 12.5px;
    letter-spacing: 2.5px; margin: 24px 0 10px 0; opacity: 0.9; text-transform: uppercase;
}

.demo-table { width: 100%; border-collapse: collapse; font-family: 'Courier New', monospace; font-size: 11.5px; }
.demo-table th { text-align: left; color: #dc2626; padding: 6px 8px; border-bottom: 1px solid #3a3a3a; text-transform: uppercase; letter-spacing: 1px; }
.demo-table td { padding: 6px 8px; border-bottom: 1px solid #262626; color: #9c9c9c; word-break: break-all; }
.demo-table td.username-cell { color: #e8e6e3; font-weight: 700; }

.stTabs [data-baseweb="tab-list"] { gap: 4px; }
.stTabs [data-baseweb="tab"] {
    background: #1f1f1f; border-radius: 4px 4px 0 0; color: #9c9c9c; font-family: 'Oswald', sans-serif;
    text-transform: uppercase; letter-spacing: 1px; font-size: 13px;
}
.stTabs [aria-selected="true"] { color: #dc2626 !important; border-bottom: 2px solid #dc2626 !important; }

hr { border-color: #3a3a3a !important; }
.stExpander { background: #1f1f1f !important; border: 1px solid #3a3a3a !important; border-radius: 4px !important; }
</style>
""", unsafe_allow_html=True)

# ---------------------------------------------------------
# UI — HEADER
# ---------------------------------------------------------
st.markdown("""
<div class="fortress-wrap">
    <div class="fortress-icon">🛡️</div>
    <div>
        <div class="hero-title">Secure <span>Login</span> System</div>
        <p class="hero-sub">Passwords are hashed with a unique salt before storage — never saved as plain text. Accounts lock temporarily after repeated failed attempts to prevent brute-force attacks.</p>
    </div>
</div>
""", unsafe_allow_html=True)

tab_login, tab_register, tab_admin = st.tabs(["Login", "Register", "Admin View (Demo)"])

with tab_register:
    st.markdown('<div class="section-label">Create Account</div>', unsafe_allow_html=True)
    reg_username = st.text_input("Username", key="reg_user", placeholder="Choose a username")
    reg_password = st.text_input("Password", key="reg_pass", type="password", placeholder="Choose a password")
    reg_confirm = st.text_input("Confirm Password", key="reg_confirm", type="password", placeholder="Re-enter password")

    if st.button("Register", key="reg_btn"):
        if not reg_username.strip() or not reg_password:
            st.markdown('<div class="status-card status-error">Please fill in all fields.</div>', unsafe_allow_html=True)
        elif reg_password != reg_confirm:
            st.markdown('<div class="status-card status-error">Passwords do not match.</div>', unsafe_allow_html=True)
        elif len(reg_password) < 6:
            st.markdown('<div class="status-card status-error">Password must be at least 6 characters.</div>', unsafe_allow_html=True)
        else:
            success, msg = register_user(reg_username.strip(), reg_password)
            css_class = "status-success" if success else "status-error"
            st.markdown(f'<div class="status-card {css_class}">{msg}</div>', unsafe_allow_html=True)

with tab_login:
    st.markdown('<div class="section-label">Log In</div>', unsafe_allow_html=True)
    login_username = st.text_input("Username", key="login_user", placeholder="Your username")
    login_password = st.text_input("Password", key="login_pass", type="password", placeholder="Your password")

    if st.button("Log In", key="login_btn"):
        if not login_username.strip() or not login_password:
            st.markdown('<div class="status-card status-error">Please enter both username and password.</div>', unsafe_allow_html=True)
        else:
            success, msg, extra = attempt_login(login_username.strip(), login_password)
            if success:
                st.markdown(f'<div class="status-card status-success">✅ {msg} Welcome, {login_username}.</div>', unsafe_allow_html=True)
                st.balloons()
            elif "locked" in msg.lower():
                st.markdown(f'<div class="status-card status-lock">🔒 {msg}</div>', unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="status-card status-error">❌ {msg}</div>', unsafe_allow_html=True)

with tab_admin:
    st.markdown('<div class="section-label">What Actually Gets Stored</div>', unsafe_allow_html=True)
    st.caption("This panel is for demonstration purposes only, to prove passwords are never stored in plain text — a real system would never expose this to users.")
    users = get_all_users_demo()
    if not users:
        st.info("No accounts registered yet. Create one in the Register tab.")
    else:
        rows_html = ""
        for username, salt, pwd_hash, created in users:
            rows_html += f"""
            <tr>
                <td class="username-cell">{username}</td>
                <td>{salt[:20]}...</td>
                <td>{pwd_hash[:24]}...</td>
                <td>{created[:19]}</td>
            </tr>
            """
        st.markdown(f"""
        <table class="demo-table">
            <tr><th>Username</th><th>Salt (truncated)</th><th>Password Hash (truncated)</th><th>Created At</th></tr>
            {rows_html}
        </table>
        """, unsafe_allow_html=True)

st.divider()
with st.expander("ℹ️  About this tool"):
    st.write(f"""
    This system demonstrates core authentication security concepts:

    - **Password hashing (PBKDF2-SHA256, {PBKDF2_ITERATIONS:,} iterations):** passwords are never stored as plain text.
      Instead, they're run through a one-way mathematical function that can't be reversed.
    - **Salting:** a random value is generated for each user and mixed into the hash. This means two users with
      the identical password end up with completely different stored hashes, defeating pre-computed
      "rainbow table" attacks.
    - **Constant-time comparison:** password verification uses a comparison method that takes the same amount
      of time regardless of how much of the password matches, preventing timing-based attacks.
    - **Account lockout:** after {MAX_ATTEMPTS} failed login attempts, the account locks for {LOCKOUT_SECONDS} seconds.
      This is the core defense against brute-force attacks, where an attacker's script tries thousands of
      password guesses per second — lockout makes that approach impractical.

    Data is stored locally in a small SQLite database file (`secure_login_users.db`) alongside this app —
    nothing is sent anywhere else.
    """)

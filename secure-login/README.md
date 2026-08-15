# Secure Login System with Attack Prevention

A register/login website that never stores passwords in plain text, and locks accounts temporarily after repeated wrong password attempts.

## How to try it out
1. Register an account (6+ character password)
2. Log in with correct details — should succeed
3. Try 3 wrong passwords in a row — account locks for 30 seconds
4. Check "Admin View (Demo)" tab — see the scrambled hash instead of the real password

## Key concepts
- **Hashing (PBKDF2-SHA256):** passwords are irreversibly scrambled before storage
- **Salting:** random unique data per user, defeats rainbow table attacks
- **Account Lockout:** blocks brute-force attacks after repeated failed attempts
- **Constant-time comparison:** prevents timing-based attacks

## How to run it locally
streamlit run secure_login.py

## Explanation for review
Built a login system using salted PBKDF2 password hashing instead of plain text storage, plus account lockout after repeated failed attempts to defend against brute-force attacks — the same core techniques used by real authentication systems.

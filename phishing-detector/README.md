# Phishing Detection System

A website that checks if a URL or email looks like phishing (a scam trying to steal your information).

## What this tool checks (in plain English)

**For URLs:**
- No HTTPS — secure sites use HTTPS; phishing sites often skip it
- Raw IP address instead of a domain name
- `@` symbol in the link — a trick to hide the real destination
- URL shorteners (bit.ly, tinyurl, etc.) hiding the real destination
- Too many hyphens or subdomains — common in fake copycat domains
- Very long URLs — used to bury the real (fake) domain
- Suspicious words (login, verify, urgent, etc.)
- Risky domain endings (.xyz, .tk, .club, etc.)
- Brand name mismatch — classic impersonation trick

**For Emails:**
- Urgency language ("act now", "account suspended")
- Generic greeting ("Dear Customer") instead of your name
- Requests for passwords/OTP/card numbers
- Mentions of prizes/lottery/free money
- Suspicious links inside the email

## How the scoring works
- 0–2 points → Safe
- 3–5 points → Suspicious
- 6+ points → Likely Phishing

## How to run it locally
pip install streamlit
streamlit run app.py

## Explanation for review
Built a rule-based phishing detection system. It scans URLs and email text against known phishing patterns — fake domains, urgent language, requests for sensitive information — and calculates a risk score to classify input as Safe, Suspicious, or Likely Phishing.

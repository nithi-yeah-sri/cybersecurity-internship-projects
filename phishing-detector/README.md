# Phishing Detection System

A website that checks if a URL or email looks like phishing (a scam trying to steal your information).

## What this tool checks (in plain English)

**For URLs:**
| Check | Why it matters |
|---|---|
| No HTTPS | Secure sites use HTTPS; phishing sites often skip it |
| Raw IP address instead of a domain name | Legit companies use proper domain names, not IPs |
| `@` symbol in the link | A trick to hide the real destination |
| URL shorteners (bit.ly, tinyurl, etc.) | Hides where the link actually goes |
| Too many hyphens or subdomains | Common in fake copycat domains |
| Very long URLs | Used to bury the real (fake) domain |
| Suspicious words (login, verify, urgent, etc.) | Common bait words in phishing links |
| Risky domain endings (.xyz, .tk, .club, etc.) | Cheap/free domains often abused by scammers |
| Brand name mismatch | Classic impersonation trick |

**For Emails:**
| Check | Why it matters |
|---|---|
| Urgency language ("act now", "account suspended") | Pressure tactics |
| Generic greeting ("Dear Customer") | Real companies usually use your name |
| Requests for passwords/OTP/card numbers | Legit companies never ask for this by email |
| Mentions of prizes/lottery/free money | Classic scam bait |
| Suspicious links inside the email | Reuses the URL checks above |

## How the scoring works
Each red flag found adds points to a "risk score":
- **0–2 points → Safe**
- **3–5 points → Suspicious**
- **6+ points → Likely Phishing**

## How to run it locally
## Explanation for review## Explanation for review

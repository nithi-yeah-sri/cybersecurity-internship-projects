# Password Strength Checker

A website that checks how strong a password is and gives specific suggestions to improve it.

## Privacy note
Nothing typed into this tool is saved, logged, or sent anywhere.

## What this tool checks
- Length (12+ characters)
- Uppercase + lowercase letters
- Numbers
- Special characters
- Not a commonly used password
- No keyboard patterns (like "qwerty")
- No repeated characters

## How scoring works
- 0–2 points → Weak
- 3–5 points → Medium
- 6+ points → Strong

## Unique feature
Instead of a random suggestion, the tool strengthens the user's own typed password by adding only what's missing (capital letter, symbol, digits) — keeping it recognizable and memorable.

## How to run it locally
pip install streamlit
streamlit run password_checker.py

## Explanation for review
Built a password strength checker that evaluates length, character variety, and common weak-password patterns, classifying passwords as Weak/Medium/Strong with tailored improvement suggestions.

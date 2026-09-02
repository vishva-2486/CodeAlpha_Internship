# CodeAlpha Secure Coding Review

## Task 3 — Secure Coding Review

This project was developed as part of the **CodeAlpha Cyber Security Internship**.

The project demonstrates a security-focused review of a Python user-management application. The original application was intentionally created with common security vulnerabilities, followed by a remediated version implementing secure coding practices.

---

## Project Overview

The project contains two versions of the application:

- `vulnerable_app.py` — Intentionally vulnerable application used for security analysis.
- `secure_app.py` — Remediated version implementing secure coding practices.

The purpose of this project is to demonstrate how security vulnerabilities can be identified during code review and how they can be fixed using appropriate security controls.

---

## Vulnerabilities Identified

The security review identified the following vulnerabilities:

1. Hardcoded administrative credentials
2. Weak MD5 password hashing
3. SQL Injection
4. Command Injection
5. Username enumeration
6. Excessive error disclosure
7. Insufficient input validation

---

## Security Improvements

The secure version implements:

- Parameterized SQL queries
- PBKDF2-HMAC-SHA256 password hashing
- Unique random password salts
- Constant-time password comparison
- Input validation
- Safe subprocess execution
- `shell=False` for command execution
- Generic authentication error messages
- Safer exception handling
- Secure password input using `getpass`

---

## Project Structure

```text
CodeAlpha_SecureCodingReview/
│
├── README.md
├── vulnerable_app.py
├── secure_app.py
├── security_review_report.md
└── screenshots/

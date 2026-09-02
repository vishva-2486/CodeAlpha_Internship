# CodeAlpha Secure Coding Review

## Task 3 — Secure Coding Review

### Project

User Management and Host Connectivity Application

### Language

Python 3

### Review Type

Static/manual secure-code review

---

# 1. Executive Summary

A security-focused review was performed on the vulnerable Python application.

The review identified several weaknesses involving:

- Hardcoded credentials
- Weak password hashing
- SQL injection
- Command injection
- Username enumeration
- Excessive error disclosure
- Insufficient input validation

A remediated version was then developed using secure coding practices.

---

# 2. Vulnerability Summary

| ID | Vulnerability | Severity | Status |
|---|---|---|---|
| VULN-01 | Hardcoded administrative credentials | High | Fixed |
| VULN-02 | Weak MD5 password hashing | High | Fixed |
| VULN-03 | SQL injection | Critical | Fixed |
| VULN-04 | Command injection | Critical | Fixed |
| VULN-05 | Username enumeration | Medium | Fixed |
| VULN-06 | Excessive error disclosure | Medium | Fixed |
| VULN-07 | Insufficient input validation | Medium | Fixed |

---

# 3. Detailed Findings

## VULN-01 — Hardcoded Administrative Credentials

### Location

`vulnerable_app.py`

```python
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
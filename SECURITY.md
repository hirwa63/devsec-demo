# Security Policy

## Supported Versions

Only the latest release on the `main` branch receives security fixes.

| Version | Supported |
|---------|-----------|
| latest  | ✅        |
| older   | ❌        |

## Reporting a Vulnerability

**Please do NOT open a public GitHub Issue for security vulnerabilities.**

If you discover a security vulnerability, please follow responsible-disclosure
practices:

1. **Email** the maintainers at the address listed on the GitHub organisation
   profile, with the subject line `[SECURITY] <short description>`.
2. Include as much detail as possible:
   - Affected component and version
   - Steps to reproduce
   - Potential impact / CVSS score estimate
3. We will acknowledge receipt within **48 hours** and aim to release a patch
   within **14 days** of a confirmed issue.

## Scope

The following are in scope:
- Authentication and session management vulnerabilities
- SQL injection / XSS / CSRF bypasses
- Privilege escalation (IDOR)
- Security misconfiguration

The following are out of scope:
- Denial of service via resource exhaustion
- Social engineering attacks
- Issues already reported

## Disclosure Policy

We follow [Coordinated Vulnerability Disclosure (CVD)](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).
Once a fix is available, we will publish a security advisory on GitHub and
credit the reporter (unless they prefer anonymity).

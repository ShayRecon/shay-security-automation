# Shay Security Automation

A collection of small security automation projects focused on practical blue-team and AppSec workflows.

## Projects Included

### 1. HTTP Security Headers Checker
Checks whether a target website implements important security headers such as:
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

### 2. Vulnerability Report Normalizer
Parses vulnerability scan exports (CSV) and normalizes fields such as:
- Severity
- Finding title
- Asset / host
- Remediation status

Useful for cleaning scanner output before reporting or tracking remediation.

### 3. IOC Enrichment Skeleton
A starter script for organizing enrichment of:
- IP addresses
- Domains
- File hashes

This project is intended as a lightweight automation lab for security operations, reporting, and analysis workflows.

---

## Repository Structure

```bash
headers-checker/
vuln-report-normalizer/
ioc-enrichment/
```

## Future Enhancements
- Wazuh alert parser
- MITRE ATT&CK mapper
- Security control evidence tracker
- Log triage helper scripts

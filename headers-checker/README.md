# HTTP Security Headers Checker

## Objective
This script checks whether a target website returns common HTTP security headers and highlights missing protections.

## Headers Checked
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

## Why These Headers Matter
Missing security headers can increase exposure to:
- Clickjacking
- MIME-type sniffing
- Insecure browser behavior
- Data leakage through referrers
- Weaker client-side hardening

## Features
- Checks for common security headers
- Displays whether each header is present or missing
- Provides a short risk explanation for missing headers
- Prints a summary of findings
- Exports results to a JSON file

## Usage
```bash
python headers_checker.py
```

Then enter a target URL when prompted.

## Example Use Cases
- Quick AppSec hygiene checks
- Recon during VAPT
- Basic review of web application response headers
- Demo project for security automation workflows

## Output
The script creates a file named:

```bash
headers_report.json
```

This contains:
- target URL
- header status
- header values (if present)
- risk note (if missing)

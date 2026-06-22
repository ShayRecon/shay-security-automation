# HTTP Security Headers Checker

## Objective
This script checks whether a target website returns common security headers and highlights missing protections.

## Headers Checked
- Content-Security-Policy
- Strict-Transport-Security
- X-Frame-Options
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

## Why It Matters
Missing security headers can increase exposure to:
- Clickjacking
- MIME-type sniffing issues
- Content injection risks
- Insecure browser behavior

## Usage
```bash
python headers_checker.py
```

Then enter a URL when prompted.

## Example Use Case
Quick security hygiene check during:
- Web application reviews
- VAPT reconnaissance
- Basic AppSec assessments

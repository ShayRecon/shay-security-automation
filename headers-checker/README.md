# Web Security Findings Automation

A lightweight Python-based AppSec automation tool that reviews web applications for missing HTTP security headers and generates remediation-ready security findings.

## Features

* Automated security header assessment
* Detection of missing security controls
* Finding generation with severity ratings
* JSON technical reporting
* CSV remediation reporting

## Security Checks

### HTTP Security Headers

* Content-Security-Policy (CSP)
* Strict-Transport-Security (HSTS)
* X-Frame-Options
* X-Content-Type-Options (nosniff)
* Referrer-Policy
* Permissions-Policy

## Output Files

### headers_report.json

Contains technical assessment results and header status.

### headers_vuln_report.csv

Contains remediation-ready findings including:

* Asset
* Finding
* Severity
* Description
* Recommendation
* Status
* Owner

## Example Workflow

1. Provide a target URL
2. Review HTTP response headers
3. Identify missing security controls
4. Generate findings
5. Export remediation report

## Example Findings

* Missing Content-Security-Policy
* Missing Strict-Transport-Security
* Missing X-Frame-Options
* Missing Referrer-Policy
* Missing Permissions-Policy

## Intended Audience

* Application Security Engineers
* VAPT Analysts
* Security Consultants
* DevSecOps Teams

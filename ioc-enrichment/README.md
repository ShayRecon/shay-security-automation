# IOC Enrichment Skeleton

## Objective
This script provides a lightweight foundation for IOC triage and enrichment workflows by identifying the IOC type and preparing a structured output format for future threat intelligence integration.

## Supported IOC Types
- IPv4 addresses
- Domains
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

## Features
- Detects IOC type using pattern matching
- Differentiates between common hash formats
- Produces structured JSON output
- Includes placeholder fields for enrichment and analyst notes
- Can be extended with:
  - VirusTotal
  - AbuseIPDB
  - AlienVault OTX
  - internal blocklists / SIEM enrichment

## Use Cases
Useful for:
- SOC alert triage
- IOC review during investigations
- preparing enrichment pipelines
- building future threat intel integrations

## Usage
```bash
python ioc_enrichment.py
```

Then enter an IOC when prompted.

## Output
The script creates:

```bash
ioc_report.json
```

This contains:
- original IOC
- detected type
- enrichment placeholder fields
- analyst notes section

## Sample Console Output

```text
IOC Enrichment Result
==================================================
IOC Type           : SHA256 Hash
Enrichment Status  : Not enriched yet
Reputation         : Unknown
Confidence         : N/A
Source             : Placeholder

Report exported to ioc_report.json
```

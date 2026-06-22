# IOC Enrichment Skeleton

## Objective
This script provides a simple starting point for organizing IOC enrichment workflows.

## Supported IOC Types
- IP addresses
- Domains
- File hashes

## Current Scope
This initial version does not query external threat intelligence platforms. Instead, it classifies the IOC type and prepares a structured output that can later be extended with:
- VirusTotal
- AbuseIPDB
- AlienVault OTX
- Internal blocklists
- SIEM enrichment pipelines

## Goal
Build a reusable enrichment helper for SOC and incident response workflows.

## Usage
```bash
python ioc_enrichment.py
```

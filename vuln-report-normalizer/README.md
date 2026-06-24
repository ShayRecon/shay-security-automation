# Vulnerability Report Normalizer

## Objective
This script reads a vulnerability CSV export, normalizes inconsistent severity values, removes duplicate findings, and prepares a cleaner output for remediation tracking.

## Features
- Normalizes severity naming
  - `critical` → `Critical`
  - `H` → `High`
  - `med` → `Medium`
  - `info` → `Informational`
- Removes duplicate rows
- Adds default tracking columns:
  - `Status`
  - `Owner`
- Prints a severity summary
- Exports a cleaned CSV report

## Use Cases
Useful when handling:
- Vulnerability scanner exports
- Pentest finding trackers
- Internal remediation sheets
- Consolidated vulnerability reporting

## Input
The script reads:

```bash
sample_vulns.csv
```

## Output
The script creates:

```bash
normalized_vulns.csv
```

## Usage
```bash
python vuln_normalizer.py
```

## Example Workflow
1. Export findings from a scanner or tracking sheet
2. Save them in CSV format
3. Run the script
4. Review the cleaned output and assign remediation owners

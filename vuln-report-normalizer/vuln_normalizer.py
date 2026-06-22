import pandas as pd

SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "h": "High",
    "medium": "Medium",
    "med": "Medium",
    "m": "Medium",
    "low": "Low",
    "l": "Low",
    "informational": "Informational",
    "info": "Informational"
}

def normalize_severity(severity):
    if pd.isna(severity):
        return "Unknown"
    key = str(severity).strip().lower()
    return SEVERITY_MAP.get(key, severity)

def main():
    input_file = "sample_vulns.csv"
    output_file = "normalized_vulns.csv"

    df = pd.read_csv(input_file)
    df["Severity"] = df["Severity"].apply(normalize_severity)
    df.to_csv(output_file, index=False)

    print(f"Normalized vulnerability report saved as {output_file}")

if __name__ == "__main__":
    main())

import requests
import json
import csv

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce XSS and content injection risks by controlling allowed content sources.",
    "Strict-Transport-Security": "Forces browsers to use HTTPS and helps reduce SSL stripping risks.",
    "X-Frame-Options": "Helps protect against clickjacking by controlling framing of the site.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing by browsers.",
    "Referrer-Policy": "Controls how much referrer information is shared with other sites.",
    "Permissions-Policy": "Restricts access to sensitive browser features like camera, microphone, and geolocation."
}

FINDING_MAP = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "recommendation": "Implement a restrictive Content-Security-Policy header."
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "recommendation": "Enable HSTS to enforce HTTPS connections."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN."
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "recommendation": "Set X-Content-Type-Options to nosniff."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "recommendation": "Define a Referrer-Policy to control referrer leakage."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "recommendation": "Restrict unnecessary browser features using Permissions-Policy."
    }
}


def check_headers(url):
    report = {
        "target": url,
        "results": []
    }

    findings = []

    found_count = 0
    missing_count = 0

    try:
        response = requests.get(url, timeout=10)

        print(f"\nChecking headers for: {url}")
        print("=" * 60)

        for header, risk_note in SECURITY_HEADERS.items():

            value = response.headers.get(header)

            # Special validation for nosniff
            if header == "X-Content-Type-Options":
                if value and value.lower() == "nosniff":
                    status = "FOUND"
                    found_count += 1

                    print(f"[FOUND] {header}")
                    print(f"        Value: {value}")

                    report["results"].append({
                        "header": header,
                        "status": status,
                        "value": value,
                        "risk_note": ""
                    })

                else:
                    status = "MISSING"
                    missing_count += 1

                    print(f"[MISSING] {header}")
                    print("          Risk: Browser MIME sniffing may be possible.")

                    report["results"].append({
                        "header": header,
                        "status": status,
                        "value": value if value else "",
                        "risk_note": risk_note
                    })

                    findings.append({
                        "Asset": url,
                        "Finding": "Missing or insecure X-Content-Type-Options",
                        "Severity": FINDING_MAP[header]["severity"],
                        "Description": risk_note,
                        "Recommendation": FINDING_MAP[header]["recommendation"],
                        "Status": "Open",
                        "Owner": "Unassigned"
                    })

            else:
                if value:
                    status = "FOUND"
                    found_count += 1

                    print(f"[FOUND] {header}")
                    print(f"        Value: {value}")

                    report["results"].append({
                        "header": header,
                        "status": status,
                        "value": value,
                        "risk_note": ""
                    })

                else:
                    status = "MISSING"
                    missing_count += 1

                    print(f"[MISSING] {header}")
                    print(f"          Risk: {risk_note}")

                    report["results"].append({
                        "header": header,
                        "status": status,
                        "value": "",
                        "risk_note": risk_note
                    })

                    findings.append({
                        "Asset": url,
                        "Finding": f"Missing {header}",
                        "Severity": FINDING_MAP[header]["severity"],
                        "Description": risk_note,
                        "Recommendation": FINDING_MAP[header]["recommendation"],
                        "Status": "Open",
                        "Owner": "Unassigned"
                    })

            print("-" * 60)

        print("\nSummary")
        print("=" * 60)
        print(f"Headers Found   : {found_count}")
        print(f"Headers Missing : {missing_count}")

        with open("headers_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

        with open("headers_vuln_report.csv", "w", newline="", encoding="utf-8") as csvfile:

            fieldnames = [
                "Asset",
                "Finding",
                "Severity",
                "Description",
                "Recommendation",
                "Status",
                "Owner"
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()

            for finding in findings:
                writer.writerow(finding)

        print("\nReport exported to headers_report.json")
        print("Report exported to headers_vuln_report.csv")

    except requests.exceptions.RequestException as e:
        print(f"Error reaching {url}: {e}")


if __name__ == "__main__":
    target = input("Enter target URL (e.g. https://example.com): ").strip()
    check_headers(target)

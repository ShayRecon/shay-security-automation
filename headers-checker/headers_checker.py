import requests
import json

SECURITY_HEADERS = {
    "Content-Security-Policy": "Helps reduce XSS and content injection risks by controlling allowed content sources.",
    "Strict-Transport-Security": "Forces browsers to use HTTPS and helps reduce SSL stripping risks.",
    "X-Frame-Options": "Helps protect against clickjacking by controlling framing of the site.",
    "X-Content-Type-Options": "Prevents MIME-type sniffing by browsers.",
    "Referrer-Policy": "Controls how much referrer information is shared with other sites.",
    "Permissions-Policy": "Restricts access to sensitive browser features like camera, microphone, and geolocation."
}

def check_headers(url):
    report = {
        "target": url,
        "results": []
    }

    found_count = 0
    missing_count = 0

    try:
        response = requests.get(url, timeout=10)
        print(f"\nChecking headers for: {url}")
        print("=" * 60)

        for header, risk_note in SECURITY_HEADERS.items():
            value = response.headers.get(header)

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

            print("-" * 60)

        print("\nSummary")
        print("=" * 60)
        print(f"Headers Found   : {found_count}")
        print(f"Headers Missing : {missing_count}")

        with open("headers_report.json", "w") as f:
            json.dump(report, f, indent=4)

        print("\nReport exported to headers_report.json")

    except requests.exceptions.RequestException as e:
        print(f"Error reaching {url}: {e}")

if __name__ == "__main__":
    target = input("Enter target URL (e.g. https://example.com): ").strip()
    check_headers(target)

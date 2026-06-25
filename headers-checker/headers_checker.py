import requests
import json
import csv
import ssl
import socket
from urllib.parse import urlparse

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "severity": "Medium",
        "risk": "Helps reduce XSS and content injection risks by controlling allowed content sources.",
        "recommendation": "Implement a restrictive Content-Security-Policy header."
    },
    "Strict-Transport-Security": {
        "severity": "Medium",
        "risk": "Forces browsers to use HTTPS and helps reduce SSL stripping risks.",
        "recommendation": "Enable HSTS to enforce HTTPS connections."
    },
    "X-Frame-Options": {
        "severity": "Medium",
        "risk": "Helps protect against clickjacking by controlling framing of the site.",
        "recommendation": "Set X-Frame-Options to DENY or SAMEORIGIN."
    },
    "X-Content-Type-Options": {
        "severity": "Medium",
        "risk": "Prevents MIME-type sniffing by browsers.",
        "recommendation": "Set X-Content-Type-Options to nosniff."
    },
    "Referrer-Policy": {
        "severity": "Low",
        "risk": "Controls how much referrer information is shared with other sites.",
        "recommendation": "Define a Referrer-Policy to control referrer leakage."
    },
    "Permissions-Policy": {
        "severity": "Low",
        "risk": "Restricts access to sensitive browser features.",
        "recommendation": "Restrict unnecessary browser features using Permissions-Policy."
    }
}


def add_finding(findings, asset, finding, severity,
                description, recommendation):

    findings.append({
        "Asset": asset,
        "Finding": finding,
        "Severity": severity,
        "Description": description,
        "Recommendation": recommendation,
        "Status": "Open",
        "Owner": "Unassigned"
    })


def check_tls(url, findings):

    try:
        hostname = urlparse(url).hostname

        if not hostname:
            return

        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                tls_version = ssock.version()

                print("\nTLS Assessment")
                print("=" * 60)
                print(f"TLS Version: {tls_version}")

                if tls_version in ["TLSv1", "TLSv1.1"]:
                    add_finding(
                        findings,
                        url,
                        "Weak TLS Configuration",
                        "High",
                        f"Server supports deprecated TLS version: {tls_version}",
                        "Disable TLS 1.0 and TLS 1.1 and enforce modern TLS versions."
                    )

    except Exception as e:
        print(f"TLS assessment skipped: {e}")


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

        # TLS Check
        check_tls(url, findings)

        # Cookie Checks
        print("\nChecking Cookies")
        print("=" * 60)
        cookie_count = len(response.cookies)

print(f"Cookies Found: {cookie_count}")

if cookie_count == 0:
    print("No cookies observed in response.")

       for cookie in response.cookies:

    print(f"Cookie: {cookie.name}")

    cookie_name = cookie.name

            if not cookie.secure:
                add_finding(
                    findings,
                    url,
                    f"Cookie '{cookie_name}' missing Secure flag",
                    "Medium",
                    "Cookie is transmitted without the Secure attribute.",
                    "Set the Secure attribute on cookies."
                )

            if "httponly" not in str(cookie).lower():
                add_finding(
                    findings,
                    url,
                    f"Cookie '{cookie_name}' missing HttpOnly flag",
                    "Medium",
                    "Cookie may be accessible through client-side scripts.",
                    "Set the HttpOnly attribute on cookies."
                )

            cookie_string = str(cookie).lower()

            if "samesite" not in cookie_string:
                add_finding(
                    findings,
                    url,
                    f"Cookie '{cookie_name}' missing SameSite attribute",
                    "Low",
                    "Cookie does not define a SameSite attribute.",
                    "Set SameSite=Lax or SameSite=Strict where appropriate."
                )

        # Information Disclosure
        server_header = response.headers.get("Server")

        if server_header:
            add_finding(
                findings,
                url,
                "Server Version Disclosure",
                "Low",
                f"Server header exposed: {server_header}",
                "Minimize or remove server banner information."
            )

        powered_by = response.headers.get("X-Powered-By")

        if powered_by:
            add_finding(
                findings,
                url,
                "X-Powered-By Header Disclosure",
                "Low",
                f"Technology disclosure detected: {powered_by}",
                "Remove or minimize technology disclosure headers."
            )

        # Header Checks
        print(f"\nChecking Headers for: {url}")
        print("=" * 60)

        for header, details in SECURITY_HEADERS.items():

            value = response.headers.get(header)

            if header == "X-Content-Type-Options":

                if value and value.lower() == "nosniff":

                    found_count += 1

                    print(f"[FOUND] {header}")

                    report["results"].append({
                        "header": header,
                        "status": "FOUND",
                        "value": value
                    })

                else:

                    missing_count += 1

                    print(f"[MISSING] {header}")

                    add_finding(
                        findings,
                        url,
                        "Missing or insecure X-Content-Type-Options",
                        details["severity"],
                        details["risk"],
                        details["recommendation"]
                    )

            else:

                if value:

                    found_count += 1

                    print(f"[FOUND] {header}")

                    report["results"].append({
                        "header": header,
                        "status": "FOUND",
                        "value": value
                    })

                else:

                    missing_count += 1

                    print(f"[MISSING] {header}")

                    add_finding(
                        findings,
                        url,
                        f"Missing {header}",
                        details["severity"],
                        details["risk"],
                        details["recommendation"]
                    )

        # Summary
        print("\nHeader Summary")
        print("=" * 60)
        print(f"Headers Found   : {found_count}")
        print(f"Headers Missing : {missing_count}")

        critical_count = len(
            [f for f in findings if f["Severity"] == "Critical"]
        )
        high_count = len(
            [f for f in findings if f["Severity"] == "High"]
        )
        medium_count = len(
            [f for f in findings if f["Severity"] == "Medium"]
        )
        low_count = len(
            [f for f in findings if f["Severity"] == "Low"]
        )

        print("\nFindings Summary")
        print("=" * 60)
        print(f"Critical : {critical_count}")
        print(f"High     : {high_count}")
        print(f"Medium   : {medium_count}")
        print(f"Low      : {low_count}")
        print(f"Total    : {len(findings)}")

        report["findings"] = findings

        report["summary"] = {
            "total_findings": len(findings),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count
        }

        # JSON Export
        with open("headers_report.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=4)

        # CSV Export
        with open(
            "headers_vuln_report.csv",
            "w",
            newline="",
            encoding="utf-8"
        ) as csvfile:

            fieldnames = [
                "Asset",
                "Finding",
                "Severity",
                "Description",
                "Recommendation",
                "Status",
                "Owner"
            ]

            writer = csv.DictWriter(
                csvfile,
                fieldnames=fieldnames
            )

            writer.writeheader()

            for finding in findings:
                writer.writerow(finding)

        print("\nReport exported to headers_report.json")
        print("Report exported to headers_vuln_report.csv")

    except requests.exceptions.RequestException as e:
        print(f"Error reaching {url}: {e}")


if __name__ == "__main__":

    target = input(
        "Enter target URL (e.g. https://example.com): "
    ).strip()

    check_headers(target)

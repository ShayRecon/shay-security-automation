import requests

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy"
]

def check_headers(url):
    try:
        response = requests.get(url, timeout=10)
        print(f"\nChecking headers for: {url}\n")
        print("-" * 50)

        for header in SECURITY_HEADERS:
            value = response.headers.get(header)
            if value:
                print(f"[FOUND] {header}: {value}")
            else:
                print(f"[MISSING] {header}")

    except requests.exceptions.RequestException as e:
        print(f"Error reaching {url}: {e}")

if __name__ == "__main__":
    target = input("Enter target URL (e.g. https://example.com): ").strip()
    check_headers(target)

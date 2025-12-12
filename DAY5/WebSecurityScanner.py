import streamlit as st
import requests

st.set_page_config(page_title="Web Security Scanner", layout="wide")

st.title("Web Security Mini Scanner")
st.write("Enter a website URL to scan for common security issues like SQL Injection, XSS, and missing security headers.")

url = st.text_input("Enter website URL (Example: https://example.com):")

sql_payloads = ["'", "\"", "' OR 1=1--", "\" OR 1=1--", "';", "' OR '1'='1"]

def test_sql_injection(base_url):
    results = []
    for payload in sql_payloads:
        try:
            test_url = base_url + payload
            res = requests.get(test_url, timeout=5)
            errors = ["mysql", "syntax error", "sql error", "warning", "unclosed quotation"]
            if any(err in res.text.lower() for err in errors):
                results.append(f"⚠️ Possible SQL Injection found using payload: {payload}")
        except:
            pass
    return results if results else ["✅ No SQL Injection symptoms detected."]

xss_payloads = [
    "<script>alert(1)</script>",
    "\"><svg/onload=alert(1)>",
    "<img src=x onerror=alert(1)>"
]

def test_xss(base_url):
    results = []
    for payload in xss_payloads:
        try:
            test_url = base_url + payload
            res = requests.get(test_url, timeout=5)
            if payload in res.text:
                results.append(f"⚠️ Possible XSS found using payload: {payload}")
        except:
            pass
    return results if results else ["✅ No reflected XSS detected."]

required_headers = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-XSS-Protection"
]

def check_headers(base_url):
    missing = []
    try:
        res = requests.get(base_url, timeout=5)
        headers = res.headers
        for h in required_headers:
            if h not in headers:
                missing.append(f"⚠️ Missing security header: {h}")
    except:
        return ["❌ Unable to fetch headers."]
    return missing if missing else ["✅ All important security headers are present."]

def check_https(base_url):
    if base_url.startswith("https://"):
        return "✅ HTTPS Enabled"
    else:
        return "❌ Website is not using HTTPS (data can be intercepted)"

common_paths = [
    "/admin", "/login", "/dashboard", "/config", "/phpinfo.php",
    "/backup", "/test", "/dev", "/server-status"
]

def scan_directories(base_url):
    found = []
    for path in common_paths:
        try:
            test_url = base_url + path
            res = requests.get(test_url, timeout=5)
            if res.status_code == 200:
                found.append(f"⚠️ Accessible sensitive endpoint: {test_url}")
        except:
            pass
    return found if found else ["✅ No exposed sensitive directories found."]

if st.button("Scan Website"):
    if not url:
        st.error("Please enter a valid URL.")
    else:
        st.markdown("### 🔎 Running Security Tests...")

        st.subheader("1. SQL Injection Test")
        for r in test_sql_injection(url):
            st.write(r)

        st.subheader("2. XSS Test")
        for r in test_xss(url):
            st.write(r)

        st.subheader("3. Security Header Analysis")
        for r in check_headers(url):
            st.write(r)

        st.subheader("4. HTTPS Check")
        st.write(check_https(url))

        st.subheader("5. Directory Scan")
        for r in scan_directories(url):
            st.write(r)

        st.success("✔️ Scan Completed!")

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, unquote

def get_forms(url):
    """Extract all HTML forms from a webpage or file."""
    if url.startswith("file://"):
        filepath = url[len("file://"):]
        filepath = unquote(filepath)  # Decode percent-encoded characters
        if filepath.startswith("/"):
            filepath = filepath[1:]  # Remove leading slash if present
        with open(filepath, 'r', encoding='utf-8') as file:
            content = file.read()
        soup = BeautifulSoup(content, "html.parser")
    else:
        response = requests.get(url, timeout=10)  # Set timeout
        soup = BeautifulSoup(response.text, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """Extract useful information about an HTML form."""
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def submit_form(form_details, url, value):
    """Submit a form with a given value."""
    target_url = urljoin(url, form_details["action"])
    data = {}
    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            input_name = input["name"]
            data[input_name] = value
    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=10)  # Set timeout
        else:
            return requests.get(target_url, params=data, timeout=10)  # Set timeout
    except requests.exceptions.Timeout:
        print(f"[!] Timeout occurred when submitting form to {target_url}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"[!] Error occurred when submitting form to {target_url}: {e}")
        return None

def check_sql_injection(url):
    vulnerabilities = []
    sql_payload = "' OR '1'='1"
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        response = submit_form(form_details, url, sql_payload)
        if response and sql_payload in response.text:
            vulnerabilities.append({
                "type": "SQL Injection",
                "form": form_details['action'],
                "payload": sql_payload,
                "exploitation": "Attackers can exploit SQL Injection by injecting malicious SQL code into form fields, potentially gaining unauthorized access to the database.",
                "mitigation": "Use prepared statements and parameterized queries to avoid SQL Injection."
            })
    return vulnerabilities

def check_xss(url):
    vulnerabilities = []
    xss_payload = "<script>alert('XSS')</script>"
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        response = submit_form(form_details, url, xss_payload)
        if response and xss_payload in response.text:
            vulnerabilities.append({
                "type": "XSS",
                "form": form_details['action'],
                "payload": xss_payload,
                "exploitation": "Attackers can exploit XSS by injecting malicious scripts into web pages, which can be executed by other users, leading to session hijacking or data theft.",
                "mitigation": "Sanitize and validate all user inputs. Encode output data to avoid XSS."
            })
    return vulnerabilities

def check_csrf(url):
    vulnerabilities = []
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        if 'csrf' not in [input["name"].lower() for input in form_details["inputs"] if input["name"]]:
            vulnerabilities.append({
                "type": "CSRF",
                "form": form_details['action'],
                "exploitation": "Attackers can exploit CSRF by tricking users into submitting malicious requests without their knowledge, potentially leading to unauthorized actions.",
                "mitigation": "Ensure that all forms include CSRF tokens to prevent Cross-Site Request Forgery attacks."
            })
    return vulnerabilities

def check_open_redirects(url):
    vulnerabilities = []
    open_redirect_payload = "http://evil.com"
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        response = submit_form(form_details, url, open_redirect_payload)
        if response and open_redirect_payload in response.url:
            vulnerabilities.append({
                "type": "Open Redirect",
                "form": form_details['action'],
                "payload": open_redirect_payload,
                "exploitation": "Attackers can exploit Open Redirects to redirect users to malicious sites, potentially leading to phishing attacks.",
                "mitigation": "Validate and sanitize all URL parameters to prevent open redirects."
            })
    return vulnerabilities

def main():
    url = input("Enter the URL to scan: ")
    print(f"Scanning {url} for vulnerabilities...")
    
    all_vulnerabilities = []

    all_vulnerabilities.extend(check_sql_injection(url))
    all_vulnerabilities.extend(check_xss(url))
    all_vulnerabilities.extend(check_csrf(url))
    all_vulnerabilities.extend(check_open_redirects(url))

    if all_vulnerabilities:
        print("Vulnerabilities found:")
        for vulnerability in all_vulnerabilities:
            print(f"[!] {vulnerability['type']} detected in form: {vulnerability['form']}")
            print(f"    Payload: {vulnerability.get('payload', 'N/A')}")
            print(f"    Exploitation: {vulnerability['exploitation']}")
            print(f"    Mitigation: {vulnerability['mitigation']}")
    else:
        print("No vulnerabilities found.")

if __name__ == "__main__":
    main()

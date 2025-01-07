import requests
from bs4 import BeautifulSoup
import re
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
        response = requests.get(url)
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
    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        return requests.get(target_url, params=data)

def check_sql_injection(url):
    vulnerabilities = []
    sql_payload = "' OR '1'='1"
    forms = get_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        response = submit_form(form_details, url, sql_payload)
        if sql_payload in response.text:
            vulnerabilities.append({
                "type": "SQL Injection",
                "form": form_details['action'],
                "payload": sql_payload,
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
        if xss_payload in response.text:
            vulnerabilities.append({
                "type": "XSS",
                "form": form_details['action'],
                "payload": xss_payload,
                "mitigation": "Sanitize and validate all user inputs. Encode output data to avoid XSS."
            })
    return vulnerabilities

def check_other_vulnerabilities(url):
    vulnerabilities = []
    # Add checks for other vulnerabilities here (e.g., CSRF, Open Redirects, etc.)
    return vulnerabilities

def main():
    url = input("Enter the URL to scan: ")
    print(f"Scanning {url} for vulnerabilities...")
    
    all_vulnerabilities = []

    all_vulnerabilities.extend(check_sql_injection(url))
    all_vulnerabilities.extend(check_xss(url))
    all_vulnerabilities.extend(check_other_vulnerabilities(url))

    if all_vulnerabilities:
        print("Vulnerabilities found:")
        for vulnerability in all_vulnerabilities:
            print(f"[!] {vulnerability['type']} detected in form: {vulnerability['form']}")
            print(f"    Payload: {vulnerability['payload']}")
            print(f"    Mitigation: {vulnerability['mitigation']}")
    else:
        print("No vulnerabilities found.")

if __name__ == "__main__":
    main()

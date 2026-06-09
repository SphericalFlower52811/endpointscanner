import asyncio
from curl_cffi import requests, CurlOpt
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
import time
import json
from playwright.sync_api import sync_playwright #headless browser to solve captcha
from playwright_stealth import Stealth #ensure strict firewalls do not block the playwright browser

HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US, en;q=0.9"
} #browser header

USELESSSTUFF = {
        "localhost", "127.0.0.1", "0.0.0.0", 
        "w3.org", "schema.org", "xml.org", "://microsoft.com", "/../"
    }
unsorted_paths = []
e_files = []
start_test_time = None
def gethtmlafterload(url):
    with sync_playwright() as p:
        try:
            browser = p.chromium.launch(
                headless=True,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-infobars"
                ])
        except Exception as e:
            error_msg = str(e).lower()
            error_type = type(e).__name__

            # Instructions to install if people do not read instructions the first time
            if "error" in error_type.lower() and ("executable" in error_msg.lower() or "install" in error_msg.lower()):
                print("\nPlaywright installations are missing.")
                print("Please read the installation instructions in the README of the repository.")
                print("README link: https://github.com/SphericalFlower52811/endpointscanner/blob/main/README.md")
            else:
                print("Unexpected Issue:", e)
            return "", {}
    
        context = browser.new_context(
            user_agent=HEADER['User-Agent'], 
            viewport={'width': 1920, 'height': 1080},
            has_touch=True
            )
        page = context.new_page()
        Stealth().apply_stealth_sync(page) #stealth

        #go to page and get code, using stealth to bypass captchas
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=60000) #wait for page content to download
            page.mouse.move(100, 100)
            page.mouse.move(200, 300)
            page.evaluate("window.scrollTo(0, 500)")

            import time
            start_time = time.time()
            while (time.time() - start_time) < 5: #only 5 second later ppl impatient
                mainhtml = page.content()
                # check if there are actually scripts loaded into the html yet
                if ".js" in mainhtml.lower() or "chunk" in mainhtml.lower() or "<script" in mainhtml.lower():
                    break
                time.sleep(0.2)
             
            page.wait_for_timeout(5000) #wait for page to load downloaded content, and cookie
            mainhtml = page.content()
            cookies = {c['name']: c['value'] for c in context.cookies()}

        except Exception as e:
            print("Unexpected Error:", e)
            mainhtml, cookies = "", {}

        browser.close()
        return mainhtml, cookies
        

def identify_javascript_type(html, headers=None):
    stack = []
    #print(f"\n[DEBUG] HTML Snippet: {html[:1000]}\n") 
    # Next.js
    if any(term in html for term in ['data-next-head', 'script id="__NEXT_DATA__"', 'next-head-count', '_next/', '_next/data']):
        stack.append("Next.js")
    # React
    if 'data-reactroot' in html or 'id="root"' in html or 'react-dom' in html.lower():
        stack.append("React")
    # Vue / Angular
    if 'id="app"' in html or 'v-bind' in html: stack.append("Vue.js")
    if 'id="__nuxt"' in html or 'window.__NUXT__' in html: stack.append("Nuxt.js (Vue)")
    if '<app-root' in html or 'ng-version' in html or '_nghost-' in html: stack.append("Angular")
    # Node.js 
    if headers:
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'express' in powered_by or 'node' in powered_by:
            stack.append(f"Node.js ({powered_by.capitalize()})")
    # vite and wekpack
    if any(term in html.lower() for term in ['@vite/client', 'vite-plugin', 'src="/@vite', '__vite__', 'modulepreload']):
        stack.append("Vite")
    if 'webpack' in html.lower(): stack.append("Webpack")

    return " + ".join(stack) if stack else "Unknown JS Stack"

async def async_rate_test(url, num_reqs=100, method="GET", rb=None, rv=None, cookies=None, rh=None):
    dyn_limit = num_reqs + 100
    payload_queue = []
    for i in range(num_reqs):
        request_number = i + 1
        current_body = rb
            
        if rb and rv:
            clean_token = f"{{{rv.strip('{}')}}}"
            current_body = rb.replace(clean_token, str(request_number))
            
        if not rh:
            current_headers = HEADER.copy()
            pa_target = urlparse(url)
            current_headers["Origin"] = f"https://{pa_target.netloc}"
            current_headers["Referer"] = f"https://{pa_target.netloc}/"
            is_json_string = rb and current_body.strip().startswith(('{', '['))
            if rb:
                if is_json_string:
                    current_headers["Content-Type"] = "application/json"
                else:
                    current_headers["Content-Type"] = "application/x-www-form-urlencoded"
            current_headers["Accept"] = "*/*"
                
            payload_queue.append((current_headers.copy(), current_body))
        else:
            normalized_rh = rh.replace('\r\n', '|').replace('\n', '|')
            raw_lines = [line.strip() for line in normalized_rh.split('|') if line.strip()]
            clean_headers = {}
            for line in raw_lines:
                if "http/" in line.lower():
                    words = line.split()
                    if words:
                        extracted_method = words[0].upper()
                        if extracted_method == 'DELETE':
                            print("\nHTTP Method DELETE is blocked.")
                            print("Running many DELETE requests on a server can easily delete a lot of important data.")
                            print("Rate limit test will not be executed.")
                            exit(1)
                        elif extracted_method in ['HEAD', 'OPTIONS']:
                            print("WARNING")
                            print(f"\nHTTP Method {extracted_method} is a light read request that omits response data bodies.")
                            print("Continuing rate limit test.")
                            method = extracted_method
                        else:
                            method = extracted_method
                    continue
                    
                if ':' in line:
                    key, val = line.split(':', 1)
                    if key.strip().lower() in ["content-length", "host"]:
                        continue
                    clean_headers[key.strip()] = val.strip()
            is_json_string = rb and current_body.strip().startswith(('{', '['))
            if rb and "Content-Type" not in clean_headers:
                if is_json_string:
                    clean_headers["Content-Type"] = "application/json"
                else:
                    clean_headers["Content-Type"] = "application/x-www-form-urlencoded"
                
            payload_queue.append((clean_headers, current_body))
    method = method.upper()
    print('----Rate Limit Test----')
    if num_reqs >= 2500 and method != 'GET':
        print("WARNING!!!")
        print(f"Running {num_reqs} requests could cause visible lag and take up a lot of memory on your computer.")
        print("This may also cause your home wifi to lag.")
        print("Scan will be continued.")
    print("WARNING!!")
    print("Rate limit test is more susceptible to being blocked by firewalls/captchas.\nSee the Weaknesses tab in the README for more details.")
    print(f"\nStarting Rate Limit Test: {num_reqs} {method} requests to {url}")
    if 1+1 == 2: #i was lazy to unindent everything, as previous code would only be done if rb existed.
        if rb:
            if rv:
                variabletoiterate = f"{{{rv.strip('{}')}}}"
                print(f"Variable to iterate: {variabletoiterate}")
            else:
                print("Payload has no variables to be changed.")
            print(f"Request body: {rb}")
            
        # async
        import httpx

        limits = httpx.Limits(max_keepalive_connections=num_reqs, max_connections=num_reqs)
        responses = [None] * len(payload_queue)

        processed_queue = []
        for h, b in payload_queue:
            is_json = b and b.strip().startswith(('{', '['))
            parsed_body = None
            if b:
                try:
                    parsed_body = json.loads(b) if is_json else b
                except Exception:
                    parsed_body = b
            processed_queue.append((h, parsed_body, is_json))

        async with httpx.AsyncClient(limits=limits) as client:
            
            async def worker(current_headers, final_body, is_json_type, index):
                try:
                    res = await client.request(
                        method=method,
                        url=url, 
                        headers=current_headers,
                        cookies=cookies,
                        json=final_body if is_json_type else None,
                        content=None if is_json_type else final_body,
                        timeout=35.0
                    )
                    responses[index] = res 
                except Exception as e:
                    responses[index] = e

            for idx, (h, body_data, json_flag) in enumerate(processed_queue):
                asyncio.create_task(worker(h, body_data, json_flag, idx))
                
            print("[+] Streaming requests into the background network pipeline...")
            await asyncio.sleep(45.0)

        #label every single request using enumerate() to find out exactly when the first request timed out, or hit a non-200.
        status_counts = {}
        first_limit_at = None
        
        for i, res in enumerate(responses):
            request_number = i + 1
            if res is None or isinstance(res, Exception):
                status_counts['Timeout/Packet Drop'] = status_counts.get('Timeout/Packet Drop', 0) + 1
                if first_limit_at is None:
                    first_limit_at = (request_number, "Timeout/Packet Drop")
                continue
            
            code = res.status_code 
            status_counts[code] = status_counts.get(code, 0) + 1
            if code != 200 and first_limit_at is None:
                first_limit_at = (request_number, code)
            # stop if 405 or 400. 
            #or 401.
            if request_number == 1 and code == 405:
                allowed_methods = res.headers.get("Allow", "Not Specified")
                label_text = "Method Not Allowed"
                print(f"\nRequest #1 instantly failed with HTTP {code} ({label_text}).")
                print("Request is not using correct HTTP method.")
                print(f"Allowed HTTP Methods: {allowed_methods}")
                print("Stopping rate limit test.\n")
                status_counts[code] = num_reqs
                break
            if request_number == 1 and code == 400:
                print("Error 400. (Bad Request/Malformed Payload)")
                try:
                    err_json = res.json()
                    detail = err_json.get("detail", err_json.get("error", err_json))
                    print(f"➔ Server Error Detail: {detail}")
                except:
                    print(f"➔ Server Raw Error Text: {res.text[:100].strip()}")
                print("Stopping rate limit test.\n")
                status_counts[code] = num_reqs
                break
            if request_number == 1 and code == 401:
                print(f"\nRequest #1 failed with HTTP 401 (Unauthorized).")
                print("Your session cookies or auth tokens are invalid or expired.")
                print("Stopping rate limit test instantly.\n")
                status_counts[code] = num_reqs
                break
        
        pa = urlparse(url)
        if pa.path and pa.path != '/':
            tardis = f"Website endpoint {pa.path}"
        else:
            tardis = f"{pa.netloc if pa.netloc else url}"
        maycrash = False
        print("\n--- Rate Limit Test Results ---")
        for code, count in status_counts.items():
            if code == 'Timeout/Packet Drop':
                print(f' {code}: {count}')
                maycrash = True
                continue
            label = "VULNERABLE" if code == 200 else "RATE-LIMITED" if code == 429 else "WAF/FORBIDDEN" if code == 403 else "UNAUTHORISED" if code == 401 else "CRASHED" if code == 500 else "MALFORMED REQUEST" if code == 400 else "METHOD NOT ALLOWED" if code == 405 else "Other"
            print(f" Status {code} ({label}): {count}")
        
        if status_counts.get(200, 0) == num_reqs:
            if num_reqs >= 100:
                print(f"\n{tardis} is potentially vulnerable to DoS or brute-forcing (No rate limit detected after {num_reqs} requests).")
            else:
                print(f"\n{tardis} accepted all {num_reqs} requests. However, most rate limits do not set a number of requests that low.")
        elif first_limit_at:
            req_num, code = first_limit_at
            if code == 403:
                print(f"\nA WAF (Firewall) likely intercepted the requests to {tardis.lower()} (403 Forbidden after {req_num} requests).")
            elif code == 429:
                print(f"\nRate limiting present on {tardis.lower()} (429 Too Many Requests detected after {req_num} requests).")
            elif code == 'Timeout/Packet Drop':
                print(f"\nServer connections began dropping or timing out to {tardis.lower()}. First Instance: {req_num}")
            else:
                print(f"\nServer began responding with HTTP Response {code} to {tardis.lower()}. First Instance: {req_num}")
        if maycrash:
            print("Server may have timed out request as it crashed, or it is dropping requests as a rate limit. \nPlease check the website to confirm if it crashed.")


def checktime(st, at):
    global start_test_time
    ct = time.perf_counter()
    em = (ct - st) / 60
    if em >= at:
        print(f"Scan has reached your chosen time limit of {at} minutes.")
        choice = input('Continue scan for another 5 minutes? (y/n):').strip().lower()
        if choice in ['y', 'yes']:
            print('Time limit extended for 5 minutes. Continuing scan...')
            return "EXTEND"
        else:
            if choice in ['n', 'no']:
                print('Scan stopped. Any data found in the time window will be printed.')
            else:
                print('Choice not recognised, and will be defaulted to no.')
                print('Scan stopped. Any data found in the time window will be printed.')
            return "STOP"
    return "CONTINUE"
def main():
    #arguments/flag
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs='?', help="URL")
    parser.add_argument("-r", "--ratelimit", nargs='?', const=100, type=int, default=None, help="Number of requests to send during the rate limit test. Default is 100.")
    parser.add_argument("-rt", "--ratelimit-type", type=str, default="GET", choices=['GET', 'POST', 'PATCH', 'PUT'], help="HTTP Method to use for the rate limit test. Defaults to GET.")
    parser.add_argument("-rb", "--ratelimit-body", type=str, default=None, help="Payload data to send in request to use for POST, PATCH and PUT requests. If the custom payload contains double quotes, please use single quotes instead of double quotes to pass this flag.")
    parser.add_argument("-rv", "--ratelimit-var", type=str, default=None, help="Variable in payload data (e.g. {X}) to use.")
    parser.add_argument("--force", action="store_true", help="Mandatory flag to pass if doing a rate limit test with over 2500 requests using a non-GET HTTP method. Has no short form flag.")
    parser.add_argument("-t", "--testpath", nargs='?', const='/', type=str, help="Endpoint to test for rate limiting.")
    parser.add_argument("-s", "--show-404s", action="store_true", help="Show endpoints tested that returned a 404")
    parser.add_argument("-d", "--disable-extra-files", action="store_true", help="Disable scanning of extra structural mapping files (robots, sitemaps, manifests, etc.)")
    parser.add_argument("-m", "--show-media", action="store_true", help="Include assets/media like images and fonts in scan results")
    parser.add_argument("-sp", "--show-prog", action="store_true", help="Print endpoints to the terminal one by one in real-time as they are found. Warning: will show duplicate paths if endpoints are defined multiple times in the code. Results will not contain duplicates.")
    parser.add_argument("-o", "--output-file", type=str, default=None, help="Save formatted results directly to a local text file.")
    parser.add_argument("-do", "--disable-og", action="store_true", help="Disable code from showing the original endpoint with variables. Keeps output tidier. Will NOT remove original tag from progress if the --show-prog flag is present.")
    parser.add_argument("-ti", "--tidy", action="store_true", help="Script will not show where it got extra endpoints from, and will not show if it is a client side route and requires login, or react shell. Will also not show if an endpoint is a potential service.")
    parser.add_argument("-ta", "--tidy-all", action="store_true", help="Flags --disable-og and --tidy combsined.")
    parser.add_argument("-or", "--only-res", action="store_true", help="Only show summarised endpoints.")
    parser.add_argument("-oo", "--only-original", action="store_true", help="Only show the original version of the flag instead of it being replaced with a 1. Will also affect show prog.")
    parser.add_argument("-ss", "--show-source", action="store_true", help="Print the source of each endpoint during progress, like printing out which file it found the endpoint from.")
    parser.add_argument("-st", "--scan-timeout", type=float, default=None, help="Stop scan completely after given number of minutes and print/save any results found in that time window. Will leave unsorted endpoints in a section labelled 'UNSORTED', and will leave out sensitive endpoints. Will NOT interrupt rate limiting test.")
    parser.add_argument("-ro", "--raw-output", action="store_true", help="Do not sort out endpoints after finding them. Will leave out sensitive endpoints whether they are exposed or not.")
    parser.add_argument("-rh", "--ratelimit-header", type=str, default=None, help="Custom headers. Must be seperated by a pipe(|), or newlines. Example use: Cookies: {ExampleCookie: example} | Accept: application/json, text/plain, */*. If the custom header contains double quotes, please use single quotes instead of double quotes to pass this flag.")
    args = parser.parse_args()
    #ratelimit type always defaults to get
    if (args.ratelimit_type != 'GET' or args.ratelimit_var or args.ratelimit_body or args.ratelimit_header) and args.ratelimit is None:
        passedrateargs = []
        if args.ratelimit_body: passedrateargs.append("-rb")
        if args.ratelimit_var: passedrateargs.append("-rv")
        if args.ratelimit_header: passedrateargs.append("-rh")
        if args.ratelimit_type: passedrateargs.append("-rt")
        print(f"Arguments {', '.join(passedrateargs)} were passed, but --ratelimit was not passed.")
        user_input = input("How many requests do you want to send for this rate limiting test? Press Enter to skip.\n >>> ")
        try:
            user_input = int(user_input)
            args.ratelimit = user_input
        except ValueError:
            if user_input == None:
                print("Test skipped by user.", end=' ')
            else:
                print("Invalid input.", end=' ')
            print("Rate limit test will not be carried out.")
    if args.ratelimit_header:
        normalized_rh_check = args.ratelimit_header.replace('\r\n', '|').replace('\n', '|')
        check_lines = [line.strip() for line in normalized_rh_check.split('|') if line.strip()]
        if check_lines:
            first_line_check = check_lines[0]
            if 'http/' in first_line_check.lower():
                words_check = first_line_check.split()
                if words_check:
                    detected_verb = words_check[0].upper()
                    # sync rh and rt
                    if detected_verb != args.ratelimit_type.upper():
                        args.ratelimit_type = detected_verb
    if args.testpath and args.ratelimit is None:
        args.ratelimit = 100 
    notget = args.ratelimit_type.upper() in ['POST', 'PATCH', 'PUT']
    if notget and args.ratelimit >= 1000:
        if args.ratelimit >= 2500:
            if not args.force:
                print(f"\nYou have requested a rate limit test of {args.ratelimit} requests that are not GET requests.")
                print("This can easily cause a Denial of Service in a website if it is not properly guarded.")
                print("It is highly recommended a lower number of requests is chosen to avoid causing a DoS, and to test for rate limiting with a non-GET HTTP method.")
                print("Scan will not be executed. In order to run the script with this number of requests, the --force flag must be passed.")
                exit(1)
        else:
            print(f"\nYou are requesting to run a rate limit test of {args.ratelimit} requests that are not GET requests.")
            print("This may cause the server to slow down if it is not properly guarded and exhaust it.")
            proceed = input("Do you wish to continue running the script and run the test after the scan? [y/n]\n\n >>> ").lower()
            if proceed not in ['y', 'yes']:
                print('Script cancelled.')
                exit(0)
    if args.ratelimit:
        if args.ratelimit_var and not args.ratelimit_body:
            print("\nA rate limit test payload variable was defined, but no payload was provided.")
            print("Scan will not be executed. Please specify a request payload with -rb if you would like to use the rate limit variable.\n")
            exit(1)
            
        if args.ratelimit_body and args.ratelimit_var:
            # bracket escaping, so if someone puts {{X}} or X, it will end up as {X}.
            expected_bracket_token = f"{{{args.ratelimit_var.strip('{}')}}}"

            if expected_bracket_token not in args.ratelimit_body:
                print(f"\nRate limit test iterator variable was defined as '{args.ratelimit_var.strip('{}')}'.")
                print(f"Payload body is missing the expected placeholder: {expected_bracket_token}")
                print("Example usage: -rb '{\"account_id\": \"{X}\"}' -rv 'X'")
                print("Scan will not be executed. Please correct your payload string syntax and re-run.\n")
                exit(1)
    args.disable_og = True if args.only_original == True else args.disable_og
    #tests for new flags
    #args.show_prog = True #comment out later, for testing.
    #args.show_source = True
    #args.scan_timeout = 0.5
    if args.only_original:
        args.disable_og = True
    args.show_assets = args.show_media
    if args.tidy_all == True:
        args.disable_og, args.tidy = True, True

    ignored_extensions = ()

    if args.testpath and args.ratelimit is None:
        parser.error("--testpath requires the --ratelimit flag.\nIf you want to do a rate limit test, use --ratelimit (number of requests) --testpath (path to test).\nIf not, don't use --ratelimit nor --testpath.")

    show_dead = args.show_404s
    target = args.target if args.target else input("Target website not found.\nEnter website (e.g. https://example.com): ").strip()
    
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
        try:
            response = requests.get(target, headers=HEADER, timeout=5, impersonate="chrome120")
        except requests.exceptions.SSLError:
            if target.startswith("https://"):
                print('HTTPS SSL Error. Trying HTTP...') #becuase some sites may use http instead of https
                target = target.replace("https://", "http://")
                try:
                    response = requests.get(target, headers=HEADER, timeout=5, impersonate="chrome120")
                except Exception as e:
                    print(f'Target unreachable on HTTP: {e}')
                    exit(1)
        except Exception as e:
            print(f'Target unreachable: {e}')
            exit(1)
    try:
        st = time.perf_counter()
        uptimeres = requests.get(target, headers=HEADER, timeout=10, impersonate="chrome120")
        et = time.perf_counter()
        restime = et - st
        if not args.only_res:
            print(f"Site responded in {round(restime, 2)} seconds.")
        if not args.only_res:
            if restime < 0.5:
                print("Server is very fast.")
            elif restime < 1:
                print("Server is fast.")
            elif restime < 2.5:
                print("Server is average speed.")
            elif restime < 4:
                print("Server is slow.")
            else:
                print("Server is very slow.")
    except requests.exceptions.Timeout:
        print("Server did not respond after 10 seconds.")
        print("Quitting script...")
        exit(1)
    start_test_time = time.perf_counter()
    #hardcoded dangerous endpoints to test
    SENSITIVE_ENDPOINT = {
        "/.env", "/.env.local", "/.env.production", "/.env.development", ".env.dev",
        "/.git/config", "/.git/HEAD", "/package.json", "/package-lock.json", "/.npmrc", "/.dockerenv",
        "/.gitignore", "/api/health", "/admin", "/login", "/config",
        "/.env.example", "/docker-compose.yml", "/.babelrc", "/.eslintrc.json",
        "/wp-config.php", "/config.json", "/.aws/credentials", "/.git/index",
        "/etc/passwd"
    }
    
    results_fromotherfiles = []
    found_paths = set(SENSITIVE_ENDPOINT)
    discovered_in_js = {}

    if not args.disable_extra_files:
        if not args.only_res:
            print("\nFinding paths from map files. (If they exist)")
        # no 304.
        E_HEADER = HEADER.copy()
        E_HEADER["Cache-Control"] = "no-cache"
        E_HEADER["Pragma"] = "no-cache"
        E_HEADER["If-None-Match"] = ""
        E_HEADER["If-Modified-Since"] = ""
        
        # bobot.txt
        try:
            r_res = requests.get(urljoin(target, "/robots.txt"), headers=E_HEADER, impersonate="chrome120", timeout=4)
            if r_res.status_code == 200 and "disallow" in r_res.text.lower():
                e_files.append('/robots.txt')
                rules = re.findall(r'(?:Disallow|Allow):\s*(/[a-zA-Z0-9_\-\./{}:|]*)', r_res.text, re.IGNORECASE)
                for rule in rules:
                    clean_rule = rule.strip()
                    if clean_rule and clean_rule not in ["/", "/*"] and clean_rule not in found_paths:
                        if clean_rule.strip() in ["/", "/*"]:
                            continue
                        found_paths.add(clean_rule)
                        results_fromotherfiles.append(f"{clean_rule} [Source: robots.txt]")
                        if args.show_prog:
                            print(f"[File from robots.txt] New path/file: {clean_rule if 'clean_rule' in locals() else clean_path if 'clean_path' in locals() else path}")
        except: pass

        # sitemap
        try:
            s_res = requests.get(urljoin(target, "/sitemap.xml"), headers=E_HEADER, impersonate="chrome120", timeout=4)
            if s_res.status_code == 200 and "<loc" in s_res.text.lower():
                e_files.append('/sitemap.xml')
                locs = re.findall(r'<loc>https?://[^/]+(/[^<]+)</loc>', s_res.text, re.IGNORECASE)
                for loc in locs:
                    clean_path = loc.strip()
                    if clean_path and clean_path != "/" and clean_path not in found_paths:
                        if clean_path.strip() == "/":
                            continue
                        found_paths.add(clean_path)
                        if not args.tidy:
                            results_fromotherfiles.append(f"{clean_path} [Source: sitemap.xml]")
                        else:
                            results_fromotherfiles.append(f"{clean_path}")
                        if args.show_prog:
                            print(f"[File from sitemap.xml] New path/file: {clean_rule if 'clean_rule' in locals() else clean_path if 'clean_path' in locals() else path}")
        except: pass

        # me when manifesto without the o
        try:
            m_res = requests.get(urljoin(target, "/asset-manifest.json"), headers=E_HEADER, impersonate="chrome120", timeout=4)
            if m_res.status_code == 200 and "{" in m_res.text:
                e_files.append('/asset-manifest.json')
                paths = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]+)["\']', m_res.text)
                for path in paths:
                    if path not in found_paths:
                        if path.strip() == "/":
                            continue
                        found_paths.add(path)
                        if not args.tidy:
                            results_fromotherfiles.append(f"{path} [Source: asset-manifest.json]")
                        else:
                            results_fromotherfiles.append(f"{path}")
                        if args.show_prog:
                            print(f"[File from asset-manifest.json] New path/file: {clean_rule if 'clean_rule' in locals() else clean_path if 'clean_path' in locals() else path}")
        except: pass
        for manifest_path in ["/web-manifest.json", "/manifest.json"]:
            try:
                m_url = urljoin(target, manifest_path)
                m_res = requests.get(m_url, headers=E_HEADER, impersonate="chrome120", timeout=4)
                if m_res.status_code == 200 and "{" in m_res.text:
                    e_files.append(manifest_path)
                    paths = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]+)["\']', m_res.text)
                    for path in paths:
                        if path not in found_paths:
                            if path.strip() == "/":
                                continue
                            found_paths.add(path)
                            if not args.tidy:
                                results_fromotherfiles.append(f"{path} [Source: {manifest_path.lstrip('/')}]")
                            else:
                                results_fromotherfiles.append(f"{path}")
                            if args.show_prog:
                                print(f"[File from {manifest_path}] New path/file: {clean_rule if 'clean_rule' in locals() else clean_path if 'clean_path' in locals() else path}")

            except: pass
        # service worker lol
        for sw_path in ["/service-worker.js", "/sw.js"]:
            try:
                sw_res = requests.get(urljoin(target, sw_path), headers=E_HEADER, impersonate="chrome120", timeout=4)
                swct = sw_res.headers.get('Content-Type', '').lower()
                if sw_res.status_code == 200 and 'javascript' in swct:
                    e_files.append(sw_path)
                    paths = re.findall(r'["\'`](/[a-zA-Z0-9_\-\./{}:]+)["\'`]', sw_res.text)
                    for path in paths:
                        if path not in found_paths and not any(path.endswith(ext) for ext in ['.js', '.css']):
                            if path.strip() == "/":
                                continue
                            found_paths.add(path)
                            if not args.tidy:
                                results_fromotherfiles.append(f"{path} [Source: {sw_path}]")
                            else:
                                results_fromotherfiles.append(f"{path}")
                            if args.show_prog:
                                print(f"[File from {sw_path}] New path/file: {clean_rule if 'clean_rule' in locals() else clean_path if 'clean_path' in locals() else path}")
            except: pass

        #openid
        try:
            oidc_res = requests.get(urljoin(target, "/.well-known/openid-configuration"), headers=E_HEADER, impersonate="chrome120", timeout=4)
            if oidc_res.status_code == 200 and "{" in oidc_res.text:
                e_files.append("/.well-known/openid-configuration")
                paths = re.findall(r'https?://[^/]+(/[^"\']*)', oidc_res.text)
                for path in paths:
                    if path not in found_paths:
                        if path.strip() == "/":
                            continue
                        found_paths.add(path)
                        if not args.tidy:
                            results_fromotherfiles.append(f"{path} [Source: openid-configuration]")
                        else:
                            results_fromotherfiles.append(f"{path}")
                        if args.show_prog:
                            print(f"[File from openid-configuration] New path/file: {clean_rule if 'clean_rule' in locals() else clean_path if 'clean_path' in locals() else path}")
        except: pass

    if not args.only_res:
        print("\nStarting headless browser to bypass captchas and detect shells with a fake path.")
    main_html, session_cookies = gethtmlafterload(target)

    fake_path = "/very-fake-page-123456123456abcdefg"
    fake_url = urljoin(target, fake_path)
    try:
        fake_res = requests.get(fake_url, cookies=session_cookies, headers=HEADER, impersonate="chrome120", timeout=10)
        shell_content = fake_res.text
    except:
        shell_content = ""
    try:
        if not args.only_res:
            print(f"Detected JS Stack: {identify_javascript_type(main_html)}")
        soup = BeautifulSoup(main_html, 'html.parser')
        
        js_files = [urljoin(target, s.get('src')) for s in soup.find_all('script') if s.get('src') and (not urlparse(s.get('src')).netloc or urlparse(s.get('src')).netloc == urlparse(target).netloc)]
        xml_files = []
        for script_tag in soup.find_all('script'):
            src = script_tag.get('src')
            if src and not src.startswith(('http://', 'https://')):
                local_path = urlparse(src).path
                if local_path:
                    clean_path = '/' + local_path.lstrip('/')
                    found_paths.add(clean_path)

        targetthings = ['stylesheet', 'modulepreload', 'preload', 'prefetch', 'icon', 'shortcut icon', 'manifest']
        #stylesheet like css
        for link_tag in soup.find_all('link', rel=targetthings):
            href = link_tag.get('href')
            if href and not href.startswith(('http://', 'https://')):
                local_path = urlparse(href).path
                if local_path:
                    clean_path = '/' + local_path.lstrip('/')
                    found_paths.add(clean_path)
        patterns = [
            r'["\'`](/[a-zA-Z0-9_\-\./{}:]*)["\'`]', 
            r'(?:path|href|to|post|get|patch|put|delete|head|options)[\s]*[:=\(\|]+[\s]*["\'`](/?[a-zA-Z0-9_\-\./{}:\$]*[\./][a-zA-Z0-9_\-\./{}:\$]*)["\'`]',
            r'["\'`](https?://[a-zA-Z0-9_\-\./{}:\$]+)["\'`]'
        ]

        current_filename = "HTML raw code"
        respo = requests.get(target, headers=HEADER, timeout=5, impersonate="chrome120")
        for p in patterns:
            if args.scan_timeout:
                ts = checktime(start_test_time, args.scan_timeout) #timer status
                if ts == "STOP":
                    break
                    
                elif ts == "EXTEND":
                    start_test_time = time.perf_counter()
                    args.scan_timeout = 5.0 #5min more
            matches = re.findall(p, respo.text)
            for m in matches:
                m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9]+)', '1', m)
                m_clean = m_clean.strip()
                if m_clean != m:
                   m_display = f"{m_clean} [Original: {m}]"
                else:
                    m_display = m_clean

                if "://" not in m_clean:
                    if not m_clean.startswith('/'): 
                        m_clean = '/' + m_clean
                        if m_clean != m:
                            m_display = '/' + m_display
                
                if not m_clean.lower().endswith(ignored_extensions):
                    if m_clean in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                        continue
                    if any(term in m_clean.lower() for term in USELESSSTUFF):
                        continue
                    found_paths.add(m_clean)
                    if m_clean not in discovered_in_js:
                        discovered_in_js[m_clean] = m_display
                        prog_display = m_display
                        if args.only_original and " [Original: " in m_display:
                            prog_display = m_display.split(" [Original: ")[1].rstrip(']')
                        elif args.disable_og and " [Original:" in m_display:
                            prog_display = m_display.split(" [Original:")
                        if args.show_prog:
                            print(f"Found: {prog_display}")
                            if args.show_source:
                                print(f"  └─ Source File: {current_filename}")
        
        current_filename = "HTML script tags"
        # check <script> for endpoint too
        inline_scripts = soup.find_all('script')
        for script in inline_scripts:
            if args.scan_timeout:
                ts = checktime(start_test_time, args.scan_timeout) #timer status
                if ts == "STOP":
                    break
                    
                elif ts == "EXTEND":
                    start_test_time = time.perf_counter()
                    args.scan_timeout = 5.0 #5min more
            if script.string:
                chunks = re.findall(r'["\'](/?[a-zA-Z0-9_\-\./]*\.js)["\']', script.string)
                for c in chunks:
                    clean_c = c if c.startswith('/') else '/' + c
                    js_files.append(urljoin(target, clean_c))
                    discovered_in_js[clean_c] = clean_c
                
                for p in patterns:
                    matches = re.findall(p, script.string)
                    for m in matches:
                        m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9]+)', '1', m)
                        m_clean = m_clean.strip()
                        if m_clean != m:
                           m_display = f"{m_clean} [Original: {m}]"
                        else:
                            m_display = m_clean

                        if "://" not in m_clean:
                            if not m_clean.startswith('/'): 
                                m_clean = '/' + m_clean
                                if m_clean != m:
                                    m_display = '/' + m_display
                        
                        if not m_clean.lower().endswith(ignored_extensions):
                            if m_clean in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ ", "localhost", "w3.org"]:
                                continue
                            if any(term in m_clean.lower() for term in USELESSSTUFF):
                                continue
                            found_paths.add(m_clean)
                            if m_clean not in discovered_in_js:
                                discovered_in_js[m_clean] = m_display
                                prog_display = m_display
                                if args.only_original and " [Original: " in m_display:
                                    prog_display = m_display.split(" [Original: ")[1].rstrip(']')
                                elif args.disable_og and " [Original:" in m_display:
                                    prog_display = m_display.split(" [Original:")
                                if args.show_prog:
                                    print(f"Found: {prog_display}")
                                    if args.show_source:
                                        print(f"  └─ Source File: {current_filename}")

        # scan all js files
        #scan all js files
        for path in list(found_paths):
            if path.lower().endswith('.js'):
                # ensure its a proper website path
                target_js_url = urljoin(target, path) 
                
                # make sure its actually part of the domain
                if urlparse(target_js_url).netloc == urlparse(target if "://" in target else f"https://{target}").netloc:
                    if target_js_url not in js_files:
                        js_files.append(target_js_url)

        for js_url in js_files:
            if args.scan_timeout:
                ts = checktime(start_test_time, args.scan_timeout) #timer status
                if ts == "STOP":
                    break
                    
                elif ts == "EXTEND":
                    start_test_time = time.perf_counter()
                    args.scan_timeout = 5.0 #5min more
            try:
                # no 304.
                DOWNLOAD_HEADERS = HEADER.copy()
                DOWNLOAD_HEADERS["Cache-Control"] = "no-cache"
                DOWNLOAD_HEADERS["Pragma"] = "no-cache"
                DOWNLOAD_HEADERS["If-None-Match"] = ""
                DOWNLOAD_HEADERS["If-Modified-Since"] = ""

                js_res = requests.get(js_url, headers=DOWNLOAD_HEADERS, cookies=session_cookies, timeout=5, impersonate="chrome120")
                
                # i found out 304 sends an empty response
                if js_res.status_code == 200:
                    current_filename = js_url
                    for p in patterns:
                        matches = re.findall(p, js_res.text)
                        for m in matches:
                            m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9]+)', '1', m)
                            m_clean = m_clean.strip()
                            if m_clean != m:
                                m_display = f"{m_clean} [Original: {m}]"
                            else:
                                m_display = m_clean
                            if "://" not in m_clean:
                                if not m_clean.startswith('/'): 
                                    m_clean = '/' + m_clean
                                    if m_clean != m:
                                        m_display = '/' + m_display
                            if not m_clean.lower().endswith(ignored_extensions):
                                if m_clean.strip in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                                    continue
                                if any(term in m_clean.lower() for term in USELESSSTUFF):
                                    continue
                                found_paths.add(m_clean)
                                if m_clean not in discovered_in_js:
                                    discovered_in_js[m_clean] = m_display
                                    prog_display = m_display
                                    if args.only_original and " [Original: " in m_display:
                                        prog_display = m_display.split(" [Original: ")[1].rstrip(']')
                                    elif args.disable_og and " [Original:" in m_display:
                                        prog_display = m_display.split(" [Original:")
                                    if args.show_prog:
                                        print(f"Found: {prog_display}")
                                        if args.show_source:
                                            print(f"  └─ Source File: {current_filename}")
            except: continue
        if not args.disable_extra_files:
            for f in list(found_paths):
                if f.lower().endswith('.xml'):
                    clean_f = '/' + f.lstrip('/')
                    target_x_url = urljoin(target, clean_f) 
                    
                    if urlparse(target_x_url).netloc == urlparse(target if "://" in target else f"https://{target}").netloc:
                        if clean_f not in xml_files:
                            xml_files.append(clean_f)
            
            for xmlfile in xml_files:
                if args.scan_timeout:
                    ts = checktime(start_test_time, args.scan_timeout) #timer status
                    if ts == "STOP":
                        break
                    elif ts == "EXTEND":
                        start_test_time = time.perf_counter()
                        args.scan_timeout = 5.0 #5min more
                try:
                    target_xml_url = urljoin(target, xmlfile)
                    x_res = requests.get(target_xml_url, headers=HEADER, impersonate="chrome120", timeout=4)

                    if x_res.status_code == 200 and "<loc" in x_res.text.lower():
                        locs = re.findall(r'<loc>https?://[^/]+(/[^<]+)</loc>', x_res.text, re.IGNORECASE)
                        for loc in locs:
                            clean_path = loc.strip()
                            if clean_path and clean_path != "/" and clean_path not in found_paths:
                                if clean_path in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                                    continue
                                if any(term in clean_path.lower() for term in USELESSSTUFF):
                                    continue
                                found_paths.add(clean_path)
                                
                                if not args.tidy:
                                    results_fromotherfiles.append(f"{clean_path} [Source: {xmlfile.lstrip('/')}]")
                                else:
                                    results_fromotherfiles.append(f"{clean_path}")
                                    
                                if args.show_prog:
                                    print(f"[File from {xmlfile.lstrip('/')}] New path/file: {clean_path}")
                except: 
                    continue
                

        unique_paths = set(found_paths)
        found_paths = list(unique_paths)
        results_200, results_dead, results_30x = [], [], []
        results_services, results_ext, results_subd = [], [], []
        results_frameworks, results_assets = [], []
        unsorted = []
        if not args.raw_output:
            if not args.only_res:
                print(f"Total paths to test: {len(found_paths)}")
                print("Testing endpoints...")
            for path in sorted(found_paths):
                display_path = discovered_in_js.get(path, path)
                #take away original if disable og actiev
                pure_path = display_path.split(" [Original:")[0]
                if pure_path.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                    continue
                if not any(char.isalnum() for char in pure_path):
                    continue
                if args.only_original and " [Original: " in display_path:
                    display_path = display_path.split(" [Original: ")[1].rstrip(']')
                elif args.disable_og and " [Original:" in display_path:
                    display_path = display_path.split(" [Original:")[0]

                try:
                    parsed_path = urlparse(path)
                    target_domain = urlparse(target).netloc
                    
                    # get the base domain (efg.hijk from abcd.efg.hijk)
                    def get_base(domain):
                        parts = domain.split('.')
                        return ".".join(parts[-2:]) if len(parts) > 1 else domain

                    is_external = parsed_path.netloc and get_base(parsed_path.netloc) != get_base(target_domain)

                    if is_external:
                        if "." not in pure_path:
                            continue
                        results_ext.append(f"{display_path.lstrip('/')}")
                        continue
                    if "://" in path and parsed_path.netloc == target_domain:
                        internal_route = parsed_path.path
                        if parsed_path.query:
                            internal_route += f"?{parsed_path.query}"
                        path = internal_route if internal_route.startswith('/') else '/' + internal_route
                        display_path = path
                        if display_path.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./"]:
                            continue
                    elif parsed_path.netloc and parsed_path.netloc != target_domain:
                        results_subd.append(display_path.lstrip('/'))
                        continue


                    r = requests.get(
                        urljoin(target, path), 
                        headers=HEADER, 
                        cookies=session_cookies, 
                        timeout=5, 
                        allow_redirects=False, 
                        impersonate="chrome120"
                    )
                    
                    content_type = r.headers.get("Content-Type", "").lower()
                    is_shell = (r.text == shell_content)
                    is_home_redirect = (r.text == main_html)
                    
                    # common service and api i think
                    service_markers = ["/api", "/v1", "/v2", "socket.io", "engine.io", "/graphql", "/webhook", "/rpc", "/actuator", "/swagger", "/v3/api-docs", "/rest/", "/ws", "/metrics"]
                    is_machine_path = any(marker in path.lower() for marker in service_markers)

                    media_extensions = ('.png', '.jpg', '.jpeg', '.svg', '.webp', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.swf')
                    framework_extensions = ('.js', '.css', '.json', '.txt', '.xml', '.map')
                    
                    is_media_asset = path.lower().endswith(media_extensions)
                    is_framework_asset = any(path.lower().endswith(ext) for ext in framework_extensions)

                    if r.status_code in [200, 304, 405]: #304 got me
                        #new 405 cuz 405 means it is a real endpoint and works, maybe not accept GET req tho.
                        statag = "" #status tag
                        if not args.tidy and r.status_code == 405:
                            statag = ' [405]'
                        is_transport = any(p in path.lower() for p in ["socket.io", "engine.io", "/rpc", "/webhook", "/graphql"])
                        if (is_shell or is_home_redirect) and not is_transport:
                            if path in discovered_in_js:
                                if not args.tidy:
                                    results_200.append(f"{display_path}{statag} [Client-Side Route, Requires Login]")
                                else:
                                    results_200.append(f"{display_path}{statag}")
                            else:
                                if not args.tidy:
                                    results_dead.append(f"404 Not Found (React Shell): {path}{statag}")
                                else:
                                    results_dead.append(f"404 Not Found: {path}{statag}")
                                    
                        # service if it doesnt get killed
                        elif is_machine_path:
                            if not args.tidy:
                                if any(a in path.lower() for a in ['/api', '/v1', '/v2', '/v3/api-docs']):
                                    results_services.append(f"{display_path}{statag} [API]")
                                else:
                                    results_services.append(f"{display_path}{statag} [Service]")
                            else:
                                results_services.append(f"{display_path}{statag}")
                            
                        else:
                            if "text/html" in content_type:
                                if not args.tidy:
                                    results_200.append(f"{display_path}{statag} [Access no matter what]")
                                else:
                                    results_200.append(f"{display_path}{statag}")
                            elif is_media_asset:
                                results_assets.append(f"{display_path}{statag}")
                            elif is_framework_asset:
                                results_frameworks.append(f"{display_path}{statag}")
                            else:
                                if not args.tidy:
                                    results_frameworks.append(f"{display_path}{statag} [Non-Standard File]")
                                else:
                                    results_frameworks.append(f"{display_path}{statag}")
                    
                    elif r.status_code == 400:
                        if is_framework_asset:
                            if not args.tidy:
                                results_frameworks.append(f"{display_path} [Asset Error - 400]")
                            else:
                                results_frameworks.append(f"{display_path}")
                        # get machine services like socket.io that reject simple GET request.
                        if "." in path or "/" in path:
                            if not args.tidy:
                                results_services.append(f"{display_path} [Potential Service/API - 400]")
                            else:
                                results_services.append(f"{display_path}")
                        elif is_machine_path:
                            results_services.append(f"{display_path}") #cuz socket
                        else:
                            results_dead.append(f"400 Bad Request: {display_path}")

                    elif r.status_code in [403, 404]:
                        results_dead.append(f"{r.status_code} Error: {display_path}")
                    elif str(r.status_code).startswith('3'):
                        results_30x.append(f"{display_path} -> {r.headers.get('Location')}")
                except: continue

                if args.scan_timeout:
                    ts = checktime(start_test_time, args.scan_timeout) #timer status
                    if ts == "STOP":
                        current_position = sorted(found_paths).index(path)
                        unsorted = sorted(found_paths)[current_position:]
                        c_unsorted = []
                        #sensitive endpoints that have not been verified will show up. May be misleading, make people think those sensitive endpoints are exposed.
                        for u in unsorted:
                            if u not in SENSITIVE_ENDPOINT:
                                c_unsorted.append(u)
                        unsorted = sorted(c_unsorted)
                        break
                        
                    elif ts == "EXTEND":
                        start_test_time = time.perf_counter()
                        args.scan_timeout = 5.0 #5min more
        else:
            for path in sorted(found_paths):
                display_path = discovered_in_js.get(path, path)
                pure_path = display_path.split(" [Original:")[0]
                if pure_path.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                    continue
                if not any(char.isalnum() for char in pure_path):
                    continue
                if args.only_original and " [Original: " in display_path:
                    display_path = display_path.split(" [Original: ")[1].rstrip(']')
                elif args.disable_og and " [Original:" in display_path:
                    display_path = display_path.split(" [Original:")[0]
                unsorted_paths.append(display_path)
        if not args.raw_output:
            if results_200:
                print("\n---- ENDPOINTS FOUND ----")
                for p in results_200: print(f"  {p}")
            else:
                print("\n----NO ENDPOITNS FOUND----")
            if results_services:
                print("\n----SERVICES/APIS USED----")
                for p in results_services: print(f"  {p}")
            else:
                print("\n----NO SERVICES/APIS FOUND----")
            if results_ext:
                print("\n----EXTERNAL LINKS----")
                for p in results_ext: print(f"  {p}")
            else:
                print("\n----NO EXTERNAL LINKS FOUND----")
            if results_subd:
                print("\n----SUBDOMAINS----")
                for p in results_subd: print(f"  {p}")
            else:
                print("\n----NO SUBDOMAINS FOUND----")
            if results_frameworks:
                print("\n----WEBSITE SOURCE CODE/FILES----")
                for p in results_frameworks: print(f"  {p}")
            else:
                print("\n----NO WEBSITE SOURCE CODE/FILES FOUND----")
            if results_30x:
                print("\n---- REDIRECTS ----")
                for p in results_30x: print(f"  {p}")
            else:
                print("\n----NO REDIRECTS FOUND----")
                # if result contains stuff
            if not args.disable_extra_files:
                if results_fromotherfiles:
                    print("\n---- PATHS FROM OTHER FILES ----")
                    for entry in results_fromotherfiles:
                        print(f"  {entry}")
                else:
                    print("\n----NO EXTRA PATHS FOUND FROM OTHER FILES----")
            else:
                pass
            if args.show_assets:
                if results_assets:
                    print("\n----WEBSITE MEDIA----")
                    for p in results_assets: print(f"  {p}")
                else:
                    print("\n----NO WEBSITE MEDIA FOUND----")
            else:
                pass
            if show_dead:
                if results_dead:
                    print("\n---- INACCESSIBLE ----")
                    for p in results_dead: print(f"  {p}")
                else:
                    print("\n---- NONE INACCESSIBLE ----")
                    print("WARNING: There should never be no inaccessble paths on a website.\nThis is most likely a false positive a fault on the script's end.\nReport this to the owner of the script immediately, whether it has found endpoints or not, and what site the script has been tested on.")
            if unsorted:
                print("\n----UNSORTED (Scan timed out)----")
                for p in unsorted_paths: print(f"  {p}")
            else:
                if args.scan_timeout:
                    if not args.only_res:
                        print("\nAll paths sorted out.")
            
            print(f"\n--- Scan Summary ---")
            if args.show_assets:
                print(f"Total Accessible Pages: {len(results_200)}\nTotal Services: {len(results_services)}\nTotal External References: {len(results_ext)}\nTotal Source Code/Files: {len(results_frameworks)}\nTotal Redirects: {len(results_30x)}\nTotal Assets: {len(results_assets)}\nTotal Inaccessible: {len(results_dead)}")
            else:
                print(f"Total Accessible Pages: {len(results_200)}\nTotal Services: {len(results_services)}\nTotal External References: {len(results_ext)}\nTotal Source Code/Files: {len(results_frameworks)}\nTotal Redirects: {len(results_30x)}\nTotal Assets: {len(results_assets)} (Hidden, use --show-assets to show)\nTotal Inaccessible: {len(results_dead)}")
            if unsorted:
                print(f"Total Unsorted: {len(unsorted)}") 
            if args.show_source:
                print(f"Files Scanned:")
                for s in js_files:
                    print(f" - {s}")
                for x in xml_files:
                    print(f" - {x}")
                for e in e_files:
                    print(f" - {e}")
            if args.output_file:
                try:
                    with open(args.output_file, 'w', encoding='utf-8') as f:
                        f.write(f"=== Endpointscanner results for {target} ===\n\n")

                        if results_200:
                            f.write("---- ENDPOINTS FOUND ----\n")
                            for p in results_200: f.write(f"  {p}\n")
                        else: f.write("  ----NO ENDPOINTS FOUND----\n")

                        if results_services:
                            f.write("\n----SERVICES/APIS USED----\n")
                            for p in results_services: f.write(f"  {p}\n")
                        else: f.write("  ----NO SERVICES/APIS FOUND----\n")
                        
                        if results_ext:
                            f.write("\n----EXTERNAL LINKS----\n")
                            for p in results_ext: f.write(f"  {p}\n")
                        else: f.write("  ----NO EXTERNAL LINKS FOUND----\n")

                        if results_subd:
                            f.write("\n----SUBDOMAINS----")
                            for p in results_subd: f.write(f"  {p}")
                        else:
                            f.write("\n----NO SUBDOMAINS FOUND----\n")
                        
                        if results_frameworks:
                            f.write("\n----SOURCE CODE/FILES----\n")
                            for p in results_frameworks: f.write(f"  {p}\n")
                        else: f.write("----NO SOURCE CODE/FILES FOUND----\n")
                        
                        if results_30x:
                            f.write("\n\n---- REDIRECTS (301/302/307) ----\n")
                            for p in results_30x: f.write(f"  {p}\n")
                        else: f.write("  ----NO REDIRECTS FOUND----\n")

                        if not args.disable_extra_files:
                            if results_fromotherfiles:
                                f.write("\n---- PATHS FROM OTHER FILES ----\n")
                                for entry in results_fromotherfiles: f.write(f"  {entry}\n")
                            else: f.write("  ----NO EXTRA PATHS FOUND FROM OTHER FILES----\n")

                        if args.show_assets:
                            if results_assets:
                                f.write("\n----WEBSITE ASSETS----\n")
                                for p in results_assets: f.write(f"  {p}\n")
                            else: f.write("  ----NO WEBSITE ASSETS FOUND----\n")

                        if args.show_404s:                      
                            if results_dead:
                                f.write("\n---- INACCESSIBLE (Confirmed 404/403) ----\n")
                                for p in results_dead: f.write(f"  {p}\n")
                            else: f.write("  ----NONE INACCESSIBLE 404/403----\n")
                        if unsorted:
                            f.write("\n----UNSORTED (Scan timed out)----\n")
                            for p in unsorted_paths: f.write(f"  {p}\n")
                        else:
                            if args.scan_timeout:
                                if not args.only_res:
                                    f.write("All paths sorted out.\n")

                        f.write(f"\n--- Scan Summary ---\n")
                        f.write(f"Total Accessible Pages: {len(results_200)}\n")
                        f.write(f"Total Services: {len(results_services)}\n")
                        f.write(f"Total External References: {len(results_ext)}\n")
                        f.write(f"Total Source Code/Files: {len(results_frameworks)}\n")
                        f.write(f"Total Redirects: {len(results_30x)}\n")
                        f.write(f"Total Inaccessible: {len(results_dead)}\n")
                        if unsorted:
                            f.write(f"Total Unsorted: {len(unsorted)}")
                        if args.show_source:
                            f.write(f"Files scanned:\n")
                            for s in js_files:
                                f.write(f" - {s}\n")
                            for x in xml_files:
                                f.write(f" - {x}\n")
                            for e in e_files:
                                f.write(f" - {e}\n")
                        
                    print(f"\nResults successfully written to '{args.output_file}'!")
                except Exception as e:
                    print(f"\nFailed to write file: {e}")
        else:
            if not args.only_res:
                print("Endpoints will not be sorted. Sensitive endpoints like '.git/config' will be automatically skipped.")
                print('----Raw Endpoints----')
            clean_found_paths = []
            #delete all sensitive endpoints, as they are not sorted and may be misleading that all are exposed.
            for p in unsorted_paths:
                if p in SENSITIVE_ENDPOINT:
                    pass
                else:
                    clean_found_paths.append(p)
            for p in clean_found_paths:
                print(p)
            if args.show_source:
                print(f"Files Scanned:")
                for s in js_files:
                    print(f" - {s}")
                for x in xml_files:
                    print(f" - {x}")
                for e in e_files:
                    print(f" - {e}")
            if args.output_file:
                try:
                    with open(args.output_file, 'w', encoding='utf-8') as fi:
                        if not args.only_res:
                            fi.write('----Raw Endpoints----\n\n')
                        for p in unsorted_paths:
                            fi.write(f'{p}\n')
                        if args.show_source:
                            f.write(f"Files scanned:\n")
                            for s in js_files:
                                f.write(f" - {s}\n")
                            for x in xml_files:
                                f.write(f" - {x}\n")
                            for e in e_files:
                                f.write(f" - {e}\n")
                    print(f"\nRaw results successfully written to '{args.output_file}'")
                except Exception as e:
                    print(f'\nFailed to write raw results to file: {e}')

        if args.ratelimit is not None:
            num = args.ratelimit
            test_path = "/"
            if args.testpath:
                test_path = args.testpath if args.testpath.startswith('/') else '/' + args.testpath
                try:
                    check_res = requests.get(urljoin(target, test_path), headers=HEADER, timeout=5, impersonate="chrome120")
                    if check_res.status_code in [301, 302, 307, 308, 403, 404]:
                        print(f"{test_path} receives status {check_res.status_code} on the first request. Testing on root domain.")
                        test_path = "/"
                except:
                    test_path = "/"

            asyncio.run(async_rate_test(
                url=urljoin(target, test_path), 
                num_reqs=num,
                method=args.ratelimit_type,
                rb=args.ratelimit_body,
                rv=args.ratelimit_var,
                cookies=session_cookies,
                rh=args.ratelimit_header
            ))

    except Exception as e:
        print(f"Main Error: {e}")

if __name__ == "__main__":
    main()
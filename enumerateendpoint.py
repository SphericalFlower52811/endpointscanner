import asyncio
from curl_cffi import requests, CurlOpt
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import ipaddress #detect ip at the start of the scan in case people use ip and not example.com.
import argparse
import time
import json
from playwright.sync_api import sync_playwright #headless browser to solve captcha
from playwright_stealth import Stealth #ensure strict firewalls do not block the playwright browser
from colorama import Fore, Style, init

HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US, en;q=0.9"
} #browser header

USELESSSTUFF = {
        "localhost", "127.0.0.1", "0.0.0.0", 
        "w3.org", "schema.org", "xml.org", "://microsoft.com", "/../",
        "schemas.microsoft.com", "schemas.openxmlformats.org"
    }
#jspdf 
JSPDF_SIGNATURE_KEYS = {
    "/ASCII85Decode", "/ASCII85Encode", "/ASCIIHexDecode", "/ASCIIHexEncode", 
    "/Annot", "/Btn", "/CIDSystemInfo", "/Ch", "/FlateDecode", "/FlateEncode", 
    "/Form", "/I", "/Image", "/Outlines", "/Pattern", "/Sig", "/Tx", "/Widget", "/XObject"
}

#pyodide emscripten vfs, as it will be confused. Especially if SPA>
PYODIDE_VFS_PRECISION_PATTERNS = [
    r'^/tmp/?$',
    r'^/dev/(null|tty\d*|urandom|random|stdin|stdout|stderr)(?:/|$)',
    r'^/dev/shm(?:/tmp)?$',
    r'^/proc(/self(/fd(/\d+)?)?)?$',
    r'^/home/(web_user|pyodide)(?:/|$)',
    r'^/lib/python\d+\.\d+(?:/|$)',
    r'^/lib/python\d+\.zip$'
]

S_HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Cache-Control": "no-store",    
    "Pragma": "no-cache",
    "If-None-Match": "",    
    "If-Modified-Since": ""      
}

unsorted_paths = []
e_files = []
unique_progress_paths = set()
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
    
def identify_javascript_type(html, headers=None, current_stack=None):
    if current_stack is None:
        current_stack = []
    html_lower = html.lower() if html else ""
        
    # Next.js
    if any(term in html for term in ['data-next-head', 'script id="__NEXT_DATA__"', 'next-head-count', '_next/', '_next/data']):
        if "Next.js" not in current_stack: current_stack.append("Next.js")
    # React
    if 'data-reactroot' in html or 'react-dom' in html_lower:
        if "React" not in current_stack: current_stack.append("React")
    # Vue / Angular / Nuxt
    if 'v-bind' in html: 
        if "Vue.js" not in current_stack: current_stack.append("Vue.js")
    if 'id="__nuxt"' in html or 'window.__NUXT__' in html: 
        if "Nuxt.js (Vue)" not in current_stack: current_stack.append("Nuxt.js (Vue)")
    if '<app-root' in html or 'ng-version' in html or '_nghost-' in html or 'ng-app' in html_lower: 
        if "Angular" not in current_stack: current_stack.append("Angular")
        
    # Astro
    if any(term in html_lower for term in ['_astro/', 'data-astro-']):
        if "Astro" not in current_stack: current_stack.append("Astro")
    # Gatsby
    if 'gatsby-ssr' in html_lower or 'id="___gatsby"' in html_lower or '__gatsby' in html_lower:
        if "Gatsby" not in current_stack: current_stack.append("Gatsby")
    # Remix
    if 'window.__remixcontext' in html_lower:
        if "Remix" not in current_stack: current_stack.append("Remix")
        
    # jQuery
    if any(term in html_lower for term in ['jquery.min.js', 'jquery-', '/jquery/']):
        if "jQuery" not in current_stack: current_stack.append("jQuery")
    # Alpine.js
    if 'alpine.min.js' in html_lower or 'x-data=' in html_lower:
        if "Alpine.js" not in current_stack: current_stack.append("Alpine.js")
    # Backbone.js
    if 'backbone.js' in html_lower or 'backbone-min.js' in html_lower:
        if "Backbone.js" not in current_stack: current_stack.append("Backbone.js")
    # Ember.js
    if 'ember.js' in html_lower or 'ember-template-' in html_lower:
        if "Ember.js" not in current_stack: current_stack.append("Ember.js")
        
    # Forem (Ruby on Rails)
    if any(term in html_lower for term in ['forem:name', 'forem:logo', 'forem:domain', 'window.forem']):
        if "Forem" not in current_stack: current_stack.append("Forem")
        if "Ruby on Rails (Backend)" not in current_stack: current_stack.append("Ruby on Rails (Backend)")

    # js stacks that can only be detected via header in requests
    if headers:
        # Node.js
        powered_by = headers.get('X-Powered-By', '').lower()
        if 'express' in powered_by or 'node' in powered_by:
            node_label = f"Node.js ({powered_by.capitalize()})"
            if node_label not in current_stack: current_stack.append(node_label)
            
        # Ruby on Rails
        server_header = headers.get('Server', '').lower()
        if any(term in server_header for term in ['phusion passenger', 'puma']):
            if "Ruby on Rails (Backend)" not in current_stack: current_stack.append("Ruby on Rails (Backend)")
        if 'x-rack-cache' in headers or '_rails_session' in headers.get('Set-Cookie', '').lower():
            if "Ruby on Rails (Backend)" not in current_stack: current_stack.append("Ruby on Rails (Backend)")
            
        powered_by_clean = powered_by.strip()
        server_header_clean = server_header.strip()
        if powered_by_clean == 'deno' or server_header_clean == 'deno':
            if "Deno (Runtime)" not in current_stack: current_stack.append("Deno (Runtime)")
            
        if powered_by_clean == 'bun' or server_header_clean == 'bun':
            if "Bun (Runtime)" not in current_stack: current_stack.append("Bun (Runtime)")

    #Build Tools
    if any(term in html_lower for term in ['@vite/client', 'vite-plugin', 'src="/@vite']):
        if "Vite" not in current_stack: current_stack.append("Vite")
    if 'webpack' in html_lower: 
        if "Webpack" not in current_stack: current_stack.append("Webpack")
        
    return current_stack


def identify_javascript_type_two(javascript_content, current_stack):
    js_lower = javascript_content.lower() if javascript_content else ""
    
    if any(term in js_lower for term in ['__reactfiber', '__reactevents']):
        if "React" not in current_stack: current_stack.append("React")
    if 'window.__vue__' in js_lower or '__vue_app__' in js_lower or 'createapp(' in js_lower:
        if "Vue.js" not in current_stack: current_stack.append("Vue.js")
    if 'ngdevmode' in js_lower or 'ɵɵdefinecomponent' in js_lower:
        if "Angular" not in current_stack: current_stack.append("Angular")
    if '_nuxt/static/' in js_lower or 'window.__nuxt__' in js_lower:
        if "Nuxt.js (Vue)" not in current_stack: current_stack.append("Nuxt.js (Vue)")
    # Svelte
    if 'create_fragment(' in js_lower or 'init(this, component, ' in js_lower:
        if "Svelte" not in current_stack: current_stack.append("Svelte")
    # SolidJS
    if '_$createcomponent' in js_lower or 'solid-js/web' in js_lower:
        if "SolidJS" not in current_stack: current_stack.append("SolidJS")
    if 'alpine.' in js_lower or 'alpine:init' in js_lower:
        if "Alpine.js" not in current_stack: current_stack.append("Alpine.js")
    if 'jquery' in js_lower and 'fn.jquery' in js_lower:
        if "jQuery" not in current_stack: current_stack.append("jQuery")
    # Backbone & Ember
    if 'backbone.model.extend' in js_lower or 'backbone.view.extend' in js_lower:
        if "Backbone.js" not in current_stack: current_stack.append("Backbone.js")
    if 'ember.component' in js_lower or 'ember.application' in js_lower:
        if "Ember.js" not in current_stack: current_stack.append("Ember.js")
        
    #Redux
    if 'redux' in js_lower and any(term in js_lower for term in ['createStore', 'combineReducers', '@@redux/']):
        if "Redux" not in current_stack: current_stack.append("Redux")

    if 'data-astro-' in js_lower or '/_astro/' in js_lower:
        if "Astro" not in current_stack: current_stack.append("Astro")
    if '___gatsby' in js_lower or '__gatsby' in js_lower:
        if "Gatsby" not in current_stack: current_stack.append("Gatsby")
    if '_next/static/chunks' in js_lower:
        if "Next.js" not in current_stack: current_stack.append("Next.js")
    if 'window.__remixcontext' in js_lower or 'remix-manifest' in js_lower:
        if "Remix" not in current_stack: current_stack.append("Remix")

    # BuildTools
    if any(term in js_lower for term in ['__vite__', '__vite_plugin_react_preamble_installed__']):
        if "Vite" not in current_stack: current_stack.append("Vite")
    if 'webpackjsonp' in js_lower or '__webpack_require__' in js_lower:
        if "Webpack" not in current_stack: current_stack.append("Webpack")
    if 'parcelrequire' in js_lower:
        if "Parcel" not in current_stack: current_stack.append("Parcel")
    if 'turbopack' in js_lower or '__turbopack_' in js_lower:
        if "Turbopack" not in current_stack: current_stack.append("Turbopack")

    return current_stack



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
                
            print("Finishing up rate limiting test...")
            #wait for all responses to load properly
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
            elif code == 405:
                print(f"HTTP Method is wrong to {tardis.lower()} (Response 405). Was the HTTP Method or endpoint passed wrong?")
            elif code == 400:
                print(f"Payload sent to {tardis.lower()} was malformed. No requests were properly sent.")
            elif code == 401:
                print(f"Request send was not authorised to {tardis.lower()}. Was an authorisation header passed in the request?")
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
                print('Sensitive endpoints like ".git/config" will be automatically skipped.')
            else:
                print('Choice not recognised, and will be defaulted to no.')
                print('Scan stopped. Any data found in the time window will be printed.')
                print('Sensitive endpoints like ".git/config" will be automatically skipped.')
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
    parser.add_argument("-s", "--show-404s", action="store_true", help="Show endpoints tested that returned a 404 or an SPA shell.")
    parser.add_argument("-d", "--disable-extra-files", action="store_true", help="Disable scanning of extra structural mapping files (robots, sitemaps, manifests, etc.)")
    parser.add_argument("-m", "--show-media", action="store_true", help="Include assets/media like images and fonts and videos in scan results")
    parser.add_argument("-sp", "--show-prog", action="store_true", help="Print endpoints to the terminal one by one in real-time as they are found. Warning: Progress will show duplicate paths if endpoints are defined multiple times in the code. Use the flag -nd to remove duplicates from progress. Results will not contain duplicates.")
    parser.add_argument("-o", "--output-file", type=str, default=None, help="Save formatted results directly to a local text file.")
    parser.add_argument("-do", "--disable-og", action="store_true", help="Disable code from showing the original endpoint with variables. Keeps output tidier. Will NOT remove original tag from progress if the --show-prog flag is present.")
    parser.add_argument("-ti", "--tidy", action="store_true", help="Script will not show where it got extra endpoints from, and will not show if it is a client side route and requires login, or react shell. Will also not show if an endpoint is a potential service.")
    parser.add_argument("-ta", "--tidy-all", action="store_true", help="Flags --disable-og and --tidy combsined.")
    parser.add_argument("-or", "--only-res", action="store_true", help="Only show summarised endpoints, and not print out extra information. Has an exception if number of endpoints exceeds 3000.")
    parser.add_argument("-oo", "--only-original", action="store_true", help="Only show the original version of the flag instead of it being replaced with a 1. Will also affect show prog.")
    parser.add_argument("-ss", "--show-source", action="store_true", help="Print the source of each endpoint during progress, like printing out which file it found the endpoint from.")
    parser.add_argument("-st", "--scan-timeout", type=float, default=None, help="Stop scan completely after given number of minutes and print/save any results found in that time window. Will leave unsorted endpoints in a section labelled 'UNSORTED', and will leave out sensitive endpoints. Will NOT interrupt rate limiting test.")
    parser.add_argument("-ro", "--raw-output", action="store_true", help="Do not sort out endpoints after finding them. Will leave out sensitive endpoints whether they are exposed or not.")
    parser.add_argument("-rh", "--ratelimit-header", type=str, default=None, help="Custom headers. Must be seperated by a pipe(|), or newlines. Example use: Cookies: {ExampleCookie: example} | Accept: application/json, text/plain, */*. If the custom header contains double quotes, please use single quotes instead of double quotes to pass this flag.")
    parser.add_argument("-nd", "--no-duplicate-prog", action="store_true", help="If --show-progress is passed, duplicate endpoints in progress will not be shown.")
    parser.add_argument("-l", "--local", action="store_true", help="Pass this flag if the target is a local site like development-server, but is not a localhost/IP address.")

    args = parser.parse_args()
    if not args.only_res:
        init(autoreset=True)
        print()
        print("-" * 40)
        print(f"{Style.BRIGHT}Endpointscanner {Fore.LIGHTMAGENTA_EX}v7.3.5")
        print("-" * 40)
        print()
    if args.no_duplicate_prog and not args.show_prog:
        print("-nd was passed but -sp wasn't passed. -nd will be deactivated as it is only for progress.")
        args.no_duplicate_prog = False
    nd = args.no_duplicate_prog
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
            expected_bracket_token = args.ratelimit_var

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

    ignored_extensions = () #bugged feature so is empty.

    if args.testpath and args.ratelimit is None:
        parser.error("--testpath requires the --ratelimit flag.\nIf you want to do a rate limit test, use --ratelimit (number of requests) --testpath (path to test).\nIf not, don't use --ratelimit nor --testpath.")

    show_dead = args.show_404s
    target = args.target if args.target else input("Target website not found.\nEnter website (e.g. https://example.com): ").strip()
    def check_if_local(target_url):
        try:
            parsed = urlparse(target_url)
            hostname = parsed.hostname
            if not hostname:
                return False
            if hostname in ("localhost", "127.0.0.1") or hostname.endswith((".local", ".lan", ".internal")):
                return True
            try:
                if ipaddress.ip_address(hostname).is_private:
                    return True
            except ValueError:
                pass
        except Exception:
            pass
            return False
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    impersonate_settings = None if (check_if_local(target) or args.local) else "chrome120" #chrome120 will not work on localhosts.
    try:
        response = requests.get(target, headers=HEADER, timeout=5, impersonate=impersonate_settings)
    except requests.exceptions.SSLError:
        if target.startswith("https://"):
            print('HTTPS SSL Error. Trying HTTP...') #becuase some sites may use http instead of https
            target = target.replace("https://", "http://")
            try:
                if not args.local:
                    response = requests.get(target, headers=HEADER, timeout=5, impersonate=impersonate_settings)
            except Exception as e:
                print(f'Target unreachable on HTTP: {e}')
                exit(1)
    except Exception as e:
        print(f'Target unreachable: {e}')
        exit(1)
    try:
        st = time.perf_counter()
        uptimeres = requests.get(target, headers=HEADER, timeout=10, impersonate=impersonate_settings)
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
    results_200, results_dead, results_30x = [], [], []
    results_services, results_ext, results_subd = [], [], []
    results_frameworks, results_assets = [], []
    xml_files = []
    emscripten_vfs_detected = False
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
        
        # robotstxt
        try:
            r_res = requests.get(urljoin(target, "/robots.txt"), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
            if r_res.status_code == 200:
                appendrobottoe = False
                
                for line in r_res.text.splitlines():
                    _local_robots_line = line.strip()
                    if not _local_robots_line or _local_robots_line.startswith("#"): #strip away comments in robots.txt file.
                        continue
                        
                    if ":" in _local_robots_line:
                        _local_parts = _local_robots_line.split(":", 1)
                        _local_directive = _local_parts[0].strip().lower()
                        _local_payload = _local_parts[1].strip()
                        
                        if _local_directive in ["disallow", "allow"]:
                            if _local_payload and _local_payload not in ["/", "/*"] and _local_payload not in found_paths:
                                found_paths.add(_local_payload)
                                if appendrobottoe == False:
                                    e_files.append('/robots.txt')
                                    appendrobottoe = True
                                if not args.tidy: 
                                    results_fromotherfiles.append(f"{_local_payload} [Source: robots.txt]")
                                else:
                                    results_fromotherfiles.append(f"{_local_payload}")
                                    
                                if args.show_prog:
                                    if not nd or _local_payload not in unique_progress_paths:
                                        if args.show_source:
                                            print(f"[File from robots.txt] New path/file: {_local_payload}")
                                        else:
                                            print(f"New path/file: {_local_payload}")
                                        unique_progress_paths.add(_local_payload)
                                        
                        elif _local_directive == "sitemap": #robots.txt can have sitemaps
                            _local_smap_path = urlparse(_local_payload).path
                            if _local_smap_path and _local_smap_path not in xml_files:
                                xml_files.append(_local_smap_path)
                                
                                if args.show_prog:
                                    if not nd or _local_smap_path not in unique_progress_paths:
                                        if args.show_source:
                                            print(f"[File from robots.txt] New path/file: {_local_smap_path}")
                                        else:
                                            print(f"New path/file: {_local_smap_path}")
                                        unique_progress_paths.add(_local_smap_path)
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            exit()
        except: 
            pass

        # sitemap
        try:
            s_res = requests.get(urljoin(target, "/sitemap.xml"), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
            if s_res.status_code == 200 and "<loc" in s_res.text.lower():
                e_files.append('/sitemap.xml')
                
                raw_locs = re.findall(r'<loc>\s*([^<]+)\s*</loc>', s_res.text, re.IGNORECASE | re.DOTALL)
                
                for loc in raw_locs:
                    loc_stripped = loc.strip()
                    if not loc_stripped:
                        continue
                        
                    if "http://" in loc_stripped.lower() or "https://" in loc_stripped.lower():
                        clean_path = urlparse(loc_stripped).path
                    else:
                        clean_path = '/' + loc_stripped.lstrip('/')
                    clean_path = '/' + clean_path.lstrip('/')
                    
                    if clean_path and clean_path != "/" and clean_path not in found_paths:
                        if clean_path.lower().endswith('.xml'):
                            if clean_path not in xml_files:
                                xml_files.append(clean_path)
                            continue
                            
                        found_paths.add(clean_path)
                        if not args.tidy:
                            results_fromotherfiles.append(f"{clean_path} [Source: sitemap.xml]")
                        else:
                            results_fromotherfiles.append(f"{clean_path}")
                        if args.show_prog:
                            if not nd or clean_path not in unique_progress_paths:
                                if args.show_source:
                                    print(f"[File from sitemap.xml] New path/file: {clean_path}")
                                else:
                                    print(f"New path/file: {clean_path}")
                                unique_progress_paths.add(clean_path)
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            exit()
        except: 
            pass

        # assetmanifest
        try:
            m_res = requests.get(urljoin(target, "/asset-manifest.json"), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
            if m_res.status_code == 200 and "{" in m_res.text:
                e_files.append('/asset-manifest.json')
                paths = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]+)["\']', m_res.text)
                for path in paths:
                    clean_m_path = path.strip()
                    if clean_m_path not in found_paths:
                        if clean_m_path == "/":
                            continue
                        found_paths.add(clean_m_path)
                        if not args.tidy:
                            results_fromotherfiles.append(f"{clean_m_path} [Source: asset-manifest.json]")
                        else:
                            results_fromotherfiles.append(f"{clean_m_path}")
                        if args.show_prog:
                            if not nd or clean_m_path not in unique_progress_paths:
                                if args.show_source:
                                    print(f"[File from asset-manifest.json] New path/file: {clean_m_path}")
                                else:
                                    print(f"New path/file: {clean_m_path}")
                                unique_progress_paths.add(clean_m_path)
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            exit()
        except: pass
        # manifests i forgot in the previous loop
        for manifest_path in ["/web-manifest.json", "/manifest.json"]:
            try:
                m_url = urljoin(target, manifest_path)
                m_res = requests.get(m_url, headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
                if m_res.status_code == 200 and "{" in m_res.text:
                    e_files.append(manifest_path)
                    paths = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]+)["\']', m_res.text)
                    for path in paths:
                        clean_manifest_path = path.strip()
                        if clean_manifest_path not in found_paths:
                            if clean_manifest_path == "/":
                                continue
                            found_paths.add(clean_manifest_path)
                            if not args.tidy:
                                results_fromotherfiles.append(f"{clean_manifest_path} [Source: {manifest_path.lstrip('/')}]")
                            else:
                                results_fromotherfiles.append(f"{clean_manifest_path}")
                            if args.show_prog:
                                if not nd or clean_manifest_path not in unique_progress_paths:
                                    if args.show_source:
                                        print(f"[File from {manifest_path}] New path/file: {clean_manifest_path}")
                                    else:
                                        print(f"New path/file: {clean_manifest_path}")
                                    unique_progress_paths.add(clean_manifest_path)
            except (KeyboardInterrupt, SystemExit):
                print("Scan cancelled by user.")
                exit()
            except: pass
        # service worker 
        for sw_path in ["/service-worker.js", "/sw.js"]:
            try:
                sw_res = requests.get(urljoin(target, sw_path), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
                swct = sw_res.headers.get('Content-Type', '').lower()
                if sw_res.status_code == 200 and 'javascript' in swct:
                    e_files.append(sw_path)
                    paths = re.findall(r'["\'`](/[a-zA-Z0-9_\-\./{}:]+)["\'`]', sw_res.text)
                    for path in paths:
                        cleanpath = path.strip()
                        if cleanpath not in found_paths and not any(cleanpath.endswith(ext) for ext in ['.js', '.css']):
                            if cleanpath == "/":
                                continue
                            found_paths.add(cleanpath)
                            if not args.tidy:
                                results_fromotherfiles.append(f"{cleanpath} [Source: {sw_path}]")
                            else:
                                results_fromotherfiles.append(f"{cleanpath}")
                            if args.show_prog:
                                if not nd or cleanpath not in unique_progress_paths:
                                    if args.show_source:
                                        print(f"[File from {sw_path}] New path/file: {cleanpath}")
                                    else:
                                        print(f"New path/file: {cleanpath}")
                                    unique_progress_paths.add(cleanpath)
            except (KeyboardInterrupt, SystemExit):
                print("Scan cancelled by user.")
                exit()
            except: pass

        #openid
        try:
            oidc_res = requests.get(urljoin(target, "/.well-known/openid-configuration"), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
            if oidc_res.status_code == 200 and "authorization_endpoint" in oidc_res.text and "issuer" in oidc_res.text:
                e_files.append("/.well-known/openid-configuration")
                paths = re.findall(r'https?://[^/]+(/[^"\']*)', oidc_res.text)
                for path in paths:
                    clean_oidc_path = path.strip()
                    if clean_oidc_path not in found_paths:
                        if clean_oidc_path == "/":
                            continue
                        found_paths.add(clean_oidc_path)
                        if not args.tidy:
                            results_fromotherfiles.append(f"{clean_oidc_path} [Source: openid-configuration]")
                        else:
                            results_fromotherfiles.append(f"{clean_oidc_path}")
                        if args.show_prog:
                            if not nd or clean_oidc_path not in unique_progress_paths:
                                if args.show_source:
                                    print(f"[File from openid-configuration] New path/file: {clean_oidc_path}")
                                else:
                                    print(f"New path/file: {clean_oidc_path}")
                                unique_progress_paths.add(clean_oidc_path)
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            exit()
        except: pass



    if not args.only_res:
        print("\nStarting headless browser to bypass captchas and detect shells with a fake path.")
    main_html, session_cookies = gethtmlafterload(target)
    #identify js stacks.
    js_stack = []
    identify_javascript_type(html=main_html, headers=None, current_stack=js_stack)
    fake_path = "/very-fake-page-123456123456abcdefg"
    fake_url = urljoin(target, fake_path)
    try:
        fake_res = requests.get(fake_url, cookies=session_cookies, headers=HEADER, impersonate=impersonate_settings, timeout=10)
        shell_content = fake_res.text
    except:
        shell_content = ""
    if not args.only_res:
        print(f"\nStarting scan on {target}.\n")
    try:
        soup = BeautifulSoup(main_html, 'html.parser')
        
        js_files = [urljoin(target, s.get('src')) for s in soup.find_all('script') if s.get('src') and (not urlparse(s.get('src')).netloc or urlparse(s.get('src')).netloc == urlparse(target).netloc)]
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
        respo = requests.get(target, headers=HEADER, timeout=5, impersonate=impersonate_settings)
        for p in patterns:
            try:
                if args.scan_timeout:
                    ts = checktime(start_test_time, args.scan_timeout) #timer status
                    if ts == "STOP":
                        break
                    elif ts == "EXTEND":
                        start_test_time = time.perf_counter()
                        args.scan_timeout = 5.0 #5min more
                matches = re.findall(p, respo.text)
                detected_library_keys = set(matches).intersection(JSPDF_SIGNATURE_KEYS)
                if len(detected_library_keys) >= 3:
                    matches = [m for m in matches if m not in JSPDF_SIGNATURE_KEYS]

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
                                prog_display = m_display.split(" [Original:")[0].strip()

                            if args.show_prog:
                                if not nd or m_clean not in unique_progress_paths:
                                    print(f"Found: {prog_display}")
                                    unique_progress_paths.add(m_clean)
                                    if args.show_source:
                                        print(f"  └─ Source File: {current_filename}")
            except (KeyboardInterrupt, SystemExit):
                print("Scan cancelled by user.")
                exit()
            except: continue

        emscripten_vfs_detected = False
        for path in list(found_paths):
            # check for js, html, and htm (htm is a older version that still exists in many sites)
            if path.lower().endswith(('.js', '.html', '.htm')):
                target_asset_url = urljoin(target, path) 
                asset_netloc = urlparse(target_asset_url).netloc.lower()
                target_netloc = urlparse(target if "://" in target else f"https://{target}").netloc.lower()
                
                def get_apex(domain_str):
                    parts = domain_str.split('.')
                    return ".".join(parts[-2:]) if len(parts) > 1 else domain_str
                
                is_safe_asset = False
                if asset_netloc == target_netloc:
                    is_safe_asset = True
                elif get_apex(asset_netloc) == get_apex(target_netloc):
                    if any(token in asset_netloc for token in ["assets.", "cdn.", "vendor."]):
                        is_safe_asset = True
                
                if is_safe_asset and target_asset_url not in js_files:
                    js_files.append(target_asset_url)
                    found_paths.add(m_clean)

        # check for pyodide
        for j in js_files:
            if 'pyodide' in j.lower():
                emscripten_vfs_detected = True
                break

        # recursive scanning 
        js_idx = 0
        while js_idx < len(js_files):
            js_url = js_files[js_idx]
            
            if args.scan_timeout:
                ts = checktime(start_test_time, args.scan_timeout) #timer status
                if ts == "STOP":
                    break
                elif ts == "EXTEND":
                    start_test_time = time.perf_counter()
                    args.scan_timeout = 5.0 #5min more
                    
            try:
                DOWNLOAD_HEADERS = HEADER.copy()
                DOWNLOAD_HEADERS["Cache-Control"] = "no-cache"
                DOWNLOAD_HEADERS["Pragma"] = "no-cache"
                DOWNLOAD_HEADERS["If-None-Match"] = ""
                DOWNLOAD_HEADERS["If-Modified-Since"] = ""

                js_res = requests.get(js_url, headers=DOWNLOAD_HEADERS, cookies=session_cookies, timeout=5, impersonate=impersonate_settings)
                
                if js_res.status_code == 200:
                    current_filename = js_url
                    if 'pyodide' in js_url.lower():
                        emscripten_vfs_detected = True
                        
                    if js_url.lower().endswith(('.html', '.htm')):
                        local_soup = BeautifulSoup(js_res.text, 'html.parser')
                            
                        for tag in local_soup.find_all(['script', 'link']):
                            src_or_href = tag.get('src') or tag.get('href')
                            if src_or_href:
                                clean_src = src_or_href.strip()
                                if clean_src.lower().endswith(('.js', '.css', '.html', '.htm')):
                                    nested_asset_url = urljoin(js_url, clean_src)
                                    nested_netloc = urlparse(nested_asset_url).netloc.lower()
                                    
                                    nested_safe = False
                                    if nested_netloc == target_netloc:
                                        nested_safe = True
                                    elif get_apex(nested_netloc) == get_apex(target_netloc):
                                        nested_safe = True
                                        
                                    if nested_safe and nested_asset_url not in js_files:
                                        js_files.append(nested_asset_url)
                                    
                                    rel_path = urlparse(nested_asset_url).path
                                    found_paths.add(rel_path)
                                    if rel_path not in discovered_in_js:
                                        discovered_in_js[rel_path] = rel_path
                                        if args.show_prog and (not nd or rel_path not in unique_progress_paths):
                                            print(f"Found: {rel_path}")
                                            unique_progress_paths.add(rel_path)
                                            if args.show_source: print(f"  └─ Source File: {current_filename}")
                            
                        for inline_tag in local_soup.find_all('script'):
                            if inline_tag.string:
                                inline_chunks = re.findall(r'["\'](/?[a-zA-Z0-9_\-\./]*\.js)["\']', inline_tag.string)
                                for c in inline_chunks:
                                    clean_c = c if c.startswith('/') else '/' + c
                                    nested_inline_url = urljoin(js_url, clean_c)
                                    if nested_inline_url not in js_files:
                                        js_files.append(nested_inline_url)
                                    found_paths.add(clean_c)
                                    discovered_in_js[clean_c] = clean_c
                                    
                    #identify js stack (2)
                    else:
                        identify_javascript_type_two(javascript_content=js_res.text, current_stack=js_stack)
                        identify_javascript_type(html="", headers=js_res.headers, current_stack=js_stack)
                        
                        for p in patterns:
                            matches = re.findall(p, js_res.text)
                            detected_library_keys = set(matches).intersection(JSPDF_SIGNATURE_KEYS)
                            if len(detected_library_keys) >= 3:
                                matches = [m for m in matches if m not in JSPDF_SIGNATURE_KEYS]
                            for m in matches:
                                m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9]+)', '1', m).strip()
                                m_display = f"{m_clean} [Original: {m}]" if m_clean != m else m_clean
                                
                                if "://" not in m_clean and not m_clean.startswith('/'): 
                                    m_clean = '/' + m_clean
                                    if m_clean != m: m_display = '/' + m_display
                                        
                                if not m_clean.lower().endswith(ignored_extensions):
                                    if m_clean.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]: continue
                                    if any(term in m_clean.lower() for term in USELESSSTUFF): continue
                                        
                                    if emscripten_vfs_detected:
                                        is_fake_vfs_path = False
                                        for vfs_pattern in PYODIDE_VFS_PRECISION_PATTERNS:
                                            if re.match(vfs_pattern, m_clean, re.IGNORECASE):
                                                is_fake_vfs_path = True
                                                break
                                        if is_fake_vfs_path: continue 
                                    
                                    if m_clean.lower().endswith(('.js', '.html', '.htm')):
                                        check_nested_url = urljoin(target, m_clean)
                                        nested_netloc = urlparse(check_nested_url).netloc.lower()
                                        
                                        nested_safe = False
                                        if nested_netloc == target_netloc:
                                            nested_safe = True
                                        elif get_apex(nested_netloc) == get_apex(target_netloc):
                                            if any(token in nested_netloc for token in ["assets.", "cdn."]):
                                                nested_safe = True
                                                
                                        if nested_safe and check_nested_url not in js_files:
                                            js_files.append(check_nested_url)
                                
                                    found_paths.add(m_clean)
                                    if m_clean not in discovered_in_js:
                                        discovered_in_js[m_clean] = m_display
                                        prog_display = m_display
                                        if args.only_original and " [Original: " in m_display:
                                            prog_display = m_display.split(" [Original: ").rstrip(']')
                                        elif args.disable_og and " [Original:" in m_display:
                                            prog_display = m_display.split(" [Original:").strip() 
                                        
                                        if args.show_prog:
                                            if not nd or m_clean not in unique_progress_paths:
                                                print(f"Found: {prog_display}")
                                                unique_progress_paths.add(m_clean)
                                                if args.show_source:
                                                    print(f"  └─ Source File: {current_filename}")
            except (KeyboardInterrupt, SystemExit):
                print("Scan cancelled by user.")
                exit()
            except: 
                js_idx += 1
                continue
                
            js_idx += 1

        if not args.disable_extra_files:
            for f in list(found_paths):
                if f.lower().endswith('.xml'):
                    if "http://" in f.lower() or "https://" in f.lower():
                        clean_f = urlparse(f).path
                    else:
                        clean_f = '/' + f.lstrip('/')
                        
                    clean_f = '/' + clean_f.lstrip('/')
                    
                    target_x_url = urljoin(target, clean_f) 
                    if urlparse(target_x_url).netloc == urlparse(target if "://" in target else f"https://{target}").netloc:
                        if clean_f not in xml_files:
                            xml_files.append(clean_f)
            
            # recursive xml loop
            xml_index = 0
            while xml_index < len(xml_files):
                xmlfile = xml_files[xml_index]
                
                if args.scan_timeout:
                    ts = checktime(start_test_time, args.scan_timeout) #timer status
                    if ts == "STOP":
                        break
                    elif ts == "EXTEND":
                        start_test_time = time.perf_counter()
                        args.scan_timeout = 5.0 #5min more
                try:
                    DOWNLOAD_XML_HEADERS = HEADER.copy()
                    DOWNLOAD_XML_HEADERS["Cache-Control"] = "no-cache"
                    DOWNLOAD_XML_HEADERS["Pragma"] = "no-cache"
                    DOWNLOAD_XML_HEADERS["If-None-Match"] = ""
                    DOWNLOAD_XML_HEADERS["If-Modified-Since"] = ""
                    target_xml_url = urljoin(target, xmlfile)
                    x_res = requests.get(target_xml_url, headers=DOWNLOAD_XML_HEADERS, impersonate=impersonate_settings, timeout=4)

                    if x_res.status_code == 200 and "<loc" in x_res.text.lower():
                        raw_locs = re.findall(r'<loc>\s*([^<]+)\s*</loc>', x_res.text, re.IGNORECASE | re.DOTALL)
                        
                        for loc in raw_locs:
                            loc_stripped = loc.strip()
                            if not loc_stripped:
                                continue
                                
                            if "http://" in loc_stripped.lower() or "https://" in loc_stripped.lower():
                                clean_path = urlparse(loc_stripped).path
                            else:
                                clean_path = '/' + loc_stripped.lstrip('/')
                            
                            clean_path = '/' + clean_path.lstrip('/')
                            
                            if clean_path and clean_path != "/":
                                if clean_path in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                                    continue
                                if any(term in clean_path.lower() for term in USELESSSTUFF):
                                    continue
                                    
                                if clean_path.lower().endswith('.xml'):
                                    if clean_path not in xml_files:
                                        xml_files.append(clean_path)
                                        if not args.tidy:
                                            results_fromotherfiles.append(f"{clean_path} [Source: Nested Sitemap Index]")
                                        else:
                                            results_fromotherfiles.append(f"{clean_path}")
                                    continue
                                    
                                if clean_path not in found_paths:
                                    found_paths.add(clean_path)
                                    
                                    if not args.tidy:
                                        results_fromotherfiles.append(f"{clean_path} [Source: {xmlfile.lstrip('/')}]")
                                    else:
                                        results_fromotherfiles.append(f"{clean_path}")
                                        
                                    if args.show_prog:
                                        if not nd or clean_path not in unique_progress_paths:
                                            print(f"[File from {xmlfile.lstrip('/')}] New path/file: {clean_path}")
                                            unique_progress_paths.add(clean_path)
                except (KeyboardInterrupt, SystemExit):
                    print("Scan cancelled by user.")
                    exit()
                except: 
                    # move index forward if it fails
                    xml_index += 1
                    continue
                
                xml_index += 1


        if not args.only_res:
            print(f"Detected JS Stack: {' + '.join(js_stack) if js_stack else 'Unknown JS Stack'}")       
        unique_paths = set(found_paths)
        if emscripten_vfs_detected:
            unique_paths = {i for i in unique_paths if i != '/dev' and i != '/dev/' and not i.startswith('/tmp/')}
        found_paths = list(unique_paths)
        unsorted = []
        
        assets_suffix = "" if args.show_assets else " (Hidden, use --show-assets to show)"
        dead_suffix = "" if args.show_404s else " (Hidden, use --show-404s to show)"
        if not args.raw_output:
            print(f"Total paths to test: {len(found_paths)} (Scraped: {len(found_paths) - len(SENSITIVE_ENDPOINT)} | Built-in: {len(SENSITIVE_ENDPOINT)})")
            print("Testing endpoints...")
            
            if len(found_paths) >= 3000:
                # every requests takes ~0.2s
                raw_seconds = 0.2 * len(found_paths)
                
                if raw_seconds >= 60:
                    raw_minutes = raw_seconds / 60
                    if raw_minutes >= 60:
                        raw_hours = raw_minutes / 60
                        esttime = f"{raw_hours:.1f}h" #1d.p. for clean output
                    else:
                        esttime = f"{raw_minutes:.1f}min"
                else:
                    esttime = f"{raw_seconds:.1f}s"
                    
                exaggerate = ""
                if len(found_paths) >= 7000:
                    exaggerate = "REALLY "
                if len(found_paths) >= 12500:
                    exaggerate = "REALLY REALLY "
                    
                print(f"\n[WARNING] Number of endpoints found is {exaggerate}large.")
                print(f"Estimated sorting time: {esttime}")
                
                try:
                    userawoutput = input("Would you like to use the raw output instead? (No sorting at all) [y/n]\n >>> ")
                    if userawoutput.lower() in ['y', 'yes']:
                        print("Endpoints will not be sorted.")
                        args.raw_output = True
                    else:
                        print("Endpoints will still be sorted.")
                        args.raw_output = False
                except (KeyboardInterrupt, SystemExit):
                    print("\nScan cancelled by user.")
                    return

                
        if not args.raw_output:
            from difflib import SequenceMatcher
            # get the base domain (efg.hijk from abcd.efg.hijk)
            def get_base(domain):
                parts = domain.split('.')
                return ".".join(parts[-2:]) if len(parts) > 1 else domain

            try:
                home_res = requests.get(target, headers=S_HEADER, cookies=session_cookies, timeout=5, allow_redirects=False, impersonate=impersonate_settings)
                home_content = home_res.text if home_res.status_code == 200 else ""
            except:
                home_content = ""


            for path in sorted(found_paths):
                display_path = discovered_in_js.get(path, path)
                #take away original if disable-og flag is active
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

                    is_external = parsed_path.netloc and get_base(parsed_path.netloc) != get_base(target_domain)

                    if is_external:
                        if "." not in pure_path:
                            continue
                        while display_path.startswith('/'):
                            display_path = display_path.lstrip('/')
                        results_ext.append(display_path)
                        continue
                    
                    request_route = path
                    if "://" in path and parsed_path.netloc == target_domain:
                        internal_route = parsed_path.path
                        if parsed_path.query:
                            internal_route += f"?{parsed_path.query}"
                        request_route = internal_route if internal_route.startswith('/') else '/' + internal_route
                        display_path = request_route
                        if display_path.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./"]:
                            continue
                    elif parsed_path.netloc and parsed_path.netloc != target_domain:
                        while display_path.startswith('/'):
                            display_path = display_path.lstrip('/')
                        results_subd.append(display_path)
                        continue

                    r = requests.get(
                        urljoin(target, request_route), 
                        headers=S_HEADER, 
                        cookies=session_cookies, 
                        timeout=5, 
                        allow_redirects=False, 
                        impersonate=impersonate_settings
                    )
                    
                    content_type = r.headers.get("Content-Type", "").lower()
                    
                    is_shell = False
                    if shell_content and "text/html" in content_type and r.status_code == 200:
                        if SequenceMatcher(None, r.text, shell_content).quick_ratio() > 0.95:
                            is_shell = True
                    
                    is_home_redirect = False
                    if home_content and "text/html" in content_type and r.status_code == 200:
                        home_len = len(home_content)
                        current_len = len(r.text)
                        
                        max_len = max(1, current_len, home_len)
                        percent_diff = (abs(current_len - home_len) / max_len) * 100
                        
                        if percent_diff <= 3.5:
                            threshold = 0.95 if home_len > 3000 else 0.92
                            similarity_score = SequenceMatcher(None, r.text, home_content).quick_ratio()
                            
                            if r.text == home_content or similarity_score > threshold:
                                is_home_redirect = True

                    # common service and api i think
                    service_markers = ["/api", "/v1", "/v2", "socket.io", "engine.io", "/graphql", "/webhook", "/rpc", "/actuator", "/swagger", "/v3/api-docs", "/rest/", "/ws", "/metrics"]
                    is_machine_path = any(marker in request_route.lower() for marker in service_markers)

                    media_extensions = ('.png', '.jpg', '.jpeg', '.svg', '.webp', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.swf', '.mp4', '.mp3', '.avif', '.webm', '.wav')
                    framework_extensions = ('.js', '.css', '.json', '.txt', '.xml', '.map', '.rels', '.md')
                    
                    is_media_asset = request_route.lower().endswith(media_extensions)
                    is_framework_asset = any(request_route.lower().endswith(ext) for ext in framework_extensions)

                    if r.status_code in [200, 304, 405]: #304 got me
                        #new 405 cuz 405 means it is a real endpoint and works, maybe not accept GET req tho.
                        statag = "" #status tag
                        if not args.tidy and r.status_code == 405:
                            statag = ''
                        is_transport = any(p in request_route.lower() for p in ["socket.io", "engine.io", "/rpc", "/webhook", "/graphql"])
                        if (is_shell or is_home_redirect) and (is_framework_asset or is_media_asset or "." in request_route) and not is_transport:
                            if not args.tidy:
                                results_dead.append(f"404 Not Found (React Shell): {request_route}{statag}")
                            else:
                                results_dead.append(f"404 Not Found: {request_route}{statag}")
                            continue
                        if (is_shell or is_home_redirect) and not is_transport and not is_framework_asset and not is_media_asset:
                            if request_route in discovered_in_js:
                                if not args.tidy:
                                    results_200.append(f"{display_path}{statag} [Client-Side Route, Requires Login]")
                                else:
                                    results_200.append(f"{display_path}{statag}")
                            else:
                                if not args.tidy:
                                    results_dead.append(f"404 Not Found (React Shell): {request_route}{statag}")
                                else:
                                    results_dead.append(f"404 Not Found: {request_route}{statag}")
                                    
                        # service if it exists
                        elif is_machine_path:
                            if not args.tidy:
                                if any(a in request_route.lower() for a in ['/api', '/v1', '/v2', '/v3/api-docs']):
                                    results_services.append(f"{display_path}{statag} [API]")
                                else:
                                    results_services.append(f"{display_path}{statag} [Service]")
                            else:
                                results_services.append(f"{display_path}{statag}")
                            
                        else:
                            if "text/html" in content_type and not ((is_shell or is_home_redirect) and (is_framework_asset or "." in request_route)):
                                if not args.tidy:
                                    results_200.append(f"{display_path}{statag} [Access no matter what]")
                                else:
                                    results_200.append(f"{display_path}{statag}")
                            elif is_media_asset:
                                results_assets.append(f"{display_path}{statag}")

                            elif is_framework_asset:
                                if is_shell or is_home_redirect:
                                    if not args.tidy:
                                        results_dead.append(f"404 Not Found (React Shell Fake File): {path}{statag}")
                                    else:
                                        results_dead.append(f"404 Not Found: {path}{statag}")
                                else:
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
            #UNSORTED_PATHS IS FOR RAW OUTPUT FLAG. FOR UNSORTED AFTER SCAN TIMEOUT IT IS THE 'UNSORTED' LIST.
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
                    print("\n---- EXTRA PATHS FROM OTHER FILES ----")
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
                for p in unsorted: print(f"  {p}")
            else:
                if args.scan_timeout:
                    if not args.only_res:
                        print("\nAll paths sorted out.")
            
            print(f"\n--- Scan Summary ---")
            summary_report = (
                f"Total Accessible Pages: {len(results_200)}\n"
                f"Total Services: {len(results_services)}\n"
                f"Total External References: {len(results_ext)}\n"
                f"Total Source Code/Files: {len(results_frameworks)}\n"
                f"Total Redirects: {len(results_30x)}\n"
                f"Total Assets: {len(results_assets)}{assets_suffix}\n"
                f"Total Inaccessible: {len(results_dead)}{dead_suffix}"
            )
            print(summary_report)
            if unsorted:
                print(f"Total Unsorted: {len(unsorted)}") 
            if args.show_source:
                print("\nFiles Scanned:")
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
                        f.write(summary_report)
                        if unsorted:
                            f.write(f"Total Unsorted: {len(unsorted)}")
                        if args.show_source:
                            f.write(f"\nFiles scanned:\n")
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
                print(f"\nFiles Scanned:")
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
                            f.write(f"\nFiles scanned:\n")
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
                    check_res = requests.get(urljoin(target, test_path), headers=HEADER, timeout=5, impersonate=impersonate_settings)
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
    except (KeyboardInterrupt, SystemExit):
        print("Scan cancelled by user.")
        exit()
    except Exception as e:
        print(f"Main Error: {e}")

if __name__ == "__main__":
    main()
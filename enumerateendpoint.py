import asyncio
from curl_cffi import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
import time
from playwright.sync_api import sync_playwright #headless browser to solve captcha
from playwright_stealth import Stealth #Ensure strict firewalls do not block the playwright browser

HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US, en;q=0.9"
} #browser header

USELESSSTUFF = {
        "localhost", "127.0.0.1", "0.0.0.0", 
        "w3.org", "schema.org", "xml.org", "://microsoft.com"
    }
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

async def async_rate_test(url, num_reqs=100):
    print(f"\nStarting Rate Limit Test: {num_reqs} requests to {url}")

    async with requests.AsyncSession(impersonate="chrome120") as session:
        tasks = [session.get(url, headers=HEADER, timeout=10) for _ in range(num_reqs)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        status_counts = {}
        first_limit_at = None
        
        for i, res in enumerate(responses):
            request_number = i + 1
            if isinstance(res, Exception):
                status_counts['Error'] = status_counts.get('Error', 0) + 1
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

        print("\n--- Rate Limit Results ---")
        for code, count in status_counts.items():
            if code == 'Error': continue
            label = "VULNERABLE" if code == 200 else "RATE-LIMITED" if code == 429 else "WAF/FORBIDDEN" if code == 403 else "CRASHED" if code == 500 else "Other"
            print(f" Status {code} ({label}): {count}")
        
        if status_counts.get(200, 0) == num_reqs:
            print(f"\n{tardis} is potentially vulnerable to DoS or brute-forcing (No rate limit detected after {num_reqs} requests).")
        elif first_limit_at:
            req_num, code = first_limit_at
            if code == 403:
                print(f"\nA WAF (Firewall) likely intercepted the requests to {tardis.lower()} (403 Forbidden after {req_num} requests).")
            elif code == 429:
                print(f"\nRate limiting present on {tardis.lower()} (429 Too Many Requests detected after {req_num} requests).")
            else:
                print(f"\nServer began responding with {code} after {req_num} requests to {tardis.lower()}.")

def main():
    #arguments/flag
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs='?', help="URL")
    parser.add_argument("-r", "--ratelimit", nargs='?', const=100, type=int, default=None, help="Number of requests")
    parser.add_argument("-t", "--testpath", nargs='?', const='/', type=str, help="Endpoint to test")
    parser.add_argument("-s", "--show-404s", action="store_true", help="Show endpoints tested that returned a 404")
    parser.add_argument("-d", "--disable-extra-files", action="store_true", help="Disable scanning of extra structural mapping files (robots, sitemaps, manifests, etc.)")
    parser.add_argument("-m", "--show-media", action="store_true", help="Include assets/media like images and fonts in scan results")
    parser.add_argument("-sp", "--show-prog", action="store_true", help="Print endpoints to the terminal one by one in real-time as they are found")
    parser.add_argument("-o", "--output-file", type=str, default=None, help="Save formatted results directly to a local text file.")
    parser.add_argument("-do", "--disable-og", action="store_true", help="Disable code from showing the original endpoint with variables. Keeps output tidier. Will NOT remove original tag from progress if the --show-prog flag is present.")
    parser.add_argument("-ti", "--tidy", action="store_true", help="Script will not show where it got extra endpoints from, and will not show if it is a client side route and requires login, or react shell. Will also not show if an endpoint is a potential service.")
    parser.add_argument("-ta", "--tidy-all", action="store_true", help="Flags --disable-og and --tidy combined.")
    parser.add_argument("-or", "--only-res", action="store_true", help="Only show summarised endpoints.")

    args = parser.parse_args()
    if args.testpath and args.ratelimit is None:
        args.ratelimit = 100 
    #tests for new flags
    #args.show_prog = True #comment out later, for testing.
    #args.tidy_all = True
    args.show_assets = args.show_media
    if args.tidy_all == True:
        args.disable_og, args.tidy = True, True

    ignored_extensions = ()

    if args.testpath and args.ratelimit is None:
        parser.error("--testpath requires the --ratelimit flag.\nIf you want to do a rate limit test, use --ratelimit (number of requests) --testpath (path to test).\nIf not, don't use --ratelimit nor --testpath.")

    show_dead = args.show_404s
    target = args.target if args.target else input("Enter website (e.g. https://example.com): ").strip()

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

    #hardcoded dangerous endpoints to test
    SENSITIVE_ENDPOINT = {
        "/.env", "/.env.local", "/.env.production", "/.env.development", 
        "/.git/config", "/.git/HEAD", "/robots.txt", "/sitemap.xml", 
        "/package.json", "/package-lock.json", "/.npmrc", "/.dockerenv",
        "/.gitignore", "/api/health", "/admin", "/login", "/config",
        "/.env.example", "/docker-compose.yml", "/.babelrc", "/.eslintrc.json",
        "/wp-config.php", "/config.json", "/.aws/credentials", "/.git/index"
    }
    
    results_fromotherfiles = []
    found_paths = set(SENSITIVE_ENDPOINT)
    discovered_in_js = {}

    if not args.disable_extra_files:
        if not args.only_res:
            print("\nFinding paths from map files. (If they exist)")
        
        # bobot.txt
        try:
            r_res = requests.get(urljoin(target, "/robots.txt"), headers=HEADER, impersonate="chrome120", timeout=4)
            if r_res.status_code == 200 and "disallow" in r_res.text.lower():
                rules = re.findall(r'(?:Disallow|Allow):\s*(/[a-zA-Z0-9_\-\./{}:|]*)', r_res.text, re.IGNORECASE)
                for rule in rules:
                    clean_rule = rule.strip()
                    if clean_rule and clean_rule not in ["/", "/*"] and clean_rule not in found_paths:
                        found_paths.add(clean_rule)
                        results_fromotherfiles.append(f"{clean_rule} [Source: robots.txt]")
                        if args.show_prog:
                            print(f"[File from robots.txt] New path/file: {clean_rule if 'clean_rule' in locals() else clean_path if 'clean_path' in locals() else path}")
        except: pass

        # sitemap
        try:
            s_res = requests.get(urljoin(target, "/sitemap.xml"), headers=HEADER, impersonate="chrome120", timeout=4)
            if s_res.status_code == 200 and "<loc" in s_res.text.lower():
                locs = re.findall(r'<loc>https?://[^/]+(/[^<]+)</loc>', s_res.text, re.IGNORECASE)
                for loc in locs:
                    clean_path = loc.strip()
                    if clean_path and clean_path != "/" and clean_path not in found_paths:
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
            m_res = requests.get(urljoin(target, "/asset-manifest.json"), headers=HEADER, impersonate="chrome120", timeout=4)
            if m_res.status_code == 200 and "{" in m_res.text:
                paths = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]+)["\']', m_res.text)
                for path in paths:
                    if path not in found_paths:
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
                m_res = requests.get(m_url, headers=HEADER, impersonate="chrome120", timeout=4)
                if m_res.status_code == 200 and "{" in m_res.text:
                    paths = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]+)["\']', m_res.text)
                    for path in paths:
                        if path not in found_paths:
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
                sw_res = requests.get(urljoin(target, sw_path), headers=HEADER, impersonate="chrome120", timeout=4)
                if sw_res.status_code == 200:
                    paths = re.findall(r'["\'`](/[a-zA-Z0-9_\-\./{}:]+)["\'`]', sw_res.text)
                    for path in paths:
                        if path not in found_paths and not any(path.endswith(ext) for ext in ['.js', '.css']):
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
            oidc_res = requests.get(urljoin(target, "/.well-known/openid-configuration"), headers=HEADER, impersonate="chrome120", timeout=4)
            if oidc_res.status_code == 200 and "{" in oidc_res.text:
                paths = re.findall(r'https?://[^/]+(/[^"\']*)', oidc_res.text)
                for path in paths:
                    if path not in found_paths:
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
        
        # next js code files
        js_files = [urljoin(target, s.get('src')) for s in soup.find_all('script') if s.get('src')]
        js_files.append(urljoin(target, "/_next/static/development/_buildManifest.js"))
        js_files.append(urljoin(target, "/_next/static/runtime/_buildManifest.js"))

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

        respo = requests.get(target, headers=HEADER, timeout=5, impersonate="chrome120")
        for p in patterns:
            matches = re.findall(p, respo.text)
            for m in matches:
                m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9]+)', '1', m)
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
                        if args.show_prog:
                            print(f"Found: {m_display}")

        
        # check <script> for endpoint too
        inline_scripts = soup.find_all('script')
        for script in inline_scripts:
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
                                if args.show_prog:
                                    print(f"Found: {m_display}")


        # scan all js files
        #scan all js files
        for path in list(found_paths):
            if path.lower().endswith('.js') and urljoin(target, path) not in js_files:
                js_files.append(urljoin(target, path))

        for js_url in js_files:
            try:
                js_res = requests.get(js_url, headers=HEADER, cookies=session_cookies, timeout=5, impersonate="chrome120")
                if js_res.status_code == 200:
                    if "index" not in js_url.lower() and "main" not in js_url.lower():
                        continue
                    for p in patterns:
                        matches = re.findall(p, js_res.text)
                        for m in matches:
                            m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9]+)', '1', m)

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
                                    if args.show_prog:
                                        print(f"Found: {m_display}")
            except: continue

        if not args.only_res:
            print(f"Total paths to test: {len(found_paths)} ({len(discovered_in_js)} scraped from JS).")
            print("Testing endpoints...")
        results_200, results_dead, results_30x = [], [], []
        results_services, results_ext, results_subd = [], [], []
        results_frameworks, results_assets = [], []

        for path in sorted(found_paths):
            display_path = discovered_in_js.get(path, path)
            #take away original if disable og actiev
            if args.disable_og and " [Original:" in display_path:
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
                    if not args.disable_og:
                        results_ext.append(f"{path.lstrip('/')} [External Reference]")
                    else: 
                        results_ext.append(f"{path.lstrip('/')}")
                    continue
                if "://" in path and parsed_path.netloc == target_domain:
                    internal_route = parsed_path.path
                    if parsed_path.query:
                        internal_route += f"?{parsed_path.query}"
                    path = internal_route if internal_route.startswith('/') else '/' + internal_route
                    display_path = path
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
                service_markers = ["/api", "/v1", "/v2", "socket.io", "engine.io", "/graphql", "/webhook", "/rpc"]
                is_machine_path = any(marker in path.lower() for marker in service_markers)

                media_extensions = ('.png', '.jpg', '.jpeg', '.svg', '.webp', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.swf')
                framework_extensions = ('.js', '.css', '.json', '.txt', '.xml', '.map')
                
                is_media_asset = path.lower().endswith(media_extensions)
                is_framework_asset = any(path.lower().endswith(ext) for ext in framework_extensions)

                if r.status_code in [200, 304]: #304 got me
                    # api counts as service even if its an endpoint
                    if is_machine_path:
                        results_services.append(f"{display_path}")
                    elif is_shell or is_home_redirect:
                        if path in discovered_in_js:
                            if not args.tidy:
                                results_200.append(f"{display_path} [Client-Side Route, Requires Login]")
                            else:
                                results_200.append(f"{display_path}")
                        else:
                            if not args.tidy:
                                results_dead.append(f"404 Not Found (React Shell): {path}")
                            else:
                                results_dead.append(f"404 Not Found: {path}")
                    else:
                        if "text/html" in content_type:
                            if not args.tidy:
                                results_200.append(f"{display_path} [Access no matter what]")
                            else:
                                results_200.append(f"{display_path}")
                        elif is_media_asset:
                            results_assets.append(f"{display_path}")
                        elif is_framework_asset:
                            results_frameworks.append(f"{display_path}")
                        else:
                            #standard is like js and css
                            if not args.tidy:
                                results_frameworks.append(f"{display_path} [Non-Standard File]")
                            else:
                                results_frameworks.append(f"{display_path}")

                
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
        
        print(f"\n--- Scan Summary ---")
        if args.show_assets:
            print(f"Total Accessible Pages: {len(results_200)}\nTotal Services: {len(results_services)}\nTotal External References: {len(results_ext)}\nTotal Source Code/Files: {len(results_frameworks)}\nTotal Redirects: {len(results_30x)}\nTotal Assets: {len(results_assets)}\nTotal Inaccessible: {len(results_dead)}")
        else:
            print(f"Total Accessible Pages: {len(results_200)}\nTotal Services: {len(results_services)}\nTotal External References: {len(results_ext)}\nTotal Source Code/Files: {len(results_frameworks)}\nTotal Redirects: {len(results_30x)}\nTotal Assets: {len(results_assets)} (Hidden, use --show-assets to show)\nTotal Inaccessible: {len(results_dead)}")
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
                        f.write("\n----NO SUBDOMAINS FOUND----")
                    
                    if results_frameworks:
                        f.write("\n----SOURCE CODE/FILES----\n")
                        for p in results_frameworks: f.write(f"  {p}\n")
                    else: f.write("  ----NO SOURCE CODE/FILES FOUND----\n")
                    
                    if results_30x:
                        f.write("\n---- REDIRECTS (301/302/307) ----\n")
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


                    f.write(f"\n--- Scan Summary ---\n")
                    f.write(f"Total Accessible Pages: {len(results_200)}\n")
                    f.write(f"Total Services: {len(results_services)}\n")
                    f.write(f"Total External References: {len(results_ext)}\n")
                    f.write(f"Total Source Code/Files: {len(results_frameworks)}\n")
                    f.write(f"Total Redirects: {len(results_30x)}\n")
                    f.write(f"Total Inaccessible: {len(results_dead)}\n")
                    
                print(f"\nResults successfully written to '{args.output_file}'!")
            except Exception as e:
                print(f"\nFailed to write file: {e}")

        if args.ratelimit is not None:
            num = args.ratelimit
            test_path = "/" #root dir
            if args.testpath:
                test_path = args.testpath if args.testpath.startswith('/') else '/' + args.testpath
                try:
                    check_res = requests.get(urljoin(target, test_path), headers=HEADER, timeout=5, impersonate="chrome120")
                    if check_res.status_code in [301, 302, 307, 308, 403, 404]:
                        print(f"{test_path} receives status {check_res.status_code} on the first request. Testing on root domain.")
                        test_path = "/"
                except:
                    test_path = "/"

            asyncio.run(async_rate_test(urljoin(target, test_path), num))

    except Exception as e:
        print(f"Main Error: {e}")

if __name__ == "__main__":
    main()
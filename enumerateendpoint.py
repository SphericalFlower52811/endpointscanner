import asyncio
from curl_cffi import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import argparse
import time
from playwright.sync_api import sync_playwright #headless browser to solve captcha
from playwright_stealth import Stealth #Ensure strict firewalls do not block the playwright browser

#Will be fixed in version 8
'''
def isthere_captcha(response):
   #me when captcha
    html_content = response.text
    html_lower = html_content.lower()
    
    # cloudflare turnstile
    if "challenge-platform" in html_content or "cf-challenge" in html_content:
        return True, "Cloudflare Turnstile (Managed Challenge)"
    if "window._cf_chl_opt" in html_content or "cf-ray:" in html_lower:
        return True, "Cloudflare WAF Block Page"
    if "cf-mitigated" in response.headers.get("Server", "").lower():
        return True, "Cloudflare Edge Mitigation"

    # perimeterx
    if "window._pxappid" in html_lower or "px-captcha" in html_lower:
        return True, "Human Security (PerimeterX) CAPTCHA"
    if "captcha.px-cdn.net" in html_content or "client.perimeterx.net" in html_content:
        return True, "Human Security (PerimeterX) Shield Active"

    #recaptcha
    if "google.com" in html_lower or "g-recaptcha" in html_lower:
        return True, "Google reCAPTCHA Challenge"
    if "recaptcha.js" in html_lower or "__recaptcha_api" in html_lower:
        return True, "Google reCAPTCHA Script Loaded"

    #h captcha
    if "hcaptcha.com" in html_content or "h-captcha" in html_lower:
        return True, "hCaptcha Verification Screen"

    #akamai
    if "akam_bm" in response.cookies or "bm_sz" in response.cookies:
        return True, "Akamai Bot Manager Cookie Block"
    if "_sec_challenge" in html_lower or "akamai-extension" in html_lower:
        return True, "Akamai WAF Challenge Injection"

    # aws/amazon captcha
    if "aws-waf-token" in html_lower or "awswaf" in html_lower:
        return True, "AWS WAF Token Challenge"
    if "amazon captcha" in html_lower or "amzn-captcha" in html_lower:
        return True, "Amazon Custom CAPTCHA Screen"

    # incapsula or soemthing
    if "incapsula" in html_lower or "_incap_" in html_lower:
        return True, "Imperva Incapsula Bot Shield"
    if "visid_incap" in response.cookies:
        return True, "Imperva Session Interception"

    # kasada
    if "kpsdk" in html_lower or "ips.js" in html_lower:
        return True, "Kasada Anti-Bot Handshake"

    # generic captchas
    if response.status_code in [403, 429]:
        generic_signals = ["captcha", "robot", "automated access", "verify you are human", "checking your browser"]
        for signal in generic_signals:
            if signal in html_lower:
                return True, f"Generic Firewall Block ({signal.title()})"
        return True, f"Unidentified Security Drop (HTTP {response.status_code})"

    return False, ""
'''
HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US, en;q=0.9"
} #browser header

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

            # idiotproofing if people GENUINELY cannot read installation instructions
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
    # Build Tools
    if any(term in html.lower() for term in ['@vite/client', 'vite-plugin', 'src="/@vite']):
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

        print("\n--- Rate Limit Results ---")
        for code, count in status_counts.items():
            if code == 'Error': continue
            label = "OK" if code == 200 else "LIMITED" if code == 429 else "WAF/FORBIDDEN" if code == 403 else "CRASHED" if code == 500 else "Other"
            print(f" Status {code} ({label}): {count}")
        
        if status_counts.get(200, 0) == num_reqs:
            print(f"\nWebsite is potentially vulnerable to DoS or brute-forcing (No rate limit detected after {num_reqs} requests).")
        elif first_limit_at:
            req_num, code = first_limit_at
            if code == 403:
                print(f"\nA WAF (Firewall) likely intercepted the requests (403 Forbidden after {req_num} requests).")
            elif code == 429:
                print(f"\nServer-side rate limiting is active (429 Too Many Requests detected after {req_num} requests).")
            else:
                print(f"\nServer began responding with {code} after {req_num} requests.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs='?', help="URL")
    parser.add_argument("--ratelimit", nargs='?', const=100, type=int, default=None, help="Number of requests")
    parser.add_argument("--testpath", nargs='?', const='/', type=str, help="Endpoint to test")
    parser.add_argument("--show-404s", action="store_true", help="Show endpoints tested that returned a 404")
    parser.add_argument("--disable-extra-files", action="store_true", help="Disable scanning of extra structural mapping files (robots, sitemaps, manifests, etc.)")
    parser.add_argument("--show-assets", action="store_true", help="Include assets like images and fonts in scan results")

    args = parser.parse_args()
    if args.testpath and args.ratelimit is None:
        args.ratelimit = 100 

    ignored_extensions = ()

    # error if the user somehow didn't read the instructions (i've idiotproofed the code ENOUGH)
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
                print('[!] HTTPS SSL Error. Trying HTTP...') #becuase later sum http noob
                target = target.replace("https://", "http://")
                try:
                    requests.get(target, headers=HEADER, timeout=5, impersonate="chrome120")
                except Exception as e:
                    print(f'[!] Target unreachable on HTTP: {e}')
                    exit()
        except Exception as e:
            print(f'Target unreachable: {e}')
            exit()
    try:
        st = time.perf_counter()
        uptimeres = requests.get(target, headers=HEADER, timeout=10, impersonate="chrome120")
        et = time.perf_counter()
        restime = et - st
        print(f"Site responded in {round(restime, 2)} seconds.")
        
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
    discovered_in_js = set()

    if not args.disable_extra_files:
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
                        results_fromotherfiles.append(f"{clean_path} [Source: sitemap.xml]")
        except: pass

        # me when manifesto without the o
        try:
            m_res = requests.get(urljoin(target, "/asset-manifest.json"), headers=HEADER, impersonate="chrome120", timeout=4)
            if m_res.status_code == 200 and "{" in m_res.text:
                paths = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]+)["\']', m_res.text)
                for path in paths:
                    if path not in found_paths:
                        found_paths.add(path)
                        results_fromotherfiles.append(f"{path} [Source: asset-manifest.json]")
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
                            results_fromotherfiles.append(f"{path} [Source: {manifest_path.lstrip('/')}]")
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
                            results_fromotherfiles.append(f"{path} [Source: {sw_path}]")
            except: pass

        #openid
        try:
            oidc_res = requests.get(urljoin(target, "/.well-known/openid-configuration"), headers=HEADER, impersonate="chrome120", timeout=4)
            if oidc_res.status_code == 200 and "{" in oidc_res.text:
                paths = re.findall(r'https?://[^/]+(/[^"\']*)', oidc_res.text)
                for path in paths:
                    if path not in found_paths:
                        found_paths.add(path)
                        results_fromotherfiles.append(f"{path} [Source: openid-configuration]")
        except: pass

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
        print(f"Detected JS Type: {identify_javascript_type(main_html)}")
        soup = BeautifulSoup(main_html, 'html.parser')
        
        # next js code files
        js_files = [urljoin(target, s.get('src')) for s in soup.find_all('script') if s.get('src')]
        js_files.append(urljoin(target, "/_next/static/development/_buildManifest.js"))
        js_files.append(urljoin(target, "/_next/static/runtime/_buildManifest.js"))

        for script_tag in soup.find_all('script'):
            src = script_tag.get('src')
            if src and not src.startswith(('http://', 'https://')):
                # Use urlparse to strip away parameters and isolate a clean local path
                local_path = urlparse(src).path
                if local_path:
                    # Guarantee exactly ONE starting slash, nothing more, nothing less
                    clean_path = '/' + local_path.lstrip('/')
                    found_paths.add(clean_path)

        # Gather stylesheets safely without corrupting string slashes
        for link_tag in soup.find_all('link', rel='stylesheet'):
            href = link_tag.get('href')
            if href and not href.startswith(('http://', 'https://')):
                local_path = urlparse(href).path
                if local_path:
                    clean_path = '/' + local_path.lstrip('/')
                    found_paths.add(clean_path)
        patterns = [
            r'["\'`](/[a-zA-Z0-9_\-\./{}:]*)["\'`]', 
            r'(?:path|href|to|post|get|patch|put|delete|head|options)[\s]*[:=\(\|]+[\s]*["\'`](/?[a-zA-Z0-9_\-\./{}:\$]*[\./][a-zA-Z0-9_\-\./{}:\$]*)["\'`]',
            r'[`](https?://[a-zA-Z0-9_\-\./{}:\$]+)[`]'
        ]

        # check <script> for endpoint too
        inline_scripts = soup.find_all('script')
        for script in inline_scripts:
            if script.string:
                chunks = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]*\.js)["\']', script.string)
                for c in chunks:
                    js_files.append(urljoin(target, c))
                
                for p in patterns:
                    matches = re.findall(p, script.string)
                    for m in matches:
                        m_clean = re.sub(r'(\$\{.*\}|:[a-zA-Z0-9]+)', '1', m)
                        if not m_clean.startswith('/'): m_clean = '/' + m_clean
                        
                        if not m_clean.lower().endswith(ignored_extensions):
                            if m_clean in ["/", "//", "///", "/.", "/..", "/..."]:
                                continue
                            found_paths.add(m_clean)
                            discovered_in_js.add(m_clean)

        # scan all js files
        for js_url in js_files:
            try:
                js_res = requests.get(js_url, headers=HEADER, cookies=session_cookies, timeout=5, impersonate="chrome120")
                if js_res.status_code == 200:
                    for p in patterns:
                        matches = re.findall(p, js_res.text)
                        for m in matches:
                            m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9]+)', '1', m)
                            if not m_clean.startswith('/'): m_clean = '/' + m_clean
                            
                            if not m_clean.lower().endswith(ignored_extensions):
                                if m_clean in ["/", "//", "///", "/.", "/..", "/..."]:
                                    continue
                                found_paths.add(m_clean)
                                discovered_in_js.add(m_clean)
            except: continue

        print(f"Total paths to test: {len(found_paths)} ({len(discovered_in_js)} scraped from JS).")
        print("Testing endpoints...")
        results_200, results_dead, results_30x = [], [], []
        results_services, results_ext = [], []
        results_frameworks, results_assets = [], []

        for path in sorted(found_paths):
            # all external url cuz https: //blahblah
            if "://" in path:
                results_ext.append(path.lstrip('/'))
                continue

            try:
                parsed_path = urlparse(path)
                target_domain = urlparse(target).netloc
                
                # get the base domain (efg.hijk from abcd.efg.hijk)
                def get_base(domain):
                    parts = domain.split('.')
                    return ".".join(parts[-2:]) if len(parts) > 1 else domain

                is_external = parsed_path.netloc and get_base(parsed_path.netloc) != get_base(target_domain)

                if is_external:
                    results_ext.append(f"{path.lstrip('/')} [External Reference]")
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

                media_extensions = ('.png', '.jpg', '.jpeg', '.svg', '.webp', '.gif', '.ico', '.woff', '.woff2', '.ttf')
                framework_extensions = ('.js', '.css', '.json', '.txt', '.xml', '.map')
                
                is_media_asset = path.lower().endswith(media_extensions)
                is_framework_asset = any(path.lower().endswith(ext) for ext in framework_extensions)

                if r.status_code in [200, 304]: #304 got me
                    # if its a service/api path then like service and stuff ykyk
                    if is_machine_path:
                        results_services.append(f"{path} [Service/API]")
                    elif is_shell or is_home_redirect:
                        if path in discovered_in_js:
                            results_200.append(f"{path} [Client-Side Route, Requires Login]")
                        else:
                            results_dead.append(f"404 Not Found (React Shell): {path}")
                    else:
                        if "text/html" in content_type:
                            results_200.append(f"{path} [Access no matter what]")
                        elif is_media_asset:
                            results_assets.append(f"{path}")
                        elif is_framework_asset:
                            results_frameworks.append(f"{path}")
                        else:
                            #standard is like js and css
                            results_frameworks.append(f"{path} [Non-Standard File]")

                
                elif r.status_code == 400:
                    if is_framework_asset:
                        results_frameworks.append(f"{path} [Asset Error - 400]")
                    # get machine services like socket.io that reject simple GET request. cuz socket stinky.
                    if "." in path or "/" in path:
                        results_services.append(f"{path} [Potential Service - 400]")
                    elif is_machine_path:
                        results_services.append(f"{path} [Service/API]") #cuz socket
                    else:
                        results_dead.append(f"400 Bad Request: {path}")

                elif r.status_code in [403, 404]:
                    results_dead.append(f"{r.status_code} Error: {path}")
                elif str(r.status_code).startswith('3'):
                    results_30x.append(f"{path} -> {r.headers.get('Location')}")
            except: continue



        if len(results_200) != 0:
            print("\n---- ENDPOINTS FOUND ----")
            for p in results_200: print(f"  {p}")
        else:
            print("\n----NO ENDPOITNS FOUND----")
        if len(results_services) != 0:
            print("\n----SERVICES/APIS USED----")
            for p in results_services: print(f" {p}")
        else:
            print("\n----NO SERVICES/APIS FOUND----")
        if len(results_ext) != 0:
            print("\n----EXTERNAL LINKS----")
            for p in results_ext: print(f" {p}")
        else:
            print("\n----NO EXTERNAL LINKS FOUND----")
        if len(results_frameworks) != 0:
            print("\n----WEBSITE FRAMEWORKS----")
            for p in results_frameworks: print(f" {p}")
        else:
            print("\n----NO WEBSITE FRAMEWORKS FOUND----")
        if len(results_30x) != 0:
            print("\n---- REDIRECTS (301/302/307) ----")
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
            if len(results_assets) != 0:
                print("\n----WEBSITE ASSETS----")
                for p in results_assets: print(f" {p}")
            else:
                print("\n----NO WEBSITE ASSETS FOUND----")
        else:
            pass
        if show_dead:
            if len(results_dead) != 0:
                print("\n---- INACCESSIBLE (Confirmed 404/403) ----")
                for p in results_dead: print(f"  {p}")
            else:
                print("\n----NONE INACCESSIBLE 404/403----")
        
        print(f"\n--- Scan Summary ---")
        if args.show_assets:
            print(f"Total Accessible Pages: {len(results_200)}\nTotal Services: {len(results_services)}\nTotal External References: {len(results_ext)}\nTotal Frameworks: {len(results_frameworks)}\nTotal Redirects: {len(results_30x)}\nTotal Assets: {len(results_assets)}\nTotal Inaccessible: {len(results_dead)}")
        else:
            print(f"Total Accessible Pages: {len(results_200)}\nTotal Services: {len(results_services)}\nTotal External References: {len(results_ext)}\nTotal Frameworks: {len(results_frameworks)}\nTotal Redirects: {len(results_30x)}\nTotal Assets: {len(results_assets)} (Hidden, use --show-assets to show)\nTotal Inaccessible: {len(results_dead)}")

        if args.ratelimit is not None:
            num = args.ratelimit
            test_path = "/" #root dir
            if args.testpath: #idiotproof
                test_path = args.testpath if args.testpath.startswith('/') else '/' + args.testpath
                try:
                    check_res = requests.get(urljoin(target, test_path), headers=HEADER, timeout=5, impersonate="chrome120")
                    if check_res.status_code in [301, 302, 307, 308, 403, 404]:
                        print(f"{test_path} is {check_res.status_code}. Testing on root domain.")
                        test_path = "/"
                except:
                    test_path = "/"

            asyncio.run(async_rate_test(urljoin(target, test_path), num))

    except Exception as e:
        print(f"Main Error: {e}")

if __name__ == "__main__":
    main()
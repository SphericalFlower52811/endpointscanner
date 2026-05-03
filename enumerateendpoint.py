import asyncio
from curl_cffi import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import argparse
import time
from playwright.sync_api import sync_playwright #headless browser to solve captcha
from playwright_stealth import Stealth #Ensure strict firewalls do not block the playwright browser

HEADER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US, en;q=0.9"
} #browser header

def gethtmlafterload(url):
    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
                "--disable-infobars"
            ])
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

                        #find shell page for not found endpoints.

        except Exception as e:
            print("Unexpected Error:", e)
            mainhtml, cookies = "", "", {}

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
    parser.add_argument("--ratelimit", nargs='?', const=100, type=int, help="Number of requests")
    parser.add_argument("--testpath", nargs='?', const='/', type=str, help="Endpoint to test")
    args = parser.parse_args()
    target = args.target if args.target else input("Enter website (e.g. https://example.com): ").strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
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

    SENSITIVE_ENDPOINT = {
        "/.env", "/.env.local", "/.env.production", "/.env.development", 
        "/.git/config", "/.git/HEAD", "/robots.txt", "/sitemap.xml", 
        "/package.json", "/package-lock.json", "/.npmrc", "/.dockerenv",
        "/.gitignore", "/api/health", "/admin", "/login", "/config"
    }
    
    found_paths = set(SENSITIVE_ENDPOINT)
    discovered_in_js = set()
    print("\nStarting headless browser to bypass captchas and detect shells with a fake path.")
    main_html, session_cookies = gethtmlafterload(target)

    fake_path = "/very-fake-page-123456123456abcdefg"
    fake_url = urljoin(target, fake_path)
    try:
        fake_res = requests.get(fake_url, cookies=session_cookies, impersonate="chrome120", timeout=10)
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
        
        patterns = [
            r'["\'`](/[a-zA-Z0-9_\-\./{}:]*)["\'`]', 
            r'(?:path|href|to|post|get|patch|put|delete|head|options)[\s]*[:=\(][\s]*["\'`](/[a-zA-Z0-9_\-\./{}:\$]*)["\'`]'
        ]

        # check <script> for endpoint too
        inline_scripts = soup.find_all('script')
        for script in inline_scripts:
            if script.string:
                # find sum chunk file in code with a regex lookin
                chunks = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]*\.js)["\']', script.string)
                for c in chunks:
                    js_files.append(urljoin(target, c))
                
                for p in patterns:
                    matches = re.findall(p, script.string)
                    for m in matches:
                        m_clean = re.sub(r'(\$\{.*\}|:[a-zA-Z0-9]+)', '1', m)
                        if not m_clean.startswith('/'): m_clean = '/' + m_clean
                        if not any(m_clean.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg', '.webp']):
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
                            if not any(m_clean.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg', '.wasm', '.webp']):
                                found_paths.add(m_clean)
                                discovered_in_js.add(m_clean)
            except: continue

        print(f"Total paths to test: {len(found_paths)} ({len(discovered_in_js)} scraped from JS).")
        print("Testing endpoints...")
        results_200, results_dead, results_30x = [], [], []

        for path in sorted(found_paths):
            try:
                r = requests.get(
                    urljoin(target, path), 
                    headers=HEADER, 
                    cookies=session_cookies, 
                    timeout=5, 
                    allow_redirects=False, 
                    impersonate="chrome120"
                )
                
                is_shell = (r.text == shell_content)
                is_home_redirect = (r.text == main_html)
                if r.status_code == 200:
                    if is_shell or is_home_redirect:
                        if path in discovered_in_js:
                            results_200.append(f"{path} [Client-Side Route, Requires Login]")
                        else:
                            results_dead.append(f"404 Not Found (React Shell): {path}")
                    else:
                        #realfile
                        results_200.append(f"{path} [Access no matter what]")
                
                elif r.status_code in [403, 404]:
                    results_dead.append(f"{r.status_code} Error: {path}")
                elif str(r.status_code).startswith('3'):
                    results_30x.append(f"{path} -> {r.headers.get('Location')}")
            except: continue

        print("\n---- 200 OK (Verified Routes & Files) ----")
        for p in results_200: print(f"  {p}")
        print("\n---- INACCESSIBLE (Confirmed 404/403) ----")
        for p in results_dead: print(f"  {p}")
        print("\n---- Redirects (301/302/307) ----")
        for p in results_30x: print(f"  {p}")
        
        print(f"\n--- Scan Summary ---")
        print(f"Total Accessible: {len(results_200)} | Total Inaccessible: {len(results_dead)} | Total Redirects: {len(results_30x)}")

        if args.ratelimit is not None:
            num = args.ratelimit
            test_path = "/" #root dir
            if args.testpath: #idiotproof
                test_path = args.testpath if args.testpath.startswith('/') else '/' + args.testpath
                try:
                    check_res = requests.get(urljoin(target, test_path), headers=HEADER, timeout=5, impersonate="chrome120")
                    if check_res.status_code in [403, 404]:
                        print(f"{test_path} is {check_res.status_code}. Testing on root domain.")
                        test_path = "/"
                except:
                    test_path = "/"

            asyncio.run(async_rate_test(urljoin(target, test_path), num))

    except Exception as e:
        print(f"Main Error: {e}")

if __name__ == "__main__":
    main()
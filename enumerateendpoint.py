import asyncio
import aiohttp
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def identify_javascript_type(response):
    stack = []
    html = response.text
    headers = response.headers
    # Next.js
    if 'script id="__NEXT_DATA__"' in html or 'next-head-count' in html:
        stack.append("Next.js")
    # React
    if 'data-reactroot' in html or 'id="root"' in html or 'react-dom' in html.lower():
        stack.append("React")
    # Vue / Angular
    if 'id="app"' in html or 'v-bind' in html: stack.append("Vue.js")
    if '<app-root' in html or 'ng-version' in html: stack.append("Angular")
    # Node.js 
    powered_by = headers.get('X-Powered-By', '').lower()
    if 'express' in powered_by or 'node' in powered_by:
        stack.append(f"Node.js ({powered_by.capitalize()})")
    # Build Tools
    if 'vite' in html.lower(): stack.append("Vite")
    if 'webpack' in html.lower(): stack.append("Webpack")

    return " + ".join(stack) if stack else "Unknown JS Stack"

async def async_rate_test(url, num_reqs=100):
    print(f"\n[*] Initializing Async Burst: {num_reqs} requests to {url}")
    async with aiohttp.ClientSession() as session:
        tasks = [session.get(url, timeout=10) for _ in range(num_reqs)]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        status_counts = {}
        first_limit_at = None
        
        for i, res in enumerate(responses):
            request_number = i + 1
            if isinstance(res, Exception):
                status_counts['Error'] = status_counts.get('Error', 0) + 1
                continue
            code = res.status
            status_counts[code] = status_counts.get(code, 0) + 1
            if code != 200 and first_limit_at is None:
                first_limit_at = (request_number, code)

        print("\n--- Rate Limit Results ---")
        for code, count in status_counts.items():
            if code == 'Error': continue
            label = "OK" if code == 200 else "LIMITED" if code == 429 else "WAF/FORBIDDEN" if code == 403 else "Other"
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
    target = input("Enter website (e.g. https://example.com): ").strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    print("\n[!] Using a fake path to test for react shells.")
    
    fake_path = "/very-fake-page-123456123456abcdefg"
    try:
        fake_res = requests.get(urljoin(target, fake_path), timeout=10)
        shell_content = fake_res.text
    except:
        shell_content = ""

    SENSITIVE_TARGETS = {
        "/.env", "/.env.local", "/.env.production", "/.env.development", 
        "/.git/config", "/.git/HEAD", "/robots.txt", "/sitemap.xml", 
        "/package.json", "/package-lock.json", "/.npmrc", "/.dockerenv",
        "/.gitignore", "/api/health", "/admin", "/login", "/config"
    }
    
    found_paths = set(SENSITIVE_TARGETS)
    discovered_in_js = set()

    try:
        res = requests.get(target, timeout=10)
        print(f"[*] Detected JS Type: {identify_javascript_type(res)}")
        soup = BeautifulSoup(res.text, 'html.parser')
        
        # next js code files
        js_files = [urljoin(target, s.get('src')) for s in soup.find_all('script') if s.get('src')]
        js_files.append(urljoin(target, "/_next/static/development/_buildManifest.js"))
        js_files.append(urljoin(target, "/_next/static/runtime/_buildManifest.js"))
        
        patterns = [
            r'["\'`](/[a-zA-Z0-9_\-\./{}:]*)["\'`]', 
            r'(?:path|href|to|post|get|put|delete)[:\s\(]*["\'`]([a-zA-Z0-9_\-\./{}:\$]*)["\'`]'
        ]

        # check <script> for endpoint too
        inline_scripts = soup.find_all('script')
        for script in inline_scripts:
            if script.string:
                # find sum chunk file in code
                chunks = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]*\.js)["\']', script.string)
                for c in chunks:
                    js_files.append(urljoin(target, c))
                
                for p in patterns:
                    matches = re.findall(p, script.string)
                    for m in matches:
                        m_clean = re.sub(r'(\$\{.*\}|:[a-zA-Z0-9]+)', '1', m)
                        if not m_clean.startswith('/'): m_clean = '/' + m_clean
                        if not any(m_clean.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg']):
                            found_paths.add(m_clean)
                            discovered_in_js.add(m_clean)

        # scan all js files
        for js_url in js_files:
            try:
                js_res = requests.get(js_url, timeout=5)
                if js_res.status_code == 200:
                    for p in patterns:
                        matches = re.findall(p, js_res.text)
                        for m in matches:
                            m_clean = re.sub(r'(\$\{.*\}|:[a-zA-Z0-9]+)', '1', m)
                            if not m_clean.startswith('/'): m_clean = '/' + m_clean
                            if not any(m_clean.endswith(ext) for ext in ['.js', '.css', '.png', '.jpg', '.svg', '.wasm']):
                                found_paths.add(m_clean)
                                discovered_in_js.add(m_clean)
            except: continue

        print(f"[*] Total paths to test: {len(found_paths)} ({len(discovered_in_js)} scraped from JS).")
        
        if input("Test all potential endpoints? (y/n): ").lower() == 'y':
            results_200, results_dead, results_30x = [], [], []

            for path in sorted(found_paths):
                try:
                    r = requests.get(urljoin(target, path), timeout=5, allow_redirects=False)
                    is_shell = (r.text == shell_content) or any(m in r.text for m in ["id=\"root\"", "id=\"app\"", "<app-root", "__NEXT_DATA__"])

                    if r.status_code == 200:
                        if is_shell:
                            if path in discovered_in_js:
                                results_200.append(f"{path} [SPA Route]")
                            else:
                                results_dead.append(f"404 Not Found (Soft): {path}")
                        else:
                            results_200.append(f"{path} [Real File/API]")
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

        if input("\nPerform Rate Limit Test? (y/n): ").lower() == 'y':
            test_path = input("Enter path to test (e.g. /app): ").strip()
            if not test_path.startswith('/'):
                test_path = '/' + test_path
            num = int(input("Number of requests (default 100): ") or 100)
            asyncio.run(async_rate_test(urljoin(target, test_path), num))

    except Exception as e:
        print(f"Main Error: {e}")

if __name__ == "__main__":
    main()

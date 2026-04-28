import asyncio
import aiohttp
import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

async def async_rate_test(url, num_reqs=100):
    print(f"\n[*] Initializing Async Burst: {num_reqs} requests to {url}")
    async with aiohttp.ClientSession() as session:
        tasks = [session.get(url, timeout=10) for _ in range(num_reqs)]
        
        # gather keeps the order of the tasks
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        status_counts = {}
        first_limit_at = None
        
        for i, res in enumerate(responses): #enumerate gives the index of the request
            # i + 1 because the loop starts at index 0, and then later kill tracking
            request_number = i + 1
            
            if isinstance(res, Exception):
                status_counts['Error'] = status_counts.get('Error', 0) + 1
                continue
                
            code = res.status
            status_counts[code] = status_counts.get(code, 0) + 1
            
            # first time that is NOT a 200 ok
            if code != 200 and first_limit_at is None:
                first_limit_at = (request_number, code)

        print("\n--- Rate Limit Results ---")
        for code, count in status_counts.items():
            if code == 'Error': continue
            label = "OK" if code == 200 else "LIMITED" if code == 429 else "WAF/FORBIDDEN" if code == 403 else "Other"
            print(f" Status {code} ({label}): {count}")
        
        # show results
        if status_counts.get(200, 0) == num_reqs:
            print(f"\nWebsite is potentially vulnerable to DoS or brute-forcing (No rate limit detected after {num_reqs} requests).")
        
        elif first_limit_at:
            req_num, code = first_limit_at
            if code == 403:
                print(f"\nA WAF (Firewall) likely intercepted the requests (403 Forbidden after {req_num} requests).")
            elif code == 429:
                print(f"\nServer-side rate limiting is active (429 Too Many Requests response in header after {req_num} requests).")
            else:
                print(f"\nServer began responding with {code} after {req_num} requests.")


def main():
    target = input("Enter website (e.g. https://example.com): ").strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    
    print("\n[!] NOTE: 200 OK react shells will be mistaken as real, accessible pages.\nThis will be patched soon maybe")
    
    # test fake page
    fake_path = "/very-fake-page-123456123456abcdefg"
    try:
        fake_res = requests.get(urljoin(target, fake_path), timeout=10)
        shell_content = fake_res.text
    except:
        shell_content = ""

    # discover endpoint
    found_paths = {
    "/.env", "/.env.local", "/.env.production", "/.env.development", 
    "/.git/config", "/.git/HEAD", "/robots.txt", "/sitemap.xml", 
    "/package.json", "/package-lock.json", "/.npmrc", "/.dockerenv",
    "/.gitignore", "/api/health", "/admin", "/login", "/config"
    }
    try:
        res = requests.get(target, timeout=10)
        soup = BeautifulSoup(res.text, 'html.parser')
        js_files = [urljoin(target, s.get('src')) for s in soup.find_all('script') if s.get('src')]
        
        pattern = r'["\'](/[a-zA-Z0-9_\-\./{}:]*)["\']' #regex
        for js_url in js_files:
            try:
                js_res = requests.get(js_url, timeout=5)
                found_paths.update(re.findall(pattern, js_res.text))
            except: continue
            
        print(f"[*] Discovered {len(found_paths)} potential paths.")
        
        if input("Test all potential endpoints? (y/n): ").lower() == 'y':
            results_200 = []
            results_dead = []
            results_30x = []

            for path in sorted(found_paths):
                try:
                    r = requests.get(urljoin(target, path), timeout=5, allow_redirects=False)
                    # if the reponse is the same as the fake path marked as 404
                    if r.status_code == 200 and r.text == shell_content:
                        results_dead.append(f"404 Not Found (Soft): {path}")
                    elif r.status_code == 200:
                        results_200.append(path)
                    elif r.status_code in [403, 404]:
                        results_dead.append(f"{r.status_code} Error: {path}")
                    elif str(r.status_code).startswith('3'):
                        results_30x.append(f"{path} -> {r.headers.get('Location')}")
                except: continue

            print("\n---- 200 OK (including react shells) ----")
            for p in results_200: print(p)

            print("\n---- INACCESSIBLE (404/403) ----")
            for p in results_dead: print(p)

            print("\n---- Redirects (301/302/307) ----")
            for p in results_30x: print(p)

        # --- test rate limit ---
        if input("\nPerform Async Rate Limit Test? (y/n): ").lower() == 'y':
            test_path = input("Enter path to test (e.g. /app, please enter a real endpoint): ").strip()
            num = int(input("Number of requests (default 100): ") or 100)
            asyncio.run(async_rate_test(urljoin(target, test_path), num))

    except Exception as e:
        print(f"Main Error: {e}")

if __name__ == "__main__":
    main()

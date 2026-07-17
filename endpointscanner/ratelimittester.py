'''
Asynchronous rate-limiting tester on any endpoint, with 4 different available HTTP methods to test.
'''

from urllib.parse import urljoin, urlparse
import asyncio
import json
from .headerconfig import HEADER


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
            current_headers["Origin"] = f"{pa_target.scheme}://{pa_target.netloc}"
            current_headers["Referer"] = f"{pa_target.scheme}://{pa_target.netloc}/"
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
            await asyncio.sleep(50.0)

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

'''
This file contains an algorithm to sort out the results based off the three flags:
-oe
-os
-oea
-oc
'''

import time
from difflib import SequenceMatcher
from curl_cffi import requests
from urllib.parse import urlparse, urljoin, unquote
from .miscfuncs import checktime
# ill make this in the next update rn its just in enumerateendpoint.py
def sort_endpoints(
    args, target, S_HEADER, session_cookies, impersonate_settings, shell_content,
    disallowed_url_chars, autoinput_timeout, found_paths, discovered_in_js,
    start_test_time, checktimestatusalready,
    results_ext, results_subd, results_200, results_services, results_assets,
    results_frameworks, results_30x, results_protected, results_dead, unsorted, unsorted_paths,
    invalidated_endpoints, invalidated_count
):
    if not args.raw_output:
        # get the base domain (efg.hijk from abcd.efg.hijk)
        def get_base(domain):
            parts = domain.split('.')
            return ".".join(parts[-2:]) if len(parts) > 1 else domain

        try:
            home_res = requests.get(target, headers=S_HEADER, cookies=session_cookies, timeout=5, allow_redirects=False, impersonate=impersonate_settings)
            home_content = home_res.text if home_res.status_code == 200 else ""
        except:
            home_content = ""
        media_extensions = ('.png', '.jpg', '.jpeg', '.svg', '.webp', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.swf', '.mp4', '.mp3', '.avif', '.webm', '.wav')
        framework_extensions = ('.js', '.css', '.json', '.txt', '.xml', '.map', '.rels', '.md', '.wasm', '.py')
        service_markers = ["/api", "/v1", "/v2", "socket.io", "engine.io", "/graphql", "/webhook", "/rpc", "/actuator", "/swagger", "/v3/api-docs", "/rest/", "/ws", "/metrics"]
        for path in sorted(found_paths):
            display_path = discovered_in_js.get(path, path)
            #take away original if disable-og flag is active
            pure_path = display_path.split(" [Original:")[0]
            if pure_path.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                continue
            decoded_path = unquote(pure_path)
            if any(c in decoded_path for c in disallowed_url_chars):
                invalidated_count += 1
                if display_path not in invalidated_endpoints:
                    invalidated_endpoints.append(display_path)
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
                is_machine_path = any(marker in request_route.lower() for marker in service_markers)
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

                elif r.status_code == 404:
                    results_dead.append(f"404 Not Found: {display_path}")
                    
                elif r.status_code in (401, 403, 407):
                    if not args.tidy:
                        results_protected.append(f"{display_path} [Status {r.status_code}]")
                    else:
                        results_protected.append(f"{display_path}")
                        
                elif str(r.status_code).startswith('3'):
                    results_30x.append(f"{display_path} -> {r.headers.get('Location')}")
                    
                elif r.status_code == 500 or str(r.status_code).startswith('5'):
                    if not args.tidy:
                        results_200.append(f"{display_path} [Crashed: {r.status_code}]")
                    else:
                        results_200.append(f"{display_path}")
                        
                else:
                    results_200.append(f"{display_path}")

            except: continue

            if args.scan_timeout:
                ts, checktimestatusalready = checktime(start_test_time, args.scan_timeout, checktimestatusalready, (not args.no_auto_input), autoinput_timeout) #timer status
                if ts == "STOP":
                    current_position = sorted(found_paths).index(path)
                    unsorted = sorted(found_paths)[current_position:]
                    c_unsorted = []
                    #PREVENTS because: sensitive endpoints that have not been verified will show up. May be misleading, make people think those sensitive endpoints are exposed.
                    for u in unsorted:
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
            decoded_path = unquote(pure_path)
            if any(c in decoded_path for c in disallowed_url_chars):
                invalidated_count += 1
                if display_path not in invalidated_endpoints:
                    invalidated_endpoints.append(display_path)
                continue
            if args.only_original and " [Original: " in display_path:
                display_path = display_path.split(" [Original: ")[1].rstrip(']')
            elif args.disable_og and " [Original:" in display_path:
                display_path = display_path.split(" [Original:")[0]
            unsorted_paths.append(display_path)

    return start_test_time, checktimestatusalready, invalidated_count
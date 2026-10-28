'''
This file (will) contain an algorithm to sort out the results based off the three flags:
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
import asyncio

async def test_path_worker(
    path, semaphore, session, args, target, home_content, shell_content, 
    disallowed_url_chars, media_extensions, framework_extensions, service_markers, 
    discovered_in_js, results_ext, results_subd, results_200, results_services, 
    results_assets, results_frameworks, results_30x, results_protected, results_dead,
    invalidated_endpoints, invalidated_count_wrapper, time_state, time_lock,
    unsorted, found_paths
):
    async with semaphore:
        if time_state.get('stop_triggered'):
            return
        if args.scan_timeout:
            async with time_lock:
                if not time_state.get('stop_triggered'):
                    ts, new_checktime_status = checktime(
                        time_state['start_time'], 
                        args.scan_timeout, 
                        time_state['status'], 
                        (not args.no_auto_input), 
                        time_state['autoinput_timeout']
                    )
                    time_state['status'] = new_checktime_status
                    
                    if ts == "STOP":
                        time_state['stop_triggered'] = True
                        current_idx = sorted(found_paths).index(path)
                        for unverified in sorted(found_paths)[current_idx:]:
                            unverified_display = discovered_in_js.get(urlparse(unverified).path if "://" in unverified else unverified, unverified)
                            if unverified_display.startswith('/'):
                                unverified_display = f"{target}{unverified_display}"
                            if unverified_display not in unsorted:
                                unsorted.append(unverified_display)
                        return
                    elif ts == "EXTEND":
                        time_state['start_time'] = time.perf_counter()
                        args.scan_timeout = 5.0 # 5 minutes more extension
                
        if time_state.get('stop_triggered'):
            return
        relative_key = urlparse(path).path if "://" in path else path
        display_path = discovered_in_js.get(relative_key, discovered_in_js.get(path, path))
        #take away original if disable-og flag is active
        pure_path = display_path.split(" [Original:")[0]
        if pure_path.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
            return
        
        decoded_path = unquote(pure_path)
        if any(c in decoded_path for c in disallowed_url_chars):
            invalidated_count_wrapper['count'] += 1
            if display_path not in invalidated_endpoints:
                if display_path.startswith('/'):
                    display_path = f"{target}{display_path}"
                invalidated_endpoints.append(display_path)
            return
        if args.only_original and " [Original: " in display_path:
            display_path = display_path.split(" [Original: ")[1].rstrip(']')
        elif args.disable_og and " [Original:" in display_path:
            display_path = display_path.split(" [Original:")[0]

        try:
            parsed_path = urlparse(path)
            target_domain = urlparse(target).netloc
            def get_base(domain):
                parts = domain.split('.')
                return ".".join(parts[-2:]) if len(parts) > 1 else domain
            is_external = parsed_path.netloc and get_base(parsed_path.netloc) != get_base(target_domain)

            if is_external:
                if "." not in pure_path:
                    return
                while display_path.startswith('/'):
                    display_path = display_path.lstrip('/')
                results_ext.append(display_path)
                return
            
            request_route = path
            if "://" in path and parsed_path.netloc == target_domain:
                internal_route = parsed_path.path
                if parsed_path.query:
                    internal_route += f"?{parsed_path.query}"
                request_route = internal_route if internal_route.startswith('/') else '/' + internal_route
                display_path = request_route
                if display_path.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./"]:
                    return
            elif parsed_path.netloc and parsed_path.netloc != target_domain:
                while display_path.startswith('/'):
                    display_path = display_path.lstrip('/')
                results_subd.append(display_path)
                return

            r = await session.get(
                urljoin(target, request_route), 
                allow_redirects=False,
                timeout=5
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
                        results_dead.append(f"404 Not Found (React Shell): {display_path}{statag}")
                    else:
                        results_dead.append(f"404 Not Found: {display_path}{statag}")
                    return
                if (is_shell or is_home_redirect) and not is_transport and not is_framework_asset and not is_media_asset:
                    if request_route in discovered_in_js:
                        if not args.tidy:
                            results_200.append(f"{display_path}{statag} [Client-Side Route, Requires Login]")
                        else:
                            results_200.append(f"{display_path}{statag}")
                    else:
                        if not args.tidy:
                            results_dead.append(f"404 Not Found (React Shell): {display_path}{statag}")
                        else:
                            results_dead.append(f"404 Not Found: {display_path}{statag}")
                            
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
                                results_dead.append(f"404 Not Found (React Shell): {display_path}{statag}")
                            else:
                                results_dead.append(f"404 Not Found: {display_path}{statag}")
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

        except: return

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
        framework_extensions = ('.js', '.css', '.json', '.txt', '.xml', '.map', '.rels', '.md', '.wasm', '.wxs')
        service_markers = ["/api", "/v1", "/v2", "socket.io", "engine.io", "/graphql", "/webhook", "/rpc", "/actuator", "/swagger", "/v3/api-docs", "/rest/", "/ws", "/metrics"]
        invalidated_count_wrapper = {'count': invalidated_count}
        time_state = {
            'start_time': start_test_time,
            'status': checktimestatusalready,
            'autoinput_timeout': autoinput_timeout,
            'stop_triggered': False
        }
        async def sort_paths():
            time_lock = asyncio.Lock()
            async with requests.AsyncSession(
                headers=S_HEADER, 
                cookies=session_cookies, 
                impersonate=impersonate_settings,
                max_clients=100
            ) as session:
                semaphore = asyncio.Semaphore(40)
                tasks = [
                    test_path_worker(
                        path, semaphore, session, args, target, home_content, shell_content, 
                        disallowed_url_chars, media_extensions, framework_extensions, service_markers, 
                        discovered_in_js, results_ext, results_subd, results_200, results_services, 
                        results_assets, results_frameworks, results_30x, results_protected, results_dead,
                        invalidated_endpoints, invalidated_count_wrapper, time_state, time_lock,
                        unsorted, found_paths
                    ) for path in sorted(found_paths)
                ]
                await asyncio.gather(*tasks)
                    
        asyncio.run(sort_paths())
        invalidated_count = invalidated_count_wrapper['count']
        start_test_time = time_state['start_time']
        checktimestatusalready = time_state['status']
    else:
        #UNSORTED_PATHS IS FOR RAW OUTPUT FLAG. FOR UNSORTED AFTER SCAN TIMEOUT IT IS THE 'UNSORTED' LIST.
        for path in sorted(found_paths):
            relative_key = urlparse(path).path if "://" in path else path
            display_path = discovered_in_js.get(relative_key, discovered_in_js.get(path, path))
            
            pure_path = display_path.split(" [Original:")[0]
            if pure_path.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                continue
            decoded_path = unquote(pure_path)
            if any(c in decoded_path for c in disallowed_url_chars):
                invalidated_count += 1
                if display_path not in invalidated_endpoints:
                    if display_path.startswith('/'):
                        display_path = f"{target}{display_path}"
                    invalidated_endpoints.append(display_path)
                continue
            if args.only_original and " [Original: " in display_path:
                display_path = display_path.split(" [Original: ")[1].rstrip(']')
            elif args.disable_og and " [Original:" in display_path:
                display_path = display_path.split(" [Original:")[0]
                
            if display_path.startswith('/'):
                display_path = f"{target}{display_path}"
                
            unsorted_paths.append(display_path)


    return start_test_time, checktimestatusalready, invalidated_count

def filter_endpoints(
    args, target, results_ext, results_subd, results_200, results_services, 
    results_assets, results_frameworks, results_30x, results_protected, 
    results_dead, invalidated_endpoints, unsorted_paths
):
    if not (args.only_endpoints or args.only_sub or args.only_external):
        return None
    all_endpoints = []
    def get_base(domain):
        parts = domain.split('.')
        return ".".join(parts[-2:]) if len(parts) > 1 else domain
    if args.raw_output:
        target_netloc = urlparse(target if "://" in target else f"https://{target}").netloc.lower()
        raw_ext, raw_subd, raw_endpoints = [], [], []
        for path in unsorted_paths:
            try:
                parsed_path = urlparse(path)
                if not parsed_path.netloc:
                    raw_endpoints.append(f"{target}{path}")
                    continue

                asset_domain = parsed_path.netloc.lower()
                is_external = get_base(asset_domain) != get_base(target_netloc)

                if is_external:
                    raw_ext.append(path)
                elif asset_domain != target_netloc:
                    raw_subd.append(path)
                else:
                    raw_endpoints.append(path)
            except:
                raw_endpoints.append(path)
        results_200.extend(raw_endpoints)
        results_ext.extend(raw_ext)
        results_subd.extend(raw_subd)
    if args.only_external:
        all_endpoints.extend(results_ext)
    if args.only_sub:
        all_endpoints.extend(results_subd)
    if args.only_endpoints:
        all_endpoints.extend(results_200)
        all_endpoints.extend(results_protected)
        all_endpoints.extend(results_services)
        all_endpoints.extend(results_frameworks)
        all_endpoints.extend(results_30x)
        if args.show_media: all_endpoints.extend(results_assets)
        if args.show_404s: all_endpoints.extend(results_dead)
        if args.still_show_invalid: all_endpoints.extend(invalidated_endpoints)

    return sorted(list(set(all_endpoints)))
        
        
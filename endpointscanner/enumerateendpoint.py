'''
Main python file used. When running the command, this is the file that runs.
'''

#module imports
import asyncio
from curl_cffi import requests, CurlOpt
import re
import sys #used for sys.exit
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, unquote
import argparse
import time
import json
import random
from colorama import Fore, Style, init
from difflib import SequenceMatcher
import secrets
#imports from other files
from .browser import gethtmlafterload
from .ratelimittester import async_rate_test
from .identifyjs import identify_javascript_type, identify_javascript_type_two
from .miscfuncs import checktime, check_if_local, startcodeargs, testhttpprotocol, checkserveruptime, verifyeacheslprotocol, timeout_input
from .outputendpointsfound import display_and_save_results
from .headerconfig import HEADER
from .mapfiles import scrape_structure_files
from .scrapefiles import tag_soup_scrape, initial_html_scrape, recursive_js_crawler, recursive_xml_crawler

def main():
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
    unsorted_paths = []
    unique_progress_paths = set()
    start_test_time = None
    #define args
    args = startcodeargs()
    #External Script Loaders
    if args.extra_header:
        for item in args.extra_header:
            if ":" in item:
                key, value = item.split(":", 1)
                HEADER[key.strip()] = value.strip()
    ignored_extensions = () #bugged feature so is empty.
    external_script_loader_list = args.external_script_loader
    preferredprotocol = args.all_esl_protocol
    #unpack external script loaders if they are in a list.
    unpacked_esls = []
    if external_script_loader_list:
        for eslitem in external_script_loader_list:
            cleaneslitem = eslitem.strip()
            if cleaneslitem:
                if cleaneslitem.endswith('.txt'):
                    try:
                        #open txt file, either separated by , or newline.
                        with open(cleaneslitem, 'r', encoding='utf-8', errors='ignore') as eslfile:
                            eslfilecontent = eslfile.read()
                            #change newlines to commas, and split the file via commas.
                            eslsfromfile = eslfilecontent.replace('\n', ",").split(",")
                            for esl in eslsfromfile:
                                cleanesl = esl.strip()
                                if cleanesl:
                                    unpacked_esls.append(cleanesl)
                    except FileNotFoundError:
                        print(f"File {cleaneslitem} not found, is the path correct?")
                        sys.exit(1)
                    except Exception as e:
                        print(f"Error opening file: {e}")
                        sys.exit(1)
                else:
                    unpacked_esls.append(cleaneslitem)  
    esl_domains = []
    esl_scripts = []      
    for esl in unpacked_esls:
        #.wxs is included cuz apparently its popular
        if '/' in esl.strip() and esl.strip().endswith(('.js', '.mjs', '.htm', '.html', '.css', '.wxs', '.cjs')):
            esl_scripts.append(esl.strip())
        else:
            esl_domains.append(esl.strip())            
    verified_esl_domains = verifyeacheslprotocol(esl_domains, preferredprotocol)
    verified_esl_scripts = verifyeacheslprotocol(esl_scripts, preferredprotocol)
    # temp addition so that js loop still works, remove this later when the js loop is modified
    listofallowedesls = verified_esl_domains + verified_esl_scripts
    nd = args.no_duplicate_prog
    show_dead = args.show_404s
    autoinput_timeout = args.auto_input_time
    try:
        user_exits = True
        target = args.target if args.target else timeout_input(
            prompt="Target website not found.\nEnter website (e.g. https://example.com): ",
            timeout=autoinput_timeout,
            default="TARGET_NOT_INPUTTED",
            auto_input_enabled=(not args.no_auto_input)
        )
        if target == "TARGET_NOT_INPUTTED":
            print(f"Target not input after {autoinput_timeout}s, exiting script.")
            user_exits = False
            sys.exit(1)
    except (KeyboardInterrupt, SystemExit):
        if user_exits:
            print("\nScan cancelled by user.")
        sys.exit(0)
    target = target.strip().rstrip('/')
    #http https
    if not target.startswith(("http://", "https://")):
        if args.local:
            target = "http://" + target 
        else:
            target = "https://" + target
    impersonate_settings = None if (check_if_local(target) or args.local) else "chrome120" #chrome120 will not work on localhosts.
    target = testhttpprotocol(target, HEADER, impersonate_settings, args)

    if not args.pipeable: print(f"\nScanning {target}...")
    # Define useless stuff
    USELESSSTUFF = {"localhost", "127.0.0.1", "0.0.0.0", "/../"}
    if args.filter_out_more:
        USELESSSTUFF.update({
            "www.w3.org", "schema.org", "xml.org", 
            "schemas.microsoft.com", "schemas.openxmlformats.org"
        })
        
    if impersonate_settings == None: #if the target is a localhost
        USELESSSTUFF.discard("localhost")
        USELESSSTUFF.discard("127.0.0.1")
    #server uptime
    serveruptime = checkserveruptime(target, HEADER, impersonate_settings, args)
    start_test_time = time.perf_counter()
    #hardcoded dangerous endpoints to test, disabled by -dse
    if not args.disable_sensitive_endpoint:
        SENSITIVE_ENDPOINT = {
            "/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.dev",
            "/.git/config", "/.git/HEAD", "/package.json", "/package-lock.json", "/.npmrc", "/.dockerenv",
            "/.gitignore", "/api/health", "/config", "/.env.example", "/docker-compose.yml", "/.babelrc", 
            "/.eslintrc.json", "/config.json", "/.aws/credentials", "/.git/index",
            "/etc/passwd", "/.DS_Store", "/.git/logs/HEAD", "/dump.sql", "/database.sqlite", "/db.sql", "/backup.sql",
            "/actuator/env", "/actuator/heapdump", "/openapi.json", "/etc/shadow", "/.htaccess", "/.htpasswd", "/.hta",
            "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.bash_history", "/.ssh/authorized_keys", "/swagger-ui.html", "/api/docs",
            "/swagger.json", "/swagger-ui/", "/health", "/docs", "/docs/oauth2-redirect", "/id_rsa", "/.ssh", "/.svn",
            "/.subversion", "/.svn/entries", "/_next/static/development/_devPagesManifest.json", "/Dockerfile",
            "/.next/required-server-files.json", "/.nuxt", "/vite.config.js", "/.vercel/project.json", "/.kube/config",
            "/.gitlab-ci.yml", "/.github/workflows/main.yml", "/graphql", "/api/graphql", "/_graphql", "/.git", "/.git/packed-refs"
        }
    else:
        SENSITIVE_ENDPOINT = {}

    results_200, results_dead, results_30x = [], [], []
    results_services, results_ext, results_subd = [], [], []
    results_frameworks, results_assets, results_protected = [], [], []
    invalidated_endpoints = []
    emscripten_vfs_detected = False
    #actually test these in 7.5.1/7.6
    found_paths = set(SENSITIVE_ENDPOINT) if SENSITIVE_ENDPOINT else set()
    discovered_in_js = {}
    scanned_xmls = set()
    scanned_js = set()
    scanned_html = set()

    if not args.only_ratelimit_test:
        e_files, xml_files, xml_depths = scrape_structure_files(args, target, HEADER, impersonate_settings, found_paths, unique_progress_paths, nd, USELESSSTUFF)
        main_html = ""
        base_res = requests.get(
            target, 
            headers=HEADER, 
            impersonate=impersonate_settings, 
            timeout=10
        )
        fake_path = f"/very-fake-page-123456123456abcdefg_{secrets.token_hex(16)}"
        if not args.pipeable:
            if args.no_headless:
                print("\nStarting browser to bypass captchas and detect shells with a fake path.")
                if not args.only_res:
                    print(f"Fake path used: {fake_path}\n")
            elif args.no_headless_browser:
                print(f"\nDetecting shells with a fake path.")
                if not args.only_res:
                    print(f"Fake path used: {fake_path}\n")
            else:
                print(f"\nStarting headless browser to bypass captchas and detect shells with a fake path.")
                if not args.only_res:
                    print(f"Fake path used: {fake_path}\n")
        try:
            user_exits = True
            main_html, session_cookies, scan_status = gethtmlafterload(
                                                                    args,
                                                                    target, 
                                                                    args.no_headless,
                                                                    initial_response=base_res
                                                                    )
            if scan_status["blocked"]:
                if not args.no_detect_captcha:
                    print("Exiting script as captcha was detected.")
                    print("It is recommended to use the -nh flag to see what is happening in the headless browser to see if it is actually blocked by a captcha and if it was a false positive.")
                    print("If this was a false positive, use the -ndc (--no-detect-captcha) flag to disable exiting.")
                    user_exits = False; sys.exit(1)
                else:
                    print("Script will not be exited, as --no-detect-captcha flag was passed. Script will continue.")
        except (KeyboardInterrupt, SystemExit):
            if user_exits:
                print("Scan stopped by user.")
            sys.exit(0)
        except Exception as e:
            if "TargetClosedError" in type(e).__name__:
                print("Scan cancelled by user.") #for web version
                sys.exit(0)
            print(f"Error starting up headless browser. Using base request to scan {target}")
            main_html = base_res.text
        cprs = args.path_sub #custom path normalization replacement string
        #identify js stacks.
        js_stack = []
        identify_javascript_type(html=main_html, headers=None, current_stack=js_stack)
        fake_url = urljoin(target, fake_path)
        try:
            fake_res = requests.get(fake_url, cookies=session_cookies, headers=HEADER, impersonate=impersonate_settings, timeout=10)
            shell_content = fake_res.text
        except:
            shell_content = ""
        if not args.pipeable:
            if args.no_headless_browser:
                print("Fake path test finished.\n")
            else:
                print("\nHeadless browser & fake path test finished.\n")
            print("Scraping files...")
        try:
            patterns = [
                            r'["\'`](/[a-zA-Z0-9_\-\./{}:~%]*?)["\'`]', 
                            r'(?<![a-zA-Z0-9_\-])(?:path|href|to|post|get|patch|put|delete|head|options|query)[\s]*[:=\(\|]+[\s]*["\'`](/?[a-zA-Z0-9_\-\./{}:\$~%<>]*[\./][a-zA-Z0-9_\-\./{}:\$~%<>]*?)["\'`]',
                            r'["\'`](https?://[a-zA-Z0-9_\-\./{}:\$~%]+)["\'`]'
                        ] #shld the first pattern find <> too 
            checktimestatusalready = None
            #scrape files
            js_files = tag_soup_scrape(
                        args, main_html, target, found_paths, scanned_html, 
                        verified_esl_domains, verified_esl_scripts, unique_progress_paths, nd
                    )
            #Scrape HTML
            start_test_time, checktimestatusalready = initial_html_scrape(
                                args, target, main_html, scanned_html, HEADER, session_cookies, impersonate_settings, 
                                patterns, JSPDF_SIGNATURE_KEYS, cprs, ignored_extensions, USELESSSTUFF, 
                                found_paths, discovered_in_js, unique_progress_paths, nd, 
                                start_test_time, checktimestatusalready, autoinput_timeout
                            )
            #scrape js
            emscripten_vfs_detected, start_test_time, checktimestatusalready = recursive_js_crawler(
                                        args, target, HEADER, session_cookies, impersonate_settings,
                                        verified_esl_domains, verified_esl_scripts, patterns,
                                        JSPDF_SIGNATURE_KEYS, PYODIDE_VFS_PRECISION_PATTERNS,
                                        cprs, ignored_extensions, USELESSSTUFF, nd,
                                        found_paths, js_files, scanned_js, discovered_in_js, unique_progress_paths, js_stack,
                                        start_test_time, checktimestatusalready, autoinput_timeout
                                    )
            #scrape xml
            start_test_time, checktimestatusalready = recursive_xml_crawler(
                args, target, HEADER, session_cookies, impersonate_settings,
                verified_esl_domains, verified_esl_scripts, USELESSSTUFF, nd,
                found_paths, xml_files, xml_depths, unique_progress_paths,
                start_test_time, checktimestatusalready, autoinput_timeout
            )

            if not args.only_res:
                print(f"\nDetected JS Stack: {' + '.join(js_stack) if js_stack else 'Unknown JS Stack'}\n")
            if emscripten_vfs_detected:
                found_paths = list({
                        i.strip() for i in found_paths 
                        if i.strip() not in ["/dev", "/dev/"] and not i.strip().startswith('/tmp/')
                    })
            else:
                found_paths = list({path.strip() for path in found_paths if path.strip()})
            unsorted = []
            
            assets_suffix = "" if args.show_assets else " (Hidden, use --show-media or -m to show)"
            dead_suffix = "" if args.show_404s else " (Hidden, use --show-404s or -s to show)"
            invalidated_suffix = "" if args.still_show_invalid else " (Hidden, use --still-show-invalid or -ssi to show)"
            if not args.raw_output:
                if not args.pipeable:
                    print(f"Total paths to test: {len(found_paths)} (Scraped: {len(found_paths) - len(SENSITIVE_ENDPOINT)} | Built-in: {len(SENSITIVE_ENDPOINT)})")
                    print("Testing paths...")
                
                if len(found_paths) >= 2000:
                    # use server uptime to estimate every request
                    raw_seconds = float(serveruptime) * len(found_paths)
                    
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
                    if len(found_paths) >= 5000:
                        exaggerate = "REALLY "
                    if len(found_paths) >= 8000:
                        exaggerate = "REALLY REALLY "
                    if len(found_paths) >= 15000:
                        exaggerate = "REALLY REALLY REALLY "
                        
                    print(f"\n[WARNING] Number of directories/paths found is {exaggerate}large.")
                    print(f"Estimated sorting time: {esttime}")
                    
                    try:
                        userawoutput = timeout_input(
                            prompt="Would you like to use the raw output instead? (No sorting at all) [y/n]: ", 
                            timeout=autoinput_timeout,
                            default='y',
                            auto_input_enabled=(not args.no_auto_input)
                        )
                        userawoutput = userawoutput.strip()
                        if userawoutput.lower() in ['y', 'yes']:
                            print("Paths will not be sorted.")
                            args.raw_output = True
                        else:
                            print("Paths will still be sorted.")
                            args.raw_output = False
                    except (KeyboardInterrupt, SystemExit):
                        print("\nScan cancelled by user.")
                        return
            else:
                if not args.pipeable: print(f"\nTotal paths found: {len(found_paths)}")

            invalidated_count = 0        
            S_HEADER = HEADER.copy()
            S_HEADER["Cache-Control"] = "no-cache"
            S_HEADER["Pragma"] = "no-cache"
            S_HEADER["If-None-Match"] = ""
            S_HEADER["If-Modified-Since"] = ""
            #illegal characters to be inside a url to remove false positives.
            backslash = chr(92) #because \ escapes quotes, because of stuff like \n \t.
            disallowed_url_chars = {
                '"', '<', '>', backslash, '^', '`', '{', '|', '}', '[', ']', "'"
            }

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

            #printing when its a set is faster
            found_paths_set = set(found_paths)
            #return extra paths

            #filter external links
            results_ext = list({el for el in results_ext if len(el) >= 4})
            all_scanned_sources = list(e_files) + list(scanned_html) + list(scanned_xmls) + list(scanned_js)

            display_and_save_results(
                args, show_dead, target,
                results_200, results_services, results_ext, results_subd,
                results_frameworks, results_30x, results_protected,
                results_assets, results_dead, unsorted,
                assets_suffix, dead_suffix, invalidated_suffix,
                all_scanned_sources,
                unsorted_paths, invalidated_count,
                invalidated_endpoints, SENSITIVE_ENDPOINT
            )

            if args.ratelimit is not None:
                num = args.ratelimit
                test_path = "/"
                if args.testpath:
                    test_path = args.testpath if args.testpath.startswith('/') else '/' + args.testpath
                    try:
                        check_res = requests.get(urljoin(target, test_path), headers=HEADER, timeout=5, impersonate=impersonate_settings)
                        if check_res.status_code in [301, 302, 307, 308, 403, 404]:
                            print(f"\n{test_path} receives status {check_res.status_code} on the first request. Testing on root domain.")
                            test_path = "/"
                    except:
                        test_path = "/"
                if not args.pipeable: print(f"\nPath to test rate-limiting: {test_path}")

                asyncio.run(async_rate_test(
                    url=urljoin(target, test_path), 
                    num_reqs=num,
                    method=args.ratelimit_type,
                    rb=args.ratelimit_body,
                    rv=args.ratelimit_var,
                    cookies=session_cookies,
                    rh=args.ratelimit_header,
                    awaittime = args.ratelimit_await_time
                ))
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            sys.exit(0)
        except Exception as e:
            print(f"Main Error: {e}")
    else:
        try:
            if args.ratelimit is not None:
                num = args.ratelimit
                test_path = "/"
                if args.testpath:
                    test_path = args.testpath if args.testpath.startswith('/') else '/' + args.testpath
                    try:
                        check_res = requests.get(urljoin(target, test_path), headers=HEADER, timeout=5, impersonate=impersonate_settings)
                        if check_res.status_code in [301, 302, 307, 308, 403, 404]:
                            print(f"\n{test_path} receives status {check_res.status_code} on the first request. Testing on root domain.")
                            test_path = "/"
                    except:
                        test_path = "/"
                if not args.pipeable: print(f"\nPath to test rate-limiting: {test_path}")
                asyncio.run(async_rate_test(
                    url=urljoin(target, test_path), 
                    num_reqs=num,
                    method=args.ratelimit_type,
                    rb=args.ratelimit_body,
                    rv=args.ratelimit_var,
                    rh=args.ratelimit_header,
                    awaittime = args.ratelimit_await_time
                ))
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            sys.exit(0)
        except Exception as e:
            print(f"Main Error: {e}")
if __name__ == "__main__":
    main()
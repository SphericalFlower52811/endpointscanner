'''
Main python file used. When running the command, this is the file that runs.
'''

#module imports
import asyncio
from curl_cffi import requests
import sys #used for sys.exit
from urllib.parse import urljoin, urlparse
import time
import secrets
#imports from other files
from .browser import gethtmlafterload
from .ratelimittester import async_rate_test
from .identifyjs import identify_javascript_type
from .miscfuncs import check_if_local, startcodeargs, testhttpprotocol, checkserveruptime, verifyeacheslprotocol, timeout_input
from .outputendpointsfound import display_and_save_results
from .headerconfig import HEADER
from .mapfiles import scrape_structure_files
from .scrapefiles import tag_soup_scrape, initial_html_scrape, recursive_script_crawler, recursive_xml_crawler
from .filtersort import sort_endpoints

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
    target = target.lower()
    target = target.strip().rstrip('/')
    #http https
    if not target.startswith(("http://", "https://")):
        if args.local:
            target = "http://" + target 
        else:
            target = "https://" + target
    impersonate_settings = None if (check_if_local(target) or args.local) else "chrome120" #chrome120 will not work on localhosts.
    target = testhttpprotocol(target, HEADER, impersonate_settings, args)

    if not args.only_ratelimit_test:
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
        #remove openapi.json this upd
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
            SENSITIVE_ENDPOINT = set()

        results_200, results_dead, results_30x = [], [], []
        results_services, results_ext, results_subd = [], [], []
        results_frameworks, results_assets, results_protected = [], [], []
        invalidated_endpoints = []
        emscripten_vfs_detected = False
        #actually test these in 7.6, below the fake page thing.
        found_paths = set(SENSITIVE_ENDPOINT) if SENSITIVE_ENDPOINT else set()
        discovered_in_js = {}
        scanned_xmls = set()
        scanned_js = set()
        scanned_html = set()

        main_html = ""
        base_res = requests.get(
            target, 
            headers=HEADER, 
            impersonate=impersonate_settings, 
            timeout=10
        )
        home_content = base_res.text
        fake_path = f"/very-fake-page-123456123456abcdefg_{secrets.token_hex(16)}"
        if not args.only_res:
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
        except (KeyboardInterrupt, SystemExit):
            if user_exits:
                print("Scan stopped by user.")
            sys.exit(0)
        except Exception as e:
            if "TargetClosedError" in type(e).__name__:
                print("Scan cancelled by user.") #for web version if i make it
                sys.exit(0)
            if not args.pipeable: print(f"Error starting up headless browser. Using base request to scan {target}")
            main_html = home_content
        cprs = args.path_sub #custom path normalization replacement string
        #identify js stacks.
        js_stack = []
        identify_javascript_type(html=main_html, headers=None, current_stack=js_stack)
        fake_url = urljoin(target, fake_path)
        shell_content = ""
        try:
            fake_res = requests.get(fake_url, cookies=session_cookies, headers=HEADER, impersonate=impersonate_settings, timeout=10)
            shell_content = fake_res.text
        except:
            shell_content = ""
        if not args.only_res:
            if args.no_headless_browser:
                print("Fake path test finished.")
            else:
                print("Headless browser & fake path test finished.")
        e_files, xml_files, xml_depths = scrape_structure_files(args, target, HEADER, impersonate_settings, found_paths, unique_progress_paths, nd, USELESSSTUFF, shell_content, home_content)
        if not args.pipeable: print("\nScraping files...")
        try:
            patterns = [
                r'["\'`](/[a-zA-Z0-9_\-\./{}:~%\?#=]*?)["\'`]', 
                r'(?<![a-zA-Z0-9_\-])(?:path|href|to|post|get|patch|put|delete|head|options|query)[\s]*[:=\(\|]+[\s]*["\'`](/?[a-zA-Z0-9_\-\./{}:\$~%<>\?#=]*[\./][a-zA-Z0-9_\-\./{}:\$~%<>\?#=]*?)["\'`]',
                r'["\'`](https?://[a-zA-Z0-9_\-\./{}:\$~%\?#=;&+@]+)["\'`]',
                r'url\([\'"`]?(/[a-zA-Z0-9_\-\./{}:\$~%<>\?#=]+)[\'"`]?\)' 
            ]

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
            emscripten_vfs_detected, start_test_time, checktimestatusalready = recursive_script_crawler(
                                        args, target, HEADER, session_cookies, impersonate_settings,
                                        verified_esl_domains, verified_esl_scripts, patterns,
                                        JSPDF_SIGNATURE_KEYS, PYODIDE_VFS_PRECISION_PATTERNS,
                                        cprs, ignored_extensions, USELESSSTUFF, nd,
                                        found_paths, js_files, scanned_js, discovered_in_js, unique_progress_paths, js_stack,
                                        start_test_time, checktimestatusalready, autoinput_timeout
                                    )
            #check map files
            if not args.disable_sensitive_endpoint:
                for js_path in js_files:
                    clean_js_path = urlparse(js_path).path
                    if not clean_js_path.startswith('/'):
                        clean_js_path = '/' + clean_js_path
                    SENSITIVE_ENDPOINT.add(f"{clean_js_path}.map")

            #scrape xml
            start_test_time, checktimestatusalready = recursive_xml_crawler(
                args, target, HEADER, session_cookies, impersonate_settings,
                verified_esl_domains, verified_esl_scripts, USELESSSTUFF, nd,
                found_paths, xml_files, xml_depths, unique_progress_paths,
                start_test_time, checktimestatusalready, autoinput_timeout
            )

            if not args.only_res:
                print(f"\nDetected JS Stack: {' + '.join(js_stack) if js_stack else 'Unknown JS Stack'}")
            found_paths = [f"{target}{p}" if p.startswith("/") else p for p in found_paths]
            # remove # because website.com/path#... is just /path but diff locations, it's the exact same page.
            found_paths = [path.split('#')[0] if '#' in path else path for path in found_paths]
            if emscripten_vfs_detected:
                found_paths = list({
                        i.strip() for i in found_paths 
                        if (urlparse(i).path if "://" in i else i).strip() not in ["/dev", "/dev/"] 
                        and not (urlparse(i).path if "://" in i else i).strip().startswith('/tmp/')
                        and not i.rstrip('/') == target
                    })
            else:
                found_paths = list({path.strip() for path in found_paths if path.strip() and not path.rstrip('/') == target})
            unsorted = []
            
            assets_suffix = "" if args.show_assets else " (Hidden, use --show-media or -m to show)"
            dead_suffix = "" if args.show_404s else " (Hidden, use --show-404s or -s to show)"
            invalidated_suffix = "" if args.still_show_invalid else " (Hidden, use --still-show-invalid or -ssi to show)"
            if not args.raw_output:
                if not args.pipeable:
                    print(f"\nTotal paths to test: {len(found_paths)} (Scraped: {len(found_paths) - len(SENSITIVE_ENDPOINT)} | Built-in: {len(SENSITIVE_ENDPOINT)})")
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
                        sys.exit(0)
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

            start_test_time, checktimestatusalready, invalidated_count = sort_endpoints(
                args, target, S_HEADER, session_cookies, impersonate_settings, shell_content,
                disallowed_url_chars, autoinput_timeout, found_paths, discovered_in_js,
                start_test_time, checktimestatusalready,
                results_ext, results_subd, results_200, results_services, results_assets,
                results_frameworks, results_30x, results_protected, results_dead, unsorted, unsorted_paths,
                invalidated_endpoints, invalidated_count
            )

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
                invalidated_endpoints
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
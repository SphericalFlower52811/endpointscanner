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
#imports from other files
from .browser import gethtmlafterload
from .ratelimittester import async_rate_test
from .identifyjs import identify_javascript_type, identify_javascript_type_two
from .miscfuncs import checktime, check_if_local, startcodeargs, testhttpprotocol, checkserveruptime, verifyeacheslprotocol, timeout_input
from .outputendpointsfound import display_and_save_results
from .headerconfig import HEADER

USELESSSTUFF = {
        "localhost", "127.0.0.1", "0.0.0.0", 
        "w3.org", "schema.org", "xml.org", "://microsoft.com", "/../",
        "schemas.microsoft.com", "schemas.openxmlformats.org"
    }
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

def main():
    unsorted_paths = []
    e_files = []
    unique_progress_paths = set()
    start_test_time = None
    #define args
    args = startcodeargs()
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
                    except Exception as e:
                        print(f"Error opening file: {e}")
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
    try:
        target = args.target if args.target else timeout_input(
            prompt="Target website not found.\nEnter website (e.g. https://example.com): ",
            timeout=90,
            default="RAISE_INTERRUPT",
            auto_input_enabled=(not args.no_auto_input)
        )
    except KeyboardInterrupt:
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

    #server uptime
    serveruptime = checkserveruptime(target, HEADER, impersonate_settings, args)
    start_test_time = time.perf_counter()
    #hardcoded dangerous endpoints to test, disabled by -dse
    if not args.disable_sensitive_endpoint:
        SENSITIVE_ENDPOINT = {
            "/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.dev",
            "/.git/config", "/.git/HEAD", "/package.json", "/package-lock.json", "/.npmrc", "/.dockerenv",
            "/.gitignore", "/api/health", "/config", "/.env.example", "/docker-compose.yml", "/.babelrc", 
            "/.eslintrc.json", "/wp-config.php", "/config.json", "/.aws/credentials", "/.git/index",
            "/etc/passwd", "/.DS_Store", "/.git/logs/HEAD", "/dump.sql", "/database.sqlite", "/db.sql", "/backup.sql",
            "/actuator/env", "/actuator/heapdump", "/openapi.json", "/etc/shadow", "/.htaccess", "/.htpasswd", "/.hta",
            "/.ssh/id_rsa", "/.ssh/id_ed25519", "/.bash_history", "/.ssh/authorized_keys", "/swagger-ui.html",
            "/swagger.json", "/swagger-ui/"
        }
    else:
        SENSITIVE_ENDPOINT = {}
    
    results_200, results_dead, results_30x = [], [], []
    results_services, results_ext, results_subd = [], [], []
    results_frameworks, results_assets, results_protected = [], [], []
    xml_files, invalidated_endpoints = [], []
    emscripten_vfs_detected = False
    found_paths = set(SENSITIVE_ENDPOINT) if SENSITIVE_ENDPOINT else set()
    discovered_in_js = {}
    scanned_xmls = set()
    scanned_js = set()

    if not args.disable_extra_files:
        if not args.only_res:
            print("\nFinding paths from extra files. (If they exist)")
        # no 304.
        E_HEADER = HEADER.copy()
        E_HEADER["Cache-Control"] = "no-cache"
        E_HEADER["Pragma"] = "no-cache"
        E_HEADER["If-None-Match"] = ""
        E_HEADER["If-Modified-Since"] = ""
        
        # robotstxt
        try:
            r_res = requests.get(urljoin(target, "/robots.txt"), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
            if r_res.status_code == 200:
                is_legit_robots = any(sig in r_res.text.lower() for sig in ["user-agent:", "disallow:", "allow:", "sitemap:", "llms.txt:"])
                
                if is_legit_robots:
                    if 'xml_depths' not in locals() and 'xml_depths' not in globals():
                        xml_depths = {}
                        
                    if '/robots.txt' not in e_files:
                        e_files.append('/robots.txt')
                        
                    if args.depth is not None and args.depth == 0:
                        pass
                    else:
                        for line in r_res.text.splitlines():
                            _local_robots_line = line.strip()
                            if not _local_robots_line or _local_robots_line.startswith("#"):
                                continue
                                
                            if ":" in _local_robots_line:
                                _local_parts = _local_robots_line.split(":", 1)
                                _local_directive = _local_parts[0].strip().lower()
                                _local_payload = _local_parts[1].strip()
                                
                                if _local_directive in ["disallow", "allow", "llms.txt"]:
                                    if _local_payload and _local_payload not in ["/", "/*", "*"]:
                                        
                                        if "://" in _local_payload:
                                            clean_payload = _local_payload
                                        else:
                                            clean_payload = _local_payload
                                            if not clean_payload.startswith('/'):
                                                clean_payload = '/' + clean_payload
                                                
                                        if '*' in clean_payload and not args.only_original:
                                            original_trace = clean_payload
                                            clean_payload = clean_payload.replace('*', '1')
                                            m_display = f"{clean_payload} [Original: {original_trace}]"
                                        else:
                                            m_display = clean_payload
                                                
                                        if clean_payload not in found_paths:
                                            found_paths.add(clean_payload)
                                            
                                            if args.show_prog and (not nd or clean_payload not in unique_progress_paths):
                                                print(f"New path/file: {m_display}  [Source File: robots.txt]")
                                                unique_progress_paths.add(clean_payload)
                                                
                                elif _local_directive == "sitemap":
                                    if _local_payload:
                                        if _local_payload not in found_paths:
                                            found_paths.add(_local_payload)
                                            
                                            if args.show_prog and (not nd or _local_payload not in unique_progress_paths):
                                                print(f"New path/file: {_local_payload}  [Source File: robots.txt]")
                                                unique_progress_paths.add(_local_payload)
                                        _local_smap_path = urlparse(_local_payload).path
                                        if _local_smap_path and _local_smap_path.lower().endswith(('.xml', '.txt', '.gz', '.rss', '.atom', '.zip')):
                                            if _local_smap_path not in xml_files:
                                                xml_files.append(_local_smap_path)
                                                xml_depths[_local_smap_path] = 1
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            sys.exit(0)
        except: 
            pass

        xml_depths = {}
        # sitemap
        try:
            s_res = requests.get(urljoin(target, "/sitemap.xml"), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
            if s_res.status_code == 200 and "<loc" in s_res.text.lower():
                e_files.append('/sitemap.xml')
                
                if '/sitemap.xml' not in found_paths:
                    found_paths.add('/sitemap.xml')
                xml_depths['/sitemap.xml'] = 1
                
                if args.show_prog and (not nd or '/sitemap.xml' not in unique_progress_paths):
                    if args.show_source:
                        print("New path/file: /sitemap.xml")
                    else:
                        print("New path/file: /sitemap.xml")
                    unique_progress_paths.add('/sitemap.xml')

                if args.depth is None or args.depth > 0:
                    raw_locs = re.findall(r'<loc>\s*([^<]+)\s*</loc>', s_res.text, re.IGNORECASE | re.DOTALL)
                    xhtml_locs = re.findall(r'<xhtml:link[^>]*href=["\']([^"\']+)["\']', s_res.text, re.IGNORECASE)

                    all_sitemap_locs = raw_locs + xhtml_locs
                    for loc in all_sitemap_locs:
                        loc_stripped = loc.strip()
                        if not loc_stripped:
                            continue
                        if "http://" in loc_stripped.lower() or "https://" in loc_stripped.lower():
                            loc_netloc = urlparse(loc_stripped).netloc.lower()
                            if loc_netloc != urlparse(target if "://" in target else f"https://{target}").netloc.lower():
                                clean_path = loc_stripped
                            else:
                                clean_path = urlparse(loc_stripped).path
                        else:
                            clean_path = '/' + loc_stripped.lstrip('/')
                            
                        if not clean_path.startswith('/') and "://" not in clean_path:
                            clean_path = '/' + clean_path
                        
                        if clean_path and clean_path != "/":
                            if clean_path in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                                continue
                            if any(term in clean_path.lower() for term in USELESSSTUFF):
                                continue
                                
                            SITEMAP_EXTENSIONS = ('.xml', '.txt', '.rss', '.atom', '.gz', '.zip', '.xml.gz', '.txt.gz', '.xml.zip', '.txt.zip')
                            if clean_path.lower().endswith(SITEMAP_EXTENSIONS):
                                if clean_path not in xml_files:
                                    xml_files.append(clean_path)
                                    xml_depths[clean_path] = 2
                                    
                                if clean_path not in found_paths:
                                    found_paths.add(clean_path)
                                    
                                    if args.show_prog and (not nd or clean_path not in unique_progress_paths):
                                        if args.show_source:
                                            print(f"New path/file: {clean_path}  [Source File: sitemap.xml]")
                                        else:
                                            print(f"New path/file: {clean_path}")
                                        unique_progress_paths.add(clean_path)
                                continue
                                
                            if clean_path not in found_paths:
                                found_paths.add(clean_path)
                                
                                if args.show_prog and (not nd or clean_path not in unique_progress_paths):
                                    if args.show_source:
                                        print(f"New path/file: {clean_path}  [Source File: sitemap.xml]")
                                    else:
                                        print(f"New path/file: {clean_path}")
                                    unique_progress_paths.add(clean_path)
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            sys.exit(0)
        except: 
            pass

        #manifests i finally put in one loop
        for manifest_path in ["/asset-manifest.json", "/web-manifest.json", "/manifest.json"]:
            try:
                m_url = urljoin(target, manifest_path)
                m_res = requests.get(m_url, headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
                if m_res.status_code == 200 and "{" in m_res.text:
                    e_files.append(manifest_path)
                    found_paths.append(manifest_path)
                    
                    if args.depth is None or args.depth > 0:
                        try:
                            m_data = json.loads(m_res.text)
                            
                            def extract_json_strings(node):
                                strings = []
                                if isinstance(node, dict):
                                    for v in node.values(): strings.extend(extract_json_strings(v))
                                elif isinstance(node, list):
                                    for item in node: strings.extend(extract_json_strings(item))
                                elif isinstance(node, str):
                                    node_strip = node.strip()
                                    
                                    is_valid_route = False
                                    if node_strip.startswith(('http://', 'https://', '/')):
                                        is_valid_route = True
                                    elif '.' in node_strip and '/' in node_strip:
                                        is_valid_route = True
                                        
                                    if is_valid_route:
                                        strings.append(node_strip)
                                return strings
                                
                            raw_values = extract_json_strings(m_data)
                        except Exception:
                            raw_values = re.findall(r'["\'`](https?://[^"\']+|//[^"\']+|\/[^"\']+)["\'`]', m_res.text)

                        for raw_val in raw_values:
                            token_clean = raw_val.strip()
                            
                            if token_clean.startswith('//'):
                                token_clean = f"https:{token_clean}"
                                
                            if "://" in token_clean:
                                clean_manifest_path = token_clean
                            else:
                                clean_manifest_path = token_clean
                                if not clean_manifest_path.startswith('/'):
                                    clean_manifest_path = '/' + clean_manifest_path

                            if not clean_manifest_path or clean_manifest_path in ["/", "//", "///"]:
                                continue

                            if clean_manifest_path not in found_paths:
                                found_paths.add(clean_manifest_path)
                                
                                if args.show_prog and (not nd or clean_manifest_path not in unique_progress_paths):
                                    if args.show_source:
                                        print(f"New path/file: {clean_manifest_path}  [Source File: {manifest_path.lstrip('/')}'")
                                    else:
                                        print(f"New path/file: {clean_manifest_path}")
                                    unique_progress_paths.add(clean_manifest_path)
            except (KeyboardInterrupt, SystemExit):
                print("Scan cancelled by user.")
                sys.exit(0)
            except: pass


        # service worker 
        for sw_path in ["/service-worker.js", "/sw.js"]:
            try:
                sw_res = requests.get(urljoin(target, sw_path), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
                swct = sw_res.headers.get('Content-Type', '').lower()
                
                is_legit_sw = sw_res.status_code == 200 and ('javascript' in swct or 'ecmascript' in swct) and 'html' not in swct
                
                if is_legit_sw:
                    e_files.append(sw_path)
                    found_paths.append(sw_path)
                    
                    if args.depth is None or args.depth > 0:
                        paths = re.findall(r'["\'`](https?://[^"\']+|//[^"\']+|\/[^"\']+)["\'`]', sw_res.text)
                        
                        for path in paths:
                            token_clean = path.strip()
                            
                            if token_clean.startswith('//'):
                                token_clean = f"https:{token_clean}"
                                
                            if "://" in token_clean:
                                cleanpath = token_clean
                            else:
                                cleanpath = token_clean
                                if not cleanpath.startswith('/'):
                                    cleanpath = '/' + cleanpath

                            if not cleanpath or cleanpath in ["/", "//", "///"]:
                                continue
                            if cleanpath not in found_paths:
                                found_paths.add(cleanpath)
                                
                                if args.show_prog and (not nd or cleanpath not in unique_progress_paths):
                                    if args.show_source:
                                        print(f"New path/file: {cleanpath}  [Source File: {sw_path.lstrip('/')}]")
                                    else:
                                        print(f"New path/file: {cleanpath}")
                                    unique_progress_paths.add(cleanpath)
            except (KeyboardInterrupt, SystemExit):
                print("Scan cancelled by user.")
                sys.exit(0)
            except: pass

        # openid
        try:
            oidc_res = requests.get(urljoin(target, "/.well-known/openid-configuration"), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
            if oidc_res.status_code == 200 and "authorization_endpoint" in oidc_res.text and "issuer" in oidc_res.text:
                e_files.append("/.well-known/openid-configuration")
                found_paths.append("/.well-known/openid-configuration")
                if args.depth is None or args.depth > 0:
                    try:
                        # json format for openidconfig
                        data = json.loads(oidc_res.text)
                        extracted_urls = []
                        for val in data.values():
                            if isinstance(val, str):
                                val_strip = val.strip()
                                # both url and /
                                if val_strip.startswith(('http://', 'https://', '/')):
                                    extracted_urls.append(val_strip)
                    except:
                        extracted_urls = re.findall(r'["\'`](https?://[^"\']+)["\'`]', oidc_res.text.replace(r'\/', '/'))
                    
                    paths = extracted_urls
                    for path in paths:
                        token_clean = path.strip()
                        
                        if token_clean.startswith('//'):
                            token_clean = f"https:{token_clean}"
                        if "://" in token_clean:
                            clean_oidc_path = token_clean
                        else:
                            clean_oidc_path = token_clean
                            if not clean_oidc_path.startswith('/'):
                                clean_oidc_path = '/' + clean_oidc_path
                                
                        if not clean_oidc_path or clean_oidc_path in ["/", "//", "///"]:
                            continue
                            
                        if clean_oidc_path not in found_paths:
                            found_paths.add(clean_oidc_path)
                            
                            if args.show_prog and (not nd or clean_oidc_path not in unique_progress_paths):
                                if args.show_source:
                                    print(f"New path/file: {clean_oidc_path}  [Source File: openid-configuration]")
                                else:
                                    print(f"New path/file: {clean_oidc_path}")
                                unique_progress_paths.add(clean_oidc_path)
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            sys.exit(0)
        except: pass


    if not args.only_ratelimit_test:
        main_html = ""
        base_res = requests.get(
            target, 
            headers=HEADER, 
            impersonate=impersonate_settings, 
            timeout=10
        )
        import secrets
        fake_path = f"/very-fake-page-123456123456abcdefg_{secrets.token_hex(16)}"
        if not args.only_res:
            if args.no_headless:
                print(f"\nStarting browser to bypass captchas and detect shells with a fake path.\nFake path used: {fake_path}")
            else:
                print(f"\nStarting headless browser to bypass captchas and detect shells with a fake path.\nFake path used: {fake_path}")
        try:
            main_html, session_cookies, scan_status = gethtmlafterload(
                                                                    target, 
                                                                    args.no_headless,
                                                                    initial_response=base_res
                                                                    )
            if scan_status["blocked"]:
                if not args.no_detect_captcha:
                    print("Exiting script as captcha was detected.")
                    print("It is recommended to use the -nh flag to see what is happening in the headless browser to see if it is actually blocked by a captcha and if it was a false positive.")
                    print("If this was a false positive, use the -ndc (--no-detect-captcha) flag to disable exiting.")
                    sys.exit(1)
                else:
                    print("Script will not be exited, as --no-detect-captcha flag was passed. Script will continue.")
        except (KeyboardInterrupt, SystemExit):
            print("Scan stopped by user.")
            sys.exit(0)
        except Exception as e:
            if "TargetClosedError" in type(e).__name__:
                print("Scan cancelled by user.") #for web version
                sys.exit(0)
            print(f"Error starting up headless browser. Using base request to scan {target}")
            main_html = base_res
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
        if not args.only_res:
            print("\nHeadless browser & fake path test finished.")
            print(f"Starting scan on {target}.\n")
        try:
            soup = BeautifulSoup(main_html, 'html.parser')
            esl_domains = [urlparse(url).netloc.lower() for url in listofallowedesls if url]
            target_netloc = urlparse(target).netloc.lower()
            js_files = []


            for s in soup.find_all('script'):
                src = s.get('src')
                if src:
                    src = src.strip()
                    if src.lower().startswith(('data:', 'blob:', 'javascript:')):
                        continue
                    if src.startswith('//'):
                        src = f"https:{src}"
                    full_src_url = urljoin(target, src)
                    src_netloc = urlparse(full_src_url).netloc.lower()
                    if not src_netloc or src_netloc == target_netloc or src_netloc in esl_domains:
                        js_files.append(full_src_url)

            for script_tag in soup.find_all('script'):
                src = script_tag.get('src')
                if src:
                    src_clean = src.strip()
                    
                    if src_clean.lower().startswith(('data:', 'blob:', 'javascript:')):
                        continue
                        
                    if src_clean.startswith('//'):
                        src_clean = f"https:{src_clean}"
                        
                    parsed_src = urlparse(src_clean)
                    src_netloc = parsed_src.netloc.lower()
                    src_path = parsed_src.path.strip()
                    
                    if any(char in src_netloc or char in src_path for char in [';', ':', ' ', ',', '(', ')', '{', '}']):
                        continue
                        
                    if not src_netloc or src_netloc == target_netloc:
                        if src_path and src_path != "/":
                            clean_path = '/' + src_path.lstrip('/')
                            found_paths.add(clean_path)
                    elif src_netloc in esl_domains:
                        if src_path and src_path != "/":
                            clean_path = '/' + src_path.lstrip('/')
                            found_paths.add(clean_path)

            targetthings = ['stylesheet', 'modulepreload', 'preload', 'prefetch', 'icon', 'shortcut icon', 'manifest']
            
            for link_tag in soup.find_all('link', rel=targetthings):
                href = link_tag.get('href')
                if href:
                    href_clean = href.strip()
                    
                    if href_clean.lower().startswith(('data:', 'blob:', 'javascript:')):
                        continue
                        
                    if href_clean.startswith('//'):
                        href_clean = f"https:{href_clean}"
                        
                    parsed_href = urlparse(href_clean)
                    href_netloc = parsed_href.netloc.lower()
                    href_path = parsed_href.path.strip()
                    
                    if any(char in href_netloc or char in href_path for char in [';', ':', ' ', ',', '(', ')', '{', '}']):
                        continue
                        
                    if not href_netloc or href_netloc == target_netloc:
                        if href_path and href_path != "/":
                            clean_path = '/' + href_path.lstrip('/')
                            found_paths.add(clean_path)
                    elif href_netloc in esl_domains:
                        if href_path and href_path != "/":
                            clean_path = '/' + href_path.lstrip('/')
                            found_paths.add(clean_path)


            patterns = [
                r'["\'`](/[a-zA-Z0-9_\-\./{}:~%]*?)["\'`]', 
                r'(?<![a-zA-Z0-9_\-])(?:path|href|to|post|get|patch|put|delete|head|options|query)[\s]*[:=\(\|]+[\s]*["\'`](/?[a-zA-Z0-9_\-\./{}:\$~%]*[\./][a-zA-Z0-9_\-\./{}:\$~%]*?)["\'`]',
                r'["\'`](https?://[a-zA-Z0-9_\-\./{}:\$~%]+)["\'`]'
            ]
            checktimestatusalready = None
            current_filename = "raw HTML"
            #HTML loop
            if main_html:
                respo = main_html
            else:
                try:
                    respo = requests.get(target, headers=HEADER, timeout=5, impersonate=impersonate_settings).text
                except:
                    respo = ""
            for p in patterns:
                try:
                    if args.scan_timeout:
                        ts, checktimestatusalready = checktime(start_test_time, args.scan_timeout, checktimestatusalready, (not args.no_auto_input)) #timer status
                        if ts == "STOP":
                            break
                        elif ts == "EXTEND":
                            start_test_time = time.perf_counter()
                            args.scan_timeout = 5.0 #5min more
                    matches = re.findall(p, respo, re.IGNORECASE | re.DOTALL)
                    detected_library_keys = set(matches).intersection(JSPDF_SIGNATURE_KEYS)
                    if len(detected_library_keys) >= 3:
                        matches = [m for m in matches if m not in JSPDF_SIGNATURE_KEYS]

                    for m in matches:
                        m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9_\-]+|\{[^{}]*\}|<[^<>]*>)', cprs, m)
                        m_clean = m_clean.strip()
                        if m_clean.startswith('//'):
                            m_clean = f"https:{m_clean}"
                        if m_clean != m:
                            m_display = f"{m_clean} [Original: {m}]"
                        else:
                            m_display = m_clean
                        if "://" not in m_clean:
                            if not m_clean.startswith('/'): 
                                m_clean = '/' + m_clean
                                if m_clean != m:
                                    m_display = '/' + m_display
                        clean_m_stripped = m_clean.lstrip('/')
                        if clean_m_stripped in ['http:', 'https:']:
                            continue
                        #previously used clean_stripped, fixed to clean_m_stripped.
                        if clean_m_stripped.lower().startswith(('http://', 'https://')) and len(clean_m_stripped) < 11:
                            continue
                        
                        if not m_clean.lower().endswith(ignored_extensions):
                            if m_clean in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                                continue
                            if any(term in m_clean.lower() for term in USELESSSTUFF):
                                continue
                            found_paths.add(m_clean)
                            if m_clean not in discovered_in_js:
                                discovered_in_js[m_clean] = m_display
                                prog_display = m_display
                                if args.only_original and " [Original: " in m_display:
                                    prog_display = m_display.split(" [Original: ")[1].rstrip(']')
                                elif args.disable_og and " [Original:" in m_display:
                                    prog_display = m_display.split(" [Original:")[0].strip()

                                if args.show_prog:
                                    if not nd or m_clean not in unique_progress_paths:
                                        print(f"Found: {prog_display}")
                                        unique_progress_paths.add(m_clean)
                                        if args.show_source:
                                            print(f"  └─ Source File: {current_filename}")
                except (KeyboardInterrupt, SystemExit):
                    print("Scan cancelled by user.")
                    sys.exit(0)
                except: continue

            # JS loop
            js_depths = {}
            emscripten_vfs_detected = False
            for path in list(found_paths):
                # check for js, html, and htm (htm is a older version that still exists in many sites)
                if path.lower().endswith(('.js', '.html', '.htm', '.mjs', '.cjs')):
                    target_asset_url = urljoin(target, path)
                    asset_netloc = urlparse(target_asset_url).netloc.lower()
                    target_netloc = urlparse(target if "://" in target else f"https://{target}").netloc.lower()
                    
                    is_safe_asset = False
                    if asset_netloc in listofallowedesls:
                        is_safe_asset = True
                    elif asset_netloc == target_netloc:
                        is_safe_asset = True
                    
                    if is_safe_asset and target_asset_url not in js_files:
                        js_files.append(target_asset_url)
                        found_paths.add(target_asset_url)
                        js_depths[target_asset_url] = 1

            # check for pyodide
            for j in js_files:
                if 'pyodide' in j.lower():
                    emscripten_vfs_detected = True
                    break

            # recursive scanning 
            js_idx = 0
            while js_idx < len(js_files):
                js_url = js_files[js_idx]

                current_depth = js_depths.get(js_url, 1)
                
                if args.scan_timeout:
                    ts, checktimestatusalready = checktime(start_test_time, args.scan_timeout, checktimestatusalready, (not args.no_auto_input)) #timer status
                    if ts == "STOP":
                        break
                    elif ts == "EXTEND":
                        start_test_time = time.perf_counter()
                        args.scan_timeout = 5.0 #5min more
                        
                try:
                    DOWNLOAD_HEADERS = HEADER.copy()
                    DOWNLOAD_HEADERS["Cache-Control"] = "no-cache"
                    DOWNLOAD_HEADERS["Pragma"] = "no-cache"
                    DOWNLOAD_HEADERS["If-None-Match"] = ""
                    DOWNLOAD_HEADERS["If-Modified-Since"] = ""

                    js_res = requests.get(js_url, headers=DOWNLOAD_HEADERS, cookies=session_cookies, timeout=5, impersonate=impersonate_settings)
                    
                    if js_res.status_code == 200:
                        current_filename = js_url
                        scanned_js.add(js_url)
                        if 'pyodide' in js_url.lower():
                            emscripten_vfs_detected = True
                        can_crawl_deeper = True
                        if args.depth is not None and current_depth >= args.depth:
                            can_crawl_deeper = False
                            
                        if js_url.lower().endswith(('.html', '.htm')):
                            local_soup = BeautifulSoup(js_res.text, 'html.parser')
                                
                            for tag in local_soup.find_all(['script', 'link']):
                                src_or_href = tag.get('src') or tag.get('href')
                                if src_or_href:
                                    clean_src = src_or_href.strip()
                                    if clean_src.lower().endswith(('.js', '.css', '.html', '.htm', '.mjs', '.cjs')):
                                        nested_asset_url = urljoin(js_url, clean_src)
                                        nested_netloc = urlparse(nested_asset_url).netloc.lower()
                                        
                                        nested_safe = False
                                        if nested_netloc in esl_domains:
                                            nested_safe = True
                                        if nested_netloc == target_netloc:
                                            nested_safe = True
                                            
                                        if nested_safe and nested_asset_url not in js_files:
                                            if can_crawl_deeper:
                                                js_files.append(nested_asset_url)
                                                js_depths[nested_asset_url] = current_depth + 1
                                        
                                        rel_path = urlparse(nested_asset_url).path
                                        found_paths.add(rel_path)
                                        if rel_path not in discovered_in_js:
                                            discovered_in_js[rel_path] = rel_path
                                            if args.show_prog and (not nd or rel_path not in unique_progress_paths):
                                                print(f"Found: {rel_path}")
                                                unique_progress_paths.add(rel_path)
                                                if args.show_source: print(f"  └─ Source File: {current_filename}")
                                
                            for inline_tag in local_soup.find_all('script'):
                                if inline_tag.string:
                                    inline_chunks = re.findall(r'["\'](/?[a-zA-Z0-9_\-\./]*\.js)["\']', inline_tag.string)
                                    for c in inline_chunks:
                                        clean_c = c if c.startswith('/') else '/' + c
                                        nested_inline_url = urljoin(js_url, clean_c)
                                        nested_netloc = urlparse(nested_inline_url).netloc.lower()
                                        safe_nested_netloc = False
                                        if nested_netloc in listofallowedesls:
                                            safe_nested_netloc = True
                                        if nested_netloc == target_netloc:
                                            safe_nested_netloc = True
                                        if safe_nested_netloc and nested_inline_url not in js_files:
                                            js_files.append(nested_inline_url)
                                        found_paths.add(clean_c)
                                        discovered_in_js[clean_c] = clean_c                      
                        #identify js stack (2)
                        else:
                            identify_javascript_type_two(javascript_content=js_res.text, current_stack=js_stack)
                            identify_javascript_type(html="", headers=js_res.headers, current_stack=js_stack)
                            
                            for p in patterns:
                                matches = re.findall(p, js_res.text)
                                detected_library_keys = set(matches).intersection(JSPDF_SIGNATURE_KEYS)
                                if len(detected_library_keys) >= 3:
                                    matches = [m for m in matches if m not in JSPDF_SIGNATURE_KEYS]
                                for m in matches:
                                    m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9_\-]+|\{[^{}]*\}|<[^<>]*>)', cprs, m).strip()
                                    m_display = f"{m_clean} [Original: {m}]" if m_clean != m else m_clean
                                    m_clean = m_clean.strip()
                                    
                                    if m_clean.startswith('//'):
                                        m_clean = f"https:{m_clean}"
                                        
                                    is_external_link = False
                                    if "://" in m_clean:
                                        m_netloc = urlparse(m_clean).netloc.lower()
                                        if m_netloc != target_netloc and m_netloc not in esl_domains and m_netloc not in listofallowedesls:
                                            is_external_link = True
                                            
                                    if not is_external_link and "://" not in m_clean and not m_clean.startswith('/'): 
                                        m_clean = '/' + m_clean
                                        if m_clean != m: 
                                            m_display = '/' + m_display
                                            
                                    clean_m_stripped = m_clean.lstrip('/')
                                    if clean_m_stripped in ['http:', 'https:']:
                                        continue
                                    if clean_m_stripped.lower().startswith(('http://', 'https://')) and len(clean_m_stripped) < 11:
                                        continue
                                            
                                    if not m_clean.lower().endswith(ignored_extensions):
                                        if m_clean.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]: continue
                                        if any(term in m_clean.lower() for term in USELESSSTUFF): continue
                                            
                                        if emscripten_vfs_detected:
                                            is_fake_vfs_path = False
                                            for vfs_pattern in PYODIDE_VFS_PRECISION_PATTERNS:
                                                if re.match(vfs_pattern, m_clean, re.IGNORECASE):
                                                    is_fake_vfs_path = True
                                                    break
                                            if is_fake_vfs_path: continue 
                                        
                                        if not is_external_link and m_clean.lower().endswith(('.js', '.html', '.htm', '.mjs', '.cjs')):
                                            check_nested_url = urljoin(target, m_clean)
                                            nested_netloc = urlparse(check_nested_url).netloc.lower()
                                            
                                            nested_safe = False
                                            if nested_netloc in esl_domains or nested_netloc in listofallowedesls:
                                                nested_safe = True
                                            elif nested_netloc == target_netloc:
                                                nested_safe = True
                                                    
                                            if nested_safe and check_nested_url not in js_files:
                                                if can_crawl_deeper:
                                                    js_files.append(check_nested_url)
                                                    js_depths[check_nested_url] = current_depth + 1
                                        found_paths.add(m_clean)
                                        if m_clean not in discovered_in_js:
                                            discovered_in_js[m_clean] = m_display
                                            prog_display = m_display
                                            if args.only_original and " [Original: " in m_display:
                                                prog_display = m_display.split(" [Original: ")[1].rstrip(']')
                                            elif args.disable_og and " [Original:" in m_display:
                                                prog_display = m_display.split(" [Original:")[0].strip() 
                                            
                                            if args.show_prog:
                                                if not nd or m_clean not in unique_progress_paths:
                                                    print(f"Found: {prog_display}")
                                                    unique_progress_paths.add(m_clean)
                                                    if args.show_source:
                                                        print(f"  └─ Source File: {current_filename}")
                except (KeyboardInterrupt, SystemExit):
                    print("Scan cancelled by user.")
                    sys.exit(0)
                except: 
                    js_idx += 1
                    continue
                    
                js_idx += 1

            # right before recursive xml loop
            if not args.disable_extra_files:
                target_netloc = urlparse(target if "://" in target else f"https://{target}").netloc.lower()
                target_apex = '.'.join(target_netloc.split('.')[-2:]) if len(target_netloc.split('.')) >= 2 else target_netloc
                SITEMAP_EXTENSIONS = ('.xml', '.txt', '.rss', '.atom', '.gz', '.zip')
                
                for f in list(found_paths):
                    if f.lower().endswith(SITEMAP_EXTENSIONS):
                        if "http://" in f.lower() or "https://" in f.lower():
                            clean_f = f
                            f_netloc = urlparse(f).netloc.lower()
                        else:
                            clean_f = '/' + f.lstrip('/')
                            f_netloc = target_netloc
                            
                        is_valid_map_domain = False
                        if f_netloc == target_netloc or f_netloc in esl_domains or f_netloc in listofallowedesls:
                            is_valid_map_domain = True
                        elif f_netloc.endswith('.' + target_apex):
                            is_valid_map_domain = True
                            
                        if is_valid_map_domain:
                            if "://" in clean_f and urlparse(clean_f).netloc.lower() != target_netloc:
                                store_f = clean_f
                            else:
                                store_f = urlparse(clean_f).path if "://" in clean_f else clean_f
                                store_f = '/' + store_f.lstrip('/')
                            
                            if store_f not in xml_files:
                                xml_files.append(store_f)
                                if store_f not in xml_depths:
                                    xml_depths[store_f] = 1

                # recursive xml loop
                xml_index = 0
                while xml_index < len(xml_files):
                    xmlfile = xml_files[xml_index]
                    current_xml_depth = xml_depths.get(xmlfile, 1)

                    x_res = None

                    if args.depth is not None and current_xml_depth > args.depth:
                        xml_index += 1
                        continue
                    
                    if args.scan_timeout:
                        ts, checktimestatusalready = checktime(start_test_time, args.scan_timeout, checktimestatusalready, (not args.no_auto_input))
                        if ts == "STOP":
                            break
                        elif ts == "EXTEND":
                            start_test_time = time.perf_counter()
                            args.scan_timeout = 5.0
                    try:
                        DOWNLOAD_XML_HEADERS = HEADER.copy()
                        DOWNLOAD_XML_HEADERS["Cache-Control"] = "no-cache"
                        DOWNLOAD_XML_HEADERS["Pragma"] = "no-cache"
                        
                        target_xml_url = xmlfile if "://" in xmlfile else urljoin(target, xmlfile)
                        x_res = requests.get(target_xml_url, headers=DOWNLOAD_XML_HEADERS, impersonate=impersonate_settings, timeout=4)


                        if x_res.status_code == 200:
                            all_sitemap_locs_recursive = []
                            smap_ct = x_res.headers.get('Content-Type', '').lower()
                            is_scraped_successfully = False
                            
                            if xmlfile.lower().endswith('.txt'):
                                if 'html' not in smap_ct:
                                    temp_locs = []
                                    is_legit_txt_sitemap = False
                                    for line in x_res.text.splitlines():
                                        line_clean = line.strip()
                                        if line_clean and not line_clean.startswith('#'):
                                            temp_locs.append(line_clean)
                                            if line_clean.startswith(('http://', 'https://', '/')):
                                                is_legit_txt_sitemap = True
                                    if is_legit_txt_sitemap:
                                        all_sitemap_locs_recursive.extend(temp_locs)
                                        is_scraped_successfully = True
                                        
                            elif xmlfile.lower().endswith(('.gz', '.zip')):
                                if args.parse_zip:
                                    import gzip
                                    import zipfile
                                    import io
                                    try:
                                        decompressed_text = ""
                                        if xmlfile.lower().endswith('.gz'):
                                            raw_binary_data = gzip.decompress(x_res.content)
                                            decompressed_text = raw_binary_data.decode('utf-8', errors='ignore')
                                        elif xmlfile.lower().endswith('.zip'):
                                            zip_buffer = io.BytesIO(x_res.content)
                                            with zipfile.ZipFile(zip_buffer) as z_file:
                                                archive_contents = z_file.namelist()
                                                if archive_contents:
                                                    with z_file.open(archive_contents[0]) as internal_file:
                                                        decompressed_text = internal_file.read().decode('utf-8', errors='ignore')
                                                        
                                        if decompressed_text:
                                            is_scraped_successfully = True
                                            if xmlfile.lower().endswith(('.txt.gz', '.txt.zip')):
                                                for line in decompressed_text.splitlines():
                                                    line_clean = line.strip()
                                                    if line_clean and not line_clean.startswith('#'):
                                                        all_sitemap_locs_recursive.append(line_clean)
                                            else:
                                                raw_locs_recursive = re.findall(r'<loc>\s*([^<]+)\s*</loc>', decompressed_text, re.IGNORECASE | re.DOTALL)
                                                xhtml_locs_recursive = re.findall(r'<xhtml:link[^>]*href=["\']([^"\']+)["\']', decompressed_text, re.IGNORECASE)
                                                rss_links_recursive = re.findall(r'<link>\s*([^<]+)\s*</link>', decompressed_text, re.IGNORECASE)
                                                all_sitemap_locs_recursive = raw_locs_recursive + xhtml_locs_recursive + rss_links_recursive                                   
                                    except Exception:
                                        pass
                            else:
                                if "<loc" in x_res.text.lower() or "<link" in x_res.text.lower():
                                    raw_locs_recursive = re.findall(r'<loc>\s*([^<]+)\s*</loc>', x_res.text, re.IGNORECASE | re.DOTALL)
                                    xhtml_locs_recursive = re.findall(r'<xhtml:link[^>]*href=["\']([^"\']+)["\']', x_res.text, re.IGNORECASE)
                                    rss_links_recursive = re.findall(r'<link>\s*([^<]+)\s*</link>', x_res.text, re.IGNORECASE)
                                    all_sitemap_locs_recursive = raw_locs_recursive + xhtml_locs_recursive + rss_links_recursive
                                    is_scraped_successfully = True

                            if is_scraped_successfully:
                                xml_files.append(xmlfile)

                            can_queue_nested_xml = True
                            if args.depth is not None and current_xml_depth >= args.depth:
                                can_queue_nested_xml = False
                                
                            for loc in all_sitemap_locs_recursive:
                                loc_stripped = loc.strip()
                                if not loc_stripped:
                                    continue
                                    
                                if "http://" in loc_stripped.lower() or "https://" in loc_stripped.lower():
                                    loc_netloc = urlparse(loc_stripped).netloc.lower()
                                    if loc_netloc != urlparse(target if "://" in target else f"https://{target}").netloc.lower():
                                        clean_path = loc_stripped
                                    else:
                                        clean_path = urlparse(loc_stripped).path
                                else:
                                    clean_path = '/' + loc_stripped.lstrip('/')
                                clean_path = '/' + clean_path.lstrip('/') if "://" not in clean_path else clean_path
                                
                                if clean_path and clean_path != "/":
                                    if clean_path in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                                        continue
                                    if any(term in clean_path.lower() for term in USELESSSTUFF):
                                        continue
                                        
                                    SITEMAP_EXTENSIONS = ('.xml', '.txt', '.rss', '.atom', '.gz', '.zip', '.xml.gz', '.txt.gz', '.xml.zip', '.txt.zip')
                                    if clean_path.lower().endswith(SITEMAP_EXTENSIONS):
                                        if clean_path not in xml_files:
                                            if can_queue_nested_xml:
                                                xml_files.append(clean_path)
                                                xml_depths[clean_path] = current_xml_depth + 1
                                                
                                                if args.show_prog and (not nd or clean_path not in unique_progress_paths):
                                                    print(f"New path/file: {clean_path}\n  └─ Source File: {xmlfile}")
                                                    unique_progress_paths.add(clean_path)
                                        continue
                                        
                                    if clean_path not in found_paths:
                                        found_paths.add(clean_path)
                                        if args.show_prog and (not nd or clean_path not in unique_progress_paths):
                                            print(f"New path/file: {clean_path}\n  └─ Source File: {xmlfile}")
                                            unique_progress_paths.add(clean_path)
                    except (KeyboardInterrupt, SystemExit):
                        print("Scan cancelled by user.")
                        sys.exit(0)
                    except: 
                        xml_index += 1
                        continue
                    xml_index += 1

            if not args.only_res:
                print(f"\nDetected JS Stack: {' + '.join(js_stack) if js_stack else 'Unknown JS Stack'}\n")
            if emscripten_vfs_detected:
                found_paths = list({i.rstrip('/') for i in found_paths if i != '/dev' and i != '/dev/' and not i.startswith('/tmp/')})
            else:
                found_paths = list({i.rstrip('/') for i in found_paths}) 
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
                            timeout=90,
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
                if not args.pipeable: print(f"Total paths found: {len(found_paths)}")

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
                from difflib import SequenceMatcher
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
                        ts, checktimestatusalready = checktime(start_test_time, args.scan_timeout, checktimestatusalready, (not args.no_auto_input)) #timer status
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

            found_paths_set = set(found_paths)
            #return extra paths

            #filter external links
            results_ext = list({el for el in results_ext if len(el) >= 4})
            all_scanned_sources = list(e_files) + list(scanned_xmls) + list(scanned_js)

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
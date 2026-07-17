'''
Main python file used. When running the command, this is the file that runs.
'''

#module imports
import asyncio
from curl_cffi import requests, CurlOpt
import re
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
from .miscfuncs import checktime, check_if_local, startcodeargs, testhttpprotocol, checkserveruptime, verifyeacheslprotocol
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
    listofallowedesls = verifyeacheslprotocol(external_script_loader_list, preferredprotocol)
    nd = args.no_duplicate_prog
    show_dead = args.show_404s
    target = args.target if args.target else input("Target website not found.\nEnter website (e.g. https://example.com): ").strip()

    #http https
    if not target.startswith(("http://", "https://")):
        if args.local:
            target = "http://" + target 
        else:
            target = "https://" + target
    impersonate_settings = None if (check_if_local(target) or args.local) else "chrome120" #chrome120 will not work on localhosts.
    target = testhttpprotocol(target, HEADER, impersonate_settings, args)

    #server uptime
    checkserveruptime(target, HEADER, impersonate_settings, args)
    start_test_time = time.perf_counter()
    #hardcoded dangerous endpoints to test, disabled by -dse
    if not args.disable_sensitive_endpoint:
        SENSITIVE_ENDPOINT = {
            "/.env", "/.env.local", "/.env.production", "/.env.development", ".env.dev",
            "/.git/config", "/.git/HEAD", "/package.json", "/package-lock.json", "/.npmrc", "/.dockerenv",
            "/.gitignore", "/api/health", "/config", "/.env.example", "/docker-compose.yml", "/.babelrc", 
            "/.eslintrc.json", "/wp-config.php", "/config.json", "/.aws/credentials", "/.git/index",
            "/etc/passwd"
        }
    else:
        SENSITIVE_ENDPOINT = {}
    
    results_fromotherfiles = []
    results_200, results_dead, results_30x = [], [], []
    results_services, results_ext, results_subd = [], [], []
    results_frameworks, results_assets = [], []
    xml_files, invalidated_endpoints = [], []
    emscripten_vfs_detected = False
    found_paths = set(SENSITIVE_ENDPOINT)
    discovered_in_js = {}

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
                appendrobottoe = False
                
                for line in r_res.text.splitlines():
                    _local_robots_line = line.strip()
                    if not _local_robots_line or _local_robots_line.startswith("#"): #strip away comments in robots.txt file.
                        continue
                        
                    if ":" in _local_robots_line:
                        _local_parts = _local_robots_line.split(":", 1)
                        _local_directive = _local_parts[0].strip().lower()
                        _local_payload = _local_parts[1].strip()
                        
                        if _local_directive in ["disallow", "allow"]:
                            if _local_payload and _local_payload not in ["/", "/*", "*"] and _local_payload not in found_paths:
                                found_paths.add(_local_payload)
                                if appendrobottoe == False:
                                    e_files.append('/robots.txt')
                                    appendrobottoe = True
                                if not args.tidy: 
                                    results_fromotherfiles.append(f"{_local_payload} [Source: robots.txt]")
                                else:
                                    results_fromotherfiles.append(f"{_local_payload}")
                                    
                                if args.show_prog:
                                    if not nd or _local_payload not in unique_progress_paths:
                                        if args.show_source:
                                            print(f"[File from robots.txt] New path/file: {_local_payload}")
                                        else:
                                            print(f"New path/file: {_local_payload}")
                                        unique_progress_paths.add(_local_payload)
                                        
                        elif _local_directive == "sitemap": #robots.txt can have sitemaps
                            _local_smap_path = urlparse(_local_payload).path
                            if _local_smap_path and _local_smap_path not in xml_files:
                                xml_files.append(_local_smap_path)
                                
                                if args.show_prog:
                                    if not nd or _local_smap_path not in unique_progress_paths:
                                        if args.show_source:
                                            print(f"[File from robots.txt] New path/file: {_local_smap_path}")
                                        else:
                                            print(f"New path/file: {_local_smap_path}")
                                        unique_progress_paths.add(_local_smap_path)
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            exit()
        except: 
            pass

        # sitemap
        try:
            s_res = requests.get(urljoin(target, "/sitemap.xml"), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
            if s_res.status_code == 200 and "<loc" in s_res.text.lower():
                e_files.append('/sitemap.xml')
                
                raw_locs = re.findall(r'<loc>\s*([^<]+)\s*</loc>', s_res.text, re.IGNORECASE | re.DOTALL)
                xhtml_locs = re.findall(r'<xhtml:link[^>]*href=["\']([^"\']+)["\']', s_res.text, re.IGNORECASE)

                all_sitemap_locs = raw_locs + xhtml_locs
                for loc in all_sitemap_locs:
                    loc_stripped = loc.strip()
                    if not loc_stripped:
                        continue
                        
                    if "http://" in loc_stripped.lower() or "https://" in loc_stripped.lower():
                        clean_path = urlparse(loc_stripped).path
                    else:
                        clean_path = '/' + loc_stripped.lstrip('/')
                    clean_path = '/' + clean_path.lstrip('/')
                    
                    if clean_path and clean_path != "/" and clean_path not in found_paths:
                        if clean_path.lower().endswith('.xml'):
                            if clean_path not in xml_files:
                                xml_files.append(clean_path)
                            continue
                            
                        found_paths.add(clean_path)
                        if not args.tidy:
                            results_fromotherfiles.append(f"{clean_path} [Source: sitemap.xml]")
                        else:
                            results_fromotherfiles.append(f"{clean_path}")
                        if args.show_prog:
                            if not nd or clean_path not in unique_progress_paths:
                                if args.show_source:
                                    print(f"[File from sitemap.xml] New path/file: {clean_path}")
                                else:
                                    print(f"New path/file: {clean_path}")
                                unique_progress_paths.add(clean_path)
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            exit()
        except: 
            pass

        # assetmanifest
        try:
            m_res = requests.get(urljoin(target, "/asset-manifest.json"), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
            if m_res.status_code == 200 and "{" in m_res.text:
                e_files.append('/asset-manifest.json')
                paths = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]+)["\']', m_res.text)
                for path in paths:
                    clean_m_path = path.strip()
                    if clean_m_path not in found_paths:
                        if clean_m_path == "/":
                            continue
                        found_paths.add(clean_m_path)
                        if not args.tidy:
                            results_fromotherfiles.append(f"{clean_m_path} [Source: asset-manifest.json]")
                        else:
                            results_fromotherfiles.append(f"{clean_m_path}")
                        if args.show_prog:
                            if not nd or clean_m_path not in unique_progress_paths:
                                if args.show_source:
                                    print(f"[File from asset-manifest.json] New path/file: {clean_m_path}")
                                else:
                                    print(f"New path/file: {clean_m_path}")
                                unique_progress_paths.add(clean_m_path)
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            exit()
        except: pass
        # manifests i forgot in the previous loop
        for manifest_path in ["/web-manifest.json", "/manifest.json"]:
            try:
                m_url = urljoin(target, manifest_path)
                m_res = requests.get(m_url, headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
                if m_res.status_code == 200 and "{" in m_res.text:
                    e_files.append(manifest_path)
                    paths = re.findall(r'["\'](/[a-zA-Z0-9_\-\./]+)["\']', m_res.text)
                    for path in paths:
                        clean_manifest_path = path.strip()
                        if clean_manifest_path not in found_paths:
                            if clean_manifest_path == "/":
                                continue
                            found_paths.add(clean_manifest_path)
                            if not args.tidy:
                                results_fromotherfiles.append(f"{clean_manifest_path} [Source: {manifest_path.lstrip('/')}]")
                            else:
                                results_fromotherfiles.append(f"{clean_manifest_path}")
                            if args.show_prog:
                                if not nd or clean_manifest_path not in unique_progress_paths:
                                    if args.show_source:
                                        print(f"[File from {manifest_path}] New path/file: {clean_manifest_path}")
                                    else:
                                        print(f"New path/file: {clean_manifest_path}")
                                    unique_progress_paths.add(clean_manifest_path)
            except (KeyboardInterrupt, SystemExit):
                print("Scan cancelled by user.")
                exit()
            except: pass
        # service worker 
        for sw_path in ["/service-worker.js", "/sw.js"]:
            try:
                sw_res = requests.get(urljoin(target, sw_path), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
                swct = sw_res.headers.get('Content-Type', '').lower()
                if sw_res.status_code == 200 and 'javascript' in swct:
                    e_files.append(sw_path)
                    paths = re.findall(r'["\'`](/[a-zA-Z0-9_\-\./{}:]+)["\'`]', sw_res.text)
                    for path in paths:
                        cleanpath = path.strip()
                        if cleanpath not in found_paths and not any(cleanpath.endswith(ext) for ext in ['.js', '.css']):
                            if cleanpath == "/":
                                continue
                            found_paths.add(cleanpath)
                            if not args.tidy:
                                results_fromotherfiles.append(f"{cleanpath} [Source: {sw_path}]")
                            else:
                                results_fromotherfiles.append(f"{cleanpath}")
                            if args.show_prog:
                                if not nd or cleanpath not in unique_progress_paths:
                                    if args.show_source:
                                        print(f"[File from {sw_path}] New path/file: {cleanpath}")
                                    else:
                                        print(f"New path/file: {cleanpath}")
                                    unique_progress_paths.add(cleanpath)
            except (KeyboardInterrupt, SystemExit):
                print("Scan cancelled by user.")
                exit()
            except: pass

        #openid
        try:
            oidc_res = requests.get(urljoin(target, "/.well-known/openid-configuration"), headers=E_HEADER, impersonate=impersonate_settings, timeout=4)
            if oidc_res.status_code == 200 and "authorization_endpoint" in oidc_res.text and "issuer" in oidc_res.text:
                e_files.append("/.well-known/openid-configuration")
                paths = re.findall(r'https?://[^/]+(/[^"\']*)', oidc_res.text)
                for path in paths:
                    clean_oidc_path = path.strip()
                    if clean_oidc_path not in found_paths:
                        if clean_oidc_path == "/":
                            continue
                        found_paths.add(clean_oidc_path)
                        if not args.tidy:
                            results_fromotherfiles.append(f"{clean_oidc_path} [Source: openid-configuration]")
                        else:
                            results_fromotherfiles.append(f"{clean_oidc_path}")
                        if args.show_prog:
                            if not nd or clean_oidc_path not in unique_progress_paths:
                                if args.show_source:
                                    print(f"[File from openid-configuration] New path/file: {clean_oidc_path}")
                                else:
                                    print(f"New path/file: {clean_oidc_path}")
                                unique_progress_paths.add(clean_oidc_path)
        except (KeyboardInterrupt, SystemExit):
            print("Scan cancelled by user.")
            exit()
        except: pass
    base_res = requests.get(
        target, 
        headers=HEADER, 
        impersonate=impersonate_settings, 
        timeout=10
    )
    import secrets
    fake_path = f"/very-fake-page-123456123456abcdefg_{secrets.token_hex(16)}"
    if not args.only_res:
        if args.no_headless_browser:
            print(f"\nStarting browser to bypass captchas and detect shells with a fake path. Fake path used: {fake_path}")
        else:
            print(f"\nStarting headless browser to bypass captchas and detect shells with a fake path. Fake path used: {fake_path}")
    main_html, session_cookies, scan_status = gethtmlafterload(
                                                            target, 
                                                            args.no_headless_browser,
                                                            initial_response=base_res
                                                            )
    if scan_status["blocked"]:
        if not args.no_detect_captcha:
            print("Exiting script as captcha was detected.")
            print("It is recommended to use the -nhb flag to see what is happening in the headless browser to see if it is actually blocked by a captcha and if it was a false positive.")
            print("If this was a false positive, use the -ndc (--no-detect-captcha) flag to disable exiting.")
            exit(1)
        else:
            print("Script will not be exited, as --no-detect-captcha flag was passed. Script will continue.")
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
                if src.startswith('//'):
                    src = f"https:{src}"
                full_src_url = urljoin(target, src)
                src_netloc = urlparse(full_src_url).netloc.lower()
                if not src_netloc or src_netloc == target_netloc or src_netloc in esl_domains:
                    js_files.append(full_src_url)
        for script_tag in soup.find_all('script'):
            src = script_tag.get('src')
            if src:
                src = src.strip()
                if src.startswith('//'):
                    src = f"https:{src}"
            if src and not src.startswith(('http://', 'https://')):
                local_path = urlparse(src).path
                if local_path:
                    clean_path = '/' + local_path.lstrip('/')
                    found_paths.add(clean_path)

        targetthings = ['stylesheet', 'modulepreload', 'preload', 'prefetch', 'icon', 'shortcut icon', 'manifest']
        #stylesheet like css
        for link_tag in soup.find_all('link', rel=targetthings):
            href = link_tag.get('href')
            if href:
                href = href.strip()
                if href.startswith('//'):
                    href = f"https:{href}"
                if href and not href.startswith(('http://', 'https://')):
                    local_path = urlparse(href).path
                    if local_path:
                        clean_path = '/' + local_path.lstrip('/')
                        found_paths.add(clean_path)
        patterns = [
            r'["\'`](/[a-zA-Z0-9_\-\./{}:~%]*)["\'`]', 
            r'(?:path|href|to|post|get|patch|put|delete|head|options)[\s]*[:=\(\|]+[\s]*["\'`](/?[a-zA-Z0-9_\-\./{}:\$~%]*[\./][a-zA-Z0-9_\-\./{}:\$~%]*)["\'`]',
            r'["\'`](https?://[a-zA-Z0-9_\-\./{}:\$~%]+)["\'`]'
        ]
        current_filename = "HTML raw code"
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
                    ts = checktime(start_test_time, args.scan_timeout) #timer status
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
                    m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9_\-]+|\{[^{}]*\}|<[^<>]*>)', '1', m)
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
                exit()
            except: continue

        emscripten_vfs_detected = False
        for path in list(found_paths):
            # check for js, html, and htm (htm is a older version that still exists in many sites)
            if path.lower().endswith(('.js', '.html', '.htm')):
                target_asset_url = urljoin(target, path)
                asset_netloc = urlparse(target_asset_url).netloc.lower()
                target_netloc = urlparse(target if "://" in target else f"https://{target}").netloc.lower()
                
                is_safe_asset = False
                if asset_netloc in listofallowedesls:
                    is_safe_asset = True
                    print(is_safe_asset)
                elif asset_netloc == target_netloc:
                    is_safe_asset = True
                
                if is_safe_asset and target_asset_url not in js_files:
                    js_files.append(target_asset_url)
                    found_paths.add(target_asset_url)

        # check for pyodide
        for j in js_files:
            if 'pyodide' in j.lower():
                emscripten_vfs_detected = True
                break

        # recursive scanning 
        js_idx = 0
        while js_idx < len(js_files):
            js_url = js_files[js_idx]
            
            if args.scan_timeout:
                ts = checktime(start_test_time, args.scan_timeout) #timer status
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
                    if 'pyodide' in js_url.lower():
                        emscripten_vfs_detected = True
                        
                    if js_url.lower().endswith(('.html', '.htm')):
                        local_soup = BeautifulSoup(js_res.text, 'html.parser')
                            
                        for tag in local_soup.find_all(['script', 'link']):
                            src_or_href = tag.get('src') or tag.get('href')
                            if src_or_href:
                                clean_src = src_or_href.strip()
                                if clean_src.lower().endswith(('.js', '.css', '.html', '.htm')):
                                    nested_asset_url = urljoin(js_url, clean_src)
                                    nested_netloc = urlparse(nested_asset_url).netloc.lower()
                                    
                                    nested_safe = False
                                    if nested_netloc in esl_domains:
                                        nested_safe = True
                                    if nested_netloc == target_netloc:
                                        nested_safe = True
                                        
                                    if nested_safe and nested_asset_url not in js_files:
                                        js_files.append(nested_asset_url)
                                    
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
                                    if nested_inline_url not in js_files:
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
                                m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9_\-]+|\{[^{}]*\}|<[^<>]*>)', '1', m).strip()
                                m_display = f"{m_clean} [Original: {m}]" if m_clean != m else m_clean
                                m_clean = m_clean.strip()
                                if m_clean.startswith('//'):
                                    m_clean = f"https:{m_clean}"
                                if "://" not in m_clean and not m_clean.startswith('/'): 
                                    m_clean = '/' + m_clean
                                    if m_clean != m: m_display = '/' + m_display
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
                                    
                                    if m_clean.lower().endswith(('.js', '.html', '.htm')):
                                        check_nested_url = urljoin(target, m_clean)
                                        nested_netloc = urlparse(check_nested_url).netloc.lower()
                                        
                                        nested_safe = False
                                        if nested_netloc in esl_domains:
                                            nested_safe = True
                                        elif nested_netloc == target_netloc:
                                            nested_safe = True
                                                
                                        if nested_safe and check_nested_url not in js_files:
                                            js_files.append(check_nested_url)
                                
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
                exit()
            except: 
                js_idx += 1
                continue
                
            js_idx += 1

        if not args.disable_extra_files:
            for f in list(found_paths):
                if f.lower().endswith('.xml'):
                    if "http://" in f.lower() or "https://" in f.lower():
                        clean_f = urlparse(f).path
                    else:
                        clean_f = '/' + f.lstrip('/')
                        
                    clean_f = '/' + clean_f.lstrip('/')
                    
                    target_x_url = urljoin(target, clean_f) 
                    if urlparse(target_x_url).netloc == urlparse(target if "://" in target else f"https://{target}").netloc:
                        if clean_f not in xml_files:
                            xml_files.append(clean_f)
            
            # recursive xml loop
            xml_index = 0
            while xml_index < len(xml_files):
                xmlfile = xml_files[xml_index]
                
                if args.scan_timeout:
                    ts = checktime(start_test_time, args.scan_timeout) #timer status
                    if ts == "STOP":
                        break
                    elif ts == "EXTEND":
                        start_test_time = time.perf_counter()
                        args.scan_timeout = 5.0 #5min more
                try:
                    DOWNLOAD_XML_HEADERS = HEADER.copy()
                    DOWNLOAD_XML_HEADERS["Cache-Control"] = "no-cache"
                    DOWNLOAD_XML_HEADERS["Pragma"] = "no-cache"
                    DOWNLOAD_XML_HEADERS["If-None-Match"] = ""
                    DOWNLOAD_XML_HEADERS["If-Modified-Since"] = ""
                    target_xml_url = urljoin(target, xmlfile)
                    x_res = requests.get(target_xml_url, headers=DOWNLOAD_XML_HEADERS, impersonate=impersonate_settings, timeout=4)

                    if x_res.status_code == 200 and "<loc" in x_res.text.lower():
                        raw_locs_recursive = re.findall(r'<loc>\s*([^<]+)\s*</loc>', x_res.text, re.IGNORECASE | re.DOTALL)
                        xhtml_locs_recursive = re.findall(r'<xhtml:link[^>]*href=["\']([^"\']+)["\']', x_res.text, re.IGNORECASE)
                        all_sitemap_locs_recursive = raw_locs_recursive + xhtml_locs_recursive
                        for loc in all_sitemap_locs_recursive:
                            loc_stripped = loc.strip()
                            if not loc_stripped:
                                continue
                                
                            if "http://" in loc_stripped.lower() or "https://" in loc_stripped.lower():
                                clean_path = urlparse(loc_stripped).path
                            else:
                                clean_path = '/' + loc_stripped.lstrip('/')
                            
                            clean_path = '/' + clean_path.lstrip('/')
                            
                            if clean_path and clean_path != "/":
                                if clean_path in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
                                    continue
                                if any(term in clean_path.lower() for term in USELESSSTUFF):
                                    continue
                                    
                                if clean_path.lower().endswith('.xml'):
                                    if clean_path not in xml_files:
                                        xml_files.append(clean_path)
                                        if not args.tidy:
                                            results_fromotherfiles.append(f"{clean_path} [Source: Nested Sitemaps]")
                                        else:
                                            results_fromotherfiles.append(f"{clean_path}")
                                    continue
                                    
                                if clean_path not in found_paths:
                                    found_paths.add(clean_path)
                                    
                                    if not args.tidy:
                                        results_fromotherfiles.append(f"{clean_path} [Source: {xmlfile.lstrip('/')}]")
                                    else:
                                        results_fromotherfiles.append(f"{clean_path}")
                                        
                                    if args.show_prog:
                                        if not nd or clean_path not in unique_progress_paths:
                                            print(f"[File from {xmlfile.lstrip('/')}] New path/file: {clean_path}")
                                            unique_progress_paths.add(clean_path)
                except (KeyboardInterrupt, SystemExit):
                    print("Scan cancelled by user.")
                    exit()
                except: 
                    # move index forward if it fails
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
            if not args.only_res:
                print(f"Total paths to test: {len(found_paths)} (Scraped: {len(found_paths) - len(SENSITIVE_ENDPOINT)} | Built-in: {len(SENSITIVE_ENDPOINT)})")
                print("Testing endpoints...")
            
            if len(found_paths) >= 2000:
                # every requests takes ~0.2s
                raw_seconds = 0.2 * len(found_paths)
                
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
                    
                print(f"\n[WARNING] Number of endpoints found is {exaggerate}large.")
                print(f"Estimated sorting time: {esttime}")
                
                try:
                    userawoutput = input("Would you like to use the raw output instead? (No sorting at all) [y/n]\n >>> ")
                    if userawoutput.lower() in ['y', 'yes']:
                        print("Endpoints will not be sorted.")
                        args.raw_output = True
                    else:
                        print("Endpoints will still be sorted.")
                        args.raw_output = False
                except (KeyboardInterrupt, SystemExit):
                    print("\nScan cancelled by user.")
                    return
        else:
            print(f"Endpoints Found: {len(found_paths) - len(SENSITIVE_ENDPOINT)}")

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
                    service_markers = ["/api", "/v1", "/v2", "socket.io", "engine.io", "/graphql", "/webhook", "/rpc", "/actuator", "/swagger", "/v3/api-docs", "/rest/", "/ws", "/metrics"]
                    is_machine_path = any(marker in request_route.lower() for marker in service_markers)

                    media_extensions = ('.png', '.jpg', '.jpeg', '.svg', '.webp', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.swf', '.mp4', '.mp3', '.avif', '.webm', '.wav')
                    framework_extensions = ('.js', '.css', '.json', '.txt', '.xml', '.map', '.rels', '.md', '.wasm')
                    
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

                    elif r.status_code in [403, 404]:
                        results_dead.append(f"{r.status_code} Error: {display_path}")
                    elif str(r.status_code).startswith('3'):
                        results_30x.append(f"{display_path} -> {r.headers.get('Location')}")
                except: continue

                if args.scan_timeout:
                    ts = checktime(start_test_time, args.scan_timeout) #timer status
                    if ts == "STOP":
                        current_position = sorted(found_paths).index(path)
                        unsorted = sorted(found_paths)[current_position:]
                        c_unsorted = []
                        #sensitive endpoints that have not been verified will show up. May be misleading, make people think those sensitive endpoints are exposed.
                        for u in unsorted:
                            if u not in SENSITIVE_ENDPOINT:
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

        found_paths_set = set(found_paths) #set makes it faster
        #return extra paths
        results_fromotherfiles = list({p for p in results_fromotherfiles if p not in found_paths_set})

        #filter external links
        #tuff set comprehension
        results_ext = list({el for el in results_ext if len(el) >= 4})
        xml_set = set(xml_files)
        e_files = [x for x in e_files if x not in xml_set]

        display_and_save_results(
            args, show_dead, target,
            results_200, results_services, results_ext, results_subd,
            results_frameworks, results_30x, results_fromotherfiles,
            results_assets, results_dead, unsorted,
            assets_suffix, dead_suffix, invalidated_suffix,
            js_files, xml_files, e_files,
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
                rh=args.ratelimit_header
            ))
    except (KeyboardInterrupt, SystemExit):
        print("Scan cancelled by user.")
        exit()
    except Exception as e:
        print(f"Main Error: {e}")

if __name__ == "__main__":
    main()
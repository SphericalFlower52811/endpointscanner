import time
import re
import sys
import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from curl_cffi import requests
from .miscfuncs import checktime
from .identifyjs import identify_javascript_type, identify_javascript_type_two

def tag_soup_scrape(
    args, main_html, target, found_paths, scanned_html, 
    verified_esl_domains, verified_esl_scripts, unique_progress_paths, nd
):
    soup = BeautifulSoup(main_html, 'html.parser')
    target_netloc = urlparse(target).netloc.lower()
    js_files = []
    current_filename = "Main Page HTML"

    if current_filename not in scanned_html:
        scanned_html.add(current_filename)

    allowed_esl_netlocs = {urlparse(d).netloc.lower() for d in verified_esl_domains if d}

    def is_allowed_external_asset(asset_url):
        parsed_asset = urlparse(asset_url)
        asset_domain = parsed_asset.netloc.lower()
        
        if asset_domain in allowed_esl_netlocs:
            return True
        if any(asset_url.lower().startswith(s.lower()) for s in verified_esl_scripts if s):
            return True
        return False

    for tag in soup.find_all(True): 
        raw_asset = tag.get('src') or tag.get('href')
        if not raw_asset:
            continue
            
        asset_clean = raw_asset.strip()
        if asset_clean.lower().startswith(('data:', 'blob:', 'javascript:')):
            continue
        if asset_clean.startswith('//'):
            asset_clean = f"https:{asset_clean}"
            
        full_asset_url = urljoin(target, asset_clean)
        parsed_asset = urlparse(full_asset_url)
        asset_domain = parsed_asset.netloc.lower()
        asset_path = parsed_asset.path.strip()
        
        if any(char in asset_domain for char in [' ', ',', '(', ')', '{', '}']):
            continue
        if any(char in asset_path for char in [' ', ',', '(', ')', '{', '}']):
            continue
            
        is_internal = not asset_domain or asset_domain == target_netloc
        is_allowed_asset = is_internal or is_allowed_external_asset(full_asset_url)
        
        if is_allowed_asset:
            if asset_clean.lower().endswith(('.js', '.mjs', '.cjs', '.wxs', '.css')):
                if args.depth is None or args.depth > 0:  
                    if full_asset_url not in js_files:
                        js_files.append(full_asset_url)
                if full_asset_url not in found_paths:
                    found_paths.add(full_asset_url)
            
            if asset_path and asset_path != "/":
                clean_path = '/' + asset_path.lstrip('/')
                if clean_path not in found_paths:
                    found_paths.add(clean_path)
                    if args.show_prog:
                        if not nd or clean_path not in unique_progress_paths:
                            print(f"Found: {clean_path}")
                            unique_progress_paths.add(clean_path)
                            if args.show_source:
                                print(f"  └─ Source File: {current_filename}")
    return js_files

def initial_html_scrape(
    args, target, main_html, scanned_html, HEADER, session_cookies, impersonate_settings, 
    patterns, JSPDF_SIGNATURE_KEYS, cprs, ignored_extensions, USELESSSTUFF, 
    found_paths, discovered_in_js, unique_progress_paths, nd, 
    start_test_time, checktimestatusalready, autoinput_timeout
):
    current_filename = "Main Page HTML"
    if current_filename not in scanned_html:
        scanned_html.add(current_filename)
    
    if main_html:
        respo = main_html
    else:
        try:
            respo = requests.get(target, headers=HEADER, cookies=session_cookies, timeout=5, impersonate=impersonate_settings).text
        except:
            respo = ""
            
    for p in patterns:
        try:
            if args.scan_timeout:
                ts, checktimestatusalready = checktime(start_test_time, args.scan_timeout, checktimestatusalready, (not args.no_auto_input), autoinput_timeout)
                if ts == "STOP":
                    break
                elif ts == "EXTEND":
                    start_test_time = time.perf_counter()
                    args.scan_timeout = 5.0
                    
            matches = re.findall(p, respo, re.IGNORECASE | re.DOTALL)
            detected_library_keys = set(matches).intersection(JSPDF_SIGNATURE_KEYS)
            if len(detected_library_keys) >= 3:
                matches = [m for m in matches if m not in JSPDF_SIGNATURE_KEYS]

            for m in matches:
                m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9_\-]+|\{[^{}]*\}|<[^<>]*>)', cprs, m)
                m_clean = m_clean.strip()
                if m_clean.startswith('//'):
                    m_clean = f"https:{m_clean}"
                if m_clean != m and not m.startswith('//'):
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
        except: 
            continue
            
    return start_test_time, checktimestatusalready

PAGE_EXTS = ('.html', '.htm', '.php', '.asp', '.aspx', '.jsp', '.shtml')
NON_PAGE_PREFIXES = ('/api', '/v1', '/v2', '/v3', '/v4', '/v5', '/graphql', '/socket.io', '/static', '/assets')
ASSET_EXTS = ('.js', '.mjs', '.cjs', '.css', '.wxs', '.png', '.jpg', '.jpeg', '.svg', '.webp', '.gif',
               '.ico', '.woff', '.woff2', '.ttf', '.map', '.json', '.txt', '.xml', '.wasm', '.pdf', '.zip', '.gz')
SITEMAP_EXTS = ('.xml', '.txt', '.rss', '.atom', '.gz', '.zip')

def is_page_like(path):
    p = path.split("?")[0].split("#")[0]
    ext = ""
    base = p.rsplit('/', 1)[-1]
    if "." in base:
        ext = "." + base.rsplit(".", 1)[-1].lower()
    if ext in ASSET_EXTS:
        return False
    if p.lower().startswith(NON_PAGE_PREFIXES):
        return False
    if ext == "" or ext in PAGE_EXTS:
        return True
    return False

def is_xml_like(path):
    p = path.split("?")[0].split("#")[0].lower()
    return p.endswith(SITEMAP_EXTS)

def recursive_crawler(
    args, target, HEADER, session_cookies, impersonate_settings,
    verified_esl_domains, verified_esl_scripts, patterns,
    JSPDF_SIGNATURE_KEYS, PYODIDE_VFS_PRECISION_PATTERNS,
    cprs, ignored_extensions, USELESSSTUFF, nd,
    found_paths, js_files, scanned_js, scanned_xmls, discovered_in_js, unique_progress_paths, js_stack,
    start_test_time, checktimestatusalready, autoinput_timeout
):
    allowed_domain_netlocs = {urlparse(d).netloc.lower() for d in verified_esl_domains if d}
    target_netloc = urlparse(target if "://" in target else f"https://{target}").netloc.lower()
    target_apex = '.'.join(target_netloc.split('.')[-2:]) if len(target_netloc.split('.')) >= 2 else target_netloc

    js_depths = {}
    js_identities = set()
    page_identities = set()
    xml_identities = set()

    for existing_js in js_files:
        ident = urlparse(existing_js).path if "://" in existing_js else existing_js.split("?")[0].split("#")[0]
        js_identities.add(ident)

    emscripten_vfs_detected = False

    work_queue = []
    for j in js_files:
        work_queue.append(('js', j, js_depths.get(j, 1)))

    if args.depth is None or args.depth > 0:
        for path in list(found_paths):
            ext_check = path.split("?")[0].split("#")[0]
            if ext_check.lower().endswith(('.js', '.html', '.htm', '.mjs', '.cjs', '.wxs', '.css')) and ext_check.lower() not in ['sw.js', 'service-worker.js']:
                target_asset_url = urljoin(target, path)
                asset_netloc = urlparse(target_asset_url).netloc.lower()
                is_safe_asset = (asset_netloc == target_netloc
                                 or asset_netloc in allowed_domain_netlocs
                                 or any(target_asset_url.lower().startswith(s.lower()) for s in verified_esl_scripts if s))
                if is_safe_asset and target_asset_url not in js_files and ext_check not in js_identities:
                    js_identities.add(ext_check)
                    js_files.append(target_asset_url)
                    found_paths.add(target_asset_url)
                    js_depths[target_asset_url] = 1
                    work_queue.append(('js', target_asset_url, 1))
        if not args.disable_structure_files:
            allowed_xml_netlocs = {urlparse(d).netloc.lower() for d in verified_esl_domains if d}
            for f in list(found_paths):
                ext_check = f.split("?")[0].split("#")[0]
                if ext_check.lower().endswith(SITEMAP_EXTS):
                    if "http://" in f.lower() or "https://" in f.lower():
                        clean_f = f
                        f_domain = urlparse(f).netloc.lower()
                    else:
                        clean_f = '/' + f.lstrip('/')
                        f_domain = target_netloc
                    is_valid_map_url = False
                    if f_domain == target_netloc: is_valid_map_url = True
                    elif f_domain in allowed_xml_netlocs: is_valid_map_url = True
                    elif any(clean_f.lower().startswith(s.lower()) for s in verified_esl_scripts if s): is_valid_map_url = True
                    elif f_domain.endswith('.' + target_apex): is_valid_map_url = True
                    if is_valid_map_url:
                        if "://" in clean_f and urlparse(clean_f).netloc.lower() != target_netloc:
                            store_f = clean_f
                        else:
                            store_f = urlparse(clean_f).path if "://" in clean_f else clean_f
                            store_f = '/' + store_f.lstrip('/')
                        if store_f.lower() not in ['/sitemap.xml', 'sitemap.xml']:
                            ident = urlparse(store_f).path if "://" in store_f else store_f
                            if ident not in xml_identities:
                                xml_identities.add(ident)
                                work_queue.append(('xml', store_f if "://" in store_f else urljoin(target, store_f), 1))

    for j in js_files:
        if 'pyodide' in j.lower():
            emscripten_vfs_detected = True
            break

    semaphore = asyncio.Semaphore(max(1, int(args.concurrency)))

    async def fetch(session, url):
        async with semaphore:
            headers = HEADER.copy()
            headers["Cache-Control"] = "no-cache"
            headers["Pragma"] = "no-cache"
            headers["If-None-Match"] = ""
            headers["If-Modified-Since"] = ""
            domain = urlparse(url).netloc.lower()
            cookies = session_cookies if domain == target_netloc else None
            try:
                return await session.get(url, headers=headers, cookies=cookies, timeout=10)
            except Exception:
                return None

    def process_js(js_url, current_depth, text):
        nonlocal emscripten_vfs_detected
        new_js, new_pages, new_xml = [], [], []
        scanned_js.add(js_url)
        if 'pyodide' in js_url.lower():
            emscripten_vfs_detected = True
        can_deeper = (args.depth is None or current_depth < args.depth)

        if js_url.lower().endswith(('.html', '.htm')):
            local_soup = BeautifulSoup(text, 'html.parser')
            for tag in local_soup.find_all(True):
                raw = tag.get('src') or tag.get('href')
                if not raw: continue
                clean_src = raw.strip()
                if clean_src.lower().startswith(('data:', 'blob:', 'javascript:')): continue
                if clean_src.startswith('//'): clean_src = f"https:{clean_src}"
                nested_asset_url = urljoin(js_url, clean_src)
                parsed_nested = urlparse(nested_asset_url)
                nested_netloc = parsed_nested.netloc.lower()
                nested_path = parsed_nested.path.strip()
                if any(c in nested_netloc for c in [' ', ',', '(', ')', '{', '}']): continue
                if any(c in nested_path for c in [' ', ',', '(', ')', '{', '}']): continue
                rel_path = clean_src if "://" in clean_src else ('/' + nested_path.lstrip('/') if nested_path else '/')
                if rel_path not in discovered_in_js:
                    discovered_in_js[rel_path] = rel_path
                    found_paths.add(rel_path)
                    if args.show_prog and (not nd or rel_path not in unique_progress_paths):
                        print(f"Found: {rel_path}"); unique_progress_paths.add(rel_path)
                        if args.show_source: print(f"  └─ Source File: {js_url}")
                nested_safe = (nested_netloc == target_netloc or nested_netloc in allowed_domain_netlocs
                               or any(nested_asset_url.lower().startswith(s.lower()) for s in verified_esl_scripts if s))
                if nested_safe:
                    ext_check = clean_src.split("?")[0].split("#")[0]
                    if ext_check.lower().endswith(('.js', '.html', '.htm', '.mjs', '.cjs', '.wxs', '.css')):
                        if can_deeper and nested_asset_url not in js_files and ext_check not in js_identities:
                            js_identities.add(ext_check); js_files.append(nested_asset_url)
                            js_depths[nested_asset_url] = current_depth + 1
                            new_js.append((nested_asset_url, current_depth + 1))
                    elif ext_check.lower().endswith(SITEMAP_EXTS) and not args.disable_structure_files:
                        if can_deeper:
                            xml_ident = urlparse(nested_asset_url).path if "://" in nested_asset_url else nested_asset_url
                            if xml_ident not in xml_identities:
                                xml_identities.add(xml_ident)
                                new_xml.append((nested_asset_url, current_depth + 1))
            for inline_tag in local_soup.find_all('script'):
                if inline_tag.string:
                    inline_chunks = re.findall(r'["\'](/?[a-zA-Z0-9_\-\./]+\.(?:js|mjs|cjs|css|wxs))["\']', inline_tag.string)
                    for c in inline_chunks:
                        clean_c = c if c.startswith('/') else '/' + c
                        nested_inline_url = urljoin(js_url, clean_c)
                        n_netloc = urlparse(nested_inline_url).netloc.lower()
                        safe = (n_netloc == target_netloc or n_netloc in allowed_domain_netlocs
                                or any(nested_inline_url.lower().startswith(s.lower()) for s in verified_esl_scripts if s))
                        ident = clean_c.split("?")[0].split("#")[0]
                        if safe and can_deeper and nested_inline_url not in js_files and ident not in js_identities:
                            js_identities.add(ident); js_files.append(nested_inline_url)
                            js_depths[nested_inline_url] = current_depth + 1
                            new_js.append((nested_inline_url, current_depth + 1))
                        found_paths.add(clean_c)
                        if clean_c not in discovered_in_js:
                            discovered_in_js[clean_c] = clean_c
                            if args.show_prog and (not nd or clean_c not in unique_progress_paths):
                                print(f"Found: {clean_c}"); unique_progress_paths.add(clean_c)
                                if args.show_source: print(f"  └─ Source File: {js_url}")
            return new_js, new_pages, new_xml

        identify_javascript_type_two(javascript_content=text, current_stack=js_stack)
        identify_javascript_type(html="", headers=None, current_stack=js_stack)
        for p in patterns:
            matches = re.findall(p, text)
            detected = set(matches).intersection(JSPDF_SIGNATURE_KEYS)
            if len(detected) >= 3:
                matches = [m for m in matches if m not in JSPDF_SIGNATURE_KEYS]
            for m in matches:
                m_clean = re.sub(r'(\$\{.*?\}|:[a-zA-Z0-9_\-]+|\{[^{}]*\}|<[^<>]*>)', cprs, m).strip()
                if m_clean.startswith('//'): m_clean = f"https:{m_clean}"
                if "://" not in m_clean and not m_clean.startswith(('./', '../')):
                    if not m_clean.startswith('/'): m_clean = '/' + m_clean
                    if not m.startswith('/'): m = '/' + m
                m_display = f"{m_clean} [Original: {m}]" if (m_clean != m and not m.startswith('//')) else m_clean
                is_external_link = False
                if "://" in m_clean:
                    m_netloc = urlparse(m_clean).netloc.lower()
                    allowed_reg = {urlparse(d).netloc.lower() for d in verified_esl_domains if d}
                    allowed_asset = (m_netloc == target_netloc or m_netloc in allowed_reg
                                     or any(m_clean.lower().startswith(s.lower()) for s in verified_esl_scripts if s))
                    if not allowed_asset: is_external_link = True
                clean_stripped = m_clean.lstrip('/')
                if clean_stripped in ['http:', 'https:']: continue
                if clean_stripped.lower().startswith(('http://', 'https://')) and (len(clean_stripped) < 11 or "." not in clean_stripped): continue
                if not m_clean.lower().endswith(ignored_extensions):
                    if m_clean.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./"]: continue
                    if any(t in m_clean.lower() for t in USELESSSTUFF): continue
                    if emscripten_vfs_detected:
                        if any(re.match(vp, m_clean, re.IGNORECASE) for vp in PYODIDE_VFS_PRECISION_PATTERNS): continue

                    ext_check = m_clean.split("?")[0].split("#")[0]
                    is_js_ref = (not is_external_link) and ext_check.lower().endswith(('.js', '.html', '.htm', '.mjs', '.cjs', '.wxs', '.css'))
                    if is_js_ref:
                        resolved = urljoin(js_url, m_clean) if m_clean.startswith(('./', '../')) else urljoin(target, m_clean)
                        resolved_netloc = urlparse(resolved).netloc.lower()
                        nested_safe = (resolved_netloc == target_netloc or resolved_netloc in allowed_domain_netlocs
                                       or any(resolved.lower().startswith(s.lower()) for s in verified_esl_scripts if s))
                        resolved_ident = urlparse(resolved).path
                        if nested_safe and can_deeper and resolved not in js_files and resolved_ident not in js_identities:
                            js_identities.add(resolved_ident); js_files.append(resolved)
                            js_depths[resolved] = current_depth + 1
                            new_js.append((resolved, current_depth + 1))

                    if not args.spa and not is_external_link and is_page_like(m_clean):
                        resolved = urljoin(js_url, m_clean) if m_clean.startswith(('./', '../')) else urljoin(target, m_clean)
                        r_netloc = urlparse(resolved).netloc.lower()
                        if r_netloc == target_netloc and can_deeper:
                            r_ident = urlparse(resolved).path
                            if r_ident not in page_identities:
                                page_identities.add(r_ident)
                                new_pages.append((resolved, current_depth + 1))

                    if not is_external_link and ext_check.lower().endswith(SITEMAP_EXTS) and not args.disable_structure_files:
                        resolved = urljoin(js_url, m_clean) if m_clean.startswith(('./', '../')) else urljoin(target, m_clean)
                        r_netloc = urlparse(resolved).netloc.lower()
                        if r_netloc == target_netloc and can_deeper:
                            xml_ident = urlparse(resolved).path
                            if xml_ident not in xml_identities:
                                xml_identities.add(xml_ident)
                                new_xml.append((resolved, current_depth + 1))

                    if "://" not in m_clean and m_clean.startswith(('./', '../')):
                        resolved_found = urljoin(js_url, m_clean)
                    elif "://" not in m_clean:
                        resolved_found = urljoin(target, m_clean)
                    else:
                        resolved_found = m_clean
                    found_paths.add(resolved_found)
                    if m_clean not in discovered_in_js:
                        discovered_in_js[m_clean] = m_display
                        prog = m_display
                        if args.only_original and " [Original: " in m_display:
                            prog = m_display.split(" [Original: ")[1].rstrip(']')
                        elif args.disable_og and " [Original:" in m_display:
                            prog = m_display.split(" [Original:")[0].strip()
                        if args.show_prog and (not nd or m_clean not in unique_progress_paths):
                            print(f"Found: {prog}"); unique_progress_paths.add(m_clean)
                            if args.show_source: print(f"  └─ Source File: {js_url}")
        return new_js, new_pages, new_xml

    def process_page(page_url, current_depth, text):
        new_js, new_pages, new_xml = [], [], []
        can_deeper = (args.depth is None or current_depth < args.depth)
        local_soup = BeautifulSoup(text, 'html.parser')
        for tag in local_soup.find_all(True):
            raw = tag.get('src') or tag.get('href')
            if not raw: continue
            clean_src = raw.strip()
            if clean_src.lower().startswith(('data:', 'blob:', 'javascript:')): continue
            if clean_src.startswith('//'): clean_src = f"https:{clean_src}"
            nested_asset_url = urljoin(page_url, clean_src)
            parsed_nested = urlparse(nested_asset_url)
            nested_netloc = parsed_nested.netloc.lower()
            nested_path = parsed_nested.path.strip()
            if any(c in nested_netloc for c in [' ', ',', '(', ')', '{', '}']): continue
            if any(c in nested_path for c in [' ', ',', '(', ')', '{', '}']): continue
            rel_path = clean_src if "://" in clean_src else ('/' + nested_path.lstrip('/') if nested_path else '/')
            if rel_path not in discovered_in_js:
                discovered_in_js[rel_path] = rel_path
                found_paths.add(rel_path)
                if args.show_prog and (not nd or rel_path not in unique_progress_paths):
                    print(f"Found: {rel_path}"); unique_progress_paths.add(rel_path)
                    if args.show_source: print(f"  └─ Source File: {page_url}")
            nested_safe = (nested_netloc == target_netloc or nested_netloc in allowed_domain_netlocs
                           or any(nested_asset_url.lower().startswith(s.lower()) for s in verified_esl_scripts if s))
            if nested_safe:
                ext_check = clean_src.split("?")[0].split("#")[0]
                if ext_check.lower().endswith(('.js', '.mjs', '.cjs', '.css', '.wxs')):
                    if can_deeper and nested_asset_url not in js_files and ext_check not in js_identities:
                        js_identities.add(ext_check); js_files.append(nested_asset_url)
                        js_depths[nested_asset_url] = current_depth + 1
                        new_js.append((nested_asset_url, current_depth + 1))
                elif not args.spa and is_page_like(nested_path):
                    if can_deeper:
                        r_ident = nested_path
                        if r_ident not in page_identities:
                            page_identities.add(r_ident)
                            new_pages.append((nested_asset_url, current_depth + 1))
                elif ext_check.lower().endswith(SITEMAP_EXTS) and not args.disable_structure_files:
                    if can_deeper:
                        xml_ident = urlparse(nested_asset_url).path if "://" in nested_asset_url else nested_asset_url
                        if xml_ident not in xml_identities:
                            xml_identities.add(xml_ident)
                            new_xml.append((nested_asset_url, current_depth + 1))
        for inline_tag in local_soup.find_all('script'):
            if inline_tag.string:
                for c in re.findall(r'["\'](/?[a-zA-Z0-9_\-\./]+\.(?:js|mjs|cjs|css|wxs))["\']', inline_tag.string):
                    clean_c = c if c.startswith('/') else '/' + c
                    nested_inline_url = urljoin(page_url, clean_c)
                    n_netloc = urlparse(nested_inline_url).netloc.lower()
                    safe = (n_netloc == target_netloc or n_netloc in allowed_domain_netlocs
                            or any(nested_inline_url.lower().startswith(s.lower()) for s in verified_esl_scripts if s))
                    ident = clean_c.split("?")[0].split("#")[0]
                    if safe and can_deeper and nested_inline_url not in js_files and ident not in js_identities:
                        js_identities.add(ident); js_files.append(nested_inline_url)
                        js_depths[nested_inline_url] = current_depth + 1
                        new_js.append((nested_inline_url, current_depth + 1))
                    found_paths.add(clean_c)
                    if clean_c not in discovered_in_js:
                        discovered_in_js[clean_c] = clean_c
        return new_js, new_pages, new_xml

    def process_xml(xml_url, current_depth, res):
        new_js, new_pages, new_xml = [], [], []
        can_deeper = (args.depth is None or current_depth < args.depth)
        scanned_xmls.add(xml_url) 
        all_locs = []
        path_only = urlparse(xml_url).path.lower()
        ct = (res.headers.get('Content-Type', '') or '').lower()

        if path_only.endswith('.txt'):
            if 'html' not in ct:
                temp, legit = [], False
                for line in res.text.splitlines():
                    s = line.strip()
                    if s and not s.startswith('#'):
                        temp.append(s)
                        if s.startswith(('http://', 'https://', '/')): legit = True
                if legit: all_locs.extend(temp)
        elif path_only.endswith(('.gz', '.zip')):
            if getattr(args, 'parse_zip', False):
                import gzip, zipfile, io
                try:
                    decompressed = ""
                    if path_only.endswith('.gz'):
                        decompressed = gzip.decompress(res.content).decode('utf-8', errors='ignore')
                    elif path_only.endswith('.zip'):
                        with zipfile.ZipFile(io.BytesIO(res.content)) as z:
                            names = z.namelist()
                            if names: decompressed = z.open(names[0]).read().decode('utf-8', errors='ignore')
                    if decompressed:
                        if path_only.endswith(('.txt.gz', '.txt.zip')):
                            for line in decompressed.splitlines():
                                s = line.strip()
                                if s and not s.startswith('#'): all_locs.append(s)
                        else:
                            all_locs.extend(re.findall(r'<loc>\s*([^<]+)\s*</loc>', decompressed, re.IGNORECASE | re.DOTALL))
                            all_locs.extend(re.findall(r'<xhtml:link[^>]*href=["\']([^"\']+)["\']', decompressed, re.IGNORECASE))
                            all_locs.extend(re.findall(r'<link>\s*([^<]+)\s*</link>', decompressed, re.IGNORECASE))
                except Exception:
                    pass
        else:
            if '<loc' in res.text.lower() or '<link' in res.text.lower():
                all_locs.extend(re.findall(r'<loc>\s*([^<]+)\s*</loc>', res.text, re.IGNORECASE | re.DOTALL))
                all_locs.extend(re.findall(r'<xhtml:link[^>]*href=["\']([^"\']+)["\']', res.text, re.IGNORECASE))
                all_locs.extend(re.findall(r'<link>\s*([^<]+)\s*</link>', res.text, re.IGNORECASE))

        for loc in all_locs:
            loc_stripped = loc.strip()
            if not loc_stripped: continue
            if "http://" in loc_stripped.lower() or "https://" in loc_stripped.lower():
                loc_netloc = urlparse(loc_stripped).netloc.lower()
                clean_path = loc_stripped if loc_netloc != target_netloc else urlparse(loc_stripped).path
            else:
                clean_path = '/' + loc_stripped.lstrip('/')
            clean_path = '/' + clean_path.lstrip('/') if "://" not in clean_path else clean_path
            if not clean_path or clean_path in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]: continue
            if any(t in clean_path.lower() for t in USELESSSTUFF): continue

            if clean_path.lower().endswith(SITEMAP_EXTS):
                check_map_token = urlparse(clean_path).path if "://" in clean_path else clean_path
                check_map_token = '/' + check_map_token.lstrip('/')
                if check_map_token not in xml_identities and can_deeper:
                    xml_identities.add(check_map_token)
                    nested_url = clean_path if "://" in clean_path else urljoin(target, clean_path)
                    new_xml.append((nested_url, current_depth + 1))
                    if args.show_prog and (not nd or check_map_token not in unique_progress_paths):
                        print(f"New path/file: {clean_path}")
                        if args.show_source: print(f"  └─ Source File: {xml_url}")
                        unique_progress_paths.add(check_map_token)
                continue

            if clean_path not in found_paths:
                found_paths.add(clean_path)
                if args.show_prog and (not nd or clean_path not in unique_progress_paths):
                    print(f"New path/file: {clean_path}")
                    if args.show_source: print(f"  └─ Source File: {xml_url}")
                    unique_progress_paths.add(clean_path)
            if not args.spa and is_page_like(clean_path) and can_deeper:
                resolved = clean_path if "://" in clean_path else urljoin(target, clean_path)
                r_ident = urlparse(resolved).path
                if r_ident not in page_identities and urlparse(resolved).netloc.lower() == target_netloc:
                    page_identities.add(r_ident)
                    new_pages.append((resolved, current_depth + 1))

        return new_js, new_pages, new_xml

    async def run_async_scrape():
        nonlocal start_test_time, checktimestatusalready
        async with requests.AsyncSession(
            headers=HEADER, cookies=session_cookies, impersonate=impersonate_settings,
            max_clients=max(1, int(args.concurrency))
        ) as session:
            queue = work_queue[:]
            wave_size = max(1, int(args.concurrency))
            processed_pages = 0
            limit = getattr(args, 'html_crawl_limit', None)
            while queue:
                if args.scan_timeout:
                    ts, checktimestatusalready = checktime(start_test_time, args.scan_timeout, checktimestatusalready, (not args.no_auto_input), autoinput_timeout)
                    if ts == "STOP": break
                    elif ts == "EXTEND":
                        start_test_time = time.perf_counter(); args.scan_timeout = 5.0

                wave, queue = queue[:wave_size], queue[wave_size:]
                wave = [(k, u, d) for (k, u, d) in wave if (args.depth is None or d <= args.depth)]
                if not wave: continue
                fetched = await asyncio.gather(*[fetch(session, u) for (k, u, d) in wave])
                for (kind, url, depth), res in zip(wave, fetched):
                    if res is None or res.status_code != 200: continue
                    if kind == 'js':
                        new_js, new_pages, new_xml = process_js(url, depth, res.text)
                    elif kind == 'xml':
                        new_js, new_pages, new_xml = process_xml(url, depth, res)
                    else:
                        new_js, new_pages, new_xml = process_page(url, depth, res.text)
                        processed_pages += 1
                        if limit is not None and processed_pages >= limit:
                            queue = []
                            break
                    for (nu, nd) in new_js:
                        queue.append(('js', nu, nd))
                    for (nu, nd) in new_pages:
                        if not args.spa:
                            queue.append(('page', nu, nd))
                    for (nu, nd) in new_xml:
                        queue.append(('xml', nu, nd))

    asyncio.run(run_async_scrape())
    return emscripten_vfs_detected, start_test_time, checktimestatusalready




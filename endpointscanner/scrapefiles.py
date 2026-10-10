# ill make this in the next update rn its just in enumerateendpoint.py

import time
import re
import sys
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
    current_filename = "raw HTML"

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
            if asset_clean.lower().endswith(('.js', '.mjs', '.cjs', '.wxs')):
                if full_asset_url not in js_files:
                    js_files.append(full_asset_url)
            
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
    current_filename = "raw HTML"
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

def recursive_js_crawler(
    args, target, HEADER, session_cookies, impersonate_settings,
    verified_esl_domains, verified_esl_scripts, patterns,
    JSPDF_SIGNATURE_KEYS, PYODIDE_VFS_PRECISION_PATTERNS,
    cprs, ignored_extensions, USELESSSTUFF, nd,
    found_paths, js_files, scanned_js, discovered_in_js, unique_progress_paths, js_stack,
    start_test_time, checktimestatusalready, autoinput_timeout
):
    # JS loop
    allowed_domain_netlocs = {urlparse(d).netloc.lower() for d in verified_esl_domains if d}
    js_depths = {}
    emscripten_vfs_detected = False
    for path in list(found_paths):
        # check for js, html, and htm (htm is a older version that still exists in many sites)
        if path.lower().endswith(('.js', '.html', '.htm', '.mjs', '.cjs')) and path.lower() not in ['sw.js', 'service-worker.js']:
            target_asset_url = urljoin(target, path)
            asset_netloc = urlparse(target_asset_url).netloc.lower()
            target_netloc = urlparse(target if "://" in target else f"https://{target}").netloc.lower()
            
            is_safe_asset = False
            if asset_netloc == target_netloc:
                is_safe_asset = True
            elif asset_netloc in allowed_domain_netlocs:
                is_safe_asset = True
            elif any(target_asset_url.lower().startswith(s.lower()) for s in verified_esl_scripts if s):
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
            ts, checktimestatusalready = checktime(start_test_time, args.scan_timeout, checktimestatusalready, (not args.no_auto_input), autoinput_timeout) #timer status
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

            current_script_domain = urlparse(js_url).netloc.lower()
            base_target_domain = urlparse(target).netloc.lower()
            
            active_download_cookies = session_cookies if current_script_domain == base_target_domain else None
            js_res = requests.get(js_url, headers=DOWNLOAD_HEADERS, cookies=active_download_cookies, timeout=5, impersonate=impersonate_settings)
            
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

                    for tag in local_soup.find_all(True):
                        raw_src_or_href = tag.get('src') or tag.get('href')
                        if not raw_src_or_href:
                            continue
                            
                        clean_src = raw_src_or_href.strip()
                        if clean_src.lower().startswith(('data:', 'blob:', 'javascript:')):
                            continue
                        if clean_src.startswith('//'):
                            clean_src = f"https:{clean_src}"
                            
                        nested_asset_url = urljoin(js_url, clean_src)
                        parsed_nested = urlparse(nested_asset_url)
                        nested_netloc = parsed_nested.netloc.lower()
                        nested_path = parsed_nested.path.strip()
                        
                        if any(char in nested_netloc for char in [' ', ',', '(', ')', '{', '}']):
                            continue
                        if any(char in nested_path for char in [' ', ',', '(', ')', '{', '}']):
                            continue
                            
                        if "://" in clean_src:
                            rel_path = clean_src
                        else:
                            rel_path = '/' + nested_path.lstrip('/') if nested_path else '/'

                        if rel_path not in discovered_in_js:
                            discovered_in_js[rel_path] = rel_path
                            found_paths.add(rel_path)
                            if args.show_prog and (not nd or rel_path not in unique_progress_paths):
                                print(f"Found: {rel_path}")
                                unique_progress_paths.add(rel_path)
                                if args.show_source: print(f"  └─ Source File: {current_filename}")

                        nested_safe = False
                        if nested_netloc == target_netloc:
                            nested_safe = True
                        elif nested_netloc in allowed_domain_netlocs:
                            nested_safe = True
                            
                        esl_prefix_check = any(nested_asset_url.lower().startswith(s.lower()) for s in verified_esl_scripts if s)
                        if esl_prefix_check:
                            nested_safe = True
                            
                        if nested_safe:
                            if clean_src.lower().endswith(('.js', '.css', '.html', '.htm', '.mjs', '.cjs', '.wxs')):
                                if nested_asset_url not in js_files:
                                    if can_crawl_deeper:
                                        js_files.append(nested_asset_url)
                                        js_depths[nested_asset_url] = current_depth + 1

                    for inline_tag in local_soup.find_all('script'):
                        if inline_tag.string:
                            inline_chunks = re.findall(r'["\'](/?[a-zA-Z0-9_\-\./]*\.js)["\']', inline_tag.string)
                            for c in inline_chunks:
                                clean_c = c if c.startswith('/') else '/' + c
                                nested_inline_url = urljoin(js_url, clean_c)
                                nested_netloc = urlparse(nested_inline_url).netloc.lower()
                                safe_nested_url = False

                                if nested_netloc == target_netloc:
                                    safe_nested_url = True
                                elif nested_netloc in allowed_domain_netlocs:
                                    safe_nested_url = True
                                elif any(nested_inline_url.lower().startswith(s.lower()) for s in verified_esl_scripts if s):
                                    safe_nested_url = True
                                    
                                if safe_nested_url and nested_inline_url not in js_files:
                                    if can_crawl_deeper:
                                        js_files.append(nested_inline_url)
                                        js_depths[nested_inline_url] = current_depth + 1
                                
                                found_paths.add(clean_c)
                                if clean_c not in discovered_in_js:
                                    discovered_in_js[clean_c] = clean_c
                                    if args.show_prog and (not nd or clean_c not in unique_progress_paths):
                                        print(f"Found: {clean_c}")
                                        unique_progress_paths.add(clean_c)
                                        if args.show_source: print(f"  └─ Source File: {current_filename}")


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
                            m_clean = m_clean.strip()
                            if m_clean.startswith('//'):
                                m_clean = f"https:{m_clean}"
                            m_display = f"{m_clean} [Original: {m}]" if m_clean != m else m_clean
                            is_external_link = False
                            if "://" in m_clean:
                                m_netloc = urlparse(m_clean).netloc.lower()
                                allowed_reg_netlocs = {urlparse(d).netloc.lower() for d in verified_esl_domains if d}
                                
                                is_allowed_reg_asset = False
                                if m_netloc == target_netloc:
                                    is_allowed_reg_asset = True
                                elif m_netloc in allowed_reg_netlocs:
                                    is_allowed_reg_asset = True
                                elif any(m_clean.lower().startswith(s.lower()) for s in verified_esl_scripts if s):
                                    is_allowed_reg_asset = True
                                    
                                if not is_allowed_reg_asset:
                                    is_external_link = True
                                    
                            if not is_external_link and "://" not in m_clean and not m_clean.startswith('/'): 
                                m_clean = '/' + m_clean
                                if m_clean != m: 
                                    m_display = '/' + m_display

                            clean_m_stripped = m_clean.lstrip('/')
                            if clean_m_stripped in ['http:', 'https:']:
                                continue
                            if clean_m_stripped.lower().startswith(('http://', 'https://')) and (len(clean_m_stripped) < 11 or "." not in clean_m_stripped):
                                continue
                                    
                            if not m_clean.lower().endswith(ignored_extensions):
                                if m_clean.strip() in ["/", "//", "///", "/.", "/..", "/...", "/./"]: continue
                                if any(term in m_clean.lower() for term in USELESSSTUFF): continue
                                    
                                if emscripten_vfs_detected:
                                    is_fake_vfs_path = False
                                    for vfs_pattern in PYODIDE_VFS_PRECISION_PATTERNS:
                                        if re.match(vfs_pattern, m_clean, re.IGNORECASE):
                                            is_fake_vfs_path = True
                                            break
                                    if is_fake_vfs_path: continue 
                                
                                if not is_external_link and m_clean.lower().endswith(('.js', '.html', '.htm', '.mjs', '.cjs', '.wxs')):
                                    check_nested_url = urljoin(target, m_clean)
                                    nested_netloc = urlparse(check_nested_url).netloc.lower()
                                    
                                    nested_safe = False
                                    if nested_netloc == target_netloc:
                                        nested_safe = True
                                    elif nested_netloc in allowed_domain_netlocs:
                                        nested_safe = True
                                    elif any(check_nested_url.lower().startswith(s.lower()) for s in verified_esl_scripts if s):
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

    return emscripten_vfs_detected, start_test_time, checktimestatusalready

def recursive_xml_crawler(
    args, target, HEADER, session_cookies, impersonate_settings,
    verified_esl_domains, verified_esl_scripts, USELESSSTUFF, nd,
    found_paths, xml_files, xml_depths, unique_progress_paths,
    start_test_time, checktimestatusalready, autoinput_timeout
):
    # right before recursive xml loop
    if not args.disable_structure_files:
        target_netloc = urlparse(target if "://" in target else f"https://{target}").netloc.lower()
        target_apex = '.'.join(target_netloc.split('.')[-2:]) if len(target_netloc.split('.')) >= 2 else target_netloc
        SITEMAP_EXTENSIONS = ('.xml', '.txt', '.rss', '.atom', '.gz', '.zip')
        
        allowed_xml_netlocs = {urlparse(d).netloc.lower() for d in verified_esl_domains if d}

        for f in list(found_paths):
            if f.lower().endswith(SITEMAP_EXTENSIONS):
                if "http://" in f.lower() or "https://" in f.lower():
                    clean_f = f
                    f_domain = urlparse(f).netloc.lower()
                else:
                    clean_f = '/' + f.lstrip('/')
                    f_domain = target_netloc
                    
                is_valid_map_url = False
                if f_domain == target_netloc:
                    is_valid_map_url = True
                elif f_domain in allowed_xml_netlocs:
                    is_valid_map_url = True
                elif any(clean_f.lower().startswith(s.lower()) for s in verified_esl_scripts if s):
                    is_valid_map_url = True
                elif f_domain.endswith('.' + target_apex):
                    is_valid_map_url = True
                    
                if is_valid_map_url:
                    if "://" in clean_f and urlparse(clean_f).netloc.lower() != target_netloc:
                        store_f = clean_f
                    else:
                        store_f = urlparse(clean_f).path if "://" in clean_f else clean_f
                        store_f = '/' + store_f.lstrip('/')
                    if store_f.lower() not in ['/sitemap.xml', 'sitemap.xml']: #do not rescan sitemap.xml
                        if store_f not in xml_files:
                            xml_files.append(store_f)
                            if store_f not in xml_depths:
                                xml_depths[store_f] = 1


        # recursive xml loop
        scanned_or_queued_xml = set(xml_files)
        xml_index = 0
        while xml_index < len(xml_files):
            xmlfile = xml_files[xml_index]
            current_xml_depth = xml_depths.get(xmlfile, 1)

            x_res = None

            if args.depth is not None and current_xml_depth > args.depth:
                xml_index += 1
                continue
            
            if args.scan_timeout:
                ts, checktimestatusalready = checktime(start_test_time, args.scan_timeout, checktimestatusalready, (not args.no_auto_input), autoinput_timeout)
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
                current_xml_domain = urlparse(target_xml_url).netloc.lower()
                base_target_domain = urlparse(target).netloc.lower()

                active_xml_cookies = session_cookies if current_xml_domain == base_target_domain else None
                x_res = requests.get(target_xml_url, headers=DOWNLOAD_XML_HEADERS, cookies=active_xml_cookies, impersonate=impersonate_settings, timeout=3)


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
                                check_map_token = urlparse(clean_path).path if "://" in clean_path else clean_path
                                check_map_token = '/' + check_map_token.lstrip('/')
                                
                                if check_map_token not in scanned_or_queued_xml:
                                    if can_queue_nested_xml:
                                        xml_files.append(check_map_token)
                                        scanned_or_queued_xml.add(check_map_token)
                                        xml_depths[check_map_token] = current_xml_depth + 1
                                        
                                        if args.show_prog and (not nd or check_map_token not in unique_progress_paths):
                                            print(f"New path/file: {clean_path}")
                                            if args.show_source:
                                                print(f"  └─ Source File: {xmlfile}")
                                            unique_progress_paths.add(check_map_token)
                                continue

                                
                            if clean_path not in found_paths:
                                found_paths.add(clean_path)
                                if args.show_prog and (not nd or clean_path not in unique_progress_paths):
                                    print(f"New path/file: {clean_path}")
                                    if args.show_source:
                                        print(f"  └─ Source File: {xmlfile}")
                                    unique_progress_paths.add(clean_path)

            except (KeyboardInterrupt, SystemExit):
                print("Scan cancelled by user.")
                sys.exit(0)
            except: 
                xml_index += 1
                continue
            xml_index += 1
    return start_test_time, checktimestatusalready




'''scrape structure files'''
import sys
import re
import json
from curl_cffi import requests
from urllib.parse import urljoin, urlparse

def scrape_structure_files(args, target, HEADER, impersonate_settings, found_paths, unique_progress_paths, nd, USELESSSTUFF):
    e_files = []
    xml_files = []
    xml_depths = {}
    if not args.disable_structure_files:
        if not args.pipeable:
            print("\nFinding paths from website structure files.")
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
                                    if _local_payload and _local_payload not in ["/", "//", "///", "/.", "/..", "/...", "/./", "/*", "*"]:
                                        
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
                    found_paths.add(manifest_path)
                    
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

                            if not clean_manifest_path or clean_manifest_path in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
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
                    found_paths.add(sw_path)
                    
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

                            if not cleanpath or cleanpath in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
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
                found_paths.add("/.well-known/openid-configuration")
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
                                
                        if not clean_oidc_path or clean_oidc_path in ["/", "//", "///", "/.", "/..", "/...", "/./", "/ "]:
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
    return e_files, xml_files, xml_depths
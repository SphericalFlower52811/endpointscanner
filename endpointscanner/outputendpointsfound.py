'''
Output all the sorted endpoints, or output the raw results into the terminal and into a text file (if applicable)
'''

def display_and_save_results(
    args, show_dead, target,
    results_200, results_services, results_ext, results_subd,
    results_frameworks, results_30x, results_fromotherfiles,
    results_assets, results_dead, unsorted,
    assets_suffix, dead_suffix, invalidated_suffix,
    js_files, xml_files, e_files,
    unsorted_paths, invalidated_count,
    invalidated_endpoints, SENSITIVE_ENDPOINT
):
    if not results_assets:
        asset_suffix = ""
    if not results_dead and not args.disable_sensitive_endpoint:
        dead_suffix = "\nWARNING: There should never be no inaccessble paths on a website.\nThis is most likely a false positive a fault on the script's end.\nReport this to the owner of the script immediately, whether it has found endpoints or not, and what site the script has been tested on."
    if not invalidated_endpoints:
        invalidated_suffix = ""
    if not args.raw_output:
        if results_200:
            print("\n---- ENDPOINTS FOUND ----")
            print("\n".join(f"  {p}" for p in results_200))
        else:
            print("\n----NO ENDPOITNS FOUND----")
            
        if results_services:
            print("\n----SERVICES/APIS USED----")
            print("\n".join(f"  {p}" for p in results_services))
        else:
            print("\n----NO SERVICES/APIS FOUND----")
            
        if results_ext:
            print("\n----EXTERNAL LINKS----")
            print("\n".join(f"  {p}" for p in results_ext))
        else:
            print("\n----NO EXTERNAL LINKS FOUND----")
            
        if results_subd:
            print("\n----SUBDOMAINS----")
            print("\n".join(f"  {p}" for p in results_subd))
        else:
            print("\n----NO SUBDOMAINS FOUND----")
            
        if font_frameworks := results_frameworks: # Using assignment to match your structural logic safely
            print("\n----WEBSITE SOURCE CODE/FILES----")
            print("\n".join(f"  {p}" for p in results_frameworks))
        else:
            print("\n----NO WEBSITE SOURCE CODE/FILES FOUND----")
            
        if results_30x:
            print("\n---- REDIRECTS ----")
            print("\n".join(f"  {p}" for p in results_30x))
        else:
            print("\n----NO REDIRECTS FOUND----")
            
        if not args.disable_extra_files:
            if results_fromotherfiles:
                print("\n---- EXTRA PATHS FROM OTHER FILES ----")
                print("\n".join(f"  {p}" for p in results_fromotherfiles))
            else:
                print("\n----NO EXTRA PATHS FOUND FROM OTHER FILES----")
        else:
            pass
            
        if args.show_assets:
            if results_assets:
                print("\n----WEBSITE MEDIA----")
                print("\n".join(f"  {p}" for p in results_assets))
            else:
                print("\n----NO WEBSITE MEDIA FOUND----")
        else:
            pass
            
        if show_dead:
            if results_dead:
                print("\n---- INACCESSIBLE ----")
                print("\n".join(f"  {p}" for p in results_dead))
            else:
                print("\n---- NONE INACCESSIBLE ----")
                print()
            
        if args.still_show_invalid:
            if invalidated_endpoints:
                print("\n----INVALIDATED (-ssi passed)----")
                print("\n".join(f"  {p}" for p in invalidated_endpoints))
                
        if unsorted:
            print("\n----UNSORTED (Scan timed out)----")
            print("\n".join(f"  {p}" for p in unsorted))
        else:
            if args.scan_timeout:
                if not args.only_res:
                    print("\nAll paths sorted out.")
        
        
        print(f"\n--- Scan Summary ---")
        summary_report = (
            f"Total Accessible Pages: {len(results_200)}\n"
            f"Total Services: {len(results_services)}\n"
            f"Total External References: {len(results_ext)}\n"
            f"Total Source Code/Files: {len(results_frameworks)}\n"
            f"Total Redirects: {len(results_30x)}\n"
            f"Total Assets: {len(results_assets)}{assets_suffix}\n"
            f"Total Inaccessible: {len(results_dead)}{dead_suffix}\n"
            f"Invalidated Endpoints: {invalidated_count}{invalidated_suffix}\n"
        )
        print(summary_report)
        
        if unsorted:
            print(f"Total Unsorted: {len(unsorted)}") 
            
        if args.show_source:
            print("\n----Files Scanned----")
            if js_files:   print("\n".join(f" - {s}" for s in sorted(set(js_files))))
            if xml_files:  print("\n".join(f" - {x}" for x in sorted(set(xml_files))))
            if e_files:    print("\n".join(f" - {e}" for e in sorted(set(e_files))))
                
        if args.output_file:
            try:
                with open(args.output_file, 'w', encoding='utf-8') as f:
                    f.write(f"=== Endpointscanner results for {target} ===\n\n")

                    if results_200:
                        f.write("---- ENDPOINTS FOUND ----\n")
                        f.write("\n".join(f"  {p}" for p in results_200) + "\n")
                    else: 
                        f.write("  ----NO ENDPOINTS FOUND----\n")

                    if results_services:
                        f.write("\n----SERVICES/APIS USED----\n")
                        f.write("\n".join(f"  {p}" for p in results_services) + "\n")
                    else: 
                        f.write("  ----NO SERVICES/APIS FOUND----\n")
                    
                    if results_ext:
                        f.write("\n----EXTERNAL LINKS----\n")
                        f.write("\n".join(f"  {p}" for p in results_ext) + "\n")
                    else: 
                        f.write("  ----NO EXTERNAL LINKS FOUND----\n")

                    if results_subd:
                        f.write("\n----SUBDOMAINS----")
                        f.write("\n".join(f"  {p}" for p in results_subd) + "\n")
                    else:
                        f.write("\n----NO SUBDOMAINS FOUND----\n")
                    
                    if results_frameworks:
                        f.write("\n----SOURCE CODE/FILES----\n")
                        f.write("\n".join(f"  {p}" for p in results_frameworks) + "\n")
                    else: 
                        f.write("----NO SOURCE CODE/FILES FOUND----\n")
                    
                    if results_30x:
                        f.write("\n\n---- REDIRECTS (301/302/307) ----\n")
                        f.write("\n".join(f"  {p}" for p in results_30x) + "\n")
                    else: 
                        f.write("  ----NO REDIRECTS FOUND----\n")

                    if not args.disable_extra_files:
                        if results_fromotherfiles:
                            f.write("\n---- PATHS FROM OTHER FILES ----\n")
                            f.write("\n".join(f"  {p}" for p in results_fromotherfiles) + "\n")
                        else: 
                            f.write("  ----NO EXTRA PATHS FOUND FROM OTHER FILES----\n")

                    if args.show_assets:
                        if results_assets:
                            f.write("\n----WEBSITE ASSETS----\n")
                            f.write("\n".join(f"  {p}" for p in results_assets) + "\n")
                        else: 
                            f.write("  ----NO WEBSITE ASSETS FOUND----\n")

                    if args.show_404s:                      
                        if results_dead:
                            f.write("\n---- INACCESSIBLE (Confirmed 404/403) ----\n")
                            f.write("\n".join(f"  {p}" for p in results_dead) + "\n")
                        else: 
                            f.write("  ----NONE INACCESSIBLE 404/403----\n")
                    if args.still_show_invalid:
                        if invalidated_endpoints:
                            f.write("\n----INVALIDATED (-ssi passed)----")
                            f.write("\n".join(f"  {p}" for p in invalidated_endpoints) + "\n")
                            
                    if unsorted:
                        f.write("\n----UNSORTED (Scan timed out)----\n")
                        f.write("\n".join(f"  {p}" for p in unsorted) + "\n")
                    else:
                        if args.scan_timeout:
                            if not args.only_res:
                                f.write("All paths sorted out.\n")

                    f.write(f"\n--- Scan Summary ---\n")
                    f.write(summary_report)
                    if unsorted:
                        f.write(f"Total Unsorted: {len(unsorted)}")
                        
                    if args.show_source:
                        f.write(f"\n\n----Files Scanned----\n")
                        if js_files:   f.write("\n".join(f" - {s}" for s in sorted(set(js_files))) + "\n")
                        if xml_files:  f.write("\n".join(f" - {x}" for x in sorted(set(xml_files))) + "\n")
                        if e_files:    f.write("\n".join(f" - {e}" for e in sorted(set(e_files))) + "\n")
                    
                print(f"\nResults successfully written to '{args.output_file}'!")
            except Exception as e:
                print(f"\nFailed to write file: {e}")

    else:
        if not args.only_res:
            print("\nEndpoints will not be sorted. Sensitive endpoints like '.git/config' will be automatically skipped.\n")
            print('----Raw Results----\n')
        clean_found_paths = [p for p in unsorted_paths if p not in SENSITIVE_ENDPOINT]
        if clean_found_paths:
            print("\n".join(clean_found_paths))
        if args.still_show_invalid:
            print('----Invalidated (-ssi passed)----\n')
            print("\n".join(f"  {p}" for p in invalidated_endpoints))
            
        if args.show_source:
            print(f"\n\n----Files Scanned----")
            if js_files:   print("\n".join(f" - {s}" for s in sorted(set(js_files))))
            if xml_files:  print("\n".join(f" - {x}" for x in sorted(set(xml_files))))
            if e_files:    print("\n".join(f" - {e}" for e in sorted(set(e_files))))

        if not args.only_res:
            print(f"\nInvalidated Endpoints: {invalidated_count}{invalidated_suffix}")
        if args.output_file:
            try:
                with open(args.output_file, 'w', encoding='utf-8') as fi:
                    if not args.only_res:
                        fi.write('----Raw Results----\n\n')
                    if clean_found_paths:
                        fi.write("\n".join(clean_found_paths) + "\n")
                    if args.still_show_invalid:
                        fi.write('----Invalidated (-ssi passed)----\n\n')
                        fi.write("\n".join(f"  {p}" for p in invalidated_endpoints) + "\n")
                        
                    if args.show_source:
                        fi.write(f"\n\n----Files Scanned----\n")
                        if js_files:   fi.write("\n".join(f" - {s}" for s in sorted(set(js_files))) + "\n")
                        if xml_files:  fi.write("\n".join(f" - {x}" for x in sorted(set(xml_files))) + "\n")
                        if e_files:    fi.write("\n".join(f" - {e}" for e in sorted(set(e_files))) + "\n")
                    if not args.only_res:
                        fi.write(f"\nInvalidated Endpoints: {invalidated_count}{invalidated_suffix}" + "\n")
                print(f"\nRaw results successfully written to '{args.output_file}'")
            except Exception as e:
                print(f'\nFailed to write raw results to file: {e}')

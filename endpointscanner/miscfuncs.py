'''
This file contains misc. functions that are short functions put into one file.
Functions:
- Check if the target is local
- Check if time limit for scan has passed (only for -st flag)
- Passing and loading all the arguments for the tool.
- checking uptime of the target
- Testing the HTTP protocol of the target, 
- and for external script loaders (only relevant if -esl is passed)

and more functions.
'''

from urllib.parse import urljoin, urlparse
import ipaddress
import time
import argparse
from colorama import init, Fore, Style
from curl_cffi import requests
from .headerconfig import HEADER
import sys
import platform

def timeout_input(prompt, timeout=90, default='y', auto_input_enabled=True):
    if not auto_input_enabled:
        try:
            val = input(prompt)
            return val.strip() if val is not None else ""
        except (KeyboardInterrupt, SystemExit):
            print("\n[!] Scan cancelled by user.")
            sys.exit(0)

    if platform.system().lower() != 'windows':
        import select
        print(prompt, end='', flush=True)
        try:
            ready, _, _ = select.select([sys.stdin], [], [], timeout)
            if ready:
                val = sys.stdin.readline()
                return val.strip() if val is not None else default
            else:
                print() # Drop cursor down cleanly
                if default == "RAISE_INTERRUPT":
                    raise KeyboardInterrupt
                return default
        except (KeyboardInterrupt, SystemExit):
            raise KeyboardInterrupt

    else:
        import threading
        user_data = {'input': None, 'interrupted': False}
        
        def read_input():
            try:
                raw_val = input(prompt)
                if raw_val is not None:
                    user_data['input'] = raw_val.strip()
            except (KeyboardInterrupt, SystemExit):
                user_data['interrupted'] = True
            except:
                user_data['input'] = default

        input_thread = threading.Thread(target=read_input)
        input_thread.daemon = True
        input_thread.start()
        
        input_thread.join(timeout)
        
        if input_thread.is_alive():
            print()
            if default == "RAISE_INTERRUPT":
                raise KeyboardInterrupt
            return default
            
        if user_data['interrupted']:
            raise KeyboardInterrupt
            
        return user_data['input'] if user_data['input'] is not None else default

def check_if_local(target_url):
    try:
        parsed = urlparse(target_url)
        hostname = parsed.hostname
        if not hostname:
            return False
        if hostname in ("localhost", "127.0.0.1") or hostname.endswith((".local", ".lan", ".internal")):
            return True
        try:
            if ipaddress.ip_address(hostname).is_private:
                return True
        except ValueError:
            pass
    except Exception:
        pass
        return False
    
def checktime(st, at, als, auto_input_enabled=True):
    global start_test_time
    ct = time.perf_counter()
    em = (ct - st) / 60
    if em >= at:
        if als == "s":
            return "STOP", "s"
        elif als == "e":
            return "EXTEND", "e"
        print(f"Scan has reached your chosen time limit of {at} minutes.")
        choice = timeout_input(
            prompt="Continue scan for another 5 minutes? (y/n): ",
            timeout=90, 
            default='n', 
            auto_input_enabled=auto_input_enabled
        )
        choice = choice.strip().lower()
        if choice in ['y', 'yes']:
            print('Time limit extended for 5 minutes. Continuing scan...')
            als = "e"
            return "EXTEND", als
        else:
            if choice in ['n', 'no']:
                print('Scan stopped. Any data found in the time window will be printed.')
                print('Sensitive endpoints like ".git/config" will be automatically skipped.')
            else:
                print('Choice not recognised, and will be defaulted to no.')
                print('Scan stopped. Any data found in the time window will be printed.')
                print('Sensitive endpoints like ".git/config" will be automatically skipped.')
            als = "s"
            return "STOP", als
    return "CONTINUE", "c"

#arguments/flag
def startcodeargs():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", nargs='?', help="URL")
    parser.add_argument("-r", "--ratelimit", nargs='?', const=100, type=int, default=None, help="Number of requests to send during the rate limit test. Default is 100.")
    parser.add_argument("-rt", "--ratelimit-type", type=str, default="GET", choices=['GET', 'POST', 'PATCH', 'PUT'], help="HTTP Method to use for the rate limit test. Defaults to GET.")
    parser.add_argument("-rb", "--ratelimit-body", type=str, default=None, help="Payload data to send in request to use for POST, PATCH and PUT requests. If the custom payload contains double quotes, please use single quotes instead of double quotes to pass this flag.")
    parser.add_argument("-rv", "--ratelimit-var", type=str, default=None, help="Variable in payload data (e.g. {X}) to use.")
    parser.add_argument("--force", action="store_true", help="Mandatory flag to pass if doing a rate limit test with over 2500 requests using a non-GET HTTP method. Has no short form flag.")
    parser.add_argument("-t", "--testpath", nargs='?', const='/', type=str, help="Endpoint to test for rate limiting.")
    parser.add_argument("-s", "--show-404s", action="store_true", help="Show endpoints tested that returned a 404 or an SPA shell.")
    parser.add_argument("-d", "--disable-extra-files", action="store_true", help="Disable scanning of extra structural mapping files (robots, sitemaps, manifests, etc.)")
    parser.add_argument("-m", "--show-media", action="store_true", help="Include assets/media like images and fonts and videos in scan results")
    parser.add_argument("-sp", "--show-prog", action="store_true", help="Print endpoints to the terminal one by one in real-time as they are found. Warning: Progress will show duplicate paths if endpoints are defined multiple times in the code. Use the flag -nd to remove duplicates from progress. Results will not contain duplicates.")
    parser.add_argument("-o", "--output-file", type=str, default=None, help="Save formatted results directly to a local text file.")
    parser.add_argument("-do", "--disable-og", action="store_true", help="Disable code from showing the original endpoint with variables. Keeps output tidier. Will NOT remove original tag from progress if the --show-prog flag is present.")
    parser.add_argument("-ti", "--tidy", action="store_true", help="Script will not show where it got extra endpoints from, and will not show if it is a client side route and requires login, or react shell. Will also not show if an endpoint is a potential service.")
    parser.add_argument("-ta", "--tidy-all", action="store_true", help="Flags --disable-og and --tidy combsined.")
    parser.add_argument("-ed", "--extra-details", action="store_true", help="Print out extra info that may not be directly related to the endpoints")
    parser.add_argument("-oo", "--only-original", action="store_true", help="Only show the original version of the flag instead of it being replaced with a 1. Will also affect show prog.")
    parser.add_argument("-ss", "--show-source", action="store_true", help="Print the source of each endpoint during progress, like printing out which file it found the endpoint from.")
    parser.add_argument("-st", "--scan-timeout", type=float, default=None, help="Stop scan completely after given number of minutes and print/save any results found in that time window. Will leave unsorted endpoints in a section labelled 'UNSORTED', and will leave out sensitive endpoints. Will NOT interrupt rate limiting test.")
    parser.add_argument("-ro", "--raw-output", action="store_true", help="Do not sort out endpoints after finding them. Will leave out sensitive endpoints whether they are exposed or not. Also means media will be shown regardless of -m, inaccessible will be shown regardless of -s, and so on.")
    parser.add_argument("-rh", "--ratelimit-header", type=str, default=None, help="Custom headers. Must be seperated by a pipe(|), or newlines. Example use: Cookies: {ExampleCookie: example} | Accept: application/json, text/plain, */*. If the custom header contains double quotes, please use single quotes instead of double quotes to pass this flag.")
    parser.add_argument("-nd", "--no-duplicate-prog", action="store_true", help="If --show-progress is passed, duplicate endpoints in progress will not be shown.")
    parser.add_argument("-l", "--local", action="store_true", help="Necessary flag if the site being tested on is a local site like a localhost or 127.0.0.1:port.")
    parser.add_argument("-ndc", "--no-detect-captcha", action="store_true", help="Flag to disable captcha detection function, in case it returns false positives and did not actually get blocked but thinks it did.")
    parser.add_argument("-esl", "--external-script-loader", action="append", default=[], help="Add external domains used for loading script files into the website itself so that their code files will also be scanned for endpoints.")
    parser.add_argument("-aep", "--all-esl-protocol", type=str, default=None, choices=['https', 'http'], help="Flag to automatically add https/http to every single external script loader that is not defined at the start. Does nothing if -esl is not passed.")
    parser.add_argument("-eH", "--extra-header", action="append", default=[], help="Add extra headers you want for the website like cookies or authorization etc. Also applies to rate limit test if -orlt is passed.")
    parser.add_argument("-nh", "--no-headless", action="store_true", help="Playwright browser used will not be headless, serves as a debug function.")
    parser.add_argument("-dse", "--disable-sensitive-endpoint", action="store_true", help="Flag to disable testing the 23 sensitive endpoints, allowing the tool to send less requests.")
    parser.add_argument("-ssi", "--still-show-invalid", action='store_true', help='Show endpoints that were flagged as invalid.') 
    parser.add_argument("-orlt", "--only-ratelimit-test", action='store_true', help="Make the scanner only test for rate limiting.")
    parser.add_argument("-rat", "--ratelimit-await-time", type=int, default=50, help="Adjust rate limiting test await time for small or extremely large request quantities. Default is 50. Time is in seconds.")
    parser.add_argument("-p", "--pipeable", action='store_true', help="Make the tool pipeable by automatically passing other arguments.")
    parser.add_argument("-ps", "--path-sub", type=str, default='1', help="Change the default path normalization replacement from 1 to a custom string.")
    parser.add_argument("-os", "--only-sub", action='store_true', help="Make the tool only output subdomains.")
    parser.add_argument("-oe", "--only-endpoints", action='store_true', help="Make the tool only output endpoints. Does not include assets, services/apis.")
    parser.add_argument("-oea", "--only-endpoints-all", action='store_true', help="Make the tool only output endpoints, assets, services/apis, paths from other files.")
    parser.add_argument("-oc", "--only-comms", action='store_true', help="Make the tool only output communications used like emails and phone numbers.")
    parser.add_argument("-de", "--depth", type=int, default=None, help="How deep the recursive scanning for both js and xml files can go. Defaults to infinite.")
    parser.add_argument("-pz", "--parse-zip", action='store_true', help="Allow the tool to expand .zip and .gz files (e.g. sitemap.xml.gz) and scrape from them.")
    parser.add_argument("-nai", "--no-auto-input", action='store_true', help="Disable automatic input after 1.5 min.")
    args = parser.parse_args()

    args.only_res = not args.extra_details
    if args.pipeable:
        args.raw_output, args.only_res, args.tidy_all = True, True, True
    if args.raw_output:
        args.disable_sensitive_endpoint = True

    github_link = "https://github.com/SphericalFlower52811/endpointscanner"
    docs_link = "https://sphericalflower52811.github.io/endpointscanner/"

    if not args.pipeable:
        init(autoreset=True)
        print()
        print("-" * 65)
        print(f"{Style.BRIGHT}Endpointscanner {Fore.LIGHTMAGENTA_EX}v7.5.0 {Fore.RED}(DEBUG){Fore.RESET}")
        print()
        print(f"Made by: {Fore.LIGHTMAGENTA_EX}SphericalFlower52811")
        print("(I was too lazy to make a 3D ASCII banner, nor do I want one.)")
        print()
        print(f"{Fore.LIGHTBLUE_EX}GitHub: {Fore.RESET}{Style.BRIGHT}{github_link}")
        print(f"{Fore.LIGHTBLUE_EX}Docs:   {Fore.RESET}{Style.BRIGHT}{docs_link}")
        print("-" * 65)
        print()

    if args.only_ratelimit_test:
        if not args.ratelimit:
            print("--ratelimit flag not passed but -orlt was passed. Exiting script...")
            sys.exit(1)
        args.disable_sensitive_endpoint = True
        args.disable_extra_files = True
    if args.no_duplicate_prog and not args.show_prog:
        print("-nd was passed but -sp wasn't passed. -nd will be deactivated as it is only for progress.")
        args.no_duplicate_prog = False
    #ratelimit type always defaults to get
    if (args.ratelimit_type != 'GET' or args.ratelimit_var or args.ratelimit_body or args.ratelimit_header) and args.ratelimit is None:
        passedrateargs = []
        if args.ratelimit_body: passedrateargs.append("-rb")
        if args.ratelimit_var: passedrateargs.append("-rv")
        if args.ratelimit_header: passedrateargs.append("-rh")
        if args.ratelimit_type: passedrateargs.append("-rt")
        print(f"Arguments {', '.join(passedrateargs)} were passed, but --ratelimit was not passed.")
        user_input = timeout_input("How many requests do you want to send for this rate limiting test? Press Enter to skip.\n >>> ",
                                   timeout=90,
                                   default='',
                                   auto_input_enabled=(not args.no_auto_input))
        user_input = user_input.strip()
        try:
            user_input = int(user_input)
            args.ratelimit = user_input
        except ValueError:
            if user_input == None:
                print("Test skipped by user.", end=' ')
            else:
                print("Invalid input.", end=' ')
            print("Rate limit test will not be carried out.")
    if args.ratelimit_header:
        normalized_rh_check = args.ratelimit_header.replace('\r\n', '|').replace('\n', '|')
        check_lines = [line.strip() for line in normalized_rh_check.split('|') if line.strip()]
        if check_lines:
            first_line_check = check_lines[0]
            if 'http/' in first_line_check.lower():
                words_check = first_line_check.split()
                if words_check:
                    detected_verb = words_check[0].upper()
                    # sync rh and rt
                    if detected_verb != args.ratelimit_type.upper():
                        args.ratelimit_type = detected_verb
    if args.testpath and args.ratelimit is None:
        args.ratelimit = 100 
    notget = args.ratelimit_type.upper() in ['POST', 'PATCH', 'PUT']
    if notget and args.ratelimit >= 1000:
        if args.ratelimit >= 2500:
            if not args.force:
                print(f"\nYou have requested a rate limit test of {args.ratelimit} requests that are not GET requests.")
                print("This can easily cause a Denial of Service in a website if it is not properly guarded.")
                print("It is highly recommended a lower number of requests is chosen to avoid causing a DoS, and to test for rate limiting with a non-GET HTTP method.")
                print("Scan will not be executed. In order to run the script with this number of requests, the --force flag must be passed.")
                sys.exit(1)
        else:
            if not args.force:
                print(f"\nYou are requesting to run a rate limit test of {args.ratelimit} requests that are not GET requests.")
                print("This may cause the server to slow down if it is not properly guarded and exhaust it.")
                proceed = timeout_input("Do you wish to continue running the script and run the test after the scan? [y/n]\n\n >>> ",
                                        timeout=90,
                                        default='n',
                                        auto_input_enabled=args.no_auto_input)
                proceed = proceed.lower()
                if proceed not in ['y', 'yes']:
                    print('Script cancelled.')
                    sys.exit(0)
    if args.ratelimit:
        if args.ratelimit_var and not args.ratelimit_body:
            print("\nA rate limit test payload variable was defined, but no payload was provided.")
            print("Scan will not be executed. Please specify a request payload with -rb if you would like to use the rate limit variable.\n")
            sys.exit(1)
            
        if args.ratelimit_body and args.ratelimit_var:
            # bracket escaping, so if someone puts {{X}} or X, it will end up as {X}.
            expected_bracket_token = args.ratelimit_var

            if expected_bracket_token not in args.ratelimit_body:
                print(f"\nRate limit test iterator variable was defined as '{args.ratelimit_var.strip('{}')}'.")
                print(f"Payload body is missing the expected placeholder: {expected_bracket_token}")
                print("Example usage: -rb '{\"account_id\": \"{X}\"}' -rv 'X'")
                print("Scan will not be executed. Please correct your payload string syntax and re-run.\n")
                sys.exit(1)
    args.disable_og = True if args.only_original == True else args.disable_og
    #tests for new flags
    #args.show_prog = True #comment out later, for testing.
    #args.show_source = True
    #args.scan_timeout = 0.5
    if args.only_original:
        args.disable_og = True
    args.show_assets = args.show_media
    if args.tidy_all == True:
        args.disable_og, args.tidy = True, True

    if args.testpath and args.ratelimit is None:
        parser.error("--testpath requires the --ratelimit flag.\nIf you want to do a rate limit test, use --ratelimit (number of requests) --testpath (path to test).\nIf not, don't use --ratelimit nor --testpath.")
    
    return args

def checkserveruptime(target, HEADER, impersonate_settings, args):
    try:
        st = time.perf_counter()
        uptimeres = requests.get(target, headers=HEADER, timeout=10, impersonate=impersonate_settings)
        et = time.perf_counter()
        restime = et - st
        if not args.only_res:
            print(f"Site responded in {round(restime, 2)} seconds.")
        if not args.only_res:
            if restime < 0.5:
                print("Server is very fast.")
            elif restime < 1:
                print("Server is fast.")
            elif restime < 2.5:
                print("Server is average speed.")
            elif restime < 4:
                print("Server is slow.")
            else:
                print("Server is very slow.")
        return round(restime, 2)
    except requests.exceptions.Timeout:
        print("Server did not respond after 10 seconds.")
        print("Quitting script...")
        sys.exit(1)

def testhttpprotocol(target, HEADER, impersonate_settings, args):
    try:
        response = requests.get(target, headers=HEADER, timeout=5, impersonate=impersonate_settings)
    except requests.exceptions.SSLError:
        if target.startswith("https://"):
            print('HTTPS SSL Error. Trying HTTP...') #becuase some sites may use http instead of https
            target = target.replace("https://", "http://")
            try:
                if not args.local:
                    response = requests.get(target, headers=HEADER, timeout=5, impersonate=impersonate_settings)
            except Exception as e:
                print(f'Target unreachable on HTTP: {e}')
                sys.exit(1)
    except requests.exceptions.Timeout:
        print("Server did not respond after 10 seconds.")
        print("Quitting script...")
        sys.exit(1)
    except Exception as e:
        print(f'Target unreachable: {e}')
        if "127.0.0.1" in target or "localhost" in target:
            print("\nRecommended to use the -l flag for localhosts.")
        sys.exit(1)
        
    return target

def verifyeacheslprotocol(listofesl, all_esl_protocol=None):
    cleanedesllist = []
    for domain in listofesl:
        domain = domain.strip().lower()
        if not domain.startswith(('https://', 'http://')):
            if all_esl_protocol:
                domain = f"{all_esl_protocol}://{domain}"
                cleanedesllist.append(domain)
            else:
                print(f"HTTP protocol for external script loader {domain} is not defined. Script will not be ran.\n")
                print(f"To solve this in the future, either manually add https:// or http:// to every single url, or pass the -aep flag along with your intended protocol.")
                sys.exit(1)
        else:
            cleanedesllist.append(domain)
    return list(set(cleanedesllist))
            
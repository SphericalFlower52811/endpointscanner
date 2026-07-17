'''
browser functions for the playwright headless browser.
Functions:
- Moving the mouse like a human
- Detecting CAPTCHA/anti-bot software 
- Using playwright to retrive hydrated html code and for anti-bot software clearance cookies.
'''

import random
from playwright.sync_api import sync_playwright #headless browser to solve captcha
from playwright_stealth import Stealth #ensure strict firewalls do not block the playwright browser
import time
from .headerconfig import HEADER

#move mouse like a human for playwright stealth.
def human_mouse_move(page, start_x, start_y, end_x, end_y, steps=20):
    current_x, current_y = start_x, start_y
    
    for i in range(steps):
        t = (i + 1) / steps

        target_x = start_x + (end_x - start_x) * t
        target_y = start_y + (end_y - start_y) * t
        
        # jitter
        jitter_reduction = (1 - t)
        current_x = target_x + (random.uniform(-4, 4) * jitter_reduction)
        current_y = target_y + (random.uniform(-4, 4) * jitter_reduction)
        
        page.mouse.move(int(current_x), int(current_y))
        
        time.sleep(random.uniform(0.003, 0.012))
        
    # land on the actual place.
    page.mouse.move(end_x, end_y)

def isthere_captcha(response, playwright_html=None):
    html_content = playwright_html if playwright_html else response.text
    html_lower = html_content.lower()
    
    #cf
    if "turnstile-wrapper" in html_content or "cf-challenge" in html_content:
        return True, "Cloudflare Turnstile"
    if "window._cf_chl_opt" in html_content or "cf-ray:" in html_lower:
        return True, "Cloudflare WAF"
    #px
    if "window._pxappid" in html_lower or 'content="px-captcha"' in html_lower or "window._pxuuid" in html_lower:
        return True, "HUMAN Security (PerimeterX) CAPTCHA"
    if "captcha.px-cdn.net" in html_content or "client.perimeterx.net" in html_content:
        return True, "HUMAN Security (PerimeterX) Shield"

    #google recapt
    if "g-recaptcha" in html_lower or "recaptcha.js" in html_lower or "__recaptcha_api" in html_lower:
        return True, "Google reCAPTCHA Challenge"

    # akamai
    if response and ("akam_bm" in response.cookies or "bm_sz" in response.cookies):
        return True, "Akamai Bot Manager"
    if "_sec_challenge" in html_lower or "akamai-extension" in html_lower:
        return True, "Akamai Bot Manager"

    #aws
    if "aws-waf-token" in html_lower or "awswaf" in html_lower:
        return True, "AWS WAF Token Challenge"
    if "amazon captcha" in html_lower or "amzn-captcha" in html_lower:
        return True, "Amazon CAPTCHA"

    # imperva
    if "incapsula" in html_lower or "_incap_" in html_lower:
        return True, "Imperva Incapsula antibot software"
    if response and "visid_incap" in response.cookies:
        return True, "Imperva CAPTCHA"

    #kasada
    if "kpsdk" in html_lower or "ips.js" in html_lower:
        return True, "Kasada Anti-bot software"

    #siteground inside captcha
    if "const sgchallenge" in html_lower or "siteground-captcha" in html_lower or "well-known/sgcaptcha" in html_lower:
        return True, "SiteGround CAPTCHA"
    #blocked by siteground
    if "<title>bg_error_lines</title>" in html_content or 'class="error content background-wrap cloud-blue"' in html_content or 'class="abstract-half-dot--circle"' in html_content:
            return True, "SiteGround Block"
    
    if "BotDetect.Init('BD_Captcha'" in html_content or "#BD_Captcha_CaptchaDiv" in html_content:
        return True, "BotDetect CAPTCHA"

    #Generic Captcha
    if response and response.status_code in [400, 403, 429, 503]:
        generic_signals = ["automated access", "verify you are human", "checking your browser", "access to this page is forbidden"]
        for signal in generic_signals:
            if signal in html_lower:
                return True, f"Generic Firewall Block ({signal.title()})"
        return True, f"Unidentified Security Drop (HTTP {response.status_code})"

    return False, ""

def gethtmlafterload(url, debugbrowser, initial_response=None):
    with sync_playwright() as p:
        try:
            extra_headers = {k: v for k, v in HEADER.items() if k.lower() != "user-agent"}
            browser = p.chromium.launch(
                headless=(not debugbrowser),
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-infobars"
                ])
        except Exception as e:
            error_msg = str(e).lower()
            error_type = type(e).__name__

            # Instructions to install if people do not read instructions the first time
            if "error" in error_type.lower() and ("executable" in error_msg.lower() or "install" in error_msg.lower()):
                print("\nPlaywright installations are missing.")
                print("Please read the installation instructions in the README of the repository.")
                print("README link: https://github.com/SphericalFlower52811/endpointscanner/blob/main/README.md")
                exit(1)
            else:
                print("Unexpected Issue:", e)
            return "", {}
    
        context = browser.new_context(
            user_agent=HEADER['User-Agent'], 
            viewport={'width': 1920, 'height': 1080},
            has_touch=True,
            extra_http_headers=extra_headers
            )
        page = context.new_page()
        Stealth().apply_stealth_sync(page) #stealth

        #go to page and get code, using stealth to bypass captchas
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=60000) #wait for page content to download
            # Start from a natural default position
            start_x, start_y = random.randint(100, 300), random.randint(100, 300)
            page.mouse.move(start_x, start_y)
            time.sleep(random.uniform(0.2, 0.5)) # pause when page is loading, but a random pause.
            
            next_x, next_y = random.randint(400, 700), random.randint(400, 600)
            human_mouse_move(page, start_x, start_y, next_x, next_y, steps=random.randint(15, 25))
            time.sleep(random.uniform(0.1, 0.3)) # micropause
            
            final_x, final_y = random.randint(200, 500), random.randint(200, 400)
            human_mouse_move(page, next_x, next_y, final_x, final_y, steps=random.randint(12, 22))

            #proper scrolling and not teleporting.
            for _ in range(random.randint(3, 5)):
                scroll_amount = random.randint(150, 250)
                page.evaluate(f"window.scrollBy(0, {scroll_amount})")
                time.sleep(random.uniform(0.1, 0.4))

            start_time = time.time()
            while (time.time() - start_time) < 5: #only 5 second later ppl impatient
                mainhtml = page.content()
                # check if there are actually scripts loaded into the html yet
                if ".js" in mainhtml.lower() or "chunk" in mainhtml.lower() or "<script" in mainhtml.lower():
                    break
                time.sleep(0.2)
             
            page.wait_for_timeout(5000) #wait for page to load downloaded content, and cookie
            mainhtml = page.content()
            is_blocked, waf_name = isthere_captcha(initial_response, mainhtml)
            if is_blocked:
                print(f"WARNING!!! Scan is blocked by a captcha.\nCaptcha Detected: {waf_name}")
                browser.close()
                return mainhtml, {}, {"blocked":True, "waf":waf_name}
            cookies = {c['name']: c['value'] for c in context.cookies()}

        except Exception as e:
            print("Unexpected Error:", e)
            mainhtml, cookies = "", {}

        browser.close()
        return mainhtml, cookies, {"blocked":False, "waf":None}
# Website Endpoint Scanner and Rate Limit Tester For Websites (Version 7.2.3)

A fast automated website reconnaissance tool that extracts endpoints, files, and even external links from websites. Automates IDOR and broken access control vulnerability testing through replacing variables with 1 in endpoints. Has a built in rate limit tester that can test on any endpoint, and can bypass simple WAFs/captchas and client-side SPAs.

For Installation, please go to the Installation section below!

## How it works

- Uses curl_cffi and playwright-stealth to bypass simple captchas
- Uses a fake path to test which are real paths and which are shells. (websites like SPAs give a lot of trouble to current tools)
- Scrapes all `.js` and `.xml` files and `<script>` tags inside the html with a regex to find paths
- Has a hardcoded set of paths that should never exist in a website to test. (e.g. .env.local, .git/config)
- Differentiates paths by website endpoints, assets, redirects etc.
- Autofills {id} variables in endpoints as '1' to test the endpoints (can reveal potential IDORs)
- Checks server uptime and prints out JS Stack of the website
- Has a rate limit tester by sending n requests to a certain endpoint
- Can scan extra files like robots.txt for more endpoints
- Also scans for assets like images with a flag to disable showing them

## How to run

Command to run after installing **(For installation, look for the 'Installation' section.)**:

Passable arguments:

| Argument                | Short Form | Description                                                                                                                                                                                                                                                                  |
| :---------------------- | :--------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `target`                | `NIL`      | URL                                                                                                                                                                                                                                                                          |
| `--ratelimit`           | `-r`       | Number of requests to send during the rate limit test. Default is 100.                                                                                                                                                                                                       |
| `--ratelimit-type`      | `-rt`      | HTTP Method to use for the rate limit test. Defaults to GET.                                                                                                                                                                                                                 |
| `--ratelimit-body`      | `-rb`      | Payload data to send in request to use for POST, PATCH and PUT requests. If the custom payload contains double quotes, please use single quotes instead of double quotes to pass this flag.                                                                                  |
| `--ratelimit-var`       | `-rv`      | Variable in payload data (e.g. {X}) to use.                                                                                                                                                                                                                                  |
| `--ratelimit-header`    | `-rh`      | Custom headers. Must be seperated by a pipe(\|), or newlines. Example use: Cookies: {ExampleCookie: example} \| Accept: application/json, text/plain, _/_. If the custom header contains double quotes, please use single quotes instead of double quotes to pass this flag. |
| `--force`               | `NIL`      | Mandatory flag to pass if doing a rate limit test with over 2500 requests using a non-GET HTTP method. Has no short form flag.                                                                                                                                               |
| `--testpath`            | `-t`       | Endpoint to test for rate limiting.                                                                                                                                                                                                                                          |
| `--show-404s`           | `-s`       | Show endpoints tested that returned a 404                                                                                                                                                                                                                                    |
| `--disable-extra-files` | `-d`       | Disable scanning of extra structural mapping files (robots, sitemaps, manifests, etc.)                                                                                                                                                                                       |
| `--show-media`          | `-m`       | Include assets/media like images and fonts in scan results                                                                                                                                                                                                                   |
| `--show-prog`           | `-sp`      | Print endpoints to the terminal one by one in real-time as they are found. Warning: will show duplicate paths if endpoints are defined multiple times in the code. Results will not contain duplicates.                                                                      |
| `--output-file`         | `-o`       | Save formatted results directly to a local text file.                                                                                                                                                                                                                        |
| `--disable-og`          | `-do`      | Disable code from showing the original endpoint with variables. Keeps output tidier. Will NOT remove original tag from progress if the --show-prog flag is present.                                                                                                          |
| `--tidy`                | `-ti`      | Script will not show where it got extra endpoints from, and will not show if it is a client side route and requires login, or react shell etc (or any SPA shell). Will also not show if an endpoint is a potential service.                                                  |
| `--tidy-all`            | `-ta`      | Flags --disable-og and --tidy combined.                                                                                                                                                                                                                                      |
| `--only-res`            | `-or`      | Only show summarised endpoints.                                                                                                                                                                                                                                              |
| `--only-original`       | `-oo`      | Only show the original version of the flag instead of it being replaced with a 1. Will also affect show prog.                                                                                                                                                                |
| `--show-source`         | `-ss`      | Print the source of each endpoint during progress, like printing out which file it found the endpoint from.                                                                                                                                                                  |
| `--scan-timeout`        | `-st`      | Stop scan completely after given number of minutes and print/save any results found in that time window. Will leave unsorted endpoints in a section labelled 'UNSORTED', and will leave out sensitive endpoints. Will NOT interrupt rate limiting test.                      |
| `--raw-output`          | `-ro`      | Do not sort out endpoints after finding them. Will leave out sensitive endpoints whether they are exposed or not.                                                                                                                                                            |

## Installation

You MUST have python 3.9 or above to use this tool!
To install the official [endpointscanner Python package](https://pypi.org/project/endpointscanner/), run the command:

```bash
python3 -m pip install endpointscanner
```

After that, install chromium on playwright (playwright will be installed when you install endpointscanner):

```bash
playwright install chromium
```

### You may need to create a virtual environment if there is PEP 668. (For the endpointscanner installation, not playwright install chromium.)

To create a virtual environment named 'myvenv':

```bash
python3 -m venv myvenv
```

To activate virtual environment on Mac/Linux:

```bash
source myvenv/bin/activate
```

To activate virtual environment on Windows Command Prompt:

```text
myvenv\Scripts\activate
```

To activate virtual environment on Windows PowerShell:

```powershell
myvenv\Scripts\Activate.ps1
```

### Alternative (Not Recommended)

If you do not want to create a virtual environment, you can run:

```bash
python3 -m pip install endpointscanner --break-system-packages
```

to install it without PEP 668.

**Warning**: Using `--break-system-packages` may corrupt your OS-managed python environment. Proceed entirely at your own risk. The author is not liable for any system damage if you run this.

### Updating script

To update the script, you can run:

```bash
python3 -m pip install --upgrade endpointscanner
```

## Example Commands

Example command to run to scan a site (show inaccessible endpoints, show assets, show progress as it finds endpoints, and show files that it got endpoints from):

```bash
endpointscanner https://example.com -s -m -sp -ss
```

Example command to run to test a site (Assuming you are testing 5000 requests and creating 5k accounts)

```bash
endpointscanner example.com -r 5000 -t /signup -rt POST -rb '{"username":"ExampleUser{X}", "pass":"ExamplePassword"}' -rv '{X}' --force -rh 'POST /signup HTTP/2
Host: example.com
Cookie: clearedcaptcha=true
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0
Accept: application/json, text/plain, */*
Accept-Language: en-US,en;q=0.9
Prefer: safe
Accept-Encoding: gzip, deflate, br
Content-Type: application/json
Content-Length: 60
Origin: https://example.com
Referer: https://example.com/
Sec-Fetch-Dest: empty
Sec-Fetch-Mode: cors
Sec-Fetch-Site: same-origin
Priority: u=0
Te: trailers'
```

Example command to only show the original endpoint, only print endpoints and output to a file:

```bash
endpointscanner example.com -oo -or -o examplescan.txt
```

## Weaknesses

- If there is a login page, the script will either show that all of the pages require login, or label all of them as 403.
- If there are shells (e.g. React SPA shells) in the page, it may give false positives for sensitive endpoints. If you see sensitive endpoints in the scan, they may not actually be exposed on the website if the website has a shell. (E.g. .gitignore, .env.local)
- The rate limit test is more susceptible to captchas as it uses a module (httpx, not curl_cffi) that is not built to specifically pass through firewalls/captchas. This is as the httpx module for requests is better for asynchronous functions for rate limit testing on websites.

## What was added

Version 7.2 added:

- Timeout after a set number of minutes (defined with the -st flag). Accepts floats, not just integers.
- Raw output flag to not sort out endpoints. Will make output faster as sorting takes up the majority of the time.
- New rate limit test flags, -rh, -rb, -rv, -rt. Allows defining of the HTTP method for the test, rate limiting headers (Either seperated by newlines or pipes), rate limiting body (may include an {X}), and rate limiting variable (can be defined as {X}, so each body will be different.) Example use is to test login attempts, testing passwords from 1 - 100 with {X} bein the iteration variable.
- -ss flag, shows source files for where endpoints are found in progress and in the final result.
- -oo flag, Show only the original endpoint with variables instead of the version replaced with 1.
- Headers to avoid 304 responses so code and files is always received.
- Detecting of 405 responses.
- More accurate sorting (previous bug that put /api/health in SPAs patched)
- Removed the 'Scraped from JS' label as extra files and html src are being scraped.

Version 7.2.1 (patch update) added:

- fixed bug where paths would still show /
- fixed bug where some external links were coded into files like e.g. https://n. It is not a real link but got included, and the bug was fixed.

Version 7.2.2 just changed wording and description of the tool to be more clear.

Version 7.2.3 added one more sensitive endpoint and fixed bug where some paths would be / from extra files.

## Plans for next version and the future

Version 7.3 is planned to have:

- More JS Stacks to detect
- Detecting what type of captcha was used if the script is blocked.
- Fix pdf keys that look like endpoints (e.g. /Btn, /Widget)
- Fix bug in scanning extra file: openid configuration. (currently no verification that the file is in the config format, meaning on SPAs it will be mistaken as a real file.)

Future plans (May be added in the next version):

- Recursive scanning (Going into each valid path to find more endpoints as some files only show up in specific endpoints.)
- Optimisation to make sorting of endpoints faster

ai assisted code btw

# Legal Disclaimer

Note that this tool is strictly meant for **authorised** testing and security research. Running this script on websites where you are not permitted to do so can result in legal action. The author of this script assumes no responsibility for any misuse or legal consequences from running this script. Ensure you have received permission from the owner of the target website before performing tests or scans on their website.

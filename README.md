# EndpointScanner: Website Endpoint Scanner and Rate Limit Tester (Version 7.3.9)

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
| `--local`               | `-l`       | Pass this flag if the target is a local site like development-server, but is not a localhost/IP address.                                                                                                                                                                     |
| `--ratelimit`           | `-r`       | Number of requests to send during the rate limit test. Default is 100.                                                                                                                                                                                                       |
| `--ratelimit-type`      | `-rt`      | HTTP Method to use for the rate limit test. Defaults to GET.                                                                                                                                                                                                                 |
| `--ratelimit-body`      | `-rb`      | Payload data to send in request to use for POST, PATCH and PUT requests. If the custom payload contains double quotes, please use single quotes instead of double quotes to pass this flag.                                                                                  |
| `--ratelimit-var`       | `-rv`      | Variable in payload data (e.g. {X}) to use.                                                                                                                                                                                                                                  |
| `--ratelimit-header`    | `-rh`      | Custom headers. Must be seperated by a pipe(\|), or newlines. Example use: Cookies: {ExampleCookie: example} \| Accept: application/json, text/plain, _/_. If the custom header contains double quotes, please use single quotes instead of double quotes to pass this flag. |
| `--force`               | `NIL`      | Mandatory flag to pass if doing a rate limit test with over 2500 requests using a non-GET HTTP method. Has no short form flag.                                                                                                                                               |
| `--testpath`            | `-t`       | Endpoint to test for rate limiting.                                                                                                                                                                                                                                          |
| `--show-404s`           | `-s`       | Show endpoints tested that returned a 404 or an SPA shell.                                                                                                                                                                                                                   |
| `--disable-extra-files` | `-d`       | Disable scanning of extra structural mapping files (robots, sitemaps, manifests, etc.)                                                                                                                                                                                       |
| `--show-media`          | `-m`       | Include assets/media like images and fonts and videos in scan results                                                                                                                                                                                                        |
| `--show-prog`           | `-sp`      | Print endpoints to the terminal one by one in real-time as they are found. Warning: Progress will show duplicate paths if endpoints are defined multiple times in the code. Use the flag -nd to remove duplicates from progress. Results will not contain duplicates.        |
| `--no-duplicate-prog`   | `-nd`      | If --show-prog is passed, duplicate endpoints in progress will not be shown.                                                                                                                                                                                                 |
| `--output-file`         | `-o`       | Save formatted results directly to a local text file.                                                                                                                                                                                                                        |
| `--disable-og`          | `-do`      | Disable code from showing the original endpoint with variables. Keeps output tidier. Will NOT remove original tag from progress if the --show-prog flag is present.                                                                                                          |
| `--tidy`                | `-ti`      | Script will not show where it got extra endpoints from, and will not show if it is a client side route and requires login, or react shell etc (or any SPA shell). Will also not show if an endpoint is a potential service.                                                  |
| `--tidy-all`            | `-ta`      | Flags --disable-og and --tidy combined.                                                                                                                                                                                                                                      |
| `--only-res`            | `-or`      | Only show summarised endpoints, and not print out extra information. Has an exception if number of endpoints exceeds 3000.                                                                                                                                                   |
| `--only-original`       | `-oo`      | Only show the original version of the flag instead of it being replaced with a 1. Will also affect show prog.                                                                                                                                                                |
| `--show-source`         | `-ss`      | Print the source of each endpoint during progress, like printing out which file it found the endpoint from.                                                                                                                                                                  |
| `--scan-timeout`        | `-st`      | Stop scan completely after given number of minutes and print/save any results found in that time window. Will leave unsorted endpoints in a section labelled 'UNSORTED', and will leave out sensitive endpoints. Will NOT interrupt rate limiting test.                      |
| `--raw-output`          | `-ro`      | Do not sort out endpoints after finding them. Will leave out sensitive endpoints whether they are exposed or not.                                                                                                                                                            |

## Installation

You can install EndpointScanner via PyPI.

### Installation via PyPI (or pip)

You MUST have python 3.9 or above to use this tool!
To install the official [endpointscanner Python package](https://pypi.org/project/endpointscanner/):
Command for MacOS/Linux:

```bash
python3 -m pip install endpointscanner
```

Command for Windows Command Prompt:

```text
py -m pip install endpointscanner
```

After that, install chromium on playwright (playwright will be installed when you install endpointscanner):
Command for MacOS/Linux:

```bash
playwright install chromium
```

Command for Windows Command Prompt:

```text
py -m playwright install chromium
```

### You may need to create a virtual environment if PEP 668 blocks you. (For the endpointscanner installation, not playwright install chromium.) Windows users do not need this step as they will not face the PEP 668 restriction.

To create a virtual environment named 'myvenv':

```bash
python3 -m venv myvenv
```

To activate virtual environment:

```bash
source myvenv/bin/activate
```

#### Alternative for Virtual Environment (Not Recommended)

If you do not want to create a virtual environment, you can run:

```bash
python3 -m pip install endpointscanner --break-system-packages
```

to install it without PEP 668.

**Warning**: Using `--break-system-packages` may corrupt your OS-managed python environment. Proceed entirely at your own risk. The author is not liable for any system damage if you run this.

#### Troubleshooting Windows "Command Not Found" Error:

If you are on Windows (especially a non-admin account) and get an 'command not recognised' error when typing `endpointscanner` or `playwright`, run this command **on PowerShell** (not Command Prompt) to fix user environmental paths automatically:

```powershell
$pDir = (py -c "import sys, os; print(os.path.dirname(sys.executable))"); if ($pDir) { $s = "$pDir\Scripts"; $p = [Environment]::GetEnvironmentVariable("Path", "User"); if ($p -notlike "*$s*") { [Environment]::SetEnvironmentVariable("Path", "$p;$s", "User") } }
```

What the PowerShell command does:
Checks the current version of python being used, and adds that python version as an environmental variable in the computer so you can run `endpointscanner` as a standalone command. Does not require admin privileges.

**Requirements for this command:** Python must already be installed.

**Note:** You MUST close the terminal (not minimise) and open a new one for the changes to work.

#### Updating script

To update the script, you can run:
MacOS and Linux Command:

```bash
python3 -m pip install --upgrade endpointscanner
```

Windows Command:

```bash
py -m pip install --upgrade endpointscanner
```

After that, you will need to install chromium on playwright for the headless browser:

```bash
playwright install chromium
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

## What was added

Version 7.3 added:

- Recursive scanning for sitemaps (all xml files)
- Recursive scanning for javascript files
- Scanning of localhost:port and IP addresses like 127.0.0.1, not just example.com.
- Filtering out Emscripten + Pyodide Virtual File System endpoints as they were false positives.
- More JS Stacks to detect, and more accurate. Full list of stacks after 7.3:
  - React
  - Nuxt.js
  - Next.js
  - Node.js
  - Vue.js
  - Angular
  - Astro
  - Gatsby
  - Remix
  - Solid.js
  - Svelte
  - Alpine.js
  - Backbone.js
  - Ember.js
  - Redux
  - Ruby on Rails
  - Forem (also ruby on rails)
  - Deno
  - Bun
  - jQuery
  - Webpack
  - Vite
  - Turbopack
  - Parcel

Version 7.3.2 fixed a glitch showing robots.txt when it was not scanned.

Version 7.3.3 was another minor patch and included a llms.txt for LLMs to digest.

Version 7.3.4 fixed header for the variable S_HEADER, as it contained an invalid User-Agent Header.

Version 7.3.5 removed endpointscanner from Homebrew.

Version 7.3.6 updated the script to exit if playwright browser does not exist.

Version 7.3.7 was a patch that added vendor.example.com to subdomains to scan as it contains code for the website.

version 7.3.8 gave more time for rate limiting test requests to settle.

Version 7.3.9 removed /admin and /login from the built-in endpoints to test, as they would be removed from the unsorted list from --raw-output flag even if they were found in the javascript code. Also changed fake path to include a random hash behind in case people actually hardcoded such a path.

## Plans for next version and the future

Version 7.4:

- Detecting what type of captcha was used if the script is blocked.
- Optimisation to make sorting of endpoints faster

Future plans (May be added in the next version):
none. please leave any suggestions you want.

## Weaknesses

- If there is a login page, the script will either show that all of the pages require login, or label all of them as 403.
- If there are shells (e.g. React SPA shells) in the page, it may give false positives for sensitive endpoints. If you see sensitive endpoints in the scan, they may not actually be exposed on the website if the website has a shell. (E.g. .gitignore, .env.local)
- The rate limit test is more susceptible to captchas as it uses a module (httpx, not curl_cffi) that is not built to specifically pass through firewalls/captchas. This is as the httpx module for requests is better for asynchronous functions for rate limit testing on websites.

ai assisted code btw

# Legal Disclaimer

Note that this tool is strictly meant for **authorised** testing and security research. Running this script on websites where you are not permitted to do so can result in legal action. The author of this script assumes no responsibility for any misuse or legal consequences from running this script. Ensure you have received permission from the owner of the target website before performing tests or scans on their website.

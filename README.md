# EndpointScanner: Website Endpoint Scanner and Rate Limit Tester (Version 7.5.0 DEBUG)

**Source code at: [EndpointScanner Repository](https://github.com/SphericalFlower52811/endpointscanner)**

Dev branch hosts new features that may not be the full update, main branch will only contain stable updates to install.

**Note: endpoints and paths in this documentation mean the same thing.**

A fast automated website reconnaissance tool for red teaming in cybersecurity that extracts paths, endpoints, files, subdomains, and even external links from websites. Automated IDOR and broken access control vulnerability testing through replacing variables with 1 in endpoints/paths. Has a built in rate limit tester that can test on any endpoint with 4 HTTP methods, and can bypass simple WAFs/captchas and SPAs.

**For Installation, please go to the [Installation section](#installation) below!**

**Feel free to contact me at `sphericalflower@gmail.com` to ask for help on how to use the tool or to leave feedback.**

## How it works

- Uses curl_cffi to bypass simple captchas via TLS/JA3 fingerperint impersonation
- Uses playwright-stealth browser instead of usual Playwright to remove giveaways in the browser. (more details about playwright near the bottom of the README)
- Scans extra map files like `robots.txt` and `sitemap.xml` for more paths
- Uses a fake path to test which are real paths and which are shells. (websites like SPAs give a lot of trouble to current tools)
- Scrapes all `.js` and `.xml` files and `<script>` tags inside the html with a regex to find paths
- Has a hardcoded set of paths that should never exist in a website to test. (e.g. .env.local, .git/config)
- Differentiates paths by website endpoints, assets, redirects etc.
- Replaces {example} variables in paths with a custom string to be able to test the paths, and can also test for broken access control.
- Checks server uptime and prints out JS Stack of the website
- Has a rate limit tester by sending `n` number requests to a certain endpoint with 4 HTTP methods, custom headers, body, variable in request body.

## How to run

Command to run after installing **(For installation, look for the 'Installation' section.)**:

| Argument                       | Short Form | Description                                                                                                                                                                                                                                                                    |
| :----------------------------- | :--------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `target`                       | `NIL`      | URL                                                                                                                                                                                                                                                                            |
| `--ratelimit`                  | `-r`       | Number of requests to send during the rate limit test. Default is 100.                                                                                                                                                                                                         |
| `--ratelimit-type`             | `-rt`      | HTTP Method to use for the rate limit test. Defaults to GET.                                                                                                                                                                                                                   |
| `--ratelimit-body`             | `-rb`      | Payload data to send in request to use for POST, PATCH and PUT requests. If the custom payload contains double quotes, please use single quotes instead of double quotes to pass this flag.                                                                                    |
| `--ratelimit-var`              | `-rv`      | Variable in payload data (e.g. {X}) to use.                                                                                                                                                                                                                                    |
| `--force`                      | `NIL`      | Mandatory flag to pass if doing a rate limit test with over 2500 requests using a non-GET HTTP method. Has no short form flag.                                                                                                                                                 |
| `--testpath`                   | `-t`       | Endpoint to test for rate limiting.                                                                                                                                                                                                                                            |
| `--show-404s`                  | `-s`       | Show endpoints tested that returned a 404 or an SPA shell.                                                                                                                                                                                                                     |
| `--disable-extra-files`        | `-d`       | Disable scanning of extra structural mapping files (robots, sitemaps, manifests, etc.)                                                                                                                                                                                         |
| `--show-media`                 | `-m`       | Include assets/media like images and fonts and videos in scan results                                                                                                                                                                                                          |
| `--show-prog`                  | `-sp`      | Print endpoints to the terminal one by one in real-time as they are found. Warning: Progress will show duplicate paths if endpoints are defined multiple times in the code. Use the flag -nd to remove duplicates from progress. Results will not contain duplicates.          |
| `--output-file`                | `-o`       | Save formatted results directly to a local text file.                                                                                                                                                                                                                          |
| `--disable-og`                 | `-do`      | Disable code from showing the original endpoint with variables. Keeps output tidier. Will NOT remove original tag from progress if the --show-prog flag is present.                                                                                                            |
| `--tidy`                       | `-ti`      | Script will not show where it got extra endpoints from, and will not show if it is a client side route and requires login, or react shell. Will also not show if an endpoint is a potential service.                                                                           |
| `--tidy-all`                   | `-ta`      | Flags --disable-og and --tidy combined.                                                                                                                                                                                                                                        |
| `--only-res`                   | `-or`      | Only show summarised endpoints, and not print out extra information. Has an exception if number of endpoints exceeds 3000, and if external script loaders are not given https/http protocol.                                                                                   |
| `--only-original`              | `-oo`      | Only show the original version of the flag instead of it being replaced with a 1. Will also affect show prog.                                                                                                                                                                  |
| `--show-source`                | `-ss`      | Print the source of each endpoint during progress, like printing out which file it found the endpoint from.                                                                                                                                                                    |
| `--scan-timeout`               | `-st`      | Stop scan completely after given number of minutes and print/save any results found in that time window. Will leave unsorted endpoints in a section labelled 'UNSORTED', and will leave out sensitive endpoints. Will NOT interrupt rate limiting test.                        |
| `--raw-output`                 | `-ro`      | Do not sort out endpoints after finding them. Will leave out sensitive endpoints whether they are exposed or not.                                                                                                                                                              |
| `--ratelimit-header`           | `-rh`      | Custom headers. Must be seperated by a pipe(\|), or newlines. Example use: Cookies: {ExampleCookie: example} \| Accept: application/json, text/plain, \*/\*. If the custom header contains double quotes, please use single quotes instead of double quotes to pass this flag. |
| `--no-duplicate-prog`          | `-nd`      | If --show-progress is passed, duplicate endpoints in progress will not be shown.                                                                                                                                                                                               |
| `--local`                      | `-l`       | Necessary flag if the site being tested on is a local site like a localhost or 127.0.0.1:port.                                                                                                                                                                                 |
| `--no-detect-captcha`          | `-ndc`     | Flag to disable captcha detection function, in case it returns false positives and did not actually get blocked but thinks it did.                                                                                                                                             |
| `--external-script-loader`     | `-esl`     | Add external domains used for loading script files into the website itself so that their code files will also be scanned for endpoints.                                                                                                                                        |
| `--all-esl-protocol`           | `-aep`     | Flag to automatically add https/http to every single external script loader that is not defined at the start. Does nothing if -esl is not passed.                                                                                                                              |
| `--extra-header`               | `-eH`      | Add extra headers you want for the website like cookies or authorization etc.                                                                                                                                                                                                  |
| `--no-headless-browser`        | `-nh`      | Playwright browser used will not be headless, serves as a debug function.                                                                                                                                                                                                      |
| `--disable-sensitive-endpoint` | `-dse`     | Flag to disable testing the 23 sensitive endpoints, allowing the tool to send less requests.                                                                                                                                                                                   |
| `--still-show-invalid`         | `-ssi`     | Show endpoints that were flagged as invalid.                                                                                                                                                                                                                                   |

## Installation

You can install EndpointScanner via PyPI.

### Installation via PyPI (or pip)

#### Main Package

You MUST have python 3.9 or above to use this tool!
To install the official [endpointscanner Python package](https://pypi.org/project/endpointscanner/):

##### Command for MacOS/Linux:

```bash
python3 -m pip install endpointscanner
```

##### Command for Windows Command Prompt:

```text
py -m pip install endpointscanner
```

#### Playwright Installation

After that, install chromium on playwright (playwright will be installed when you install endpointscanner):

##### Command for MacOS/Linux:

```bash
playwright install chromium
```

##### Command for Windows Command Prompt:

```text
py -m playwright install chromium
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

## Comparison against the industry standard

For comparisons against the industry standard, go to the [comparison file](COMPARISON.md)

## Release notes for Update 7.5

### New features in update 7.5

- `-rat`/`--ratelimit-await-time` flag, as th default is 50s and for a PoC with 50-100 requests 50 seconds is way too long.
- `-p`/`--pipeable` flag to make the output of the tool pipeable into other automated payload testing tools. (E.g. sqlmap)
- `-ps`/`--path-sub` flag to change the automated path normalization from replacing variables to 1 to any custom string. Defaults to 1.
- Merged `asset-manifest.json`, `web-manifest.json`, `manifest.json` into one loop.
- added `-de`/`--depth` flag
- added `-ps`/`--path-sub` flag
- Added flags to only print parts of the output
  - `-oe`/`--only-endpoints` flag
    - Only output endpoints
  - `-oea`/`--only-endpoints-all` flag
    - Only print endpoints + assets + inaccessible endpoints
- Made the sitemap loop (which previous only scanned `.xml` files) be able to scan `.xml, .txt, .rss, .atom` files.
  - Able to scan `.gz` and `.zip` files if the flag `-pz`/`--parse-zip` is passed. (Detects based off the file extension)
- Added endpoints to the `SENSITIVE_ENDPOINT` set like actuator endpoints and swagger ui
- Added automatic input where if you don't answer input questions after a set time (e.g. do you want to sort endpoints). Can be disabled via the `-nai/--no-auto-input` flag.
- Fixed a bug in the rate-limiting tester where the rate limit testing function would crash if the number of requests was too high by using a queue.
- Replace `/*` paths in robots.txt with '1' as \* means everything, showing you the original path. This will also be affected by the -ps and -oo flag.
- Added a section to the sorted endpoints which are 'protected endpoints', for endpoints that return 401/403 or other status codes showing it exists but is protected.
- Let the scanner scan `.mjs` and `.cjs` files besides just `.js`
- Allow text files for the -esl flag
- Changed the `-or` flag to the `-ed` flag, now you have to pass `-ed` for the extra details, instead of extra details being shown by default (for example, JS Stack detected). Things like found path count will still be shown.

### Bug Fixes/Code improvements

- Fixed regex problems in the map file check for:
  - `openid-configuration`
  - `asset-manifest.json`
  - `web-manifest.json`
  - `manifest.json`
  - `sw.js`
  - `service-worker.js`
- Changed `-nhb`/`--no-headless-browser` to `-nh`/`--no-headless` as `-nhb` was misleading.
- Fixed an issue where the scraping would find data MIME types (e.g. application/x-javascript) and mistake them for real endpoints
- Fixed a scope bug in the tool
- Improve regex.

## Plans for next version and the future

Continuing 7.5:

- Allow user to add an entire domain, or only one file as an external script loader (e.g. `examplegiganticcdn.com/example.js`)
- Moving large loops like map files into `mapfiles.py`, `scrapefiles.py`, and `filtersort.py`
- Optimise the sorting loop by making it asynchronous
- Properly update `README.md`
- Add `openapi.json` to map files and move it out of `SENSITIVE_ENDPOINT`

Version 7.6:

- Fixing a URL parameter problem in the tool

Future plans (May be added in the next version):

none right now

## Weaknesses

- If there is a login page, the script will either show that all of the pages require login, or label all of them as 403.
- If there are shells (e.g. React SPA shells) in the page, it may give false positives for sensitive endpoints. If you see sensitive endpoints in the scan, they may not actually be exposed on the website if the website has a shell. (E.g. .gitignore, .env.local)
- The rate limit test is more susceptible to captchas as it uses a module (httpx, not curl_cffi) that is not built to specifically pass through firewalls/captchas. This is as the underlying library used to build curl_cffi, libcurl, recommends you not to use more than 15 max connections (see at [curlmopt_max_total_connections docs](https://curl.se/libcurl/c/CURLMOPT_MAX_TOTAL_CONNECTIONS.html)). Httpx was hence used instead of curl_cffi.
  - **This information is accurate as of 11 August 2026.**

ai assisted code btw

## Playwright details:

Playwright is an automated browser which means it launches a browser from the cli that does not load a GUI when in headless mode, which is the mode EndpointScanner uses unless the flag to turn off the headless mode is passed. see more at [Playwright Python module documentation](https://playwright.dev/python/docs/api/class-playwright).

EndpointScanner uses playwright-stealth, playwright-stealth at [Playwright-stealth docs](https://pypi.org/project/playwright-stealth/)

# Legal Disclaimer

Note that this tool is strictly meant for **authorised** testing and security research. Running this script on websites where you are not permitted to do so can result in legal action. The author of this script assumes no responsibility for any misuse or legal consequences from running this script. Ensure you have received permission from the owner of the target website before performing tests or scans on their website.

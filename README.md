# Website Endpoint Scanner and Rate Limit Tester For Websites (Version 7.1)

A fast automated website reconnaissance tool that extracts endpoints, files, and even external links from websites. Tests for IDOR or other broken access control bugs on websites by changing variables in endpoints to 1. Has a built in rate limit tester that can test on any endpoint, and can bypass simple WAFs/captchas and client-side SPAs.

For Installation, please go to the Installation section below!

## How it works

- Uses curl_cffi and playwright-stealth to bypass simple captchas
- Uses a fake path to test which are real paths and which are shells. (websites like SPAs give a lot of trouble to current tools)
- Scrapes all `.js` files and `<script>` tags inside the html with a regex to find paths
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

| Argument                | Short Form | Description                                                                                                                                                                                          |
| :---------------------- | :--------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `target`                | `NIL`      | URL to test                                                                                                                                                                                          |
| `--ratelimit`           | `-r`       | Number of requests                                                                                                                                                                                   |
| `--testpath`            | `-t`       | Endpoint to test                                                                                                                                                                                     |
| `--show-404s`           | `-s`       | Show endpoints tested that returned a 404                                                                                                                                                            |
| `--disable-extra-files` | `-d`       | Disable scanning of extra structural mapping files (robots, sitemaps, manifests, etc.)                                                                                                               |
| `--show-media`          | `-m`       | Include assets/media like images and fonts in scan results                                                                                                                                           |
| `--show-prog`           | `-sp`      | Print endpoints to the terminal one by one in real-time as they are found                                                                                                                            |
| `--output-file`         | `-o`       | Save formatted results directly to a local text file.                                                                                                                                                |
| `--disable-og`          | `-do`      | Disable code from showing the original endpoint with variables. Keeps output tidier. Will NOT remove original tag from progress if the --show-prog flag is present.                                  |
| `--tidy`                | `-ti`      | Script will not show where it got extra endpoints from, and will not show if it is a client side route and requires login, or react shell. Will also not show if an endpoint is a potential service. |
| `--tidy-all`            | `-ta`      | Flags --disable-og and --tidy combined.                                                                                                                                                              |
| `--only-res`            | `-or`      | Only show summarised endpoints.                                                                                                                                                                      |

Example command to run (assuming you are testing on https://example.com):

```bash
endpointscanner https://example.com --ratelimit 100 --testpath /login --show-404s --show-media --show-prog
```

Example but with shorted flags:

```bash
endpointscanner https://example.com -r 100 -t /login -s -m -sp
```

## Installation

You MUST have python 3.9 or above to use this!!
To install endpointscanner, run the command:

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

## Weaknesses

- If there is a login page, the script will either show that all of the pages require login, or label all of them as 403.
- If there are shells (e.g. React SPA shells) in the page, it may give false positives for sensitive endpoints. If you see sensitive endpoints in the scan, they may not actually be exposed on the website if the website has a shell. (E.g. .gitignore, .env.local)

## What was added

Version 7.1 added:

- flag (--show-prog, or -sp) to show endpoints in finds in real time
- flag (--output-file, or -o) to export summarised results to a local text file
- flag (--disable-og, or -do) to disable showing original endpoints (with variables)
- flag (--only-res, or -or) to only show summarised endpoints (No longer shows if server is fast or not, and no longer says JS Stack of website if the flag is passed in the command)
- flag (-ti, or --tidy) to disable extra info like source of the file or client side route in summarised results
- Shortened versions of flags for faster running of the command
- Subdomains section in the summarised results
- Exit code if the server is unreachable (Not responding after 10s)

## Plans for next version and the future

Version 7.2 is planned to have:

- Read extra sitemaps that may have a different name from sitemap.xml
- New flag to only print the original endpoint (and not show it replaced with the number 1)
- Flag to stop the scan after a time (in minutes) has been exceeded
- Check for other errors such as a 405 which means it is a real endpoint on the website
- Different HTTP methods for the rate limit test. (POST, PUT, PATCH will be added)

Future plans:

- Detecting what type of captcha was used if the script cannot bypass it.
- Adding more JS Stacks to the identification function.
- Optimisation to the tool. (Maybe by using an async function to check endpoint accessibility multiple times instead one at a time)

ai assisted code btw

# Legal Disclaimer

Note that this tool is strictly meant for **authorised** testing and security research. Running this script on websites where you are not permitted to do so can result in legal action. The author of this script assumes no responsibility for any misuse or legal consequences from running this script. Ensure you have received permission from the owner of the target website before performing tests or scans on their website.

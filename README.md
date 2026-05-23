# Website Endpoint Scanner and Rate Limit Tester For Websites (Version 7.0.3)

For Installation, please go to the Installation section below!

## How it works

- Uses curl_cffi and playwright-stealth to bypass simple captchas
- Uses a fake path to test which are real paths and which are shells. (websites like SPAs give a lot of trouble to current tools)
- Scrapes all `.js` files and `<script>` tags inside the html with a regex to find paths
- Differentiates paths by website endpoints, assets, redirects etc.
- Autofills {id} variables in endpoints as '1' to test the endpoints (can reveal potential IDORs)
- Checks server uptime and prints out JS Stack of the website
- Has a rate limit tester by sending n requests to a certain endpoint
- Can scan extra files like robots.txt for more endpoints
- Also scans for assets like images with a flag to disable showing them

## How to run

Command to run after installing **(For installation, look for the 'Installation' section.)**:

Example commands to run:

```bash
endpointscanner https://example.com(or the website you want to test) --ratelimit 100 --testpath /app --show-404s --show-assets
```

Passable arguments:

```bash
--ratelimit
--testpath
--show-404s
--disable-extra-files
--show-assets
```

| Argument                | What the argument does                                                                                                                                                                                   |
| :---------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--ratelimit`           | how many requests to send to server to test. Without this argument, the rate limit test is not performed.                                                                                                |
| `--testpath`            | which endpoint to test for rate limiting. Without this argument, the rate limit test will happen on the root directory ('/'). If an endpoint here returns a 404, it also defaults to the root directory. |
| `--show-404s`           | Show inaccessible endpoints.                                                                                                                                                                             |
| `--disable-extra-files` | The script won't scan through extra map files like robots.txt for extra endpoints.                                                                                                                       |
| `--show-assets`         | Show assets like images that the script finds.                                                                                                                                                           |

Example use:

```bash
endpointscanner example.com --ratelimit 100 --testpath /api/v1
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
- If there are shells in the page, it may give false positives for sensitive endpoints. If you see sensitive endpoints in the scan, they may not actually be exposed on the website if the website has a shell. (E.g. .gitignore, .env.local)

## What was added

Version 7.0.3 added:

- Patches for more accuracy in scanning
- Showing original endpoints (replaces with 1, but also prints out the endpoint with variables in the actual website code)

## Plans for next version

Version 7.1 is planned to have:

- Flag to display endpoints as it finds them to show progress
- Flag to export endpoints found to a text file
- Flag to disable showing the original endpoints to reduce cluttering (So it just replaces the endpoint with 1 and doesn't show end original endpoint with variables, makes terminal neater but loses original endpoint)

ai assisted code btw

# Legal Disclaimer

Note that this tool is strictly meant for **authorised** testing and security research. Running this script on websites where you are not permitted to do so can result in legal action. The author of this script assumes no responsibility for any misuse or legal consequences from running this script. Ensure you have received permission from the owner of the target owner before performing tests or scans on their website.

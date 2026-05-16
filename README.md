# Website Endpoint Scanner and Rate Limit Tester For Websites (Version 7)

## How to run

Command to run after installing **(For installation, look for the 'Installation' section.)**:

Example commands to run:

```bash
enumendpoint (domain, e.g. https://example.com) --ratelimit 100 --testpath /app --show-404s --show-assets
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
enumendpoint example.com --ratelimit 100 --testpath /api/v1
```

## Installation

To install enumendpoint, run the command:

```bash
python3 -m pip install git+https://github.com/SphericalFlower52811/endpointscanner.git
```

After that, install chromium on playwright (playwright will be installed when you install endpointscanner):

```bash
playwright install chromium
```

### You may need to create a virtual environment if there is PEP 668.

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
python3 -m pip install git+https://github.com/SphericalFlower52811/endpointscanner.git --break-system-packages
```

to install it without PEP 668.

**Warning**: Using `--break-system-packages` may corrupt your OS-managed python environment. Proceed entirely at your own risk. The author is not liable for any system damage if you run this.

### Updating script

To update the script, you can run:

```bash
python3 -m pip install --upgrade git+https://github.com/SphericalFlower52811/endpointscanner.git
```

## Details

I made this a command line tool that you install with the instructions above

The command prints out how many endpoints to test, and lists them all out after testing them.
It can only bypass simple captchas.
If there is a captcha in the website, it will detect what captcha it is (as long as it is one of the captcha types below)

- google recaptcha
- hcaptcha
- cloudflare turnstile
- perimeterX
- akamai bot manager
- kasada
- incapsula
- amazon captcha

If there are signs of a generic captcha in the website, it will say it is a generic captcha.

The python code scans for endpoints in websites by looking through all the js files listed in the htmml, and also checks <script></script> tags. It also prints what JS type it uses. It scans for code like get, post etc, href and much more.

Types of JS it can detect, but it is a bit buggy and may list the wrong js type.
Node.js
React
Next.js
Vue
Angular
Vite
Webpack

If there is a {id} inside the path, it replaces it with 1 to test the endpoint whether it is a 200 OK, 404/403, or a redirect (30x Header)

404(Soft) means the server incorrectly returns 200 response while giving a 404 page instead.

It also tries very sensitive endpoints like .env, .git/config, and a lot more.

ai assisted code btw

The code prints the website uptime, how many seconds it takes to load and whether it is fast or not.

The code can also test for rate limiting in the website by performing an async function to send 100 GET requests to an endpoint the user wants to test.

## Weaknesses

- If there are shells in the page, it may mistake some sensitive endpoints as real. If you see sensitive endpoints in the scan, they may not actually be exposed on the website if the website has a shell. (E.g. .gitignore, .env)
- If there is a login page, the script will either show that all of the pages require login, or label all of them as 403.

## What was added

Version 7 added:

- Scanning extra map files (e.g. robots.txt, sitemap.xml) for more endpoints
- Being able to show assets
- Hiding inaccessible pages by default

## Plans for next version

Version 8 is planned to have:

- Detecting what captcha was used if it is blocked
- Proper detection of timeouts
- Optimisation (maybe, if not in v9)

# Legal Disclaimer

Note that this tool is strictly meant for **authorised** testing and security research. Running this script on websites where you are not permitted to do so can result in legal action. The author of this script assumes no responsibility for any misuse or legal consequences from running this script. Ensure you have received permission from the owner of the target owner before performing tests or scans on their website.

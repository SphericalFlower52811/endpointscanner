# Website Endpoint Scanner and Rate Limit Tester

## Installation

Run the command:

```bash
python3 -m pip install git+https://github.com/SphericalFlower52811/endpointscanner.git
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

I made this a command line tool

How to run: enumendpoint (domain, e.g. https://example.com) --ratelimit (number of requests to send, default 100) --testpath (endpoint to test rate limiting. Default root domain)

The command prints out how many endpoints to test, and lists them all out after testing them.

The python code scans for endpoints in websites by looking through all the js files listed in the htmml, and also checks <script></script> tags. It also prints what JS type it uses.

If there is a {id} inside the path, it replaces it with 1 to test the endpoint whether it is a 200 OK, 404/403, or a redirect (30x Header)

404(Soft) means there is a 200 response, but a 404 page.

It also tries very sensitive endpoints like .env, .git/config, and a lot more.

If there is a WAF (firewall, basically) in the application, it will sense the sensitive endpoints (including robots.txt) as a 403, even if publicly accessible.

Types of JS it can detect, but it is a bit buggy and may list the wrong js type.
Node.js
React
Next.js
Vue
Angular
Vite
Webpack

ai assisted code btw

It is not good at differentiating between react shells and actual pages in single-page applications though, so after listing endpoints in such websites you would have to test them, cuz some are not allowed while some are.

The code prints the website uptime, how many seconds it takes to load and whether it is fast or not.

The code can also test for rate limiting in the website by performing an async function to send 100 GET requests to an endpoint the user wants to test.

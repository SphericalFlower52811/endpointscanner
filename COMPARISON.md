# Comparisons of EndpointScanner against other tools

## Info

This file will provide a comparison of EndpointScanner against other popular web reconnaissance tools, tested on a website where I have been given permission to pentest by the developer of the website.

Time taken is measured through the MacOS `time` command, and will be present in the tools' outputs.

This information is updated as of 18 October 2026.

## Navigation Links for websites

- [Website 1](#website-1)
- [Website 2](#website-2)

## Website 1

- [Navigation to website 2](#website-2)

### Details

I have not asked for permission to publicly disclose what this website is, so this website will remain anonymous. Files like index-[HASH].js will have the hash censored for privacy purposes and part of some paths will be censored with [HIDDEN]. Parameters will be hidden as {PARAM}. Website will be censored as [TARGET].

### Navigation Links for scanners

- [Jump to EndpointScanner's result](#endpointscanners-result-on-website-1)
- [Jump to Katana's result](#katanas-result-on-website-1)
- [Jump to Gobuster's results](#gobusters-result-on-website-1)
- [Jump to FFuF's results](#ffufs-result-on-website-1)
- [Jump to Feroxbuster's results](#feroxbusters-result-on-website-1)

### Quick Comparison

Note: This is simply a table on how many directories/paths were found and how much time was taken.

The endpoint count will include:

- Valid paths
- Invalid paths (false positives)

and will not include:

- Duplicate paths
- External links
- Subdomains

| Tool                             | Command used                                                                      | Endpoints found | Time taken (in seconds) |
| :------------------------------- | :-------------------------------------------------------------------------------- | :-------------- | :---------------------- |
| **EndpointScanner**              | `time endpointscanner [TARGET] -dse -ds -oo`                                      | **221**         | **16.386**              |
| **Katana** (by ProjectDiscovery) | `time katana -u https://[TARGET] -d 5 -jc`                                        | 4               | 16.187                  |
| **Gobuster**                     | `time gobuster dir -u https://[TARGET] -w common.txt --exclude-length 480 -t 100` | 2               | 20.858                  |
| **FFuF**                         | `time ffuf -u https://[TARGET]/FUZZ -w common.txt -fs 480 -s -t 100`              | 2               | 18.090                  |
| **Feroxbuster**                  | `time feroxbuster -u https://[TARGET] -w common.txt -t 100`                       | 2               | 83.68                   |

> ⚠️: Gobuster and FFuF were run with --exclude-length and -fs respectively as the website is an SPA.

### Full Comparison

---

#### EndpointScanner's result on website 1

<details>
<summary><b>Click to open EndpointScanner's result:</b></summary>

```text
-----------------------------------------------------------------
Endpointscanner v7.5.0

Made by: SphericalFlower52811

GitHub: https://github.com/SphericalFlower52811/endpointscanner
Docs:   https://sphericalflower52811.github.io/endpointscanner/
-----------------------------------------------------------------

Scanning https://[TARGET]...

Scraping files...

Total paths found: 221

Endpoints will not be sorted. Sensitive endpoints like '.git/config' will be automatically skipped.

----Raw Results----

{PARAM}/admin/topics/csv-template
{PARAM}/[HIDDEN]
{PARAM}/[HIDDEN]/{PARAM}/content
{PARAM}/[HIDDEN]/{PARAM}/resolve
{PARAM}/[HIDDEN]/{PARAM}/resolve-apply
{PARAM}/[HIDDEN]/{PARAM}/resolve-status
{PARAM}/[HIDDEN]/{PARAM}/review-answer
/accuracy-explained
/admin
/admin/catalog
/admin/catalog/import
/admin/catalog/packs/{PARAM}
/admin/catalog/packs/{PARAM}/publish
/admin/catalog/[HIDDEN]
/admin/catalog/[HIDDEN]/{PARAM}
/admin/catalog/[HIDDEN]/{PARAM}/attach
/admin/catalog/[HIDDEN]/{PARAM}/preview
/admin/ingest
/admin/[HIDDEN]
/admin/[HIDDEN]/providers/{PARAM}
/admin/[HIDDEN]/test
/admin/[HIDDEN]/test-vision
/admin/[HIDDEN]/workflows/{PARAM}
/admin/[HIDDEN]/workflows/{PARAM}/reset
/admin/pdfs
/admin/[HIDDEN]
/admin/[HIDDEN]/{PARAM}
/admin/[HIDDEN]/import-csv
/admin/settings/email
/admin/settings/email/test
/admin/settings/features
/admin/settings/features/{PARAM}
/admin/settings/users/{PARAM}/beta
/admin/[HIDDEN]
/admin/[HIDDEN]/{PARAM}
/admin/[HIDDEN]/{PARAM}/[HIDDEN]
/admin/[HIDDEN]/{PARAM}/[HIDDEN]/{PARAM}
/admin/[HIDDEN]/{PARAM}/[HIDDEN]/{PARAM}/sub-[HIDDEN]
/admin/[HIDDEN]/{PARAM}/[HIDDEN]/{PARAM}/sub-[HIDDEN]/{PARAM}
/admin/[HIDDEN]/import-csv
/admin/[HIDDEN]/tree
/admin/topics
/admin/topics/{PARAM}
/admin/topics/{PARAM}/subtopics
/admin/topics/{PARAM}/subtopics/{PARAM}
/admin/topics/bulk
/admin/topics/filters
/admin/topics/import-csv
/admin/topics/tree
/admin/users
/admin/users/{PARAM}
/admin/users/{PARAM}/associated-users
/assets/index-[HASH].css
/assets/index-[HASH].js
/[HIDDEN]
/[HIDDEN]/{PARAM}
/[HIDDEN]/{PARAM}/approve
/[HIDDEN]/{PARAM}/class-summary
/[HIDDEN]/{PARAM}/diagnostic-followup
/[HIDDEN]/{PARAM}/diagnostic-report
/[HIDDEN]/{PARAM}/duplicate
/[HIDDEN]/{PARAM}/explanation-cards
/[HIDDEN]/{PARAM}/generation-status
/[HIDDEN]/{PARAM}/meta
/[HIDDEN]/{PARAM}/my-sessions
/[HIDDEN]/{PARAM}/prerequisite-report
/[HIDDEN]/{PARAM}/preview
/[HIDDEN]/:assignmentId/print
/[HIDDEN]/{PARAM}/questions/{PARAM}
/[HIDDEN]/{PARAM}/questions/{PARAM}/regenerate
/[HIDDEN]/{PARAM}/remediation
/[HIDDEN]/{PARAM}/results
/[HIDDEN]/{PARAM}/retry-generation
/[HIDDEN]/{PARAM}/student-review/{PARAM}
/[HIDDEN]/{PARAM}/student-review/{PARAM}/attempts/{PARAM}
/[HIDDEN]/{PARAM}/visibility
/[HIDDEN]/{PARAM}/worksheet
/[HIDDEN]/{PARAM}/worksheet-diagram/{PARAM}
/[HIDDEN]/{PARAM}/worksheet-page/{PARAM}
/[HIDDEN]/{PARAM}/[HIDDEN]
/[HIDDEN]/derive-prerequisite-skills
/[HIDDEN]/extract-mcq-source
/[HIDDEN]/extract-progress/{PARAM}
/[HIDDEN]/extract-worksheet
/[HIDDEN]/mcq-bundle
/[HIDDEN]/parent-assigned
/[HIDDEN]/re-extract-worksheet/{PARAM}
/[HIDDEN]/regenerate-diagram/{PARAM}/{PARAM}
/[HIDDEN]/worksheet-preview-page/{PARAM}/{PARAM}
/auth/forgot-password
/auth/google
/auth/login
/auth/me
/auth/register
/auth/resend-verification
/auth/reset-password
/auth/role
/auth/verify-email
/[HIDDEN]/[HIDDEN]/{PARAM}
/[HIDDEN]/[HIDDEN]/{PARAM}/analyze
/[HIDDEN]/[HIDDEN]/{PARAM}/insights
/[HIDDEN]/[HIDDEN]/{PARAM}/mark-read
/[HIDDEN]/[HIDDEN]/{PARAM}/questions
/[HIDDEN]/[HIDDEN]/{PARAM}/sessions
/[HIDDEN]/questions/{PARAM}/broadcast
/[HIDDEN]/questions/{PARAM}/dismiss
/[HIDDEN]/questions/{PARAM}/regenerate-draft
/[HIDDEN]/questions/{PARAM}/reply
/[HIDDEN]/sessions/{PARAM}
/[HIDDEN]/student/feed
/[HIDDEN]/teacher/summary
/billing/checkout
/billing/portal
/billing/status
/billing/success
/[HIDDEN]
/[HIDDEN]/{PARAM}
/[HIDDEN]/{PARAM}/at-risk
/[HIDDEN]/{PARAM}/collaborators/{PARAM}
/[HIDDEN]/{PARAM}/name
/[HIDDEN]/{PARAM}/quote
/[HIDDEN]/{PARAM}/roster
/[HIDDEN]/{PARAM}/students
/[HIDDEN]/{PARAM}/students/{PARAM}
/[HIDDEN]/collaborate
/[HIDDEN]/join
/[HIDDEN]/my
/favicon.svg
/forgot-password
/lessons
/lessons/{PARAM}
/lessons/{PARAM}/content
/lessons/{PARAM}/copy
/lessons/{PARAM}/original
/lessons/{PARAM}/page/{PARAM}
/lessons/{PARAM}/quiz-result
/lessons/{PARAM}/results
/lessons/{PARAM}/thumbnail
/lessons/{PARAM}/visibility
/lessons/check-security
/lessons/classroom/{PARAM}
/lessons/media
/lessons/my
/lessons/packs/candidates
/lessons/packs/import
/lessons/packs/my
/lessons/packs/report
/lessons/upload
/login
/login/email
/mastery-explained
/parent
/parent/catalog
/parent/children
/parent/children/{PARAM}
/parent/children/{PARAM}/catalog/{PARAM}
/parent/children/{PARAM}/password
/parent/children/{PARAM}/profile
/parent/progress/{PARAM}
/parent/review/:assignmentId/:childId
/parent/worksheets
/parent/worksheets/{PARAM}
/parent/worksheets/{PARAM}/preview
/parent/worksheets/{PARAM}/retry-generation
/parent/worksheets/{PARAM}/review/{PARAM}
/practice/:sessionId
/preview/:sessionId
/preview/upload/:sessionId
/pricing
/profile
/prompts
/prompts/{PARAM}
/prompts/{PARAM}/reset
/prompts/meta
/question-bank/{PARAM}
/question-bank/{PARAM}/share
/question-bank/bulk
/reflect/:sessionId
/register
/reset-password
/review/:assignmentId
/select-role
/sessions/{PARAM}
/sessions/{PARAM}/action
/sessions/{PARAM}/feedback
/sessions/{PARAM}/finish
/sessions/{PARAM}/marking-status
/sessions/{PARAM}/questions/{PARAM}/explain-card
/sessions/{PARAM}/reflect
/sessions/{PARAM}/reflection
/sessions/{PARAM}/upload-page/{PARAM}
/sessions/{PARAM}/upload-work
/sessions/preview/{PARAM}
/sessions/preview/start
/sessions/review/{PARAM}
/sessions/start
/start
/students/:studentId
/teacher/profile
/teacher/review/:assignmentId/:studentId
/teacher/tools/:tool
/[HIDDEN]
/[HIDDEN]/{PARAM}/[HIDDEN]
/topics/meta
/topics/unified
/translate
/upload/:sessionId
/users/profile
/users/profile/password
/users/profile/study-scope
/verify-email
http://www.w3.org/1998/Math/MathML
http://www.w3.org/1999/xhtml
http://www.w3.org/1999/xlink
http://www.w3.org/2000/svg
http://www.w3.org/2000/xmlns/
http://www.w3.org/XML/1998/namespace
https://accounts.google.com/gsi/client
https://github.com/[HIDDEN]
https://react.dev/errors/

Invalidated Endpoints: 1 (Hidden, use --still-show-invalid or -ssi to show)
endpointscanner [TARGET] -dse -ds -oo  1.24s user 0.49s system 10% cpu 16.386 total
```

</details>

---

#### Katana's result on website 1

<details>
<summary><b>Click to open Katana's result:</b></summary>

```text
   __        __
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \/ _  /
/_/\_\\_,_/\__/\_,_/_//_/\_,_/

		projectdiscovery.io

[INF] Current katana version v1.8.0 (latest)
[INF] Started standard crawling for => https://[TARGET]
https://[TARGET]
https://[TARGET]/assets/index-[HASH].css
https://[TARGET]/assets/index-[HASH].js
https://[TARGET]/assets/%60+up%28this.src%29+%60
[INF] Crawl completed in 15s. 4 endpoints found.
katana -u [TARGET] -jc  0.36s user 0.10s system 2% cpu 16.187 total
```

</details>

---

#### Gobuster's result on website 1

<details>
<summary><b>Click to open Gobuster's result:</b></summary>

```text
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://[TARGET]
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          480
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
health               (Status: 200) [Size: 15]
topics               (Status: 401) [Size: 30]
Progress: 4614 / 4614 (100.00%)
===============================================================
Finished
===============================================================
gobuster dir -u https://[TARGET] -w common.txt --exclude-length 480 -t 100  1.49s user 0.96s system 11% cpu 20.858 total
```

</details>

---

#### FFuF's result on website 1

<details>
<summary><b>Click to open FFuF's result:</b></summary>

```text
health
topics
ffuf -u https://[TARGET]/FUZZ -w common.txt -fs 480 -s -t 100  1.12s user 1.68s system 15% cpu 18.090 total
```

</details>

---

#### Feroxbuster's result on website 1

<details>
<summary><b>Click to open Feroxbuster's result:</b></summary>

```text
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://[TARGET]/
 🚩  In-Scope Url          │ [TARGET]
 🚀  Threads               │ 100
 📖  Wordlist              │ common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       15l       38w      480c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET        1l        1w       15c https://[TARGET]/health
401      GET        1l        2w       30c https://[TARGET]/topics
[####################] - 82s    18460/18460   0s      found:2       errors:1
[####################] - 51s     4615/4615    90/s    https://[TARGET]/
[####################] - 58s     4615/4615    79/s    https://[TARGET]/cgi-bin/
[####################] - 64s     4615/4615    72/s    https://[TARGET]/cgi-bin/cgi-bin/
[####################] - 60s     4615/4615    77/s    https://[TARGET]/cgi-bin/cgi-bin/cgi-bin/
feroxbuster -u https://[TARGET] -w common.txt -t 100  4.72s user 3.17s system 9% cpu 1:23.68 total
```

</details>

## Website 2

[Navigation to website 1](#website-1)

### Details

The developer has asked to keep their website anonymous, hence the website will also be censored as [TARGET]. Other details in paths related to the website that could reveal it will be labeled as [HIDDEN], code files with hashes with be `index-[HASH].js`. Parameters will be hidden as {PARAM}.

### Navigation Links

- [Jump to EndpointScanner's result](#endpointscanners-result-on-website-2)
- [Jump to Katana's result](#katanas-result-on-website-2)
- [Jump to Gobuster's results](#gobusters-result-on-website-2)
- [Jump to FFuF's results](#ffufs-result-on-website-2)
- [Jump to Feroxbuster's results](#feroxbusters-result-on-website-2)

### Quick Comparison

Note: This is simply a table on how many directories/paths were found and how much time was taken.

The endpoint count will include:

- Valid paths
- Invalid paths (false positives)

and will not include:

- Duplicate paths
- External links
- Subdomains

| Tool                             | Command used                                                                      | Endpoints found | Time taken (in seconds) |
| :------------------------------- | :-------------------------------------------------------------------------------- | :-------------- | :---------------------- |
| **EndpointScanner**              | `time endpointscanner https://[TARGET] -ds -dse -oo`                              | **134**         | **15.598**              |
| **Katana** (by ProjectDiscovery) | `time katana -u https://[TARGET] -jc`                                             | 3               | 12.004                  |
| **Gobuster**                     | `time gobuster dir -u https://[TARGET] -w common.txt --exclude-length 480 -t 100` | 3               | 13.066                  |
| **FFuF**                         | `time ffuf -u https://[TARGET]/FUZZ -w common.txt -fs 516 -s -t 100`              | 3               | 13.371                  |
| **Feroxbuster**                  | `time feroxbuster -u https://[TARGET] -w common.txt -t 100`                       | 3               | 56.646                  |

> ⚠️: Gobuster and FFuF were run with --exclude-length and -fs respectively as the website is an SPA.

---

#### EndpointScanner's result on website 2

<details><summary><b>Click to open EndpointScanner's result:</b></summary>

```text
-----------------------------------------------------------------
Endpointscanner v7.5.0

Made by: SphericalFlower52811

GitHub: https://github.com/SphericalFlower52811/endpointscanner
Docs:   https://sphericalflower52811.github.io/endpointscanner/
-----------------------------------------------------------------

Scanning https://[TARGET]...

Scraping files...

Total paths found: 134

Endpoints will not be sorted. Sensitive endpoints like '.git/config' will be automatically skipped.

----Raw Results----

{PARAM}delete-icon.svg
{PARAM}foldout-icon.svg
{PARAM}resize-handle.svg
/404
/admin
/admin/api/[HIDDEN]
/admin/api/[HIDDEN]
/admin/api/impersonate/{PARAM}
/admin/api/projects
/admin/api/projects/{PARAM}
/admin/api/stats
/admin/api/users
/admin/api/users/{PARAM}
/admin/api/users/{PARAM}/{PARAM}
/app
/app/
/app/[HIDDEN]auth
/assets/favicon.ico
/assets/index-[HASH].js
/assets/index-[HASH].css
/assets/[HIDDEN].wasm
/assets/[HIDDEN].js
/assets/[HIDDEN].png
/assets/[HIDDEN].js
/assets/[HIDDEN].js
/auth/google/complete-signup
/auth/google/start
/auth/login
/auth/passkey/credentials
/auth/passkey/credentials/{PARAM}
/auth/passkey/login/complete
/auth/passkey/login/options
/auth/passkey/register/complete
/auth/passkey/register/options
/auth/register
/[HIDDEN]
/engine.io
/explore
/home
/login
/messages
/messages/:conversationId
/messages/conversation/{PARAM}
/messages/conversation/{PARAM}/accept
/messages/conversation/{PARAM}/decline
/messages/conversation/{PARAM}/send
/messages/conversation/start
/messages/inbox
/messages/requests
/onboarding
/projects
/projects-view
/projects/:id
/projects/{PARAM}/block-documents
/projects/{PARAM}/block-documents/{PARAM}
/projects/{PARAM}/duplicate
/projects/{PARAM}/export
/projects/{PARAM}/files
/projects/{PARAM}/files/{PARAM}
/projects/{PARAM}/folders
/projects/{PARAM}/folders/{PARAM}
/projects/{PARAM}/share
/projects/{PARAM}/snapshots
/projects/{PARAM}/snapshots/{PARAM}
/projects/{PARAM}/snapshots/{PARAM}/export
/projects/{PARAM}/snapshots/{PARAM}/inspect
/projects/{PARAM}/snapshots/{PARAM}/restore
/projects/{PARAM}/tasks
/projects/{PARAM}/tasks/{PARAM}
/projects/{PARAM}/tree/move
/projects/{PARAM}/visibility
/projects/access/{PARAM}
/projects/explore/all
/[HIDDEN].html
/[HIDDEN].js
/register
/runtime/[HIDDEN]
/settings
/share/
/share/:code
/socket.io
/users/:userId
/users/{PARAM}/{PARAM}
/users/{PARAM}/block
/users/{PARAM}/follow
/users/{PARAM}/projects
/users/{PARAM}/stats
/users/{PARAM}/unblock
/users/me
/users/me/email/verify/google
/users/me/picture
/vendor/[HIDDEN]
/vendor/[HIDDEN]/static/css/[HIDDEN].chunk.css
/vendor/[HIDDEN]/static/css/[HIDDEN].chunk.css
/vendor/[HIDDEN]/static/css/[HIDDEN].chunk.css
/vendor/[HIDDEN]/
/welcome
/workspace
http://[HIDDEN]
http://www.w3.org/1998/Math/MathML
http://www.w3.org/1999/xhtml
http://www.w3.org/1999/xlink
http://www.w3.org/2000/svg
http://www.w3.org/XML/1998/namespace
https://{PARAM}/favicon.ico
https://accounts.google.com/gsi/client
https://accounts.google.com/o/oauth2/v2/auth
https://[HIDDEN]/static/[HIDDEN]
https://[HIDDEN]/static/docs/[HIDDEN]/{PARAM}
https://[HIDDEN]/static/media/
https://developers.google.com/[HIDDEN]/xml
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://en.wikipedia.org/wiki/[HIDDEN]
https://github.com/[HIDDEN]
https://github.com/[HIDDEN]
https://github.com/[HIDDEN]
https://github.com/[HIDDEN]
https://[HIDDEN].ico
https://[HIDDEN]
https://www.instagram.com/[HIDDEN]
https://www.linkedin.com/company/[HIDDEN]

Invalidated Endpoints: 1 (Hidden, use --still-show-invalid or -ssi to show)
endpointscanner [TARGET] -dse -ds -oo  9.26s user 1.14s system 66% cpu 15.598 total

```

</details>

---

#### Katana's result on website 2

<details><summary><b>Click to open Katana's result:</b></summary>

```text

   __        __
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \/ _  /
/_/\_\\_,_/\__/\_,_/_//_/\_,_/

		projectdiscovery.io

[INF] Current katana version v1.8.0 (latest)
[INF] Started standard crawling for => https://[TARGET]
https://[TARGET]
https://[TARGET]/assets/index-[HASH].css
https://[TARGET]/assets/index-[HASH].js
[INF] Crawl completed in 11s. 3 endpoints found.
katana -u https://[TARGET] -jc  0.20s user 0.06s system 2% cpu 12.004 total

```

</details>

---

#### Gobuster's result on website 2

<details><summary><b>Click to open Gobuster's result:</b></summary>

```text

===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://[TARGET]
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                common.txt
[+] Negative Status codes:   404
[+] Exclude Length:          516
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
favicon.ico          (Status: 500) [Size: 21]
health               (Status: 200) [Size: 15]
projects             (Status: 401) [Size: 30]
Progress: 4614 / 4614 (100.00%)
===============================================================
Finished
===============================================================
gobuster dir -u https://[TARGET] -w common.txt --exclude-length 516 -t 100  1.38s user 0.77s system 16% cpu 13.066 total

```

</details>

---

#### FFuF's result on website 2

<details><summary><b>Click to open FFuF's result:</b></summary>

```text

favicon.ico
health
projects
ffuf -u https://[TARGET]/FUZZ -w common.txt -fs 516 -s -t 100  0.98s user 1.30s system 17% cpu 13.371 total

```

</details>

---

#### Feroxbuster's result on website 2

<details><summary><b>Click to open Feroxbuster's result:</b></summary>

```text

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.13.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ https://[TARGET]/
 🚩  In-Scope Url          │ [TARGET]
 🚀  Threads               │ 100
 📖  Wordlist              │ common.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.13.1
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
200      GET       17l       34w      516c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
500      GET        1l        3w       21c https://[TARGET]/favicon.ico
200      GET        1l        1w       15c https://[TARGET]/health
401      GET        1l        2w       30c https://[TARGET]/projects
[####################] - 56s    18460/18460   0s      found:3       errors:0
[####################] - 37s     4615/4615    124/s   https://[TARGET]/
[####################] - 42s     4615/4615    109/s   https://[TARGET]/cgi-bin/
[####################] - 44s     4615/4615    104/s   https://[TARGET]/cgi-bin/cgi-bin/
[####################] - 40s     4615/4615    116/s   https://[TARGET]/cgi-bin/cgi-bin/cgi-bin/
feroxbuster -u https://[TARGET] -w common.txt -t 100  3.58s user 2.21s system 10% cpu 56.646 total
```

</details>

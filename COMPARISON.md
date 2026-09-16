# Comparisons of EndpointScanner against other tools

## Info

This file will provide a comparison of EndpointScanner against other popular web reconnaissance tools, tested on a website where I have been given permission to pentest by the developer of the website. The tools are also ran with the `time` command, so the time they take will be displayed too.

This information is updated as of 16 September 2026.

## Website 1

### Details + Context

I have not asked for permission to publicly disclose what this website is, so this website will remain anonymous. Files like index-[HASH].js will have the hash censored for privacy purposes.

### Nagivation Links

- [Jump to Katana's result](#result-from-katana-by-projectdiscovery)
- [Jump to Gobuster's results](#result-from-gobuster)
- [Jump to FFuF's results](#result-from-ffuf)
- [Jump to Feroxbuster's results](#result-from-feroxbuster)
- [Jump to EndpointScanner's result](#result-from-endpointscanner)

### Quick Comparison

Note: This is simply a table on how many directories/paths were found and how much time was taken.

The endpoint count will include:

- Valid paths
- Invalid paths (false positives)

and will not include:

- Duplicate paths
- External links
- Subdomains

| Tool                             | Command used                                         | Endpoints found | Time taken (in seconds) |
| :------------------------------- | :--------------------------------------------------- | :-------------- | :---------------------- |
| **Katana** (by ProjectDiscovery) | `time katana -u https://[TARGET] -d 5 -jc`           | 5               | 15.845 total            |
| **Gobuster**                     | `gobuster dir -u https://[TARGET] -w common.txt`     | 0 ⚠️            | 1.503                   |
| **FFuF**                         | `time ffuf -u [TARGET]/FUZZ -w common.txt`           | 4614 ⚠️         | 23.992                  |
| **Feroxbuster**                  | `time feroxbuster -u https://[TARGET] -w common.txt` | 5               | 59.632                  |
| **EndpointScanner**              | `endpointscanner https://[TARGET] -p -dse -oo`       | 189             | 13.765                  |

⚠️: Gobuster printed nothing as it found out the target was an SPA and it automtically stopped the code to not flood the temrinal. FFuF outputted all 4614 paths from the wordlist as the target was an SPA.

### Full Comparison

---

#### Result from Katana (by ProjectDiscovery)

<details>
<summary><b>Click to open Katana's result:</b></summary>

```text

   __        __
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \/ _  /
/_/\_\\_,_/\__/\_,_/_//_/\_,_/

		projectdiscovery.io

[INF] Current katana version v1.7.0 (latest)
[INF] Started standard crawling for => https://[TARGET]
https://[TARGET]
https://[TARGET]/assets/index-DWNs42Sd.css
https://[TARGET]/assets/index-CwHS1lxH.js
https://[TARGET]/assets/%60+up%28this.src%29+%60
[INF] Crawl completed in 14s. 4 endpoints found.
katana -u https://[TARGET] -d 5 -jc  0.33s user 0.09s system 2% cpu 15.845 total
```

</details>

---

##### Katana's result with a headless browser

EndpointScanner automatically uses a headless browser, so I also did a test using Katana allowing it to have the `-hl` flag for a headless browser. These results are not shown in the summary table.

<details>
<summary>Click to open Katana's result with headless browser</summary>

```text

   __        __
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \/ _  /
/_/\_\\_,_/\__/\_,_/_//_/\_,_/

		projectdiscovery.io

[INF] Current katana version v1.7.0 (latest)
https://[TARGET]/assets/index-DWNs42Sd.css
https://[TARGET]/assets/index-CwHS1lxH.js
https://[TARGET]/
https://[TARGET]/assets/%60+up%28this.src%29+%60
https://[TARGET]/register
[INF] Crawl completed in 1m 14s. 5 endpoints found.
katana -u https://[TARGET] -jc -hl  1.22s user 0.83s system 2% cpu 1:15.29 total
```

</details>

---

#### Result from Gobuster

Warning: since this is an SPA, excluding this specific length will also make it return 0 endpoints.

<details>
<summary><b>Click to open Gobuster's result:</b></summary>

```text
===============================================================
Gobuster v3.8.2
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     https://[TARGET]
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8.2
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
Progress: 0 / 1 (0.00%)
2026/09/16 09:45:22 the server returns a status code that matches the provided options for non existing urls. https://[TARGET]/09a4626e-b4fa-43f9-b5bb-399f699fe134 => 200 (Length: 480). Please exclude the response length or the status code or set the wildcard option.. To continue please exclude the status code or the length
gobuster dir -u https://[TARGET] -w common.txt  0.01s user 0.02s system 2% cpu 1.391 total
```

</details>

---

#### Result from FFuF

Warning: All 4614 endpoints from common2.txt (which was just a duplicate of common.txt) were outputted as the target is an SPA, and FFuF got tricked by the SPA shells returning all of the endpoints as valid. Full output will not be provided as it is too long, it will be truncated.

<details>
<summary><b>Click to open FFuF's result:</b></summary>

```text
        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://[TARGET]/FUZZ
 :: Wordlist         : FUZZ: /Users/xavier9/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

:: Progress: [1/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors:: Progress: [40/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error:: Progress: [40/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error1996                    [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 203ms]
:: Progress: [40/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error10                      [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 199ms]
:: Progress: [41/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error101                     [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 204ms]
:: Progress: [42/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error13                      [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 208ms]
:: Progress: [43/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error20                      [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 205ms]
:: Progress: [44/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error1995                    [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 216ms]
:: Progress: [45/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error@                       [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 220ms]
:: Progress: [46/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error1991                    [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 219ms]
:: Progress: [47/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error1001                    [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 220ms]
:: Progress: [48/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error11                      [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 225ms]
:: Progress: [49/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error1990                    [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 227ms]
:: Progress: [50/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error1x1                     [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 227ms]
:: Progress: [51/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error0                       [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 226ms]
:: Progress: [52/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error04                      [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 226ms]
:: Progress: [53/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error08                      [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 230ms]
:: Progress: [54/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error05                      [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 227ms]
:: Progress: [55/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error1000                    [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 232ms]
:: Progress: [56/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error102                     [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 232ms]
:: Progress: [57/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error100                     [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 228ms]
:: Progress: [58/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error103                     [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 238ms]
:: Progress: [59/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error03                      [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 231ms]
:: Progress: [60/4614] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Error01                      [Status: 200, Size: 480, Words: 64, Lines: 16, Duration: 261ms]

...OUTPUT TRUNCATED AS IT WILL BE TOO LONG.
ffuf -u https://[TARGET]/FUZZ -w common.txt  1.32s user 2.23s system 14% cpu 23.992 total
```

</details>

---

#### Result from Feroxbuster

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
 🚀  Threads               │ 50
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
200      GET       81l      240w     3012c https://[TARGET]/docs/oauth2-redirect
200      GET        1l     2368w   178942c https://[TARGET]/openapi.json
200      GET       32l       69w     1018c https://[TARGET]/docs
200      GET        1l        1w       15c https://[TARGET]/health
401      GET        1l        2w       30c https://[TARGET]/topics
[####################] - 59s    18465/18465   0s      found:5       errors:1
[####################] - 42s     4615/4615    109/s   https://[TARGET]/
[####################] - 46s     4615/4615    101/s   https://[TARGET]/cgi-bin/
[####################] - 46s     4615/4615    101/s   https://[TARGET]/cgi-bin/cgi-bin/
[####################] - 42s     4615/4615    110/s   https://[TARGET]/cgi-bin/cgi-bin/cgi-bin/                                              feroxbuster -u https://[TARGET] -w common.txt  4.79s user 2.54s system 12% cpu 59.632 total
```

</details>

---

#### Result from EndpointScanner

<details>
<summary><b>Click to open EndpointScanner's result:</b></summary>

```text
-----------------------------------------------------------------
Endpointscanner v7.4.0

Made by: SphericalFlower52811
(I was too lazy to make a 3D ASCII banner, nor do I want one.)

GitHub: https://github.com/SphericalFlower52811/endpointscanner
Docs:   https://sphericalflower52811.github.io/endpointscanner/
-----------------------------------------------------------------

Site responded in 0.26 seconds.
Server is very fast.

Starting headless browser to bypass captchas and detect shells with a fake path.
Fake path used: /very-fake-page-123456123456abcdefg_d8fc8a92c172839537454e8a62e84936

Headless browser & fake path test finished.
Starting scan on https://[TARGET].


Detected JS Stack: React + Vite

Endpoints Found: 190

Endpoints will not be sorted. Sensitive endpoints like '.git/config' will be automatically skipped.

----Raw Results----

${N.defaults.baseURL}/admin/topics/csv-template
/accuracy-explained
/admin
/admin/ingest
/admin/llm-settings
/admin/llm-settings/providers/${e}
/admin/llm-settings/test
/admin/llm-settings/test-vision
/admin/llm-settings/workflows/${e}
/admin/llm-settings/workflows/${e}/reset
/admin/pdfs
/admin/schools
/admin/schools/${de.school.id}
/admin/schools/import-csv
/admin/settings/email
/admin/settings/email/test
/admin/settings/features
/admin/settings/features/${e}
/admin/settings/users/${e}/beta
/admin/textbooks
/admin/textbooks/${e}
/admin/textbooks/${e}/chapters
/admin/textbooks/${e}/chapters/${t}
/admin/textbooks/${e}/chapters/${t}/sub-chapters
/admin/textbooks/${e}/chapters/${t}/sub-chapters/${n}
/admin/textbooks/import-csv
/admin/textbooks/tree
/admin/topics
/admin/topics/${e}
/admin/topics/${e}/subtopics
/admin/topics/${e}/subtopics/${t}
/admin/topics/bulk
/admin/topics/filters
/admin/topics/import-csv
/admin/topics/tree
/admin/users
/admin/users/${d.user.id}
/admin/users/${e}/associated-users
/assets/index-CwHS1lxH.js
/assets/index-DWNs42Sd.css
/assignments
/assignments/${e}
/assignments/${e}/approve
/assignments/${ua}/class-summary
/assignments/${ua}/diagnostic-followup
/assignments/${e}/diagnostic-report
/assignments/${e}/duplicate
/assignments/${e}/generation-status
/assignments/${e}/meta
/assignments/${e.assignment_id}/my-sessions
/assignments/${e}/prerequisite-report
/assignments/${e}/preview
/assignments/:assignmentId/print
/assignments/${Ja}/questions/${e}
/assignments/${Ja}/questions/${e}/regenerate
/assignments/${ua}/remediation
/assignments/${e}/results
/assignments/${e}/retry-generation
/assignments/${e}/student-review/${t}
/assignments/${e}/student-review/${t}/attempts/${n.attempt_id}
/assignments/${e}/visibility
/assignments/${Fn.assignment_id}/worksheet
/assignments/${e}/worksheet-diagram/${n}
/assignments/${e}/worksheet-page/${t}
/assignments/${e}/worksheet-questions
/assignments/${e}/worksheet-questions/${t}/resolve
/assignments/${e}/worksheet-questions/${t}/resolve-apply
/assignments/${e}/worksheet-questions/${t}/resolve-status
/assignments/${e}/worksheet-questions/${t}/review-answer
/assignments/derive-prerequisite-skills
/assignments/extract-mcq-source
/assignments/extract-progress/${e}
/assignments/extract-worksheet
/assignments/mcq-bundle
/assignments/parent-assigned
/assignments/re-extract-worksheet/${hi}
/assignments/regenerate-diagram/${hi}/${t}
/assignments/worksheet-preview-page/${e}/${n}
/auth/forgot-password
/auth/google
/auth/login
/auth/me
/auth/register
/auth/resend-verification
/auth/reset-password
/auth/role
/auth/verify-email
/backchannel/classrooms/${Fe}
/backchannel/classrooms/${Fe}/analyze
/backchannel/classrooms/${Fe}/insights
/backchannel/classrooms/${e.classroom_id}/mark-read
/backchannel/classrooms/${r}/questions
/backchannel/classrooms/${e}/sessions
/backchannel/questions/${e}/broadcast
/backchannel/questions/${e}/dismiss
/backchannel/questions/${e}/regenerate-draft
/backchannel/questions/${e}/reply
/backchannel/sessions/${e.id}
/backchannel/student/feed
/backchannel/teacher/summary
/billing/checkout
/billing/portal
/billing/status
/billing/success
/classrooms
/classrooms/${e}
/classrooms/${e}/at-risk
/classrooms/${e}/collaborators/${t}
/classrooms/${e}/name
/classrooms/${e}/quote
/classrooms/${n}/roster
/classrooms/${n}/students
/classrooms/${t.classroom_id}/students/${e.student_id}
/classrooms/collaborate
/classrooms/join
/classrooms/my
/favicon.svg
/forgot-password
/lessons
/lessons/${e}
/lessons/${e.lesson_id}/content
/lessons/${T.lesson_id}/quiz-result
/lessons/${e}/results
/lessons/${e}/visibility
/lessons/check-security
/lessons/classroom/${e}
/lessons/my
/lessons/upload
/login
/login/email
/mastery-explained
/parent
/parent/children
/parent/children/${e.user_id}
/parent/children/${e}/password
/parent/children/${p.user_id}/profile
/parent/progress/${e}
/parent/review/:assignmentId/:childId
/parent/worksheets
/parent/worksheets/${e}
/parent/worksheets/${e}/preview
/parent/worksheets/${e}/retry-generation
/parent/worksheets/${e}/review/${t}
/practice/:sessionId
/preview/:sessionId
/preview/upload/:sessionId
/pricing
/profile
/prompts
/prompts/${nt.key}
/prompts/${e}/reset
/question-bank/${t.id}
/question-bank/${t.id}/share
/question-bank/bulk
/reflect/:sessionId
/register
/reset-password
/review/:assignmentId
/select-role
/sessions/${t}
/sessions/${t}/action
/sessions/${t}/feedback
/sessions/${t}/finish
/sessions/${t}/marking-status
/sessions/${e}/reflect
/sessions/${e}/reflection
/sessions/${e}/upload-page/${n}
/sessions/${t}/upload-work
/sessions/preview/${t}
/sessions/preview/start
/sessions/review/${e}
/sessions/start
/start
/students/:studentId
/teacher/profile
/teacher/review/:assignmentId/:studentId
/teacher/tools/:tool
/textbooks
/textbooks/${wr}/chapters
/topics/meta
/topics/unified
/translate
/upload/:sessionId
/users/profile
/users/profile/password
/verify-email
https://accounts.google.com/gsi/client
https://github.com/syntax-tree/hast-util-to-jsx-runtime
https://react.dev/errors

Invalidated Endpoints: 1 (Hidden, use --still-show-invalid or -ssi to show)
endpointscanner [TARGET] -d -ro -oo  1.29s user 0.42s system 12% cpu 13.765 total
```

</details>

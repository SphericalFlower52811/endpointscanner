# Comparisons of EndpointScanner against other tools

## Info

This file will provide a comparison of EndpointScanner against other popular web reconnaissance tools, tested on a website where I have been given permission to pentest by the developer of the website.

Time taken is measured through the MacOS `time` command, and will be present in the tools' outputs.

This information is updated as of 30 September 2026.

## Navigation Links for websites

- [Website 1](#website-1)
- [Website 2](#website-2)

## Website 1

### Details

I have not asked for permission to publicly disclose what this website is, so this website will remain anonymous. Files like index-[HASH].js will have the hash censored for privacy purposes.

### Navigation Links for scanners

- [Jump to EndpointScanner's result](#result-from-endpointscanner-on-website-1)
- [Jump to Katana's result](#result-from-katana-by-projectdiscovery-on-website-1)
- [Jump to Gobuster's results](#result-from-gobuster-on-website-1)
- [Jump to FFuF's results](#result-from-ffuf-on-website-1)
- [Jump to Feroxbuster's results](#result-from-feroxbuster-on-website-1)

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
| **Katana** (by ProjectDiscovery) | `time katana -u https://[TARGET] -d 5 -jc`                                        | 5               | 21.090 total            |
| **Gobuster**                     | `time gobuster dir -u https://[TARGET] -w common.txt --exclude-length 480 -t 100` | 3               | 1.503                   |
| **FFuF**                         | `time ffuf -u https://[TARGET]/FUZZ -w common.txt -fs 480 -s -t 100`              | 3               | 18.440                  |
| **Feroxbuster**                  | `time feroxbuster -u https://[TARGET] -w common.txt -t 100`                       | 5               | 85.68                   |
| **EndpointScanner**              | `time endpointscanner [TARGET] -dse -ds -oo`                                      | **213**         | **15.728**              |

> ⚠️: Gobuster and FFuF was run with --exclude-length and -fs resspectively as the website is an SPA.

### Full Comparison

---

#### Result from EndpointScanner on website 1

<details>
<summary><b>Click to open EndpointScanner's result:</b></summary>

```text
-----------------------------------------------------------------
Endpointscanner v7.5.0 (DEBUG)

Made by: SphericalFlower52811
(I was too lazy to make a 3D ASCII banner, nor do I want one.)

GitHub: https://github.com/SphericalFlower52811/endpointscanner
Docs:   https://sphericalflower52811.github.io/endpointscanner/
-----------------------------------------------------------------

Scanning https://[TARGET]...

Starting headless browser to bypass captchas and detect shells with a fake path.
Sensitive endpoints like '.git/config' will be automatically skipped as sorting is not enabled.
This will be fixed in 7.5.1 to verify all sensitive files.

Total paths found: 213

Endpoints will not be sorted. Sensitive endpoints like '.git/config' will be automatically skipped.

----Raw Results----

${P.defaults.baseURL}/admin/topics/csv-template
/accuracy-explained
/admin
/admin/catalog
/admin/catalog/import
/admin/catalog/packs/${e.curriculum_topic_id}
/admin/catalog/packs/${e.curriculum_topic_id}/publish
/admin/ingest
/admin/[HIDDEN]
/admin/[HIDDEN]/providers/${e}
/admin/[HIDDEN]/test
/admin/[HIDDEN]/test-vision
/admin/[HIDDEN]/[HIDDEN]/${e}
/admin/[HIDDEN]/[HIDDEN]/${e}/reset
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
/assets/index-[HASH].js
/assets/index-[HASH].css
/assignments
/assignments/${e}
/assignments/${e}/approve
/assignments/${Ga}/class-summary
/assignments/${Ga}/diagnostic-followup
/assignments/${e}/diagnostic-report
/assignments/${e}/duplicate
/assignments/${e}/explanation-cards
/assignments/${e}/generation-status
/assignments/${e}/meta
/assignments/${e.assignment_id}/my-sessions
/assignments/${e}/prerequisite-report
/assignments/${e}/preview
/assignments/:assignmentId/print
/assignments/${jo}/questions/${e}
/assignments/${jo}/questions/${e}/regenerate
/assignments/${Ga}/remediation
/assignments/${e}/results
/assignments/${e}/retry-generation
/assignments/${e}/student-review/${t}
/assignments/${e}/student-review/${t}/attempts/${n.attempt_id}
/assignments/${e}/visibility
/assignments/${fr.assignment_id}/worksheet
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
/assignments/re-extract-worksheet/${Xi}
/assignments/regenerate-diagram/${Xi}/${t}
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
/backchannel/classrooms/${nt}
/backchannel/classrooms/${nt}/analyze
/backchannel/classrooms/${nt}/insights
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
/classrooms/${La}/students/${e.student_id}
/classrooms/collaborate
/classrooms/join
/classrooms/my
/favicon.svg
/forgot-password
/lessons
/lessons/${e}
/lessons/${e.lesson_id}/content
/lessons/${e}/copy
/lessons/${e.lesson_id}/original
/lessons/${e.lesson_id}/page/${n}
/lessons/${D.lesson_id}/quiz-result
/lessons/${e}/results
/lessons/${n.lesson_id}/thumbnail
/lessons/${e}/visibility
/lessons/check-security
/lessons/classroom/${e}
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
/parent/children/${e.user_id}
/parent/children/${t}/catalog/${e.curriculum_topic_id}
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
/sessions/${t}/questions/${e}/explain-card
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
/textbooks/${ni}/chapters
/topics/meta
/topics/unified
/translate
/upload/:sessionId
/users/profile
/users/profile/password
/verify-email
http://www.w3.org/1998/Math/MathML
http://www.w3.org/1999/xhtml
http://www.w3.org/1999/xlink
http://www.w3.org/2000/svg
http://www.w3.org/2000/xmlns/
http://www.w3.org/XML/1998/namespace
https://accounts.google.com/gsi/client
https://github.com/syntax-tree/hast-util-to-jsx-runtime
https://react.dev/errors/

Invalidated Endpoints: 1 (Hidden, use --still-show-invalid or -ssi to show)
endpointscanner [TARGET] -dse -ds -oo  1.22s user 0.48s system 10% cpu 15.728 total
```

</details>

---

#### Result from Katana (by ProjectDiscovery) on website 1

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
https://[TARGET]/assets/index-[HASH].css
https://[TARGET]/assets/index-[HASH].js
https://[TARGET]/assets/%60+dp%28this.src%29+%60
[INF] Crawl completed in 16s. 4 endpoints found.
katana -u https://[TARGET] -d 5 -jc  0.35s user 0.09s system 2% cpu 21.090 total
```

</details>

---

#### Result from Gobuster on website 1

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
docs                 (Status: 200) [Size: 1018]
health               (Status: 200) [Size: 15]
topics               (Status: 401) [Size: 30]
Progress: 4614 / 4614 (100.00%)
===============================================================
Finished
===============================================================
gobuster dir -u https://[TARGET] -w common.txt --exclude-length 480 -  1.72s user 0.90s system 12% cpu 20.589 total
```

</details>

---

#### Result from FFuF on website 1

<details>
<summary><b>Click to open FFuF's result:</b></summary>

```text
time ffuf -u https://[TARGET]/FUZZ -w common.txt -fs 480 -s -t 100
docs
health
topics
ffuf -u https://[TARGET]/FUZZ -w common.txt -fs 480 -s -t 100  1.09s user 1.78s system 15% cpu 18.440 total
```

</details>

---

#### Result from Feroxbuster on website 1

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
200      GET       81l      240w     3012c https://[TARGET]/docs/oauth2-redirect
200      GET        1l     3442w   201628c https://[TARGET]/openapi.json
200      GET       32l       69w     1018c https://[TARGET]/docs
200      GET        1l        1w       15c https://[TARGET]/health
401      GET        1l        2w       30c https://[TARGET]/topics
[####################] - 84s    18465/18465   0s      found:5       errors:1
[####################] - 60s     4615/4615    77/s    https://[TARGET]/
[####################] - 66s     4615/4615    70/s    https://[TARGET]/cgi-bin/
[####################] - 67s     4615/4615    69/s    https://[TARGET]/cgi-bin/cgi-bin/
[####################] - 58s     4615/4615    79/s    https://[TARGET]/cgi-bin/cgi-bin/cgi-bin/
feroxbuster -u https://[TARGET] -w common.txt -t 100  4.90s user 2.52s system 8% cpu 1:25.68 total
```

</details>

## Website 2

The developer has asked to keep their website anonymous, hence the website will also be censored as [TARGET]. Other details in paths related to the website that could reveal it will be labeled as [HIDDEN], code files with hashes with be `index-[HASH].js`.

### Navigation Links

[Jump to EndpointScanner's results](#endpointscanners-result-for-website-2)

### Quick Comparison

Note: This is simply a table on how many directories/paths were found and how much time was taken.

The endpoint count will include:

- Valid paths
- Invalid paths (false positives)

and will not include:

- Duplicate paths
- External links
- Subdomains

| Tool                             | Command used                                                         | Endpoints found | Time taken (in seconds) |
| :------------------------------- | :------------------------------------------------------------------- | :-------------- | :---------------------- |
| **Katana** (by ProjectDiscovery) | `time katana -u https://[TARGET] -jc`                                | 3               | 15.845 total            |
| **Gobuster**                     | `gobuster dir -u https://[TARGET] -w common.txt`                     | 3               | 15.890                  |
| **FFuF**                         | `time ffuf -u https://[TARGET]/FUZZ -w common.txt -fs 516 -s -t 100` | 3               | 12.317                  |
| **Feroxbuster**                  | `time feroxbuster -u https://[TARGET] -w common.txt -t 100`          | 3               | 54.149                  |
| **EndpointScanner**              | `endpointscanner https://[TARGET] -ds -dse -oo`                      | **134**         | **14.968**              |

> ⚠️: Gobuster and FFuF was run with --exclude-length and -fs resspectively as the website is an SPA.

---

#### EndpointScanner's result for website 2

<details><summary><b>Click to open EndpointScanner's result:</b></summary>

```text
-----------------------------------------------------------------
Endpointscanner v7.5.0 (DEBUG)

Made by: SphericalFlower52811
(I was too lazy to make a 3D ASCII banner, nor do I want one.)

GitHub: https://github.com/SphericalFlower52811/endpointscanner
Docs:   https://sphericalflower52811.github.io/endpointscanner/
-----------------------------------------------------------------

Scanning https://[TARGET]...

Starting headless browser to bypass captchas and detect shells with a fake path.
Sensitive endpoints like '.git/config' will be automatically skipped as sorting is not enabled.
This will be fixed in 7.5.1 to verify all sensitive files.

Total paths found: 134

Endpoints will not be sorted. Sensitive endpoints like '.git/config' will be automatically skipped.

----Raw Results----

${this.workspace.options.pathToMedia}delete-icon.svg
${this.workspace.options.pathToMedia}foldout-icon.svg
${o.options.pathToMedia}resize-handle.svg
/404
/admin
/admin/api/force/follow
/admin/api/force/project
/admin/api/impersonate/${N.id}
/admin/api/projects
/admin/api/projects/${N.id}
/admin/api/stats
/admin/api/users
/admin/api/users/${N.id}
/admin/api/users/${N.id}/${ze}
/app
/app/
/app/desktop-google-auth
/assets/favicon.ico
/assets/index-[HASH].js
/assets/index-[HASH].css
/assets/mpy-cross-v6-[HASH].wasm
/assets/mpy-cross-v6-[HASH].js
/assets/[HIDDEN].png
/assets/[HIDDEN].js
/assets/[HIDDEN].js
/auth/google/complete-signup
/auth/google/start
/auth/login
/auth/passkey/credentials
/auth/passkey/credentials/${_e}
/auth/passkey/login/complete
/auth/passkey/login/options
/auth/passkey/register/complete
/auth/passkey/register/options
/auth/register
/[HIDDEN]-media/
/engine.io
/explore
/home
/login
/messages
/messages/:conversationId
/messages/conversation/${ye}
/messages/conversation/${E}/accept
/messages/conversation/${E}/decline
/messages/conversation/${E}/send
/messages/conversation/start
/messages/inbox
/messages/requests
/onboarding
/projects
/projects-view
/projects/:id
/projects/${Nt}/block-documents
/projects/${Nt}/block-documents/${$.id}
/projects/${ke.id}/duplicate
/projects/${Nt}/export
/projects/${Nt}/files
/projects/${Nt}/files/${$}
/projects/${Nt}/folders
/projects/${Nt}/folders/${$.id}
/projects/${Nt}/share
/projects/${rt}/snapshots
/projects/${Nt}/snapshots/${$}
/projects/${Nt}/snapshots/${$.id}/export
/projects/${Nt}/snapshots/${$.id}/inspect
/projects/${Nt}/snapshots/${$.id}/restore
/projects/${rt}/tasks
/projects/${Nt}/tasks/${$.id}
/projects/${Nt}/tree/move
/projects/${ue.id}/visibility
/projects/access/${ke}
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
/users/${n}/${Q}
/users/${It.id}/block
/users/${n}/follow
/users/${_e}/projects
/users/${_e}/stats
/users/${It.id}/unblock
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
http://randomcolour.com
http://www.w3.org/1998/Math/MathML
http://www.w3.org/1999/xhtml
http://www.w3.org/1999/xlink
http://www.w3.org/2000/svg
http://www.w3.org/XML/1998/namespace
https://${t}/favicon.ico
https://accounts.google.com/gsi/client
https://accounts.google.com/o/oauth2/v2/auth
https://[HIDDEN]/static/[HIDDEN]/
https://[HIDDEN]/static/docs/v2.20.0/${H.docsPath}
https://[HIDDEN].com/static/media/
https://developers.google.com/[HIDDEN]/xml
https://en.wikipedia.org/wiki/%3F:
https://en.wikipedia.org/wiki/Arithmetic
https://en.wikipedia.org/wiki/Atan2
https://en.wikipedia.org/wiki/Color
https://en.wikipedia.org/wiki/For_loop
https://en.wikipedia.org/wiki/Mathematical_constant
https://en.wikipedia.org/wiki/Modulo_operation
https://en.wikipedia.org/wiki/Nullable_type
https://en.wikipedia.org/wiki/Number
https://en.wikipedia.org/wiki/Random_number_generation
https://en.wikipedia.org/wiki/Rounding
https://en.wikipedia.org/wiki/Square_root
https://en.wikipedia.org/wiki/Subroutine
https://en.wikipedia.org/wiki/Trigonometric_functions
https://github.com/RaspberryPiFoundation/[HIDDEN]
https://github.com/[HIDDEN]
https://github.com/[HIDDEN]/IDE/releases/latest/download/[HIDDEN]
https://github.com/username
https://icons.duckduckgo.com/ip3/${t}.ico
https://www.december.com/html/spec/colorpercompact.html
https://www.instagram.com/[HIDDEN]
https://www.linkedin.com/company/[HIDDEN]

Invalidated Endpoints: 1 (Hidden, use --still-show-invalid or -ssi to show)
endpointscanner [TARGET] -dse -ds -oo  8.64s user 1.01s system 64% cpu 14.968 total


```

</details>

---

#### Katana's result for website 2

<details><summary><b>Click to open Katana's result:</b></summary>

```text

   __        __
  / /_____ _/ /____ ____  ___ _
 /  '_/ _  / __/ _  / _ \/ _  /
/_/\_\\_,_/\__/\_,_/_//_/\_,_/

		projectdiscovery.io

[INF] Current katana version v1.7.0 (latest)
[INF] Started standard crawling for => https://[TARGET]
https://[TARGET]
https://[TARGET]/assets/index-[HASH].css
https://[TARGET]/assets/index-[HASH].js
[INF] Crawl completed in 11s. 3 endpoints found.
katana -u [TARGET] -jc  0.19s user 0.09s system 2% cpu 12.534 total

```

</details>

---

#### Gobuster's result for website 2

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
gobuster dir -u https://[TARGET] -w common.txt --exclude-length 516 -t 10  1.26s user 0.64s system 11% cpu 15.890 total
```
</details>

---

#### FFuF's result for website 2

<details><summary><b>Click to open FFuF's result:</b></summary>

```text
favicon.ico
health
projects
ffuf -u https://[TARGET]/FUZZ -w common.txt -fs 516 -s -t 100  0.83s user 1.29s system 17% cpu 12.317 total

```

</details>

---

#### Feroxbuster's result for website 2

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
[####################] - 53s    18460/18460   0s      found:3       errors:0
[####################] - 36s     4615/4615    128/s   https://[TARGET]/
[####################] - 43s     4615/4615    108/s   https://[TARGET]/cgi-bin/
[####################] - 43s     4615/4615    108/s   https://[TARGET]/cgi-bin/cgi-bin/
[####################] - 38s     4615/4615    122/s   https://[TARGET]/cgi-bin/cgi-bin/cgi-bin/
feroxbuster -u https://[TARGET] -w common.txt -t 100  3.40s user 1.56s system 9% cpu 54.149 total
```

</details>

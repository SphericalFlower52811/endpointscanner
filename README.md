## Website Endpoint Scanner and Rate Limit Tester

The python code scans for endpoints in websites by looking through all the js files listed in the htmml, and also checks <script></script> tags. It also prints what JS type it uses.

If there is a {id} inside the path, it replaces it with 1 to test the endpoint whether it is a 200 OK, 404/403, or a redirect (30x Header)

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

It is not good at differentiating between react shells and actual pages in single-page applications though, so after listing endpoints in such websites you would have to test them, cuz some are not allowed while some are.

It can also test for rate limiting in the website by performing an async function to send 100 GET requests to an endpoint the user wants to test.

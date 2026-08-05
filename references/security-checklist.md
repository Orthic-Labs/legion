# Application-Security Checklist (audit · security lens)

Detection + remediation cues for the `security` reasoning lens — the app-level
security taxonomy the scanners (gitleaks / npm-audit / semgrep) do NOT cover.
Reason over these against the repo; every finding still needs a real `file:line`.
Deterministic backers where the project configures them: `eslint-plugin-security`,
semgrep app-sec rulesets. Source: vibecoder security-audit (prescriptive remediation
prompts repurposed here as audit detection cues).

### 1. Hash passwords with a modern algorithm
*Area: Authentication. Why it matters: Plain-text or weakly hashed passwords mean a single database leak hands attackers every user's credentials — this is the most consequential account-protection fix you can make.*

Audit the entire codebase for how user passwords are created, stored, and verified. Flag any passwords saved in plain text, reversible encryption, or fast/outdated hashes like MD5 or SHA1, and replace them with a slow, salted algorithm appropriate to my stack such as bcrypt, scrypt, or Argon2id with sensible work factors. Add a transparent upgrade path that re-hashes each user's password on their next successful login so existing accounts migrate without a forced reset. When done, summarize what you found and changed in plain language.

### 2. Enforce strong password requirements
*Area: Authentication. Why it matters: Weak or reused passwords are the easiest way into an account, and enforcing a sane policy at signup stops the problem before it starts.*

Review the user registration and password-change flows and add server-side password strength validation that rejects short, common, and obviously weak passwords. Enforce a reasonable minimum length (at least 12 characters), check submitted passwords against a list of known-breached or common passwords, and return a clear, friendly error explaining why a password was rejected. Make sure the validation runs on the server and is not only enforced in the browser, then tell me which files you touched.

### 3. Rate limit login attempts
*Area: Authentication. Why it matters: Without throttling, attackers can guess passwords thousands of times per minute; rate limiting makes brute-force and credential-stuffing attacks impractical.*

Add rate limiting to the login endpoint and any other authentication endpoints in my app, scoped by both IP address and the account being targeted. Use an approach that fits my stack and infrastructure — a middleware, a library, or a shared store like Redis — and return a standard 429 response with a Retry-After header once the limit is exceeded. Make the limits strict enough to stop automated guessing but loose enough that a real user mistyping their password a few times is unaffected, and explain the thresholds you chose.

### 4. Lock accounts after repeated failures
*Area: Authentication. Why it matters: Temporary lockouts add a second layer of brute-force defense and give you a signal that an account is under attack.*

Implement a temporary account lockout that triggers after a configurable number of consecutive failed login attempts for a given account. Track failed attempts server-side, lock the account for a cooling-off period that increases with repeated lockouts, and reset the counter on a successful login. Make sure the lockout cannot be trivially bypassed by changing IP addresses or casing of the username, and avoid revealing to an attacker exactly how many attempts remain. Describe the lockout logic you implemented.

### 5. Stop username and email enumeration
*Area: Authentication. Why it matters: If your app reveals whether an email is registered, attackers can build target lists; consistent responses keep that information private.*

Audit the login, signup, password reset, and any "check if email exists" flows for username and email enumeration. Make the responses, status codes, and timing identical whether or not an account exists — for example, always show "if an account exists, we've sent a reset link" rather than confirming or denying the address. Pay attention to subtle leaks like different error messages, redirect behavior, or response times between the two cases, and report everywhere you found enumeration was possible.

### 6. Secure the password reset flow
*Area: Authentication. Why it matters: Password reset is a common backdoor into accounts; reset tokens must be unguessable, single-use, and short-lived.*

Review the entire password reset feature end to end and harden it. Ensure reset tokens are generated with a cryptographically secure random source, are long and unguessable, are stored hashed rather than in plain text, expire after a short window, and are invalidated immediately after a single use or when a new reset is requested. Confirm that completing a reset also invalidates existing sessions for that account, and walk me through the flow you ended up with.

### 7. Regenerate sessions to block fixation
*Area: Authentication. Why it matters: If the session identifier doesn't change when a user logs in, an attacker who planted a known session ID can ride into the authenticated session.*

Check how my app handles sessions during authentication and fix any session fixation risk. Ensure that a brand-new session identifier is generated at the moment of successful login and again on any privilege change, and that the pre-login session is fully discarded server-side rather than reused. Verify this works with my session store and framework, then confirm whether the previous behavior was vulnerable.

### 8. Add multi-factor authentication support
*Area: Authentication. Why it matters: A second factor means a stolen password alone is no longer enough to take over an account, dramatically reducing account-takeover risk.*

Add support for time-based one-time-password (TOTP) multi-factor authentication that works with standard authenticator apps. Implement secure secret generation and storage, QR-code provisioning, verification during login, and a set of single-use recovery codes stored hashed for when a user loses their device. Make MFA opt-in per user without breaking existing accounts, and rate-limit verification attempts. Explain how a user would enroll and how the verification step fits into my existing login flow.

### 9. Compare credentials in constant time
*Area: Authentication. Why it matters: Naive string comparison of secrets can leak information through timing differences; constant-time comparison closes that side channel.*

Find every place where the app compares secrets — passwords, hashes, tokens, API keys, signatures, or one-time codes — and ensure each comparison uses a constant-time comparison function rather than a standard equality check. Use the constant-time comparison utility built into my language or a vetted library, so that an attacker cannot infer how much of a secret is correct by measuring response time. List each comparison you changed and confirm none were missed.

### 10. Harden the remember-me feature
*Area: Authentication. Why it matters: Persistent login tokens are convenient but become a long-lived skeleton key if they aren't built carefully.*

Audit any "remember me" or persistent-login functionality and rebuild it securely if needed. Use long, random, single-use tokens stored hashed on the server and set in a secure, HttpOnly cookie, rotate the token on each use so a stolen token has a short useful life, and tie each token to an individual device so a user can revoke them independently. Ensure these tokens expire and that logging out everywhere clears them all, then describe the design you implemented.

### 11. Add bot protection to forms
*Area: Authentication. Why it matters: Automated bots abuse signup, login, contact, and other public forms for spam and attacks; a challenge step filters most of them out cheaply.*

Add bot and abuse protection to the publicly reachable forms in my app, such as signup, login, password reset, and contact. Integrate a privacy-respecting challenge or invisible verification appropriate to my stack, and combine it with server-side checks like honeypot fields and per-IP submission limits so the protection cannot be bypassed by calling the endpoint directly. Make sure legitimate users with assistive technology can still complete the forms, and tell me which forms you protected.

### 12. Throttle password reset and verification emails
*Area: Authentication. Why it matters: Unthrottled email-sending endpoints let attackers spam victims and rack up your provider bill; rate limiting prevents both.*

Add rate limiting to every endpoint that triggers an outbound email or SMS — password reset, email verification, magic links, and invitations. Limit by recipient address and by source IP, enforce a minimum interval between sends to the same address, and cap the total per hour and per day. Return a neutral response that doesn't reveal whether the address is registered, and explain the limits you set and where they live in the code.

### 13. Set secure session cookie flags
*Area: Sessions, Cookies & Tokens. Why it matters: Missing cookie security flags let session cookies leak over plain HTTP or be read by malicious scripts — the flags are a one-line fix with outsized impact.*

Audit every cookie my app sets, especially session and authentication cookies, and apply the correct security flags. Set HttpOnly so scripts cannot read them, Secure so they are only sent over HTTPS, and an appropriate SameSite value to limit cross-site sending, and scope the Path and Domain as narrowly as the app allows. Verify the flags are actually present on the responses rather than just configured, and list each cookie with the flags you applied.

### 14. Add idle and absolute session timeouts
*Area: Sessions, Cookies & Tokens. Why it matters: Sessions that never expire become a standing liability on shared or compromised devices; timeouts bound the window of exposure.*

Review how long sessions stay valid and add both an idle timeout and an absolute maximum lifetime. Expire a session after a period of inactivity and also after a hard maximum regardless of activity, enforcing both checks on the server rather than trusting the client. Make sure expiration actually invalidates the session server-side and prompts a clean re-login, and tell me the timeout values you chose and why.

### 15. Fully invalidate sessions on logout
*Area: Sessions, Cookies & Tokens. Why it matters: If logout only clears the browser cookie, the session can often still be used; true logout must destroy the session on the server.*

Check the logout flow and ensure it fully terminates the session rather than just clearing the cookie in the browser. Delete or invalidate the session record on the server so the old session identifier can no longer be used, clear the relevant cookies with proper attributes, and provide a "log out of all devices" option that invalidates every active session for the account. Confirm a captured session token is useless after logout and summarize the changes.

### 16. Validate every JWT claim properly
*Area: Sessions, Cookies & Tokens. Why it matters: A JWT that isn't fully validated can be forged or replayed; verifying the signature alone is not enough.*

If my app uses JSON Web Tokens, audit how they are validated on every protected request. Ensure the code verifies the signature with the correct key, enforces the expected algorithm, and checks the standard claims — expiration, not-before, issuer, audience, and subject — rejecting any token that fails any check. Make sure validation happens server-side on every request and that no endpoint trusts an unverified token, then report any gaps you found.

### 17. Block JWT algorithm confusion attacks
*Area: Sessions, Cookies & Tokens. Why it matters: Accepting the algorithm declared in the token lets attackers forge tokens by switching it to "none" or swapping signing schemes.*

Review my JWT verification for algorithm confusion vulnerabilities. Configure the library to accept only an explicit allowlist of expected signing algorithms, reject tokens using "none", and never let the algorithm field inside the token decide how the signature is verified. Confirm the verification key cannot be confused between asymmetric and symmetric schemes, and explain how you locked the accepted algorithm down.

### 18. Strengthen and rotate signing secrets
*Area: Sessions, Cookies & Tokens. Why it matters: Weak or static signing secrets let attackers forge tokens; strong, rotatable secrets keep your tokens trustworthy.*

Audit the secrets used to sign sessions, JWTs, cookies, and any other signed data. Ensure each signing key is long, random, and loaded from configuration rather than hardcoded, and design the verification to support key rotation by accepting multiple valid keys during a changeover window. Add documentation or a mechanism for rotating these keys without logging everyone out instantly, and tell me where each key is now sourced from.

### 19. Store auth tokens safely client-side
*Area: Sessions, Cookies & Tokens. Why it matters: Storing tokens in the wrong place on the client exposes them to theft via malicious scripts; the storage choice matters as much as the token itself.*

Review how authentication tokens are stored and transmitted on the client side. Where possible, prefer secure, HttpOnly cookies for session tokens so scripts cannot read them, and if tokens must live in the browser, document the tradeoffs and minimize their exposure and lifetime. Ensure tokens are never placed in URLs, logs, or persistent storage that other scripts can reach, and describe the approach you settled on for my app.

### 20. Issue short-lived access tokens
*Area: Sessions, Cookies & Tokens. Why it matters: Long-lived access tokens stay dangerous long after a leak; short lifetimes paired with refresh tokens limit the damage.*

If my app issues access tokens, shorten their lifetime and pair them with a refresh mechanism. Make access tokens expire quickly so a leaked one is useful only briefly, and use longer-lived refresh tokens to obtain new access tokens without re-login. Ensure refresh happens over a secure channel and that the refresh token is stored more securely than the access token, then explain the lifetimes and flow you implemented.

### 21. Rotate refresh tokens on use
*Area: Sessions, Cookies & Tokens. Why it matters: Reusing the same refresh token indefinitely turns one leak into permanent access; rotation plus reuse detection shuts that down.*

Implement refresh token rotation with reuse detection. Each time a refresh token is exchanged, issue a new refresh token and invalidate the old one, and if an already-used refresh token is presented again, treat it as a compromise signal and revoke the entire token family for that session. Store refresh tokens hashed and tie them to a session so they can be revoked, and walk me through how a stolen token would be caught.

### 22. Build a token revocation mechanism
*Area: Sessions, Cookies & Tokens. Why it matters: Stateless tokens normally can't be cancelled before they expire; a revocation list lets you actually kill a compromised session.*

Add the ability to revoke active tokens or sessions before they naturally expire. Maintain a server-side record of valid or revoked sessions — for example a denylist of revoked token identifiers or a session store checked on each request — so that a compromised token can be invalidated immediately. Wire this into logout, password change, and an admin "force logout" action, and explain how revocation is enforced on each request.

### 23. Enforce authorization on the server
*Area: Authorization & Access Control. Why it matters: If the only thing stopping a user from accessing data is a hidden button, anyone can reach it by calling the API directly — every check must be re-enforced on the server.*

Audit my app for authorization that is enforced only in the frontend. For every endpoint that returns or modifies data, verify that the server independently confirms the authenticated user is allowed to perform that action, rather than relying on the UI hiding a button or a route. Find places where a logged-in user could access another action simply by calling the API directly, add the missing server-side checks, and give me a list of every endpoint you had to fix.

### 24. Fix insecure direct object references
*Area: Authorization & Access Control. Why it matters: When an app trusts an ID from the request without checking ownership, users can read or change other people's records just by changing a number in the URL.*

Search the codebase for insecure direct object references, where a resource is fetched or modified using an identifier from the request without verifying the current user is allowed to access that specific resource. For each one, add an ownership or permission check so users can only act on records they are authorized for, and consider using non-sequential identifiers so records cannot be trivially enumerated. Report each vulnerable endpoint and the check you added.

### 25. Implement role-based access control
*Area: Authorization & Access Control. Why it matters: Ad-hoc permission checks scattered through the code are easy to get wrong; a clear role model makes access rules consistent and reviewable.*

Introduce or clean up a role-based access control model for my app. Define clear roles and the permissions each role grants, centralize the permission checks into reusable middleware or guards instead of scattered inline conditionals, and apply them consistently to every protected route and action. Ensure roles are assigned and verified server-side and that the default for an unspecified route is to deny, then summarize the role model you put in place.

### 26. Apply a default-deny access policy
*Area: Authorization & Access Control. Why it matters: If routes are open unless someone remembers to lock them, new endpoints ship insecure by default — flipping to default-deny makes safety the baseline.*

Refactor my app's access control so the default posture is deny rather than allow. Ensure that any route or action without an explicit, satisfied authorization check is rejected, so a newly added endpoint is locked down until access is deliberately granted. Audit the current routes for anything unintentionally public, lock down what should be protected, and confirm which endpoints are intentionally public and why.

### 27. Lock down all admin routes
*Area: Authorization & Access Control. Why it matters: Administrative functionality is the highest-value target in any app; these routes need stricter protection than the rest.*

Find every administrative or privileged route, endpoint, and dashboard in my app and verify it is properly protected. Confirm each one requires authentication and an explicit admin-level authorization check on the server, is not discoverable or usable by a normal user, and ideally has additional safeguards like re-authentication for the most sensitive actions. Look for forgotten debug, internal, or setup endpoints that should not be exposed, and list everything you secured.

### 28. Close privilege escalation paths
*Area: Authorization & Access Control. Why it matters: Subtle gaps let ordinary users grant themselves elevated rights; finding and closing these paths protects the integrity of your whole permission system.*

Audit my app for privilege escalation paths where a user could gain rights they should not have. Look for endpoints that let a user change their own role or permissions, modify another user's account, or perform admin actions through an under-protected route, including indirect paths via mass assignment or trusting client-supplied role fields. Add server-side checks that prevent users from elevating their own or others' privileges, and report each path you closed.

### 29. Isolate data between tenants
*Area: Authorization & Access Control. Why it matters: In any app serving multiple customers or organizations, a missing scope check can leak one tenant's data to another — the most damaging failure for a SaaS product.*

If my app serves multiple users, teams, or organizations, audit it for tenant isolation failures where one tenant could access another's data. Ensure every query that reads or writes tenant-scoped data is filtered by the current user's tenant on the server, not just by an identifier supplied in the request, and that this scoping cannot be bypassed by changing an ID. Check background jobs, exports, and shared resources too, and report any place isolation was missing.

### 30. Add function-level permission checks
*Area: Authorization & Access Control. Why it matters: Having access to one action in a feature shouldn't imply access to all of them; each sensitive function needs its own check.*

Review my app for missing function-level authorization, where access to one part of a feature wrongly grants access to more sensitive actions within it. Ensure each individual action — especially create, update, delete, and export operations — has its own explicit permission check rather than assuming that viewing implies editing or that membership implies administration. Make these checks consistent across the codebase and tell me which functions were under-protected.

### 31. Block mass assignment of fields
*Area: Authorization & Access Control. Why it matters: When user input is bound directly to a database record, attackers can set fields they were never meant to touch, like roles or balances.*

Search for mass assignment vulnerabilities where incoming request data is bound directly to a database model or object without restricting which fields can be set. For each case, define an explicit allowlist of fields a user may set and ignore everything else, so sensitive attributes like role, permissions, account status, or pricing cannot be overwritten through the request. Confirm the protection covers both create and update paths and list the models you secured.

### 32. Re-verify access on each request
*Area: Authorization & Access Control. Why it matters: Checking permissions once and trusting that decision later lets a user keep access after their rights have been revoked; every request should be re-evaluated.*

Ensure authorization is re-evaluated on every request rather than cached from an earlier point such as login. Verify that a change to a user's roles, permissions, or account status takes effect on their very next request, so revoking access actually locks the user out promptly. Check that long-lived sessions and tokens still honor current permissions, and explain how access decisions are now kept fresh.

### 33. Use parameterized database queries
*Area: Injection & Query Safety. Why it matters: Building SQL by stitching strings together with user input is the classic path to a full database breach; parameterized queries make it structurally impossible.*

Audit every database query in the codebase for SQL injection. Find any query built by concatenating or interpolating user-controlled input into the query string, and convert each one to a parameterized query or prepared statement so that input is always treated as data, never as executable SQL. Where my ORM or query builder is used, confirm I'm using its safe parameter-binding features rather than raw string interpolation, and give me a list of every query you fixed.

### 34. Prevent NoSQL query injection
*Area: Injection & Query Safety. Why it matters: NoSQL databases are just as injectable as SQL ones when query objects are built from raw input, letting attackers bypass auth or dump data.*

If my app uses a NoSQL database, audit it for injection where user input is placed directly into query objects or operators. Ensure inputs are validated and cast to expected types so an attacker cannot smuggle in query operators or expressions that alter the query's logic — for example turning a value into an object that always matches. Sanitize or reject unexpected structures in incoming data, and report each query you hardened.

### 35. Block operating system command injection
*Area: Injection & Query Safety. Why it matters: If user input ever reaches a shell command, attackers can run arbitrary commands on your server; this is among the most severe vulnerabilities possible.*

Search the codebase for any place where the app runs operating-system commands, shell scripts, or external processes, and check whether user-controlled input can influence them. Eliminate command injection by avoiding the shell entirely where possible, passing arguments as a structured array rather than a concatenated string, and strictly validating any input that must be included. If a piece of functionality doesn't truly need to shell out, refactor it, and report every command-execution site you found.

### 36. Close ORM-level injection vectors
*Area: Injection & Query Safety. Why it matters: ORMs are safe by default but still expose raw-query and dynamic-condition escape hatches that reintroduce injection if misused.*

Review how my ORM or query builder is used and find places where its raw-query, raw-fragment, or dynamic-condition features are fed user input unsafely. Replace unsafe raw fragments with parameterized equivalents, validate any user input used to choose column names, sort fields, or operators against an allowlist, and ensure dynamic filters cannot be manipulated into unintended queries. Summarize the unsafe ORM usage you found and how you fixed it.

### 37. Sanitize inputs used in LDAP
*Area: Injection & Query Safety. Why it matters: Apps that talk to a directory service can be tricked into auth bypass or data disclosure when user input is dropped unescaped into LDAP filters.*

If my app builds LDAP queries or filters — for example for directory lookups or authentication — audit them for LDAP injection. Ensure all user-supplied values are escaped using the proper LDAP escaping rules before being placed into a filter or distinguished name, and validate inputs against expected formats. Confirm that no input can alter the structure of a filter to bypass authentication or widen a search, and report what you changed.

### 38. Escape identifiers in dynamic queries
*Area: Injection & Query Safety. Why it matters: Even with parameterized values, letting user input choose table or column names reopens the injection door; identifiers need their own allowlist.*

Find queries where user input determines structural parts of the query that cannot be parameterized — such as table names, column names, sort directions, or operators. For each, validate the input against a strict allowlist of permitted identifiers rather than passing it through, and use the database driver's identifier-quoting facilities where appropriate. Make sure no user-controlled string is ever concatenated into a query as a raw identifier, and list the spots you secured.

### 39. Validate and bound user regex
*Area: Injection & Query Safety. Why it matters: A maliciously crafted input against a vulnerable regular expression can pin your server's CPU and take the app down — a denial-of-service hiding in plain sight.*

Audit the codebase for regular-expression denial-of-service risks. Find regexes that run against user-controlled input, especially ones with nested or overlapping repetition that can backtrack catastrophically, and rewrite them into safe linear-time patterns or replace them with non-regex parsing. Add input length limits before regex evaluation and, where supported, a matching timeout, and tell me which patterns were dangerous and how you fixed them.

### 40. Prevent prototype pollution in objects
*Area: Injection & Query Safety. Why it matters: In JavaScript apps, attacker-controlled keys merged into objects can poison shared prototypes and lead to crashes, bypasses, or code execution.*

If my app is JavaScript or TypeScript, audit it for prototype pollution. Find places where user-controlled keys are used to set object properties or where untrusted data is deeply merged or cloned, and block dangerous keys like "__proto__", "constructor", and "prototype" from being written. Prefer safe data structures such as Map or null-prototype objects for untrusted key-value data, validate object shapes, and report each merge or assignment you secured.

### 41. Disable XML external entity parsing
*Area: Injection & Query Safety. Why it matters: XML parsers that resolve external entities can be coerced into reading local files or making server-side requests; disabling that feature closes a serious hole.*

If my app parses XML or formats built on it, audit the parser configuration for XML external entity vulnerabilities. Disable resolution of external entities and external document type definitions in every XML parser the app uses, so a malicious document cannot read local files, reach internal services, or trigger denial of service. Verify the safe configuration on each parsing site rather than assuming the default is safe, and tell me which parsers you reconfigured.

### 42. Prevent formula injection in exports
*Area: Injection & Query Safety. Why it matters: Data exported to spreadsheets can carry hidden formulas that execute on the victim's machine when they open the file — a quiet but real attack on your users.*

Audit any feature that exports user-influenced data to CSV or spreadsheet files for formula injection. Before writing a cell, neutralize values that begin with characters a spreadsheet treats as a formula trigger — such as equals, plus, minus, or at signs — by prefixing or quoting them so they are rendered as text rather than executed. Apply this consistently to every exported field that can contain user input, and confirm which export paths you protected.

### 43. Encode output to stop XSS
*Area: Cross-Site Scripting & Output Encoding. Why it matters: When user input is rendered back into a page without encoding, attackers can run scripts in your users' browsers — context-aware encoding neutralizes that.*

Audit how user-controlled data is rendered into HTML responses across my app and fix cross-site scripting issues. Ensure every piece of dynamic data is encoded for the exact context it appears in — HTML body, attribute, URL, or script — using my framework's built-in escaping rather than manual or partial escaping. Find any place output is inserted unescaped, fix it, and give me a list of the locations and the encoding you applied.

### 44. Sanitize user-submitted HTML content
*Area: Cross-Site Scripting & Output Encoding. Why it matters: Features that intentionally allow rich text can't just escape everything; they need a sanitizer that strips dangerous markup while keeping safe formatting.*

If my app accepts and displays rich text or HTML from users — such as comments, posts, or profile bios — add server-side HTML sanitization. Run untrusted HTML through a vetted sanitizer configured with a strict allowlist of safe tags and attributes, stripping scripts, event handlers, dangerous URLs, and style-based attacks. Sanitize on input, on output, or both as appropriate, and tell me which fields are now sanitized and what the allowlist permits.

### 45. Add a Content Security Policy
*Area: Cross-Site Scripting & Output Encoding. Why it matters: A Content Security Policy is a powerful backstop that limits what a page can load and execute, sharply reducing the impact of any XSS that slips through.*

Add a Content Security Policy to my app to limit the damage of cross-site scripting. Start by restricting script, style, and resource sources to trusted origins, eliminate or tightly control inline scripts, and set the policy via response headers on every page. Begin in report-only mode if needed to find violations without breaking the app, then enforce it, and explain the directives you chose and what they block.

### 46. Eliminate DOM-based XSS sinks
*Area: Cross-Site Scripting & Output Encoding. Why it matters: Some XSS never touches the server — it happens entirely in the browser when scripts write untrusted data into dangerous DOM sinks.*

Audit my client-side JavaScript for DOM-based cross-site scripting. Find places where untrusted data — from the URL, query string, fragment, postMessage, or storage — flows into dangerous sinks like innerHTML, document.write, or dynamic script and event handlers, and rewrite them to use safe APIs such as textContent or properly sanitized insertion. Treat all browser-supplied data as untrusted, and report each source-to-sink flow you remediated.

### 47. Prevent stored XSS in content
*Area: Cross-Site Scripting & Output Encoding. Why it matters: Stored XSS is especially dangerous because the malicious payload is saved once and then served to everyone who views it — these need both input and output defenses.*

Audit the paths where user-submitted content is saved and later displayed to other users for stored cross-site scripting. Ensure content is validated and sanitized appropriately when stored and consistently encoded when rendered, so a payload saved by one user cannot execute in another user's browser. Check less obvious surfaces too — usernames, file names, notification text, and admin views — and report each stored-content flow you secured.

### 48. Block server-side template injection
*Area: Cross-Site Scripting & Output Encoding. Why it matters: When user input is rendered as part of a template rather than as data, attackers can execute code on the server through the template engine.*

Audit my server-side templating for template injection. Find any place where user-controlled input is concatenated into a template or passed where the engine will evaluate it as template syntax, and refactor so untrusted input is always supplied as data to a static template, never used to build the template itself. Confirm the engine's auto-escaping is enabled and that no user input can reach template evaluation, then report what you found.

### 49. Audit unsafe HTML render bypasses
*Area: Cross-Site Scripting & Output Encoding. Why it matters: Modern frameworks escape output by default, but every one has an explicit "render raw HTML" escape hatch that reintroduces XSS when fed untrusted data.*

Search the codebase for uses of my framework's raw-HTML rendering escape hatches — such as dangerouslySetInnerHTML, v-html, bypassSecurityTrust, or the equivalent that disables automatic escaping. For each occurrence, determine whether the content can include untrusted input and, if so, either remove the bypass or run the content through a strict sanitizer first. Document every bypass you found, whether it was safe, and how you handled it.

### 50. Sanitize content rendered into emails
*Area: Cross-Site Scripting & Output Encoding. Why it matters: HTML emails are a frequently forgotten XSS and injection surface; user data placed into emails needs the same care as data placed into web pages.*

Audit any emails or notifications my app generates that include user-controlled content. Encode or sanitize that content for the email's format so it cannot inject markup, scripts, or misleading links into the message, and ensure values placed into headers like subject, to, and from cannot inject additional headers. Treat email templates with the same output-encoding discipline as web pages, and report which email flows you hardened.

### 51. Add CSRF protection to mutations
*Area: Cross-Origin & Request Forgery. Why it matters: Without CSRF protection, a malicious site can trick a logged-in user's browser into performing actions on your app without their knowledge.*

Audit my app for cross-site request forgery on any state-changing request — anything that creates, updates, or deletes data. Add CSRF protection appropriate to my architecture, such as synchronizer tokens validated on the server for form-based apps, and pair it with the SameSite cookie attribute. Ensure safe, read-only requests aren't needlessly blocked and that the protection covers every mutating endpoint, then list the endpoints you secured and the mechanism used.

### 52. Configure CORS without dangerous wildcards
*Area: Cross-Origin & Request Forgery. Why it matters: A loose cross-origin policy can let untrusted websites read responses from your API on behalf of your users; CORS needs to be explicit and minimal.*

Review my Cross-Origin Resource Sharing configuration for unsafe settings. Replace any wildcard origin — especially when combined with credentials — with an explicit allowlist of trusted origins, allow only the methods and headers actually needed, and never reflect the incoming Origin header back without validating it against the allowlist. Confirm that credentials are only permitted for trusted origins, and explain the final CORS policy you set.

### 53. Verify Origin and Referer headers
*Area: Cross-Origin & Request Forgery. Why it matters: Checking where a sensitive request came from adds a cheap, effective layer of defense against cross-site and forged requests.*

For sensitive state-changing endpoints, add server-side validation of the Origin and Referer headers as an additional defense. Confirm that requests to these endpoints originate from my own application's expected origins and reject those that don't, while handling the cases where these headers may legitimately be absent. Use this as a complement to, not a replacement for, token-based CSRF protection, and tell me which endpoints now perform this check.

### 54. Set the SameSite cookie attribute
*Area: Cross-Origin & Request Forgery. Why it matters: The SameSite attribute is a simple cookie setting that blocks many cross-site request forgery attacks by default.*

Audit the cookies my app sets and apply an appropriate SameSite attribute to each, especially session and authentication cookies. Choose a strict or lax policy that prevents cookies from being sent on cross-site requests that could be forged, while preserving any legitimately needed cross-site behavior. Confirm the attribute is present on the actual responses and consistent with the rest of my CSRF defenses, then summarize the values you chose and why.

### 55. Block open redirect vulnerabilities
*Area: Cross-Origin & Request Forgery. Why it matters: An open redirect lets attackers use your trusted domain to send users to malicious sites, powering convincing phishing and sometimes token theft.*

Search for open redirect vulnerabilities where my app redirects the browser to a URL taken from user input, such as a "next" or "return" parameter after login. For each, validate the destination against an allowlist of permitted internal paths or trusted hosts, and reject or default anything that points off-site or uses an unexpected scheme. Make sure attackers cannot smuggle external destinations through encoding tricks, and report each redirect you secured.

### 56. Prevent clickjacking with frame controls
*Area: Cross-Origin & Request Forgery. Why it matters: Clickjacking tricks users into clicking hidden elements by loading your site inside an invisible frame; frame restrictions stop your pages from being embedded maliciously.*

Protect my app against clickjacking by controlling whether and where its pages can be embedded in frames. Set the appropriate response headers — a frame-ancestors directive in the Content Security Policy and, for older browsers, X-Frame-Options — to deny framing or restrict it to trusted origins, and apply this across all pages, especially authenticated and sensitive ones. Confirm the headers are present on responses, and tell me the framing policy you enforced.

### 57. Validate OAuth redirect URIs strictly
*Area: Cross-Origin & Request Forgery. Why it matters: Loose redirect handling in an OAuth flow can let attackers intercept authorization codes and hijack accounts; exact-match validation closes that.*

If my app implements an OAuth or social-login flow, audit how redirect URIs and state are handled. Validate the redirect URI against an exact allowlist rather than a loose prefix or pattern match, use and verify a random state parameter to prevent CSRF on the callback, and use PKCE for the authorization-code flow where applicable. Ensure authorization codes are single-use and short-lived, and walk me through the hardened flow.

### 58. Validate input on the server
*Area: Input Validation & Request Handling. Why it matters: Browser-side validation is only a convenience for users; an attacker bypasses it instantly by calling your API directly, so the server must validate everything.*

Audit my app to ensure all input validation is enforced on the server, not only in the browser. For every endpoint, validate that incoming data matches the expected type, shape, and constraints server-side, treating any client-side validation as a user-experience nicety rather than a security control. Find endpoints that trust client-validated input and add the missing server-side checks, then give me a list of the endpoints you hardened.

### 59. Validate types, lengths, and formats
*Area: Input Validation & Request Handling. Why it matters: Accepting whatever shape of data arrives invites a long tail of bugs and attacks; strict allowlist validation rejects bad input before it reaches your logic.*

Add strict, allowlist-based validation to my app's inputs. For each endpoint, define and enforce the expected data type, length or range, and format for every field, rejecting anything that doesn't conform rather than trying to clean it up. Prefer a schema-based validation approach suited to my stack so validation is centralized and consistent, and apply sensible maximum lengths everywhere. Summarize where you added validation and the rules you enforced.

### 60. Cap request body and payload size
*Area: Input Validation & Request Handling. Why it matters: Without size limits, a single oversized request can exhaust memory and take your app offline; limits are a simple, effective denial-of-service defense.*

Add limits on the size of incoming requests across my app. Configure maximum request body sizes at the server or framework level, cap the size of uploaded files and individual fields, and limit the number of items in arrays and the depth of nested JSON so a malicious payload can't exhaust memory or CPU. Return a clear error when a limit is exceeded, and tell me the limits you set and where they're enforced.

### 61. Block path traversal in file access
*Area: Input Validation & Request Handling. Why it matters: When file paths are built from user input, attackers can climb out of the intended directory and read or overwrite sensitive files using sequences like "../".*

Search for path traversal vulnerabilities anywhere my app uses user input to build a file path — for reading, writing, serving, or including files. For each, resolve the final path and verify it stays within an explicitly allowed base directory, reject traversal sequences and absolute paths, and prefer mapping user input to known-safe identifiers instead of using it directly as a filename. Report each file-access site you secured and how.

### 62. Prevent server-side request forgery
*Area: Input Validation & Request Handling. Why it matters: SSRF lets an attacker make your server send requests to internal systems or cloud metadata endpoints it should never reach — a frequent path to full compromise.*

Audit any feature where my server fetches a URL or makes a request based on user input — webhooks, link previews, importers, or image fetchers — for server-side request forgery. Validate and restrict the target so it cannot reach internal addresses, the loopback interface, or cloud metadata endpoints, using an allowlist of permitted hosts where possible and blocking redirects to disallowed targets. Confirm the checks survive DNS and redirect tricks, and report each fetch you secured.

### 63. Stop HTTP header and CRLF injection
*Area: Input Validation & Request Handling. Why it matters: If user input flows into response headers unchecked, attackers can inject new headers or split responses, enabling cache poisoning and other attacks.*

Audit places where user-controlled input is used to construct HTTP headers, redirect locations, or cookies, and check for header (CRLF) injection. Ensure newline and carriage-return characters cannot be smuggled into a header value to inject additional headers or split the response, by validating and stripping control characters or using framework APIs that encode header values safely. Report every header-construction site that handled user input and how you fixed it.

### 64. Enforce strict Content-Type validation
*Area: Input Validation & Request Handling. Why it matters: Accepting requests without checking their declared content type invites confusion attacks and bypasses; the server should require and verify the expected type.*

Review how my app handles the Content-Type of incoming requests. For endpoints that expect a specific format such as JSON, require and verify that content type rather than parsing whatever arrives, and reject mismatched or missing types with a clear error. Ensure the body parser doesn't silently accept unexpected formats that could bypass validation or CSRF defenses, and tell me which endpoints now enforce strict content-type checks.

### 65. Reject malformed and unexpected fields
*Area: Input Validation & Request Handling. Why it matters: Silently ignoring extra or malformed fields hides bugs and can mask attacks; strict parsing surfaces problems and shrinks the attack surface.*

Make my app's request handling strict about unexpected and malformed input. Configure validation to reject requests containing unknown or extra fields rather than silently ignoring them, fail clearly on malformed JSON or bad encoding, and ensure parsing errors return a safe, generic error without leaking internals. This narrows what an attacker can smuggle in alongside valid data — report where you tightened parsing and what now gets rejected.

### 66. Move hardcoded secrets to environment variables
*Area: Secrets & Configuration. Why it matters: Secrets written directly into source code leak the moment anyone sees the repository; moving them to configuration is foundational hygiene.*

Scan the entire codebase for hardcoded secrets — API keys, database passwords, tokens, private keys, and signing secrets embedded directly in source files. Move each one into environment variables or a configuration system loaded at runtime, replace the literals with references to that configuration, and add a sample configuration file documenting the required variables without real values. Give me a list of every secret you found and relocated so I can rotate them.

### 67. Remove committed secrets from git history
*Area: Secrets & Configuration. Why it matters: Deleting a secret from the current code doesn't help if it's still sitting in your git history where anyone can find it; it must be purged and rotated.*

Check whether any secrets have been committed to my git history, including in configuration files, environment files, or earlier versions of source files. Identify what was exposed and where, advise me on safely purging those secrets from the history, and make sure the relevant files are properly ignored going forward. Emphasize which exposed secrets I must now rotate, since anything ever committed should be treated as compromised, and give me that list.

### 68. Keep secrets out of client bundles
*Area: Secrets & Configuration. Why it matters: Anything shipped to the browser is fully visible to users; secrets must never be embedded in frontend code or build output.*

Audit my frontend and build configuration to ensure no secrets are exposed in code that ships to the browser. Find any API keys, tokens, or credentials embedded in client-side code or build-time variables that end up in the bundle, and move sensitive operations behind a server endpoint so the secret stays on the server. Distinguish values that are genuinely safe to expose from those that are not, and report every secret that was reaching the client.

### 69. Separate development and production credentials
*Area: Secrets & Configuration. Why it matters: Sharing credentials across environments means a leak in a low-security dev setup compromises production; each environment needs its own isolated secrets.*

Review how my app manages configuration and secrets across environments and ensure development, staging, and production each use separate credentials and settings. Confirm that production secrets are never present in development or test configuration, that debugging and verbose features are environment-gated, and that the app loads the correct configuration per environment without risk of mixing them. Tell me how environments are now separated and flag anything currently shared.

### 70. Rotate any exposed or leaked secrets
*Area: Secrets & Configuration. Why it matters: Once a secret has been exposed, the only real fix is to replace it; rotation invalidates whatever an attacker may already hold.*

Help me identify and rotate secrets that may have been exposed — through commits, logs, client bundles, error messages, or third-party services. Make a list of every credential that could plausibly be compromised, walk me through rotating each one safely with minimal downtime, and update the app to load the new values from secure configuration. Where supported, set up a routine for periodic rotation, and summarize which secrets need rotating now.

### 71. Hide stack traces in production
*Area: Secrets & Configuration. Why it matters: Detailed error pages are gold for attackers, revealing your stack, file paths, and sometimes secrets; production should show users a generic message instead.*

Audit my app's error handling to ensure detailed errors are never exposed to users in production. Configure the app so that unhandled errors return a generic, user-friendly message and a safe status code, while full stack traces and diagnostic details go only to server-side logs. Disable framework debug modes in production and check that database errors, file paths, and dependency details aren't leaked in responses, then confirm what users now see versus what gets logged.

### 72. Remove revealing server response headers
*Area: Secrets & Configuration. Why it matters: Headers that announce your server software and versions hand attackers a roadmap of known exploits to try; stripping them reduces your visible attack surface.*

Review the HTTP response headers my app and server send and remove or genericize ones that reveal implementation details, such as server software names, framework identifiers, and version numbers. While you're there, confirm the recommended security headers are present and correctly configured. Make these changes at the application or server layer so they apply to all responses, and give me a before-and-after of the headers being sent.

### 73. Disable directory listing and indexes
*Area: Secrets & Configuration. Why it matters: If your server lists the contents of directories without an index file, attackers can browse for sensitive files you never meant to expose.*

Check whether my app or web server exposes directory listings, where requesting a folder without an index file reveals its contents. Disable automatic directory listing across the server and application, ensure that sensitive directories and files are not web-accessible at all, and confirm that backup files, configuration, and version-control folders cannot be browsed or downloaded. Tell me what was exposed and what you locked down.

### 74. Harden insecure default framework settings
*Area: Secrets & Configuration. Why it matters: Frameworks often ship with permissive defaults meant for convenience, not production; reviewing and tightening them closes gaps you didn't know were open.*

Audit my framework and server configuration for insecure defaults that should be hardened for production. Review settings governing debug output, default credentials, sample or admin routes, permissive CORS, verbose logging, and exposed management endpoints, and tighten each to a secure value. Cross-check against the security configuration recommendations for my specific framework, fix what's off, and give me a summary of every default you changed.

### 75. Force HTTPS across the application
*Area: Cryptography & Data Protection. Why it matters: Traffic sent over plain HTTP can be read and tampered with in transit; redirecting everything to HTTPS protects credentials, sessions, and data.*

Audit my app to ensure all traffic is served exclusively over HTTPS. Redirect any plain HTTP requests to HTTPS, confirm that cookies are flagged Secure so they're never sent unencrypted, and check that internal links, API calls, and third-party resources use HTTPS to avoid mixed content. Verify there are no endpoints reachable only over HTTP, and tell me what you changed to enforce encryption everywhere.

### 76. Enable HSTS to enforce TLS
*Area: Cryptography & Data Protection. Why it matters: HTTP Strict Transport Security tells browsers to refuse to connect to your site over plain HTTP, closing the gap before the first redirect even happens.*

Add an HTTP Strict Transport Security header to my app so browsers always use HTTPS for my domain. Set a sensible max-age and, once you've confirmed every subdomain supports HTTPS, consider including subdomains and preload. Make sure the header is sent on HTTPS responses across the app, warn me about the implications of the preload commitment, and explain the exact policy you configured.

### 77. Encrypt sensitive data at rest
*Area: Cryptography & Data Protection. Why it matters: Even with good access control, sensitive data stored unencrypted is fully exposed if the storage layer is breached; encryption at rest adds a crucial backstop.*

Identify the sensitive data my app stores — such as personal information, financial details, health data, or secrets — and ensure it is encrypted at rest. Enable encryption at the database or storage layer, and for especially sensitive fields add application-level encryption using a vetted library and a securely managed key. Ensure encryption keys are stored separately from the data and never hardcoded, then summarize what data is now encrypted and how keys are handled.

### 78. Replace weak cryptographic algorithms
*Area: Cryptography & Data Protection. Why it matters: Outdated algorithms like MD5, SHA1, and DES are broken or broken-enough that relying on them provides a false sense of security; modern replacements are essential.*

Scan the codebase for weak or outdated cryptography and replace it. Find uses of broken hash functions like MD5 or SHA1, weak ciphers like DES, insecure modes like ECB, hardcoded encryption keys or initialization vectors, and homegrown crypto, and replace each with a current, well-vetted algorithm and a standard library implementation. Confirm that hashing for passwords specifically uses a slow algorithm, and report every weak primitive you found and what you replaced it with.

### 79. Use a cryptographically secure random generator
*Area: Cryptography & Data Protection. Why it matters: Security-sensitive values generated with an ordinary random function can be predicted by attackers; only a cryptographically secure generator is safe for tokens and secrets.*

Audit how my app generates random values and ensure anything security-sensitive uses a cryptographically secure random source. Find tokens, session identifiers, password-reset codes, salts, and any other security values generated with a standard or predictable random function, and replace those with my platform's cryptographically secure generator. Confirm the values are long enough to resist guessing, and list each generator you replaced and where.

### 80. Hash security tokens before storage
*Area: Cryptography & Data Protection. Why it matters: Storing reset tokens, API keys, and session identifiers in plain text means a database leak hands attackers working credentials; hashing them limits the damage.*

Review how my app stores sensitive tokens — password-reset tokens, API keys, session identifiers, email-verification codes, and similar. Ensure each is stored as a hash rather than in plain text, so that a database leak does not expose usable tokens, and verify incoming tokens by hashing and comparing rather than storing the original. Use a fast hash for high-entropy random tokens and constant-time comparison, then report which token types you changed.

### 81. Mask sensitive values in logs
*Area: Cryptography & Data Protection. Why it matters: Logs are frequently exposed, shared, or shipped to third parties; sensitive data written into them quietly becomes a leak vector.*

Audit my app's logging for sensitive data exposure. Find places where passwords, tokens, API keys, full payment details, personal information, or full request bodies are written to logs, and redact, mask, or remove them so logs capture what's needed for debugging without leaking secrets or personal data. Add a consistent approach for masking sensitive fields before they're logged, and give me a list of the log statements you cleaned up.

### 82. Encrypt stored personal identifiable information
*Area: Cryptography & Data Protection. Why it matters: Personal data carries legal and ethical obligations; encrypting it protects users and reduces your exposure if data is stolen.*

Identify where my app stores personally identifiable information — names, emails, addresses, phone numbers, government identifiers, and similar — and strengthen its protection. Encrypt the most sensitive fields at the application level, ensure access is restricted and logged, and avoid storing any personal data you don't actually need. Where a value only needs to be matched rather than read back, consider storing a hash instead, and summarize what personal data you secured and how.

### 83. Prevent caching of sensitive pages
*Area: Cryptography & Data Protection. Why it matters: Sensitive pages cached by browsers or shared proxies can be retrieved later by the next person on a device or by an attacker; cache headers prevent that.*

Audit responses that contain sensitive or personalized data and ensure they aren't cached where they shouldn't be. Set appropriate Cache-Control, Pragma, and related headers on authenticated and sensitive pages and API responses so browsers and intermediary caches don't store them, while still allowing safe caching of genuinely public, static assets. Confirm that pages behind login can't be retrieved from cache after logout, and tell me which responses you adjusted.

### 84. Add global API rate limiting
*Area: API & Rate Limiting. Why it matters: Unthrottled APIs invite abuse, scraping, brute force, and denial of service; baseline rate limiting protects availability and curbs automated attacks.*

Add rate limiting across my app's API endpoints to protect against abuse and denial of service. Apply sensible per-client limits keyed on a reliable identifier such as authenticated user or IP, with stricter limits on expensive or sensitive operations, and return standard 429 responses with a Retry-After header when limits are hit. Use an approach that works across my deployment, including multiple server instances, and explain the tiers of limits you configured.

### 85. Limit GraphQL query depth and cost
*Area: API & Rate Limiting. Why it matters: A single deeply nested or expansive GraphQL query can overwhelm your backend; depth and cost limits keep one request from doing disproportionate damage.*

If my app exposes a GraphQL API, add protections against expensive and abusive queries. Enforce a maximum query depth and a query-cost or complexity limit so a single deeply nested or broad query can't exhaust the backend, cap pagination sizes, and apply rate limiting. Reject queries that exceed the limits with a clear error, and tell me the depth and cost thresholds you set and why.

### 86. Disable GraphQL introspection in production
*Area: API & Rate Limiting. Why it matters: Introspection conveniently exposes your entire API schema — including endpoints you'd rather not advertise — making it a gift to attackers mapping your app.*

If my app uses GraphQL, review whether schema introspection is exposed in production. Disable introspection and any interactive query playground in production environments so attackers can't trivially enumerate the full schema, while keeping these tools available in development. Confirm error responses don't leak schema details either, and tell me how introspection is now gated per environment.

### 87. Trim over-exposed fields in responses
*Area: API & Rate Limiting. Why it matters: APIs that return whole database records often leak fields the client never needs — internal flags, other users' data, or secrets — and attackers read every byte.*

Audit my API responses for excessive data exposure, where endpoints return more fields than the client needs. For each endpoint, define an explicit output shape that includes only the fields required, and strip internal flags, security-relevant fields, and other users' data rather than serializing whole database records. Pay special attention to user, account, and nested related objects, and report which endpoints were over-sharing and what you removed.

### 88. Enforce maximum pagination page sizes
*Area: API & Rate Limiting. Why it matters: If a client can request an unlimited page size, a single call can pull your entire dataset and strain the system; capping page size prevents that.*

Review every paginated or list endpoint in my app and enforce a maximum page size on the server. Cap how many records a single request can return regardless of what the client asks for, apply a sensible default, and validate pagination parameters so they can't be manipulated into returning everything or causing errors. Ensure this protects both performance and data exposure, and tell me the limits you applied across endpoints.

### 89. Verify signatures on incoming webhooks
*Area: API & Rate Limiting. Why it matters: Webhook endpoints are publicly reachable and easy to spoof; verifying the sender's signature ensures you only act on genuine events.*

Audit any webhook endpoints my app exposes to receive events from third-party services. For each, verify the authenticity of incoming requests using the provider's signature mechanism — validating the signature against the raw request body with the shared secret and a constant-time comparison — and reject anything that fails. Add protection against replayed events using timestamps or event identifiers, and tell me which webhooks now verify their senders.

### 90. Add idempotency keys to mutations
*Area: API & Rate Limiting. Why it matters: Network retries and double-clicks can cause sensitive operations to run twice; idempotency keys ensure a repeated request has the same effect as a single one.*

For sensitive, non-repeatable operations such as payments, orders, or account changes, add idempotency so a retried or duplicated request doesn't execute twice. Accept an idempotency key from the client, record the result of the first request keyed on it, and return that stored result for any repeat within a reasonable window instead of performing the action again. Make this safe under concurrent duplicate requests, and explain how idempotency is enforced for these endpoints.

### 91. Validate upload types by content
*Area: File Uploads. Why it matters: Trusting a file's extension or declared type is easy to fake; inspecting the actual content stops attackers from sneaking dangerous files past your checks.*

Audit my file upload handling and validate file types by their actual content, not just the extension or the client-supplied content type. Inspect each upload's real format using its signature or a trusted detection method, enforce an allowlist of permitted types for each upload feature, and reject anything that doesn't match. Combine this with the other upload protections, and tell me which upload endpoints now verify content type and what they allow.

### 92. Enforce a maximum upload size
*Area: File Uploads. Why it matters: Without a size cap, a single large upload can fill your disk or exhaust memory, taking the app down; a strict limit is a basic availability safeguard.*

Add and enforce maximum file size limits on every upload feature in my app. Set the limit at the server or framework level so oversized uploads are rejected early before consuming memory or disk, choose sensible limits per upload type, and return a clear error when a file is too large. Confirm the limit can't be bypassed by chunked or streamed uploads, and tell me the limits you configured for each upload path.

### 93. Store uploads outside the webroot
*Area: File Uploads. Why it matters: Files saved inside the web-served directory can sometimes be executed or accessed directly; storing them elsewhere and serving them deliberately is far safer.*

Review where my app stores uploaded files and ensure they aren't placed where they can be directly served or executed by the web server. Store uploads outside the public web root or in a dedicated object store, and serve them back only through a controlled endpoint that applies authentication, authorization, and safe response headers. Confirm uploaded files can never be executed as code, and describe how files are now stored and served.

### 94. Randomize and sanitize stored filenames
*Area: File Uploads. Why it matters: User-controlled filenames enable path traversal, overwrites, and confusing collisions; generating safe server-side names removes that whole class of problems.*

Audit how my app names and stores uploaded files and stop trusting user-supplied filenames. Generate a new, random, safe identifier as the stored filename, strip or neutralize path separators and special characters from any original name you retain for display, and ensure uploads can't overwrite existing files or escape the intended storage location. Preserve the original name only as metadata, and report how filenames are now handled.

### 95. Serve user files without execution
*Area: File Uploads. Why it matters: When user-uploaded files are served back, the wrong content handling can let a malicious file run as a page or script in the victim's browser.*

Review how my app serves user-uploaded files back to users and ensure they're delivered safely. Set response headers that force download or safe rendering rather than execution — such as a content-disposition that prompts download, a correct and locked content type, and nosniff — and serve user content from a separate domain or path where feasible to isolate it. Confirm an uploaded HTML or script file can't run in another user's session, and summarize the headers you applied.

### 96. Audit dependencies for known vulnerabilities
*Area: Dependencies, Logging & Monitoring. Why it matters: Most app code is third-party packages, and known vulnerabilities in them are a leading cause of breaches; scanning surfaces the ones you need to patch.*

Scan my project's dependencies for known security vulnerabilities using the appropriate audit tool for my package ecosystem. Produce a list of vulnerable packages with their severity, identify which are exploitable in my app's context, and update or replace them to patched versions, taking care with breaking changes. Where no fix exists, suggest mitigations, and give me a prioritized summary of what was vulnerable and what you updated.

### 97. Lock dependency versions with a lockfile
*Area: Dependencies, Logging & Monitoring. Why it matters: Without a lockfile, your app can silently pull in different — possibly malicious or broken — package versions on each install; locking makes builds reproducible and safer.*

Ensure my project uses a committed lockfile that pins exact versions of every direct and transitive dependency. Generate or update the lockfile, confirm it's committed to version control, and verify the install process uses it so builds are reproducible and can't silently pull unexpected versions. Remove any unused dependencies you find along the way to shrink the attack surface, and tell me the state of dependency pinning before and after.

### 98. Add Subresource Integrity to scripts
*Area: Dependencies, Logging & Monitoring. Why it matters: Scripts and styles loaded from a CDN can be tampered with at the source; Subresource Integrity makes the browser refuse anything that's been altered.*

Audit my app for third-party scripts and stylesheets loaded from external sources such as CDNs, and add Subresource Integrity protection. For each external resource, add an integrity hash and appropriate cross-origin attribute so the browser only executes the resource if it matches the expected content, blocking tampered or compromised files. Prefer self-hosting or pinned versions where integrity hashes aren't practical, and list the resources you protected.

### 99. Log security events for monitoring
*Area: Dependencies, Logging & Monitoring. Why it matters: You can't respond to an attack you can't see; recording key security events gives you the visibility to detect and investigate suspicious activity.*

Add structured logging of security-relevant events across my app — logins and failures, logout, password and permission changes, access-control denials, and other sensitive actions. Capture useful context like timestamp, the acting user, and source, while deliberately excluding secrets and sensitive personal data from the logs. Make the logs consistent and queryable so suspicious patterns can be spotted, and tell me which events are now being recorded.

### 100. Prevent log injection and forgery
*Area: Dependencies, Logging & Monitoring. Why it matters: If untrusted input is written straight into logs, attackers can forge entries or break your logging pipeline; sanitizing log input keeps your records trustworthy.*

Audit how my app writes user-controlled data into logs and protect against log injection. Ensure newline and control characters in user input can't be used to forge fake log entries or split lines, by sanitizing or encoding values before logging and preferring structured logging where each field is recorded distinctly. Confirm that log output rendered in any viewer or dashboard can't execute or mislead, and report where you hardened logging.

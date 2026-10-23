# Application-Security Checklist (audit · security lens)

Audit cues for the `security` reasoning lens: the app-level security taxonomy
the scanners (gitleaks / npm-audit / semgrep) do NOT cover. Reason over these
against the repo; every finding still needs a real `file:line`. Each cue states
what to inspect, what evidence makes it a finding, and when the answer is
`unknown`. The cues are detection prompts only: they never ask for edits, file
lists, rotation walkthroughs, or other remediation work, and they carry no
payloads. Remediation belongs to a separate, user-authorized fix pass.

Deterministic backers where the project configures them: `eslint-plugin-security`,
semgrep app-sec rulesets. Source: vibecoder security-audit (its remediation
prompts rewritten here as audit cues).

Scope and applicability: sections 1-100 cover the always-on core and common web
surfaces. Surface-specific and specialist families (SSRF/egress, HTTP
proxy/cache/smuggling, authentication and session state machines, native
workspace trust, AI memory and RAG, admin and support workflows, smart
contracts, embedded/IoT, ICS/OT) are selected from inventory evidence by the
security pattern-card groups (see `pattern-cards.md` and
`security-lens-catalog.md`). An unselected specialist family is an applicability
record, never a clean claim.

### 1. Hash passwords with a modern algorithm
*Area: Authentication. Why it matters: Plain-text or weakly hashed passwords mean a single database leak hands attackers every user's credentials — this is the most consequential account-protection fix you can make.*

Audit cue: Inspect where passwords are created, stored, and verified. A finding is a password kept in plain text, reversible encryption, or a fast or outdated hash such as MD5 or SHA1; a slow salted algorithm (bcrypt, scrypt, Argon2id) with a sensible work factor is the passing shape. Note whether an upgrade-on-login re-hash path exists. Unknown when: hashing performed by an external identity provider outside the supplied source; report `unknown`, never a clean result.

### 2. Enforce strong password requirements
*Area: Authentication. Why it matters: Weak or reused passwords are the easiest way into an account, and enforcing a sane policy at signup stops the problem before it starts.*

Audit cue: Inspect registration and password-change handlers for server-side strength checks: minimum length (12 or more is the usual bar), common or breached-password rejection, and a clear rejection reason. A finding is validation that exists only in the browser or accepts short or common passwords. Unknown when: a validation service or policy defined outside the supplied source; report `unknown`, never a clean result.

### 3. Rate limit login attempts
*Area: Authentication. Why it matters: Without throttling, attackers can guess passwords thousands of times per minute; rate limiting makes brute-force and credential-stuffing attacks impractical.*

Audit cue: Inspect login and other authentication endpoints for throttling scoped by both source address and targeted account, with a 429 and Retry-After style response. A finding is an unthrottled authentication endpoint or a limit keyed on one dimension that the other trivially bypasses. Unknown when: limits enforced at a gateway or proxy not present in the source; report `unknown`, never a clean result.

### 4. Lock accounts after repeated failures
*Area: Authentication. Why it matters: Temporary lockouts add a second layer of brute-force defense and give you a signal that an account is under attack.*

Audit cue: Inspect the failed-attempt path for server-side tracking per account, a cooling-off lock that grows with repeats, reset on success, and no trivial bypass by IP or username casing. A finding is no lockout, a client-tracked counter, or a lock that reveals remaining attempts. Unknown when: lockout owned by an external identity provider; report `unknown`, never a clean result.

### 5. Stop username and email enumeration
*Area: Authentication. Why it matters: If your app reveals whether an email is registered, attackers can build target lists; consistent responses keep that information private.*

Audit cue: Compare responses, status codes, redirects, and timing for login, signup, reset, and email-exists flows with and without an existing account. A finding is any observable difference that reveals whether an account exists. Unknown when: timing or response shaping done by infrastructure outside the source; report `unknown`, never a clean result.

### 6. Secure the password reset flow
*Area: Authentication. Why it matters: Password reset is a common backdoor into accounts; reset tokens must be unguessable, single-use, and short-lived.*

Audit cue: Trace the password-reset flow: token source (cryptographically secure, long), storage (hashed), expiry, single use, invalidation on re-request, and invalidation of existing sessions on completion. A finding is any missing property on that list. Unknown when: token issuance delegated to an external provider; report `unknown`, never a clean result.

### 7. Regenerate sessions to block fixation
*Area: Authentication. Why it matters: If the session identifier doesn't change when a user logs in, an attacker who planted a known session ID can ride into the authenticated session.*

Audit cue: Trace session creation at login and at privilege change. A finding is a pre-login session identifier carried into the authenticated session, or an old session not discarded server-side. Unknown when: session store behavior hidden behind a framework or service not in the source; report `unknown`, never a clean result.

### 8. Add multi-factor authentication support
*Area: Authentication. Why it matters: A second factor means a stolen password alone is no longer enough to take over an account, dramatically reducing account-takeover risk.*

Audit cue: Where MFA exists, inspect secret generation and storage, recovery-code storage (hashed, single use), verification rate limiting, and whether every login path (including recovery and SSO) enforces it. A finding is a path that reaches an authenticated session without the second factor when the user enrolled one. Unknown when: MFA enforced by an external identity provider; report `unknown`, never a clean result.

### 9. Compare credentials in constant time
*Area: Authentication. Why it matters: Naive string comparison of secrets can leak information through timing differences; constant-time comparison closes that side channel.*

Audit cue: Locate comparisons of passwords, hashes, tokens, API keys, signatures, and one-time codes. A finding is a standard equality check on a secret where a constant-time comparison is available. Unknown when: comparison done inside a vetted library whose behavior is not in the source; report `unknown`, never a clean result.

### 10. Harden the remember-me feature
*Area: Authentication. Why it matters: Persistent login tokens are convenient but become a long-lived skeleton key if they aren't built carefully.*

Audit cue: Inspect persistent-login tokens: random and long, stored hashed, delivered in a Secure HttpOnly cookie, rotated on use, bound per device, revocable, and cleared by logout-everywhere. A finding is a reusable, plain-stored, or non-expiring remember-me token. Unknown when: token handling inside an external session service; report `unknown`, never a clean result.

### 11. Add bot protection to forms
*Area: Authentication. Why it matters: Automated bots abuse signup, login, contact, and other public forms for spam and attacks; a challenge step filters most of them out cheaply.*

Audit cue: Inspect public forms (signup, login, reset, contact) for bot or abuse controls enforced server-side, including per-source submission limits that direct endpoint calls cannot bypass. A finding is protection present only in client code. Unknown when: bot protection applied by an edge service not in the source; report `unknown`, never a clean result.

### 12. Throttle password reset and verification emails
*Area: Authentication. Why it matters: Unthrottled email-sending endpoints let attackers spam victims and rack up your provider bill; rate limiting prevents both.*

Audit cue: Inspect every endpoint that sends email or SMS (reset, verification, magic links, invitations) for limits by recipient and source, a minimum send interval, and a neutral response. A finding is an unthrottled sender or a response that reveals registration. Unknown when: limits applied by the mail provider or a gateway outside the source; report `unknown`, never a clean result.

### 13. Set secure session cookie flags
*Area: Sessions, Cookies & Tokens. Why it matters: Missing cookie security flags let session cookies leak over plain HTTP or be read by malicious scripts — the flags are a one-line fix with outsized impact.*

Audit cue: List every cookie set by the app. A finding is a session or authentication cookie missing HttpOnly, Secure, or a deliberate SameSite value, or with broader Path or Domain scope than needed. Prefer evidence from set-cookie construction, not only configuration. Unknown when: cookie flags set by a proxy or framework default not visible in the source; report `unknown`, never a clean result.

### 14. Add idle and absolute session timeouts
*Area: Sessions, Cookies & Tokens. Why it matters: Sessions that never expire become a standing liability on shared or compromised devices; timeouts bound the window of exposure.*

Audit cue: Inspect session validity checks for both an idle timeout and an absolute lifetime enforced on the server. A finding is a session without either bound, or bounds trusted from the client. Unknown when: session lifetime configured in an external store; report `unknown`, never a clean result.

### 15. Fully invalidate sessions on logout
*Area: Sessions, Cookies & Tokens. Why it matters: If logout only clears the browser cookie, the session can often still be used; true logout must destroy the session on the server.*

Audit cue: Trace logout: the server-side session record must be deleted or invalidated, cookies cleared with matching attributes, and a log-out-everywhere path should exist. A finding is logout that only clears the browser cookie. Unknown when: session invalidation owned by an external provider; report `unknown`, never a clean result.

### 16. Validate every JWT claim properly
*Area: Sessions, Cookies & Tokens. Why it matters: A JWT that isn't fully validated can be forged or replayed; verifying the signature alone is not enough.*

Audit cue: Inspect JWT verification on every protected request for signature check with the correct key, an enforced algorithm, and exp, nbf, iss, aud, and sub checks. A finding is decode without verify, or any missing claim check that the app's design relies on. Unknown when: verification performed by a gateway outside the source; report `unknown`, never a clean result.

### 17. Block JWT algorithm confusion attacks
*Area: Sessions, Cookies & Tokens. Why it matters: Accepting the algorithm declared in the token lets attackers forge tokens by switching it to "none" or swapping signing schemes.*

Audit cue: Inspect JWT verification configuration for an explicit algorithm allow-list, rejection of none, and no algorithm or key selection driven by the token header. A finding is a verifier that accepts the token-declared algorithm or mixes symmetric and asymmetric keys. Unknown when: library defaults not visible in the source; report `unknown`, never a clean result.

### 18. Strengthen and rotate signing secrets
*Area: Sessions, Cookies & Tokens. Why it matters: Weak or static signing secrets let attackers forge tokens; strong, rotatable secrets keep your tokens trustworthy.*

Audit cue: Inspect signing secrets for sessions, JWTs, and cookies: long and random, loaded from configuration rather than hardcoded, and verification that accepts multiple keys during rotation. A finding is a hardcoded, short, or shared-with-other-purpose signing key. Unknown when: key custody in an external secrets manager; report `unknown`, never a clean result.

### 19. Store auth tokens safely client-side
*Area: Sessions, Cookies & Tokens. Why it matters: Storing tokens in the wrong place on the client exposes them to theft via malicious scripts; the storage choice matters as much as the token itself.*

Audit cue: Inspect client-side token storage and transport. A finding is a token in a URL, a log, or script-readable persistent storage where an HttpOnly cookie is feasible; tradeoffs for tokens that must live in the browser should be documented. Unknown when: client code not included in the supplied source; report `unknown`, never a clean result.

### 20. Issue short-lived access tokens
*Area: Sessions, Cookies & Tokens. Why it matters: Long-lived access tokens stay dangerous long after a leak; short lifetimes paired with refresh tokens limit the damage.*

Audit cue: Inspect access-token lifetime and the refresh mechanism: short access lifetime, a longer-lived refresh token stored more securely, refresh over a secure channel. A finding is a long-lived access token with no refresh or revocation. Unknown when: token lifetimes configured in an external identity provider; report `unknown`, never a clean result.

### 21. Rotate refresh tokens on use
*Area: Sessions, Cookies & Tokens. Why it matters: Reusing the same refresh token indefinitely turns one leak into permanent access; rotation plus reuse detection shuts that down.*

Audit cue: Trace refresh-token exchange for rotation (new token issued, old invalidated), reuse detection that revokes the token family, hashed storage, and session binding. A finding is a refresh token reusable indefinitely without detection. Unknown when: rotation handled by an external identity provider; report `unknown`, never a clean result.

### 22. Build a token revocation mechanism
*Area: Sessions, Cookies & Tokens. Why it matters: Stateless tokens normally can't be cancelled before they expire; a revocation list lets you actually kill a compromised session.*

Audit cue: Inspect for a server-side revocation mechanism (denylist of token ids or session store checked per request) wired to logout, password change, and forced logout. A finding is a stateless token that cannot be cancelled before expiry for those events. Unknown when: revocation enforced by an external provider; report `unknown`, never a clean result.

### 23. Enforce authorization on the server
*Area: Authorization & Access Control. Why it matters: If the only thing stopping a user from accessing data is a hidden button, anyone can reach it by calling the API directly — every check must be re-enforced on the server.*

Audit cue: For each data-returning or mutating endpoint, check that the server independently enforces the user's right to the action. A finding is authorization present only as a hidden UI element or client route guard. Unknown when: authorization middleware or policy defined outside the supplied source; report `unknown`, never a clean result.

### 24. Fix insecure direct object references
*Area: Authorization & Access Control. Why it matters: When an app trusts an ID from the request without checking ownership, users can read or change other people's records just by changing a number in the URL.*

Audit cue: Find resources fetched or changed by a request-supplied identifier and check each for an ownership or permission check. A finding is an identifier trusted without verifying the caller's right to that specific record; non-sequential identifiers are only defense in depth. Unknown when: ownership enforced in a data layer or database policy not in the source; report `unknown`, never a clean result.

### 25. Implement role-based access control
*Area: Authorization & Access Control. Why it matters: Ad-hoc permission checks scattered through the code are easy to get wrong; a clear role model makes access rules consistent and reviewable.*

Audit cue: Inspect the role model: roles and permissions defined centrally, checks in shared middleware or guards, roles assigned and verified server-side, and unspecified routes denied. A finding is scattered inline checks with inconsistent coverage. Unknown when: role definitions held in an external system; report `unknown`, never a clean result.

### 26. Apply a default-deny access policy
*Area: Authorization & Access Control. Why it matters: If routes are open unless someone remembers to lock them, new endpoints ship insecure by default — flipping to default-deny makes safety the baseline.*

Audit cue: Compare the route table against authorization checks. A finding is a route or action reachable without an explicit satisfied check where the design intends protection; intentionally public routes should be identifiable. Unknown when: routes registered dynamically or by a framework not visible in the source; report `unknown`, never a clean result.

### 27. Lock down all admin routes
*Area: Authorization & Access Control. Why it matters: Administrative functionality is the highest-value target in any app; these routes need stricter protection than the rest.*

Audit cue: Enumerate administrative, privileged, debug, internal, and setup routes and dashboards. A finding is one reachable without authentication and a server-side admin-level check, or one left exposed from development. Unknown when: admin surfaces served by a separate deployment not in the source; report `unknown`, never a clean result.

### 28. Close privilege escalation paths
*Area: Authorization & Access Control. Why it matters: Subtle gaps let ordinary users grant themselves elevated rights; finding and closing these paths protects the integrity of your whole permission system.*

Audit cue: Look for paths where a user can change their own role or permissions, edit another account, or reach admin actions through an under-protected route, including mass assignment and client-supplied role fields. A finding is any such path without a server-side guard. Unknown when: role changes mediated by an external system; report `unknown`, never a clean result.

### 29. Isolate data between tenants
*Area: Authorization & Access Control. Why it matters: In any app serving multiple customers or organizations, a missing scope check can leak one tenant's data to another — the most damaging failure for a SaaS product.*

Audit cue: For multi-tenant data, check that every read and write is scoped by the caller's tenant on the server (not only by a request-supplied id), including background jobs, exports, and shared resources. A finding is any unscoped tenant data access. Unknown when: tenant scoping enforced by database row policies not in the source; report `unknown`, never a clean result.

### 30. Add function-level permission checks
*Area: Authorization & Access Control. Why it matters: Having access to one action in a feature shouldn't imply access to all of them; each sensitive function needs its own check.*

Audit cue: Check that create, update, delete, and export operations each carry their own permission check rather than inheriting access from viewing or membership. A finding is a sensitive function guarded only by feature-level access. Unknown when: permission checks in a service not in the source; report `unknown`, never a clean result.

### 31. Block mass assignment of fields
*Area: Authorization & Access Control. Why it matters: When user input is bound directly to a database record, attackers can set fields they were never meant to touch, like roles or balances.*

Audit cue: Find request data bound directly to models or objects. A finding is a bind without a field allow-list on create or update where role, permissions, status, or price fields could be overwritten. Unknown when: binding behavior in a framework configuration not visible in the source; report `unknown`, never a clean result.

### 32. Re-verify access on each request
*Area: Authorization & Access Control. Why it matters: Checking permissions once and trusting that decision later lets a user keep access after their rights have been revoked; every request should be re-evaluated.*

Audit cue: Check that authorization is re-evaluated per request and that a role, permission, or account-status change takes effect on the next request, including for long-lived sessions and tokens. A finding is a decision cached from login that outlives revocation. Unknown when: permission caching in an external system; report `unknown`, never a clean result.

### 33. Use parameterized database queries
*Area: Injection & Query Safety. Why it matters: Building SQL by stitching strings together with user input is the classic path to a full database breach; parameterized queries make it structurally impossible.*

Audit cue: Inspect each database query for string concatenation or interpolation of user-controlled input. A finding is input reaching the query text rather than a bound parameter, including raw-interpolation escape hatches in an ORM or query builder. Unknown when: queries constructed in a layer not in the source; report `unknown`, never a clean result.

### 34. Prevent NoSQL query injection
*Area: Injection & Query Safety. Why it matters: NoSQL databases are just as injectable as SQL ones when query objects are built from raw input, letting attackers bypass auth or dump data.*

Audit cue: Inspect NoSQL query construction for input placed into query objects or operators. A finding is an unvalidated value that could become an operator object that alters the query logic. Unknown when: query objects built by a library not in the source; report `unknown`, never a clean result.

### 35. Block operating system command injection
*Area: Injection & Query Safety. Why it matters: If user input ever reaches a shell command, attackers can run arbitrary commands on your server; this is among the most severe vulnerabilities possible.*

Audit cue: Find every site that runs a shell, script, or external process and trace whether user-controlled input reaches it. A finding is shell use or string-concatenated commands with influenced input where an argument array would do. Unknown when: command construction hidden behind a wrapper not in the source; report `unknown`, never a clean result.

### 36. Close ORM-level injection vectors
*Area: Injection & Query Safety. Why it matters: ORMs are safe by default but still expose raw-query and dynamic-condition escape hatches that reintroduce injection if misused.*

Audit cue: Inspect raw-query, raw-fragment, and dynamic-condition features of the ORM or query builder, including user-chosen column names, sort fields, and operators. A finding is influenced input in a raw fragment or an identifier without an allow-list. Unknown when: ORM wrapper code not in the source; report `unknown`, never a clean result.

### 37. Sanitize inputs used in LDAP
*Area: Injection & Query Safety. Why it matters: Apps that talk to a directory service can be tricked into auth bypass or data disclosure when user input is dropped unescaped into LDAP filters.*

Audit cue: Inspect LDAP filter and distinguished-name construction for proper escaping of user values and format validation. A finding is input that can alter filter structure. Unknown when: directory queries issued by a library not in the source; report `unknown`, never a clean result.

### 38. Escape identifiers in dynamic queries
*Area: Injection & Query Safety. Why it matters: Even with parameterized values, letting user input choose table or column names reopens the injection door; identifiers need their own allowlist.*

Audit cue: Find queries where user input selects table names, column names, sort directions, or operators. A finding is a raw identifier concatenated without a strict allow-list or driver identifier quoting. Unknown when: identifier handling in a layer not in the source; report `unknown`, never a clean result.

### 39. Validate and bound user regex
*Area: Injection & Query Safety. Why it matters: A maliciously crafted input against a vulnerable regular expression can pin your server's CPU and take the app down — a denial-of-service hiding in plain sight.*

Audit cue: Find regular expressions applied to user-controlled input, especially with nested or overlapping repetition. A finding is a catastrophically backtracking pattern with no input length bound or matching timeout. Unknown when: regex engine with guaranteed linear time that cannot be confirmed from the source; report `unknown`, never a clean result.

### 40. Prevent prototype pollution in objects
*Area: Injection & Query Safety. Why it matters: In JavaScript apps, attacker-controlled keys merged into objects can poison shared prototypes and lead to crashes, bypasses, or code execution.*

Audit cue: In JavaScript or TypeScript, inspect deep merges, clones, and dynamic property assignment from untrusted keys. A finding is a path that can write __proto__, constructor, or prototype; Map or null-prototype objects are the safe shape. Unknown when: merge utility implementation not in the source; report `unknown`, never a clean result.

### 41. Disable XML external entity parsing
*Area: Injection & Query Safety. Why it matters: XML parsers that resolve external entities can be coerced into reading local files or making server-side requests; disabling that feature closes a serious hole.*

Audit cue: Inspect every XML parser configuration for external entity and external DTD resolution. A finding is a parser on untrusted input with entity resolution enabled or left at an unsafe default. Unknown when: parser defaults for a library version not determinable from the source; report `unknown`, never a clean result.

### 42. Prevent formula injection in exports
*Area: Injection & Query Safety. Why it matters: Data exported to spreadsheets can carry hidden formulas that execute on the victim's machine when they open the file — a quiet but real attack on your users.*

Audit cue: Inspect CSV and spreadsheet exports of user-influenced data. A finding is a cell value beginning with =, +, -, or @ written without a prefix or quoting that renders it as text. Unknown when: export performed by an external service; report `unknown`, never a clean result.

### 43. Encode output to stop XSS
*Area: Cross-Site Scripting & Output Encoding. Why it matters: When user input is rendered back into a page without encoding, attackers can run scripts in your users' browsers — context-aware encoding neutralizes that.*

Audit cue: Inspect how dynamic data is rendered into HTML, attributes, URLs, and scripts. A finding is output inserted unescaped or with partial manual escaping instead of the framework's context-aware encoding. Unknown when: templates or renderers not in the source; report `unknown`, never a clean result.

### 44. Sanitize user-submitted HTML content
*Area: Cross-Site Scripting & Output Encoding. Why it matters: Features that intentionally allow rich text can't just escape everything; they need a sanitizer that strips dangerous markup while keeping safe formatting.*

Audit cue: Where users can submit rich text or HTML, inspect the sanitizer: vetted library, strict tag and attribute allow-list, scripts, event handlers, and dangerous URLs stripped. A finding is unsanitized user HTML rendered to other users. Unknown when: sanitization performed by a service not in the source; report `unknown`, never a clean result.

### 45. Add a Content Security Policy
*Area: Cross-Site Scripting & Output Encoding. Why it matters: A Content Security Policy is a powerful backstop that limits what a page can load and execute, sharply reducing the impact of any XSS that slips through.*

Audit cue: Inspect the Content Security Policy sent on pages: restricted script, style, and resource sources, controlled inline scripts, set on every page, report-only versus enforced. A finding is a missing policy or one that permits arbitrary inline script or wildcard sources on pages handling sensitive data. Unknown when: headers added by a proxy or CDN not in the source; report `unknown`, never a clean result.

### 46. Eliminate DOM-based XSS sinks
*Area: Cross-Site Scripting & Output Encoding. Why it matters: Some XSS never touches the server — it happens entirely in the browser when scripts write untrusted data into dangerous DOM sinks.*

Audit cue: Trace untrusted browser sources (URL, fragment, postMessage, storage) into dangerous sinks such as innerHTML, document.write, and dynamic script or handlers. A finding is a source-to-sink flow without safe APIs or sanitization. Unknown when: client bundles not included in the supplied source; report `unknown`, never a clean result.

### 47. Prevent stored XSS in content
*Area: Cross-Site Scripting & Output Encoding. Why it matters: Stored XSS is especially dangerous because the malicious payload is saved once and then served to everyone who views it — these need both input and output defenses.*

Audit cue: Trace content stored from one user and displayed to others, including less obvious surfaces (usernames, file names, notification text, admin views). A finding is stored content rendered without context-aware encoding or sanitization. Unknown when: rendering code not in the source; report `unknown`, never a clean result.

### 48. Block server-side template injection
*Area: Cross-Site Scripting & Output Encoding. Why it matters: When user input is rendered as part of a template rather than as data, attackers can execute code on the server through the template engine.*

Audit cue: Inspect server-side templating for user input concatenated into a template or passed where the engine evaluates it as template syntax. A finding is input used to build the template rather than supplied as data to a static template; confirm auto-escaping is enabled. Unknown when: template engine configuration not in the source; report `unknown`, never a clean result.

### 49. Audit unsafe HTML render bypasses
*Area: Cross-Site Scripting & Output Encoding. Why it matters: Modern frameworks escape output by default, but every one has an explicit "render raw HTML" escape hatch that reintroduces XSS when fed untrusted data.*

Audit cue: Search for raw-HTML escape hatches (dangerouslySetInnerHTML, v-html, bypassSecurityTrust, and equivalents). A finding is a bypass fed content that can include untrusted input without a strict sanitizer; record each bypass and whether its input is trusted. Unknown when: the origin of the rendered content is not determinable from the source; report `unknown`, never a clean result.

### 50. Sanitize content rendered into emails
*Area: Cross-Site Scripting & Output Encoding. Why it matters: HTML emails are a frequently forgotten XSS and injection surface; user data placed into emails needs the same care as data placed into web pages.*

Audit cue: Inspect email and notification generation for user-controlled content in bodies and in headers (subject, to, from). A finding is content not encoded for the email format or a header value that can inject additional headers. Unknown when: email templating performed by an external service; report `unknown`, never a clean result.

### 51. Add CSRF protection to mutations
*Area: Cross-Origin & Request Forgery. Why it matters: Without CSRF protection, a malicious site can trick a logged-in user's browser into performing actions on your app without their knowledge.*

Audit cue: Inspect state-changing endpoints for CSRF protection (synchronizer tokens or equivalent) paired with SameSite cookies. A finding is a mutating endpoint reachable by a cross-site request carrying ambient credentials without such a defense. Unknown when: protection enforced by a gateway or framework default not visible in the source; report `unknown`, never a clean result.

### 52. Configure CORS without dangerous wildcards
*Area: Cross-Origin & Request Forgery. Why it matters: A loose cross-origin policy can let untrusted websites read responses from your API on behalf of your users; CORS needs to be explicit and minimal.*

Audit cue: Inspect the CORS configuration. A finding is a wildcard origin with credentials, an Origin header reflected without allow-list validation, or broader methods and headers than needed. Unknown when: CORS handled by a proxy not in the source; report `unknown`, never a clean result.

### 53. Verify Origin and Referer headers
*Area: Cross-Origin & Request Forgery. Why it matters: Checking where a sensitive request came from adds a cheap, effective layer of defense against cross-site and forged requests.*

Audit cue: Inspect sensitive state-changing endpoints for Origin and Referer validation against expected origins, with sensible handling when the headers are absent, as a complement to CSRF tokens. A finding is none on endpoints that rely on cookies alone. Unknown when: validation enforced at an edge not in the source; report `unknown`, never a clean result.

### 54. Set the SameSite cookie attribute
*Area: Cross-Origin & Request Forgery. Why it matters: The SameSite attribute is a simple cookie setting that blocks many cross-site request forgery attacks by default.*

Audit cue: Inspect each cookie for a deliberate SameSite attribute, especially session and authentication cookies, consistent with the CSRF design. A finding is a missing or unintended None on such a cookie. Unknown when: attributes added by infrastructure not in the source; report `unknown`, never a clean result.

### 55. Block open redirect vulnerabilities
*Area: Cross-Origin & Request Forgery. Why it matters: An open redirect lets attackers use your trusted domain to send users to malicious sites, powering convincing phishing and sometimes token theft.*

Audit cue: Find redirects to a URL taken from user input (next, return parameters). A finding is a destination not validated against internal paths or an allow-list of hosts, or defeated by encoding or scheme tricks. Unknown when: redirect targets validated in a library not in the source; report `unknown`, never a clean result.

### 56. Prevent clickjacking with frame controls
*Area: Cross-Origin & Request Forgery. Why it matters: Clickjacking tricks users into clicking hidden elements by loading your site inside an invisible frame; frame restrictions stop your pages from being embedded maliciously.*

Audit cue: Inspect framing controls on responses: a frame-ancestors directive and, for older browsers, X-Frame-Options, on authenticated and sensitive pages. A finding is no framing restriction on such pages. Unknown when: headers set by a proxy not in the source; report `unknown`, never a clean result.

### 57. Validate OAuth redirect URIs strictly
*Area: Cross-Origin & Request Forgery. Why it matters: Loose redirect handling in an OAuth flow can let attackers intercept authorization codes and hijack accounts; exact-match validation closes that.*

Audit cue: Inspect OAuth and social-login flows: exact-match redirect URI allow-list, verified random state, PKCE for the authorization-code flow, and single-use short-lived codes. A finding is prefix or pattern redirect matching or an unchecked state. Unknown when: flow handled entirely by an external identity provider; report `unknown`, never a clean result.

### 58. Validate input on the server
*Area: Input Validation & Request Handling. Why it matters: Browser-side validation is only a convenience for users; an attacker bypasses it instantly by calling your API directly, so the server must validate everything.*

Audit cue: Check that every endpoint validates type, shape, and constraints on the server, treating client-side validation as a convenience. A finding is an endpoint trusting client-validated input. Unknown when: validation defined in middleware not in the source; report `unknown`, never a clean result.

### 59. Validate types, lengths, and formats
*Area: Input Validation & Request Handling. Why it matters: Accepting whatever shape of data arrives invites a long tail of bugs and attacks; strict allowlist validation rejects bad input before it reaches your logic.*

Audit cue: Inspect endpoint validation for allow-list rules on type, length or range, and format for each field, preferably schema-based and centralized, with maximum lengths. A finding is a field accepted without these bounds. Unknown when: schemas defined outside the supplied source; report `unknown`, never a clean result.

### 60. Cap request body and payload size
*Area: Input Validation & Request Handling. Why it matters: Without size limits, a single oversized request can exhaust memory and take your app offline; limits are a simple, effective denial-of-service defense.*

Audit cue: Inspect request body, upload, field, array-length, and JSON nesting limits at the server or framework level. A finding is an unbounded body or structure that can exhaust memory or CPU. Unknown when: limits applied at a proxy not in the source; report `unknown`, never a clean result.

### 61. Block path traversal in file access
*Area: Input Validation & Request Handling. Why it matters: When file paths are built from user input, attackers can climb out of the intended directory and read or overwrite sensitive files using sequences like "../".*

Audit cue: Find file reads, writes, serving, and includes that build a path from user input. A finding is a path not resolved and confined to an allowed base directory, or one that accepts traversal sequences or absolute paths. Unknown when: path handling in a library not in the source; report `unknown`, never a clean result.

### 62. Prevent server-side request forgery
*Area: Input Validation & Request Handling. Why it matters: SSRF lets an attacker make your server send requests to internal systems or cloud metadata endpoints it should never reach — a frequent path to full compromise.*

Audit cue: Find server-side fetches of user-influenced URLs (webhooks, link previews, importers, image fetchers). A finding is a destination not restricted to an allow-list or checked against internal, loopback, and metadata addresses, including after redirects and DNS resolution. See `ssrf-egress-url-fetch`. Unknown when: egress controls outside the supplied source; report `unknown`, never a clean result.

### 63. Stop HTTP header and CRLF injection
*Area: Input Validation & Request Handling. Why it matters: If user input flows into response headers unchecked, attackers can inject new headers or split responses, enabling cache poisoning and other attacks.*

Audit cue: Find user-controlled input used in response headers, redirect locations, or cookies. A finding is a value that can carry CR or LF characters into a header, where framework APIs that encode header values would be safe. Unknown when: header encoding by a framework not in the source; report `unknown`, never a clean result.

### 64. Enforce strict Content-Type validation
*Area: Input Validation & Request Handling. Why it matters: Accepting requests without checking their declared content type invites confusion attacks and bypasses; the server should require and verify the expected type.*

Audit cue: Inspect endpoints that expect a specific format for required and verified Content-Type. A finding is a parser that accepts unexpected types in a way that could bypass validation or CSRF defenses. Unknown when: parser behavior defined outside the source; report `unknown`, never a clean result.

### 65. Reject malformed and unexpected fields
*Area: Input Validation & Request Handling. Why it matters: Silently ignoring extra or malformed fields hides bugs and can mask attacks; strict parsing surfaces problems and shrinks the attack surface.*

Audit cue: Inspect request handling for rejection of unknown fields, malformed JSON, and bad encoding, with generic safe parse errors. A finding is silent acceptance of extra fields where that matters, or parse errors that leak internals. Unknown when: validation library configuration not in the source; report `unknown`, never a clean result.

### 66. Move hardcoded secrets to environment variables
*Area: Secrets & Configuration. Why it matters: Secrets written directly into source code leak the moment anyone sees the repository; moving them to configuration is foundational hygiene.*

Audit cue: Scan for hardcoded API keys, database passwords, tokens, private keys, and signing secrets in source and committed configuration. A finding is a live-looking literal; a sample configuration with placeholder values is the passing shape. Unknown when: values that cannot be classified as real or placeholder from the source; report `unknown`, never a clean result.

### 67. Remove committed secrets from git history
*Area: Secrets & Configuration. Why it matters: Deleting a secret from the current code doesn't help if it's still sitting in your git history where anyone can find it; it must be purged and rotated.*

Audit cue: Inspect committed history, configuration, and environment files for secrets, and whether the relevant files are ignored. A finding is a secret present in history; treat any committed secret as compromised. Unknown when: history not available in the supplied snapshot; report `unknown`, never a clean result.

### 68. Keep secrets out of client bundles
*Area: Secrets & Configuration. Why it matters: Anything shipped to the browser is fully visible to users; secrets must never be embedded in frontend code or build output.*

Audit cue: Inspect frontend and build configuration for secrets reaching the client bundle (client-exposed build-time variables, embedded keys). A finding is a secret-grade value shipped to the browser; distinguish values designed to be public. Unknown when: build output not included in the source; report `unknown`, never a clean result.

### 69. Separate development and production credentials
*Area: Secrets & Configuration. Why it matters: Sharing credentials across environments means a leak in a low-security dev setup compromises production; each environment needs its own isolated secrets.*

Audit cue: Inspect configuration across development, staging, and production for separate credentials, environment-gated debug and verbose features, and no production secrets in development or test configuration. A finding is a shared or mixed credential. Unknown when: environment configuration held outside the repository; report `unknown`, never a clean result.

### 70. Rotate any exposed or leaked secrets
*Area: Secrets & Configuration. Why it matters: Once a secret has been exposed, the only real fix is to replace it; rotation invalidates whatever an attacker may already hold.*

Audit cue: Inspect logs, client bundles, error messages, and commit history for plausibly exposed credentials, and whether configuration loads new values from secure storage with a rotation routine. A finding is an exposed credential with no rotation path. Unknown when: exposure that cannot be established from the supplied source; report `unknown`, never a clean result.

### 71. Hide stack traces in production
*Area: Secrets & Configuration. Why it matters: Detailed error pages are gold for attackers, revealing your stack, file paths, and sometimes secrets; production should show users a generic message instead.*

Audit cue: Inspect error handling for production behavior: generic user-facing errors, details only in server logs, debug modes off, and no database errors, paths, or dependency details in responses. A finding is a stack trace or diagnostic detail returned to users. Unknown when: environment-specific error configuration not in the source; report `unknown`, never a clean result.

### 72. Remove revealing server response headers
*Area: Secrets & Configuration. Why it matters: Headers that announce your server software and versions hand attackers a roadmap of known exploits to try; stripping them reduces your visible attack surface.*

Audit cue: Inspect response headers for server software names, framework identifiers, and versions, and for the recommended security headers. A finding is a revealing header or a missing security header on sensitive responses. Unknown when: headers added by infrastructure not in the source; report `unknown`, never a clean result.

### 73. Disable directory listing and indexes
*Area: Secrets & Configuration. Why it matters: If your server lists the contents of directories without an index file, attackers can browse for sensitive files you never meant to expose.*

Audit cue: Inspect server and application configuration for directory listings and web-accessible backup, configuration, and version-control files. A finding is an enabled listing or a sensitive file inside a served directory. Unknown when: web server configuration not in the source; report `unknown`, never a clean result.

### 74. Harden insecure default framework settings
*Area: Secrets & Configuration. Why it matters: Frameworks often ship with permissive defaults meant for convenience, not production; reviewing and tightening them closes gaps you didn't know were open.*

Audit cue: Review framework and server configuration for insecure production defaults: debug output, default credentials, sample or admin routes, permissive CORS, verbose logging, exposed management endpoints. A finding is any left at a permissive value. Unknown when: framework version defaults not determinable from the source; report `unknown`, never a clean result.

### 75. Force HTTPS across the application
*Area: Cryptography & Data Protection. Why it matters: Traffic sent over plain HTTP can be read and tampered with in transit; redirecting everything to HTTPS protects credentials, sessions, and data.*

Audit cue: Check that traffic is served only over HTTPS: HTTP redirected, cookies marked Secure, no mixed content, no HTTP-only endpoints. A finding is a plain-HTTP path for sensitive data. Unknown when: TLS termination configured outside the source; report `unknown`, never a clean result.

### 76. Enable HSTS to enforce TLS
*Area: Cryptography & Data Protection. Why it matters: HTTP Strict Transport Security tells browsers to refuse to connect to your site over plain HTTP, closing the gap before the first redirect even happens.*

Audit cue: Inspect HTTP Strict Transport Security on HTTPS responses: a sensible max-age and, only where every subdomain supports HTTPS, includeSubDomains and preload. A finding is no HSTS on a site that handles sessions; note the commitment preload implies. Unknown when: headers set by a CDN not in the source; report `unknown`, never a clean result.

### 77. Encrypt sensitive data at rest
*Area: Cryptography & Data Protection. Why it matters: Even with good access control, sensitive data stored unencrypted is fully exposed if the storage layer is breached; encryption at rest adds a crucial backstop.*

Audit cue: Identify stored personal, financial, health, and secret data and check encryption at rest at the storage layer and, for especially sensitive fields, at the application layer with keys stored separately from the data. A finding is sensitive data stored unencrypted with a hardcoded or colocated key. Unknown when: storage-layer encryption configured outside the source; report `unknown`, never a clean result.

### 78. Replace weak cryptographic algorithms
*Area: Cryptography & Data Protection. Why it matters: Outdated algorithms like MD5, SHA1, and DES are broken or broken-enough that relying on them provides a false sense of security; modern replacements are essential.*

Audit cue: Scan for weak or outdated cryptography: MD5 or SHA1 for security purposes, DES, ECB mode, hardcoded keys or IVs, and homegrown crypto, and confirm password hashing uses a slow algorithm. A finding is any such primitive protecting a security property. Unknown when: primitive choice hidden in a dependency not in the source; report `unknown`, never a clean result.

### 79. Use a cryptographically secure random generator
*Area: Cryptography & Data Protection. Why it matters: Security-sensitive values generated with an ordinary random function can be predicted by attackers; only a cryptographically secure generator is safe for tokens and secrets.*

Audit cue: Inspect generation of tokens, session identifiers, reset codes, and salts. A finding is a security-sensitive value produced by a predictable random function or one too short to resist guessing. Unknown when: generator behavior in a library not in the source; report `unknown`, never a clean result.

### 80. Hash security tokens before storage
*Area: Cryptography & Data Protection. Why it matters: Storing reset tokens, API keys, and session identifiers in plain text means a database leak hands attackers working credentials; hashing them limits the damage.*

Audit cue: Inspect storage of reset tokens, API keys, session identifiers, and verification codes. A finding is a usable token stored in plain text where hashing and constant-time comparison would be safe for high-entropy tokens. Unknown when: storage in an external service; report `unknown`, never a clean result.

### 81. Mask sensitive values in logs
*Area: Cryptography & Data Protection. Why it matters: Logs are frequently exposed, shared, or shipped to third parties; sensitive data written into them quietly becomes a leak vector.*

Audit cue: Inspect log statements for passwords, tokens, API keys, payment details, personal data, and full request bodies. A finding is such data written to logs without masking or redaction. See `secret-serialization-through-logs-and-telemetry`. Unknown when: logging configuration or sinks outside the source; report `unknown`, never a clean result.

### 82. Encrypt stored personal identifiable information
*Area: Cryptography & Data Protection. Why it matters: Personal data carries legal and ethical obligations; encrypting it protects users and reduces your exposure if data is stolen.*

Audit cue: Identify stored personally identifiable information and check field-level protection, access restriction and logging, data minimization, and hashing where a value only needs matching. A finding is unneeded or unprotected sensitive PII. Unknown when: protection applied by the storage layer not in the source; report `unknown`, never a clean result.

### 83. Prevent caching of sensitive pages
*Area: Cryptography & Data Protection. Why it matters: Sensitive pages cached by browsers or shared proxies can be retrieved later by the next person on a device or by an attacker; cache headers prevent that.*

Audit cue: Inspect responses with sensitive or personalized data for Cache-Control, Pragma, and related headers, and whether pages behind login can be retrieved from cache after logout. A finding is a cacheable sensitive response. Public static assets may be cached. Unknown when: caching rules set at a CDN not in the source; report `unknown`, never a clean result.

### 84. Add global API rate limiting
*Area: API & Rate Limiting. Why it matters: Unthrottled APIs invite abuse, scraping, brute force, and denial of service; baseline rate limiting protects availability and curbs automated attacks.*

Audit cue: Inspect API rate limiting: per-client limits keyed on a reliable identifier, stricter on expensive or sensitive operations, 429 with Retry-After, and a store that works across multiple instances. A finding is no limit on abuse-prone endpoints. Unknown when: limits applied at a gateway not in the source; report `unknown`, never a clean result.

### 85. Limit GraphQL query depth and cost
*Area: API & Rate Limiting. Why it matters: A single deeply nested or expansive GraphQL query can overwhelm your backend; depth and cost limits keep one request from doing disproportionate damage.*

Audit cue: For GraphQL, inspect maximum query depth, a cost or complexity limit, pagination caps, and rate limiting. A finding is none of these on a public endpoint. Unknown when: limits enforced at a gateway not in the source; report `unknown`, never a clean result.

### 86. Disable GraphQL introspection in production
*Area: API & Rate Limiting. Why it matters: Introspection conveniently exposes your entire API schema — including endpoints you'd rather not advertise — making it a gift to attackers mapping your app.*

Audit cue: For GraphQL, check whether introspection and interactive playgrounds are disabled in production and whether errors leak schema details. A finding is introspection enabled in the production configuration. Unknown when: environment-specific configuration not in the source; report `unknown`, never a clean result.

### 87. Trim over-exposed fields in responses
*Area: API & Rate Limiting. Why it matters: APIs that return whole database records often leak fields the client never needs — internal flags, other users' data, or secrets — and attackers read every byte.*

Audit cue: Compare API response shapes with what clients need. A finding is a whole database record serialized with internal flags, security-relevant fields, or other users' data, especially user, account, and nested related objects. Unknown when: serializer or view layer not in the source; report `unknown`, never a clean result.

### 88. Enforce maximum pagination page sizes
*Area: API & Rate Limiting. Why it matters: If a client can request an unlimited page size, a single call can pull your entire dataset and strain the system; capping page size prevents that.*

Audit cue: Inspect paginated and list endpoints for a server-enforced maximum page size, a default, and validated pagination parameters. A finding is a client-controlled page size with no server cap. Unknown when: limits enforced in a data layer not in the source; report `unknown`, never a clean result.

### 89. Verify signatures on incoming webhooks
*Area: API & Rate Limiting. Why it matters: Webhook endpoints are publicly reachable and easy to spoof; verifying the sender's signature ensures you only act on genuine events.*

Audit cue: Inspect each webhook endpoint for signature verification against the raw body with the shared secret and a constant-time comparison, plus replay protection by timestamp or event id. A finding is an endpoint acting on an unverified request. See `webhook-idempotency-and-verification-order`. Unknown when: verification done by a gateway not in the source; report `unknown`, never a clean result.

### 90. Add idempotency keys to mutations
*Area: API & Rate Limiting. Why it matters: Network retries and double-clicks can cause sensitive operations to run twice; idempotency keys ensure a repeated request has the same effect as a single one.*

Audit cue: For payments, orders, and account changes, inspect idempotency: a client-supplied key, the first result stored and returned for repeats, and safety under concurrent duplicates. A finding is a non-repeatable operation that runs twice on retry. Unknown when: idempotency enforced by an external provider; report `unknown`, never a clean result.

### 91. Validate upload types by content
*Area: File Uploads. Why it matters: Trusting a file's extension or declared type is easy to fake; inspecting the actual content stops attackers from sneaking dangerous files past your checks.*

Audit cue: Inspect upload handling for content-based type validation with a per-feature allow-list rather than trusting the extension or declared content type. A finding is type decided only by name or client header. Unknown when: validation by an external scanning service; report `unknown`, never a clean result.

### 92. Enforce a maximum upload size
*Area: File Uploads. Why it matters: Without a size cap, a single large upload can fill your disk or exhaust memory, taking the app down; a strict limit is a basic availability safeguard.*

Audit cue: Inspect upload size limits at the server or framework level, per upload type, including chunked or streamed uploads. A finding is an unbounded upload path. Unknown when: limits applied at a proxy not in the source; report `unknown`, never a clean result.

### 93. Store uploads outside the webroot
*Area: File Uploads. Why it matters: Files saved inside the web-served directory can sometimes be executed or accessed directly; storing them elsewhere and serving them deliberately is far safer.*

Audit cue: Inspect where uploads are stored and served: outside the public web root or in an object store, served through a controlled endpoint with authentication, authorization, and safe headers. A finding is an upload placed where it can be served or executed directly. Unknown when: storage configuration outside the source; report `unknown`, never a clean result.

### 94. Randomize and sanitize stored filenames
*Area: File Uploads. Why it matters: User-controlled filenames enable path traversal, overwrites, and confusing collisions; generating safe server-side names removes that whole class of problems.*

Audit cue: Inspect stored filenames. A finding is a user-supplied name used as the stored name, path separators or special characters not neutralized, or an upload that can overwrite or escape its storage location. Unknown when: naming performed by a storage service not in the source; report `unknown`, never a clean result.

### 95. Serve user files without execution
*Area: File Uploads. Why it matters: When user-uploaded files are served back, the wrong content handling can let a malicious file run as a page or script in the victim's browser.*

Audit cue: Inspect how user files are served back: content-disposition, a fixed content type, nosniff, and isolation on a separate domain or path where feasible. A finding is uploaded HTML or script that can run in another user's session. Unknown when: serving configuration outside the source; report `unknown`, never a clean result.

### 96. Audit dependencies for known vulnerabilities
*Area: Dependencies, Logging & Monitoring. Why it matters: Most app code is third-party packages, and known vulnerabilities in them are a leading cause of breaches; scanning surfaces the ones you need to patch.*

Audit cue: Inspect dependency vulnerability evidence from the ecosystem's audit tool, with exploitability considered in the app's context. A finding is a known-vulnerable dependency reachable in the app; absence of scanner output is not-scanned, never clean. Unknown when: scanner not run or lockfile absent; report `unknown`, never a clean result.

### 97. Lock dependency versions with a lockfile
*Area: Dependencies, Logging & Monitoring. Why it matters: Without a lockfile, your app can silently pull in different — possibly malicious or broken — package versions on each install; locking makes builds reproducible and safer.*

Audit cue: Check that a lockfile pins every direct and transitive dependency, is committed, and is used by the install process. A finding is a missing or unused lockfile or an unpinned install path. Unknown when: install process defined outside the source; report `unknown`, never a clean result.

### 98. Add Subresource Integrity to scripts
*Area: Dependencies, Logging & Monitoring. Why it matters: Scripts and styles loaded from a CDN can be tampered with at the source; Subresource Integrity makes the browser refuse anything that's been altered.*

Audit cue: Inspect third-party scripts and stylesheets loaded from external origins for integrity hashes and cross-origin attributes. A finding is an unpinned external resource executed in a page; self-hosting or pinned versions are alternatives. Unknown when: resources injected at the edge; report `unknown`, never a clean result.

### 99. Log security events for monitoring
*Area: Dependencies, Logging & Monitoring. Why it matters: You can't respond to an attack you can't see; recording key security events gives you the visibility to detect and investigate suspicious activity.*

Audit cue: Inspect security-event logging: logins and failures, logout, password and permission changes, and access-control denials with timestamp, actor, and source, excluding secrets and personal data. A finding is a sensitive action with no record. Unknown when: audit logging in an external service; report `unknown`, never a clean result.

### 100. Prevent log injection and forgery
*Area: Dependencies, Logging & Monitoring. Why it matters: If untrusted input is written straight into logs, attackers can forge entries or break your logging pipeline; sanitizing log input keeps your records trustworthy.*

Audit cue: Inspect how user-controlled data is written into logs. A finding is a value that can carry newlines or control characters into a log line, where structured logging that records fields distinctly is the safe shape. Unknown when: log sink or viewer behavior not in the source; report `unknown`, never a clean result.

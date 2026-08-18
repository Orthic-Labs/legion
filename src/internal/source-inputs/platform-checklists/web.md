# Senior pre-release audit checklist for a web app or website

A serious pre-release audit is not a Lighthouse report, a dependency scan, or a manual click-through. It is an evidence-based review of the product, source code, architecture, infrastructure, security posture, operational readiness, and user experience of the exact build intended for production.

Use `Pass / Fail / Not applicable / Accepted risk` for every control. A pass should point to evidence: a test result, configuration, screenshot, trace, query plan, pull request, runbook, or deployment record.

## Recommended audit baselines

For most public production applications, use OWASP ASVS 5.0.0 as the detailed security control catalogue. Level 2 is the usual target for normal production systems; Level 3 is more appropriate for high-value transactions, sensitive regulated data, or high-assurance systems. Supplement it with the OWASP Top 10:2025, OWASP API Security Top 10:2023, and the OWASP Web Security Testing Guide. ([OWASP][1])

Use WCAG 2.2 Level AA as the default accessibility target. ([W3C][2])

For public-facing performance, target Core Web Vitals at the 75th percentile, separately for mobile and desktop:

* LCP: no more than 2.5 seconds.
* INP: no more than 200 milliseconds.
* CLS: no more than 0.1. ([web.dev][3])

Use NIST SSDF 1.1 for secure development-process coverage and SLSA 1.2 for source/build integrity and provenance. ([NIST Publications][4])

Use an explicit browser-support policy informed by actual users. MDN Baseline is useful for evaluating web-platform support, but it is not a substitute for browser, accessibility, usability, performance, or security testing. ([MDN Web Docs][5])

For public websites and indexable application pages, audit against Google Search Essentials and its crawling/indexing guidance. ([Google for Developers][6])

---

# Top-line audit domains

At the highest level, the review should cover:

1. Product scope and release risk.
2. Requirements and functional correctness.
3. User journeys, UX, content, and trust.
4. Architecture and system design.
5. Technology-stack suitability.
6. Source-code quality and maintainability.
7. Frontend implementation.
8. Backend and API design.
9. Database and data lifecycle.
10. Authentication, authorization, and tenant isolation.
11. Application and browser security.
12. Software supply chain and build integrity.
13. Infrastructure, cloud, network, and DNS.
14. Performance and resource efficiency.
15. Capacity and scalability.
16. Reliability and resilience.
17. Observability and alerting.
18. Testing strategy and release coverage.
19. Accessibility.
20. Browser, device, and responsive compatibility.
21. SEO and discoverability.
22. Privacy, compliance, and legal readiness.
23. Internationalization and localization.
24. Third-party integrations, email, notifications, and payments.
25. Analytics, experimentation, and product telemetry.
26. CI/CD, deployment, migration, and rollback.
27. Backup, disaster recovery, and business continuity.
28. Operational ownership, support, and incident response.
29. Cost, quotas, and abuse economics.
30. Conditional areas such as AI, PWA, user-generated content, and real-time features.

---

# 1. Audit scope, risk, and evidence

Before testing anything, establish exactly what is being audited.

### Scope

* [ ] Record the exact release commit, tag, build ID, artifact digest, and deployment environment.
* [ ] Identify every production domain, subdomain, API host, CDN, object store, WebSocket endpoint, webhook endpoint, admin interface, and background worker.
* [ ] Identify all environments: local, development, test, staging, preview, production, disaster recovery.
* [ ] Document supported user roles, administrative roles, service accounts, tenants, plans, and entitlement levels.
* [ ] Map the critical user journeys: registration, login, purchase, creation, editing, saving, exporting, sharing, recovery, cancellation, deletion, and support.
* [ ] Identify sensitive business flows: payments, invitations, password resets, entitlement changes, refunds, data exports, administrative actions.
* [ ] Identify all sensitive data categories and where they enter, travel, persist, and leave the system.
* [ ] Inventory third-party processors, analytics systems, authentication providers, payment providers, email services, storage systems, APIs, and SDKs.
* [ ] Define what is explicitly outside the audit and why.
* [ ] Confirm that staging is materially representative of production.

### Risk classification

* [ ] Define likely threat actors and plausible abuse scenarios.
* [ ] Determine whether the application is low, moderate, high, or critical assurance.
* [ ] Establish expected traffic, peak traffic, data volume, transaction value, and reputational impact.
* [ ] Define release-blocking severity levels before findings are produced.
* [ ] Name the individual who has authority to accept residual risk.
* [ ] Require accepted risks to have an owner, compensating control, expiry date, and re-review date.

### Evidence requirements

Each finding should contain:

* Affected release and environment.
* Reproduction steps.
* Affected users, roles, tenants, or records.
* Expected versus actual behavior.
* Security, financial, privacy, reliability, or usability impact.
* Severity and rationale.
* Remediation.
* Regression-test requirement.
* Owner and due date.
* Retest result.

---

# 2. Product requirements and functional correctness

## Requirements

* [ ] Every release requirement has explicit acceptance criteria.
* [ ] Product behavior matches the current specification, not an outdated design or ticket.
* [ ] User roles and entitlement rules are documented.
* [ ] Feature-flag behavior is documented for enabled, disabled, and partially rolled-out states.
* [ ] Unsupported workflows fail clearly rather than behaving unpredictably.
* [ ] Known limitations are intentional and documented.
* [ ] Metrics exist to determine whether the released feature is succeeding.

## Critical-path testing

Test each important journey as:

* A logged-out visitor.
* A new user.
* A returning user.
* A user with incomplete onboarding.
* Each paid or permission tier.
* An expired, suspended, deleted, or disabled user.
* An administrator.
* A user from another tenant.
* A user with stale browser state.
* A user on a slow or interrupted connection.

## Behavioral coverage

* [ ] Happy paths work.
* [ ] Invalid inputs are rejected correctly.
* [ ] Boundary values are tested.
* [ ] Empty states are intentional and helpful.
* [ ] Loading states appear and resolve correctly.
* [ ] Partial failures do not leave corrupt or misleading UI.
* [ ] Double-clicking or repeated submission does not duplicate work.
* [ ] Refreshing during an operation behaves safely.
* [ ] Browser back and forward navigation behaves correctly.
* [ ] Deep links work when opened directly.
* [ ] Opening the same resource in multiple tabs behaves correctly.
* [ ] Concurrent edits are detected, merged, versioned, or rejected deliberately.
* [ ] Unsaved changes are preserved or clearly warned about.
* [ ] Offline-to-online transitions do not duplicate requests.
* [ ] Timeouts present a recoverable state.
* [ ] Retried requests do not duplicate transactions.
* [ ] Cancellation actually cancels or safely ignores the operation.
* [ ] Search, sort, filter, and pagination combinations produce correct results.
* [ ] Exported data matches what the user is authorized to see.
* [ ] Imported files handle valid, malformed, duplicate, and oversized data.
* [ ] Dates, deadlines, and scheduled actions behave correctly around time-zone and daylight-saving transitions.
* [ ] Account creation, verification, suspension, reactivation, and deletion work end to end.
* [ ] Plan upgrades, downgrades, cancellations, expirations, and grace periods behave correctly.
* [ ] Error messages are accurate and do not blame the user for system failures.

---

# 3. UX, content, and product trust

## Comprehension

For a public website, a new visitor should be able to establish quickly:

* What the product is.
* Who it is for.
* What problem it solves.
* Why it is materially different.
* What it costs.
* What the primary next action is.

Audit:

* [ ] The primary value proposition is concrete rather than vague marketing language.
* [ ] The homepage communicates the product without requiring a full scroll.
* [ ] Claims are demonstrable and not misleading.
* [ ] Product screenshots and examples reflect the current product.
* [ ] Pricing, limits, and renewal terms are discoverable.
* [ ] Primary calls to action are visually and verbally consistent.
* [ ] Navigation labels match user terminology.
* [ ] Important information is not hidden behind ambiguous icons.
* [ ] Empty states explain what to do next.
* [ ] Errors explain what happened, what was preserved, and how to recover.
* [ ] Destructive actions are distinguishable from routine actions.
* [ ] Destructive actions have confirmation, undo, delayed execution, or another appropriate safeguard.
* [ ] Forms preserve entered information after validation failures.
* [ ] Field-level validation appears at the useful time, not only after submission.
* [ ] Help is available where users encounter complexity.
* [ ] Support and contact routes are easy to locate.
* [ ] User-facing terminology is consistent across UI, documentation, email, and billing.
* [ ] Placeholder text, test accounts, lorem ipsum, broken media, and unfinished copy are absent.
* [ ] The 404, 403, 500, maintenance, and offline pages are intentional.
* [ ] Favicon, application icons, page title, social preview, and branding are complete.
* [ ] Dark mode, high contrast, and system theme behavior are deliberate where supported.
* [ ] Mobile layouts do not conceal essential controls.
* [ ] Trust-sensitive information—privacy, security, refund rules, data handling—is stated plainly.

---

# 4. Architecture and system design

## Architecture documentation

* [ ] A current context diagram shows users, systems, services, databases, queues, storage, and external dependencies.
* [ ] A deployment diagram shows regions, networks, ingress, compute, storage, and failover.
* [ ] Data-flow diagrams show sensitive-data paths and trust boundaries.
* [ ] Architectural decision records explain major choices and constraints.
* [ ] Ownership is clear for every service, database, queue, and scheduled job.
* [ ] The deployed architecture matches the documented architecture.

## Boundaries and coupling

* [ ] Components have clearly defined responsibilities.
* [ ] Dependency direction is intentional.
* [ ] Shared libraries do not create hidden coupling between unrelated domains.
* [ ] Service boundaries follow meaningful operational or domain boundaries.
* [ ] The design is not fragmented into microservices without a real scaling, ownership, or isolation requirement.
* [ ] A monolith is not carrying unrelated failure domains that require separation.
* [ ] Cross-service contracts are versioned.
* [ ] Data ownership is unambiguous.
* [ ] One service does not modify another service’s database directly without an explicit architecture decision.
* [ ] Frontend code does not depend on undocumented backend behavior.
* [ ] External providers are accessed through replaceable adapters where lock-in or failure risk is material.

## Distributed-system correctness

* [ ] Operations that may be retried are idempotent.
* [ ] Duplicate messages and events are tolerated.
* [ ] Out-of-order delivery is handled where possible.
* [ ] Eventual consistency is visible and understandable to users.
* [ ] Transactions do not pretend to span systems when they do not.
* [ ] Compensating actions exist for multi-step workflows.
* [ ] Race conditions have been considered in payments, quotas, inventory, entitlements, invitations, and account state.
* [ ] Clock skew and time-source assumptions are understood.
* [ ] Background jobs can resume after interruption.
* [ ] Poison messages are isolated.
* [ ] Queue backlogs cannot grow without a limit or alert.
* [ ] State is not stored on ephemeral instances unless explicitly replicated.
* [ ] Cache invalidation and ownership are defined.
* [ ] A cache failure does not silently change authorization or correctness.
* [ ] Single points of failure are documented and accepted or removed.
* [ ] Blast radius is limited by tenant, service, region, queue, or other appropriate boundary.

## Complexity review

* [ ] Operational complexity is proportionate to the product’s needs.
* [ ] The system can be understood and debugged by more than one engineer.
* [ ] Critical behavior does not rely on undocumented framework magic.
* [ ] The architecture allows realistic testing outside production.
* [ ] There is a deliberate strategy for schema, API, and event evolution.
* [ ] Deprecated components have owners and removal dates.
* [ ] There is a migration path away from critical vendor-specific components where appropriate.

---

# 5. Technology-stack audit

Review every major language, runtime, framework, library, database, build tool, cloud service, and third-party SDK.

* [ ] The version is supported and receiving security fixes.
* [ ] The framework is suitable for the expected traffic, interaction model, and team.
* [ ] Runtime and framework versions are mutually compatible.
* [ ] The production runtime matches the tested runtime.
* [ ] Experimental features are not used unknowingly.
* [ ] Non-Baseline browser APIs have fallbacks where required.
* [ ] Libraries are not duplicated at incompatible versions without reason.
* [ ] The framework’s default security behavior is understood.
* [ ] The framework’s caching, rendering, and deployment model is understood.
* [ ] Server-side and client-side code boundaries are explicit.
* [ ] Server-only environment variables cannot enter the client bundle.
* [ ] The stack supports required accessibility and SEO behavior.
* [ ] The stack has acceptable cold-start, memory, CPU, and bundle characteristics.
* [ ] The stack has sufficient debugging, profiling, tracing, and testing support.
* [ ] Critical dependencies are actively maintained.
* [ ] Abandoned libraries have been replaced or isolated.
* [ ] Licensing is compatible with the product and distribution model.
* [ ] The dependency footprint is justified; trivial features do not import large dependency trees.
* [ ] Vendor lock-in is documented where material.
* [ ] Upgrade ownership and cadence are defined.

---

# 6. Source-code quality and maintainability

## Static quality

* [ ] Formatting, linting, type checking, and compilation pass without ignored failures.
* [ ] Compiler and linter warnings are reviewed.
* [ ] Type-escape mechanisms such as `any`, unchecked casts, or suppression comments are justified.
* [ ] Dead code and unused feature flags are removed.
* [ ] Debugging code, test endpoints, mock credentials, and verbose logging are removed.
* [ ] TODO, FIXME, temporary bypass, and “remove before launch” comments are resolved or ticketed.
* [ ] Critical constants are named rather than duplicated as magic values.
* [ ] Configuration is externalized appropriately.
* [ ] Environment-specific behavior is centralized and testable.
* [ ] Error handling is explicit.
* [ ] Exceptions are not swallowed.
* [ ] Resource acquisition has corresponding cleanup.
* [ ] Network and filesystem operations have timeouts and cancellation.
* [ ] Async tasks cannot become unobserved or silently fail.
* [ ] Concurrency-sensitive code has explicit synchronization or transactional behavior.
* [ ] Recursive or unbounded operations have limits.
* [ ] Regular expressions are reviewed for catastrophic backtracking.
* [ ] User-controlled data is not dynamically interpreted as code, query syntax, template syntax, or shell syntax.
* [ ] Security-critical comparisons use appropriate constant-time functions where necessary.
* [ ] Random values used for security are cryptographically generated.
* [ ] Critical code is understandable without one specific developer’s context.

## Maintainability

* [ ] Module and function responsibilities are cohesive.
* [ ] Large or highly complex functions have been decomposed where beneficial.
* [ ] Abstractions remove actual duplication rather than hiding behavior.
* [ ] Business rules are not scattered across UI, API handlers, jobs, and database hooks.
* [ ] Critical policy—authorization, billing, quotas—is implemented centrally.
* [ ] Tests describe expected business behavior.
* [ ] Comments explain intent and constraints rather than restating the code.
* [ ] Public interfaces and non-obvious operational behavior are documented.
* [ ] There is a clear deprecation process.
* [ ] Code ownership covers sensitive and operationally critical areas.

---

# 7. Frontend audit

## Rendering and routing

* [ ] Every route renders without console errors or hydration warnings.
* [ ] Direct navigation to every route works.
* [ ] Route guards are backed by server-side authorization.
* [ ] Loading, empty, partial, success, and failure states exist.
* [ ] Error boundaries prevent one component failure from destroying the entire application where appropriate.
* [ ] Server-rendered and client-rendered output are consistent.
* [ ] Public indexable content is present in crawlable output or has been validated through rendered-page testing.
* [ ] Browser history behavior is correct.
* [ ] Scroll restoration is deliberate.
* [ ] Links are real links where navigation is intended.
* [ ] Buttons are used for actions.
* [ ] Modal and drawer URLs are shareable where the product requires it.

## State management

* [ ] There is one authoritative source for each piece of state.
* [ ] Server state and local UI state are not conflated.
* [ ] Stale cached data is invalidated after writes.
* [ ] Optimistic updates roll back correctly after failure.
* [ ] Rapid navigation does not allow stale responses to overwrite newer state.
* [ ] Component unmounting cancels or ignores pending work safely.
* [ ] Authentication state is synchronized across tabs where required.
* [ ] Logging out clears sensitive cached state.
* [ ] Tenant or account switching clears tenant-specific state.
* [ ] Persisted state has a version and migration strategy.
* [ ] Sensitive information is not unnecessarily stored in local storage, IndexedDB, URL parameters, or browser caches.
* [ ] High-value bearer credentials are not exposed to client-side script without a justified design.

## Forms and interaction

* [ ] Native browser form behavior is preserved where useful.
* [ ] All controls have visible, persistent labels.
* [ ] Validation exists on both client and server.
* [ ] Paste, autofill, password managers, and mobile keyboards work.
* [ ] Enter and Escape behavior is predictable.
* [ ] Submission controls prevent accidental duplicate requests without trapping the user.
* [ ] Long operations display progress where possible.
* [ ] Cancellation behavior is honest.
* [ ] Failed submissions preserve the user’s work.
* [ ] File uploads show size, type, progress, and failure clearly.
* [ ] Clipboard interaction has a fallback and clear feedback.
* [ ] Drag-and-drop functionality has a non-drag alternative.
* [ ] Touch targets do not depend on hover.

## Frontend resources

* [ ] Third-party scripts are inventoried and justified.
* [ ] Analytics and advertising scripts do not block the critical rendering path.
* [ ] Fonts have sensible fallbacks.
* [ ] Font loading does not cause unacceptable layout movement.
* [ ] Images have dimensions or reserved aspect ratios.
* [ ] Large media is responsive and appropriately encoded.
* [ ] Event listeners, observers, timers, workers, and subscriptions are cleaned up.
* [ ] Long-lived sessions have been checked for memory growth.
* [ ] Source-map publication is an explicit, reviewed decision.
* [ ] Service workers cannot serve incompatible stale application versions.
* [ ] Sensitive authenticated responses are not cached inappropriately.

---

# 8. Backend and API audit

## API contracts

* [ ] REST, GraphQL, RPC, and event interfaces are documented.
* [ ] Request and response schemas are machine-validated.
* [ ] Unknown and prohibited fields are handled deliberately.
* [ ] Required, nullable, optional, and default semantics are unambiguous.
* [ ] Error responses use a stable schema.
* [ ] Status codes accurately reflect outcomes.
* [ ] Correlation or request IDs are returned where useful.
* [ ] Pagination has documented ordering and stable cursors.
* [ ] Maximum page sizes are enforced.
* [ ] Filtering and sorting fields are allowlisted.
* [ ] APIs do not expose internal fields merely because they exist on a database model.
* [ ] Date, currency, identifier, and decimal formats are explicit.
* [ ] API compatibility is tested against existing clients.
* [ ] Deprecated versions have timelines and telemetry.
* [ ] Documentation is generated from or tested against implementation where possible.

## Request handling

* [ ] Every request is authenticated when required.
* [ ] Every requested operation and object is authorized independently.
* [ ] Input validation happens before business logic.
* [ ] Server-side rules do not trust client-calculated amounts, roles, limits, or state.
* [ ] Payload sizes are bounded.
* [ ] Request-processing time is bounded.
* [ ] Expensive operations have cost and concurrency limits.
* [ ] File, archive, image, and document processing has resource limits.
* [ ] Client-controlled URLs cannot reach arbitrary internal or external resources.
* [ ] Database queries are parameterized.
* [ ] OS commands are avoided or safely parameterized.
* [ ] Redirect destinations are validated.
* [ ] Responses use explicit content types.
* [ ] Content negotiation cannot produce unsafe formats unexpectedly.
* [ ] Compression cannot be abused to exhaust resources.

## Correctness and resilience

* [ ] Write operations that can be replayed support idempotency.
* [ ] Idempotency keys are scoped to the correct user, tenant, and operation.
* [ ] Transaction boundaries match business invariants.
* [ ] Partial writes are rolled back or compensated.
* [ ] Timeouts are shorter than upstream timeouts.
* [ ] Retries are limited, back off, and include jitter.
* [ ] Retries are only applied to safe or idempotent operations.
* [ ] Circuit breakers or failure isolation exist for unstable critical dependencies.
* [ ] The application distinguishes dependency failure from invalid user input.
* [ ] Rate limits return understandable responses and retry guidance.
* [ ] Graceful shutdown stops accepting work and drains in-flight operations safely.
* [ ] Health checks distinguish process liveness from actual readiness.

## Protocol-specific checks

### GraphQL

* [ ] Resolver-level authorization is enforced.
* [ ] Query depth, complexity, aliases, and batching are limited.
* [ ] Pagination is enforced on collections.
* [ ] Introspection exposure is an explicit decision.
* [ ] Field-level sensitive-data exposure is tested.
* [ ] N+1 query behavior is controlled.
* [ ] Persisted queries or equivalent controls are considered for high-risk deployments.

### WebSockets and real-time connections

* [ ] Authentication occurs during connection establishment.
* [ ] Authorization is checked for every channel, room, topic, and message action.
* [ ] Session expiry and revocation affect existing connections.
* [ ] Origin validation is configured.
* [ ] Message size and rate are limited.
* [ ] Reconnection cannot replay unsafe operations.
* [ ] Tenant switching or logout closes relevant connections.
* [ ] Backpressure and slow consumers are handled.

### Webhooks

* [ ] Webhook signatures are verified.
* [ ] Timestamp or nonce validation limits replay.
* [ ] Secret rotation is supported.
* [ ] Delivery is idempotent.
* [ ] Retries, ordering, duplicate events, and late events are handled.
* [ ] Unknown event types fail safely.
* [ ] Webhook payloads are treated as untrusted input.
* [ ] Failed events have a retry or dead-letter process.

---

# 9. Database and data-layer audit

## Schema integrity

* [ ] Primary keys and identifier semantics are deliberate.
* [ ] Foreign keys exist where the data model requires them.
* [ ] Uniqueness constraints enforce actual business invariants.
* [ ] Nullability matches application semantics.
* [ ] Check constraints enforce important ranges and states.
* [ ] Tenant identifiers are present and consistently enforced.
* [ ] Currency and other exact values use appropriate fixed precision.
* [ ] Time-zone storage and conversion strategy is consistent.
* [ ] Soft deletion does not accidentally expose or resurrect data.
* [ ] Audit fields cannot be spoofed by clients.
* [ ] Referential cleanup behavior is explicit.

## Queries and indexing

* [ ] Production-like query plans have been reviewed for critical paths.
* [ ] Required indexes exist.
* [ ] Redundant or harmful indexes are understood.
* [ ] N+1 query patterns are removed.
* [ ] Full-table scans are acceptable or eliminated.
* [ ] Sort operations are indexed where necessary.
* [ ] Large result sets cannot be fetched without pagination or limits.
* [ ] Search behavior is tested with realistic data volume.
* [ ] Connection-pool limits align with database capacity and instance scaling.
* [ ] Slow-query logging and monitoring are enabled.
* [ ] Long-running transactions are identified.
* [ ] Lock contention and deadlocks have been tested for high-concurrency operations.

## Transactions and consistency

* [ ] Transaction isolation is suitable for the invariants being protected.
* [ ] Race-sensitive checks and writes happen atomically.
* [ ] Retry behavior for serialization failures or deadlocks is safe.
* [ ] Cache updates cannot make stale authorization or entitlement state authoritative.
* [ ] Replication lag is acceptable for reads that use replicas.
* [ ] Read-after-write expectations are documented.
* [ ] Event publication and database writes cannot diverge silently.
* [ ] Batch jobs are restartable and checkpointed.
* [ ] Data migrations are deterministic and observable.

## Migrations

* [ ] Migrations have been tested against a production-scale copy or representative dataset.
* [ ] Migration duration and locking behavior are known.
* [ ] Application and schema changes are backward compatible during rolling deployment.
* [ ] Destructive schema changes use an expand-migrate-contract sequence where required.
* [ ] Failed migrations leave a known recoverable state.
* [ ] Migration progress and failures are observable.
* [ ] A rollback or roll-forward plan exists.
* [ ] Data backfills are rate-limited and restartable.
* [ ] New constraints are validated without causing unacceptable downtime.
* [ ] Old code cannot corrupt the new schema during a mixed-version deployment.

## Data lifecycle

* [ ] Data ownership and classification are documented.
* [ ] Collection is limited to what the product actually needs.
* [ ] Retention periods are defined.
* [ ] Expired data is actually deleted or irreversibly anonymized.
* [ ] Account deletion covers primary data, derived data, search indexes, caches, analytics where applicable, and backups according to policy.
* [ ] User exports are complete, secure, and correctly authorized.
* [ ] Legal holds or contractual retention exceptions are supported where required.
* [ ] Test environments do not contain uncontrolled production personal data.
* [ ] Synthetic or properly anonymized test data is preferred.
* [ ] Data correction and reconciliation procedures exist.

---

# 10. Security audit

The security review should explicitly cover all OWASP Top 10:2025 areas: broken access control, security misconfiguration, software supply-chain failures, cryptographic failures, injection, insecure design, authentication failures, software or data integrity failures, logging and alerting failures, and mishandling of exceptional conditions. ([OWASP][7])

## Threat model and attack surface

* [ ] Sensitive assets and trust boundaries are identified.
* [ ] Threats are modeled for anonymous users, normal users, administrators, insiders, compromised accounts, and compromised third parties.
* [ ] Abuse cases cover financial, quota, moderation, referral, invitation, export, search, scraping, and automation abuse.
* [ ] All exposed hosts, ports, endpoints, storage buckets, dashboards, and admin tools are inventoried.
* [ ] Deprecated APIs and old application versions are removed or protected.
* [ ] Staging, preview, debug, documentation, and test systems are not accidentally public.
* [ ] Security assumptions are documented and tested.
* [ ] Controls fail closed when state is uncertain.

## Authentication

* [ ] Authentication uses a mature protocol or identity system rather than custom cryptography.
* [ ] OAuth/OIDC implementations validate issuer, audience, signature, expiry, state, nonce, and redirect URI.
* [ ] Public clients use PKCE where applicable.
* [ ] Tokens are never accepted solely because they can be decoded.
* [ ] Login does not reveal whether an account exists unnecessarily.
* [ ] Brute-force, credential-stuffing, and password-spraying controls exist.
* [ ] Rate limiting considers account, IP, device, tenant, and distributed attacks.
* [ ] Administrative and high-risk accounts require appropriate MFA.
* [ ] MFA enrollment and removal require reauthentication.
* [ ] Recovery mechanisms are not weaker than normal authentication.
* [ ] Password-reset tokens are random, scoped, short-lived, and single-use.
* [ ] Password changes and recovery can revoke other sessions.
* [ ] Email-address changes require appropriate verification and reauthentication.
* [ ] Sensitive operations require recent authentication where warranted.
* [ ] Account linking cannot be abused to take over an existing account.
* [ ] Disabled, deleted, suspended, or unverified accounts cannot authenticate improperly.
* [ ] Authentication provider outages produce a safe, understandable failure state.

## Sessions and tokens

* [ ] Session identifiers are unpredictable.
* [ ] Sessions rotate after login, privilege change, recovery, and other sensitive transitions.
* [ ] Logout invalidates the server-side session where applicable.
* [ ] Global logout and administrative revocation work.
* [ ] Expired credentials cannot be refreshed indefinitely.
* [ ] Refresh-token reuse or theft is detected where appropriate.
* [ ] Browser cookies use `Secure`, `HttpOnly`, and an appropriate `SameSite` policy.
* [ ] Authentication tokens do not appear in URLs, logs, analytics, referrers, or error messages.
* [ ] Session lifetime matches application risk.
* [ ] Concurrent-session policy is intentional.
* [ ] Device and session listings are accurate.
* [ ] “Remember me” behavior is separately secured.
* [ ] Tenant switching does not retain stale authorization state.

## Authorization and tenant isolation

* [ ] Authorization is enforced server side.
* [ ] Access is denied by default.
* [ ] Every object read, update, delete, export, and action is authorized.
* [ ] Object ownership is checked, not merely possession of an identifier.
* [ ] Function-level permissions are enforced for administrative and privileged operations.
* [ ] Property-level authorization prevents users modifying protected fields.
* [ ] Users cannot change role, tenant, ownership, plan, price, approval, or entitlement fields through request manipulation.
* [ ] Sequential and guessable identifiers do not create unauthorized access.
* [ ] Two-user and two-tenant adversarial tests have been performed.
* [ ] Cross-tenant isolation is tested in APIs, caches, search, exports, background jobs, analytics, object storage, and notifications.
* [ ] Administrative impersonation is scoped, time-limited, visible, and audited.
* [ ] Support tooling cannot bypass policy silently.
* [ ] Archived, soft-deleted, or hidden resources retain correct access controls.
* [ ] Authorization changes invalidate cached permissions promptly.
* [ ] WebSocket subscriptions and queued jobs re-check relevant authorization.

Broken object- and function-level authorization are central API risks and should be tested with separate authenticated identities rather than only anonymous scans. ([OWASP][8])

## Injection and unsafe interpretation

* [ ] SQL and NoSQL queries use safe parameterization.
* [ ] HTML output is encoded for the correct context.
* [ ] Rich text, Markdown, SVG, and user-supplied HTML are sanitized with an allowlist-based approach.
* [ ] Template expressions cannot be injected.
* [ ] Shell commands do not concatenate untrusted data.
* [ ] LDAP, XPath, search-query, and expression-language injection are addressed where applicable.
* [ ] CSV and spreadsheet exports prevent formula injection.
* [ ] XML parsers disable unsafe external entity behavior.
* [ ] Deserialization of untrusted polymorphic or executable objects is prohibited.
* [ ] User-controlled regular expressions, glob patterns, or filters cannot exhaust resources.
* [ ] File paths are normalized and restricted to intended roots.
* [ ] Log entries cannot be forged through newline or control-character injection.
* [ ] Header values cannot be injected.
* [ ] Email templates and headers cannot be manipulated by user input.
* [ ] Model-generated or AI-generated text is treated as untrusted input before rendering or execution.

## Browser and HTTP security

* [ ] HTTPS is enforced everywhere.
* [ ] Mixed content is absent.
* [ ] TLS and certificate configuration are current and monitored.
* [ ] HSTS is enabled after confirming HTTPS readiness across relevant subdomains.
* [ ] A restrictive Content Security Policy is deployed and tested.
* [ ] CSP uses nonces or hashes where appropriate rather than broad unsafe allowances.
* [ ] Framing is restricted with CSP `frame-ancestors` or an equivalent policy.
* [ ] `X-Content-Type-Options: nosniff` is configured.
* [ ] Referrer policy is appropriate for sensitive URLs.
* [ ] Permissions Policy restricts browser capabilities not required by the application.
* [ ] Cross-origin isolation headers are configured where the product requires them.
* [ ] CORS allows only intended origins, methods, headers, and credential behavior.
* [ ] Credentialed CORS does not use wildcard origins.
* [ ] Cookie-authenticated state-changing requests are protected against CSRF.
* [ ] Open redirects are prevented.
* [ ] `postMessage` handlers validate origin and message shape.
* [ ] DOM sinks do not receive untrusted HTML or script content.
* [ ] Third-party scripts are minimized and constrained.
* [ ] Subresource Integrity is considered for externally hosted static scripts.
* [ ] Sensitive pages use appropriate cache controls.
* [ ] Authentication and reset pages do not leak information through referrers or embedded third parties.

OWASP’s security-header guidance specifically treats response headers as defense-in-depth controls against classes such as XSS, clickjacking, and information disclosure; they do not replace secure application logic. ([OWASP Cheat Sheet Series][9])

## Data protection and cryptography

* [ ] Sensitive data is classified.
* [ ] Sensitive data is minimized in requests, responses, storage, logs, analytics, and support tools.
* [ ] Encryption is applied in transit and at rest where risk requires it.
* [ ] Keys and secrets are stored in a dedicated secret-management system.
* [ ] Secrets are not committed, baked into images, exposed in frontend bundles, or copied into tickets.
* [ ] Separate environments use separate credentials.
* [ ] Key rotation is supported and tested.
* [ ] Rotation does not require an unsafe all-at-once cutover.
* [ ] Cryptographic algorithms and libraries are current and centrally managed.
* [ ] Custom cryptographic constructions are absent.
* [ ] Security-sensitive random values use a cryptographically secure generator.
* [ ] Passwords are stored using a dedicated, modern password-hashing function.
* [ ] Encrypted backups have independent key-management and recovery procedures.
* [ ] Sensitive query parameters are avoided.
* [ ] Error monitoring and session-replay tools redact sensitive fields.
* [ ] Client-side encryption claims accurately reflect where plaintext is available.
* [ ] Data-integrity signatures are verified before use.
* [ ] Signed URLs are appropriately scoped and expire.

## File uploads and downloads

* [ ] Maximum file size is enforced before expensive processing.
* [ ] File extension, declared MIME type, and detected content are validated.
* [ ] File names are generated or normalized safely.
* [ ] Files are stored outside executable or public web roots unless explicitly public.
* [ ] Private object-store permissions are verified.
* [ ] User-provided SVG, HTML, PDF, office, archive, and media formats receive format-specific treatment.
* [ ] Archives have extraction-count, depth, path, and decompression-ratio limits.
* [ ] Malware scanning is applied where the threat model requires it.
* [ ] Image and document parsers are patched and sandboxed where feasible.
* [ ] Downloads set safe content type and disposition.
* [ ] One user cannot overwrite another user’s file through naming or path manipulation.
* [ ] Temporary files are deleted.
* [ ] Failed processing does not leave public or orphaned files.
* [ ] Thumbnail, preview, indexing, OCR, and conversion services preserve authorization.

## SSRF and outbound connections

* [ ] User-controlled URLs are not fetched without strict validation.
* [ ] Destination schemes, hosts, ports, and paths are allowlisted where possible.
* [ ] Cloud metadata endpoints and internal address ranges are inaccessible.
* [ ] Redirect chains are revalidated.
* [ ] DNS rebinding is considered.
* [ ] Outbound network access is restricted at the infrastructure layer.
* [ ] URL parsing is consistent between validation and request execution.
* [ ] Response size and time are bounded.
* [ ] Proxy and webhook functionality cannot be used as an anonymous scanning or relay service.

## Abuse resistance and resource consumption

* [ ] Rate limits exist on login, signup, reset, verification, invitations, search, export, upload, messaging, and expensive compute.
* [ ] Limits apply to the actual constrained resource, not merely request count.
* [ ] Per-user, per-tenant, per-IP, and global safeguards are considered.
* [ ] Requests have CPU, memory, time, token, database, and third-party-cost ceilings.
* [ ] Pagination cannot be bypassed.
* [ ] GraphQL and search complexity are bounded.
* [ ] Email, SMS, AI, image processing, and paid API operations have spend limits.
* [ ] Trial, coupon, referral, voting, review, and invitation mechanisms resist automation and replay.
* [ ] Concurrency cannot bypass quotas, balances, or inventory.
* [ ] Expensive unauthenticated operations are minimized.
* [ ] DDoS protection and provider limits are understood.
* [ ] Abuse controls have monitoring and an administrative response path.

## Configuration and administrative security

* [ ] Default credentials and accounts are removed.
* [ ] Debug mode is disabled.
* [ ] Stack traces and internal exception details are not returned to users.
* [ ] Directory listing is disabled.
* [ ] Unnecessary services, ports, modules, samples, and documentation endpoints are removed.
* [ ] Cloud storage and database network exposure are reviewed.
* [ ] Administrative interfaces require strong authentication and least privilege.
* [ ] Production access uses individual accounts rather than shared credentials.
* [ ] Privileged access is logged.
* [ ] Emergency access is controlled and reviewed.
* [ ] Infrastructure management endpoints are not internet-exposed unnecessarily.
* [ ] Environment variables and configuration values are validated at startup.
* [ ] Unsafe or missing configuration prevents startup rather than silently weakening security.
* [ ] Security configuration is automated and tested consistently between environments.

## Exception handling

* [ ] Invalid and exceptional states fail closed.
* [ ] Missing parameters do not accidentally enable broader access.
* [ ] Authorization infrastructure failure does not grant access.
* [ ] Payment-provider uncertainty does not grant unpaid entitlements.
* [ ] Database and queue errors do not leave contradictory state.
* [ ] Error handlers do not themselves throw or expose secrets.
* [ ] Retries cannot create duplicate financial or destructive operations.
* [ ] Users receive a stable error reference without internal details.
* [ ] Internal logs retain enough context for diagnosis.
* [ ] Resource exhaustion degrades predictably rather than crashing the whole system.

Mishandling exceptional conditions became a distinct OWASP Top 10 category in the 2025 release, covering problems such as failing open, incomplete validation, inconsistent exception handling, and unsafe behavior under abnormal conditions. ([OWASP][10])

## Security verification

* [ ] Threat-model review has occurred.
* [ ] Security-sensitive code has received human review.
* [ ] Secret scanning runs on commits and history.
* [ ] Static application security testing runs with reviewed results.
* [ ] Dependency and container vulnerability scanning runs.
* [ ] Infrastructure-as-code scanning runs.
* [ ] Dynamic scanning runs against the deployed application.
* [ ] Authenticated dynamic scanning covers multiple roles.
* [ ] Manual authorization and business-logic testing is performed.
* [ ] API testing includes two-user and two-tenant cases.
* [ ] Security headers and TLS are independently verified.
* [ ] File-upload and SSRF testing is performed where applicable.
* [ ] Critical dependencies are checked against current advisories.
* [ ] False positives are documented rather than silently suppressed.
* [ ] Critical and high findings have remediation service levels.
* [ ] A penetration test is performed when risk, contract, or launch exposure warrants it.
* [ ] A security contact and vulnerability-reporting path exist.
* [ ] An incident-response plan exists for credential, data, dependency, and infrastructure compromise.

---

# 11. Software supply-chain and build audit

OWASP Top 10:2025 expanded dependency risk into “Software Supply Chain Failures,” covering dependencies, build systems, and distribution infrastructure. ([OWASP][7])

## Dependencies

* [ ] Direct and transitive dependencies are inventoried.
* [ ] Lockfiles are committed and enforced.
* [ ] Dependency versions are pinned to an appropriate degree.
* [ ] Package names are checked for typosquatting and dependency-confusion risk.
* [ ] Private package namespaces cannot resolve unexpectedly from public registries.
* [ ] Installation lifecycle scripts are reviewed or constrained.
* [ ] Dependencies originate from approved registries.
* [ ] Package integrity hashes or signatures are verified.
* [ ] Vulnerability monitoring continues after release.
* [ ] Unmaintained and end-of-life dependencies are identified.
* [ ] License obligations are recorded.
* [ ] Runtime dependencies are separated from development-only dependencies.
* [ ] Optional and unused dependencies are removed.
* [ ] Browser bundles do not include server-only libraries or secrets.
* [ ] Emergency dependency-patching procedures exist.

## Source control

* [ ] Main and release branches are protected.
* [ ] Direct pushes are restricted.
* [ ] Required reviews apply to critical code.
* [ ] Required status checks cannot be bypassed casually.
* [ ] CODEOWNERS or equivalent covers sensitive paths.
* [ ] Deleted or rewritten history is controlled.
* [ ] Repository administrators use MFA.
* [ ] Automation tokens have minimal scope.
* [ ] Fork and pull-request workflows do not expose secrets.
* [ ] Generated code and vendored code have clear provenance.
* [ ] Release tags are protected.
* [ ] Changes can be traced to an authorized review and build.

## CI build

* [ ] Builds run in isolated, ephemeral, or controlled environments.
* [ ] CI dependencies and actions are pinned.
* [ ] Build runners do not retain secrets or artifacts between untrusted jobs.
* [ ] Untrusted pull requests cannot execute with production credentials.
* [ ] Build output is deterministic enough to investigate and reproduce.
* [ ] The build fails on relevant test, lint, type, security, and license violations.
* [ ] The exact tested artifact is promoted to production rather than rebuilt.
* [ ] Artifacts are immutable and content-addressed where practical.
* [ ] Artifact signatures or attestations are generated.
* [ ] Production verifies artifact identity.
* [ ] An SBOM is generated and retained.
* [ ] Build provenance records source revision, builder, dependencies, and parameters.
* [ ] Secrets are injected only at the stage that needs them.
* [ ] Production deployment authority is separate from ordinary pull-request execution.
* [ ] Build logs do not expose secrets.

A practical target is at least SLSA Build L2 semantics: signed provenance produced by a hosted build platform. Higher-assurance systems should consider hardened-build requirements represented by Build L3. ([SLSA][11])

---

# 12. Infrastructure, cloud, network, DNS, and domain audit

## Infrastructure management

* [ ] Infrastructure is defined as code where feasible.
* [ ] Manual production changes are detected and reconciled.
* [ ] Development, staging, and production are isolated.
* [ ] Production credentials are never reused in lower environments.
* [ ] Cloud accounts, projects, or subscriptions have clear ownership.
* [ ] IAM follows least privilege.
* [ ] Human access uses SSO and MFA.
* [ ] Service identities use short-lived or managed credentials where available.
* [ ] Access keys have rotation and removal procedures.
* [ ] Privileged production access is logged and periodically reviewed.
* [ ] Unused resources, identities, keys, and firewall rules are removed.
* [ ] Provider audit logging is enabled.
* [ ] Regions and data residency match product commitments.
* [ ] Provider quotas and account limits are known.

## Network

* [ ] Databases, caches, queues, and administrative endpoints are private unless exposure is justified.
* [ ] Network rules permit only necessary sources, destinations, and ports.
* [ ] Outbound traffic is controlled where SSRF or data-exfiltration risk is material.
* [ ] Production management access does not rely on an open public port.
* [ ] Load balancers and reverse proxies preserve correct client and protocol information.
* [ ] Trusted-proxy configuration cannot be spoofed.
* [ ] Internal service authentication is appropriate for the threat model.
* [ ] A CDN or edge layer cannot bypass origin authentication rules.
* [ ] Origin servers are protected from unintended direct access where necessary.
* [ ] WAF rules are tested and treated as supplementary controls.
* [ ] DDoS protections and escalation routes are known.

## Compute and containers

* [ ] Base images are minimal and patched.
* [ ] Containers run as non-root where feasible.
* [ ] Unnecessary Linux capabilities are removed.
* [ ] Filesystems are read-only where feasible.
* [ ] CPU, memory, process, and storage limits are set.
* [ ] Ephemeral storage exhaustion is monitored.
* [ ] Container images are scanned and signed where appropriate.
* [ ] Images use immutable tags or digests.
* [ ] Startup, readiness, liveness, and shutdown behavior is correct.
* [ ] Autoscaling uses meaningful metrics.
* [ ] Autoscaling limits prevent both outage and runaway cost.
* [ ] Scheduled jobs cannot overlap unsafely.
* [ ] Serverless concurrency and timeout settings are intentional.
* [ ] Cold-start behavior is acceptable.

## Edge, TLS, and DNS

* [ ] All domains and subdomains are inventoried.
* [ ] Registrar accounts use strong MFA.
* [ ] Domain auto-renewal and payment methods are monitored.
* [ ] DNS changes are controlled and audited.
* [ ] Dangling DNS records and abandoned cloud resources are removed.
* [ ] Subdomain-takeover risk is checked.
* [ ] TLS certificates renew automatically.
* [ ] Certificate expiry is independently monitored.
* [ ] Certificate issuance controls such as CAA are considered.
* [ ] Redirects from alternate hosts and HTTP are correct.
* [ ] Canonical host behavior is consistent.
* [ ] CDN caches cannot mix tenants, users, languages, or authorization states.
* [ ] Cache keys include all relevant request dimensions.
* [ ] Cache purge and rollback procedures exist.

---

# 13. Performance audit

## Performance budgets

Define budgets for each important route and operation:

* JavaScript transferred and executed.
* CSS transferred.
* Image and media size.
* Font size and count.
* Number of requests.
* Main-thread blocking time.
* DOM size.
* Server-render duration.
* API p50, p95, and p99 latency.
* Database query latency.
* Memory and CPU consumption.
* Third-party request cost.
* Time to usable content on representative mobile hardware.

## Frontend performance

* [ ] Core Web Vitals meet the release target.
* [ ] Field data is used where sufficient traffic exists.
* [ ] Lab testing covers representative slower devices and networks.
* [ ] Largest Contentful Paint content is identified and prioritized.
* [ ] Render-blocking CSS and script are minimized.
* [ ] JavaScript is code-split by meaningful route or capability.
* [ ] Large dependencies are justified.
* [ ] Unused JavaScript and CSS are minimized.
* [ ] Long tasks and interaction delays are profiled.
* [ ] Hydration work is proportionate to the page.
* [ ] Static or server rendering is used where it materially improves experience or indexing.
* [ ] Images use responsive dimensions and appropriate modern encodings.
* [ ] Images below the fold are lazy-loaded appropriately.
* [ ] The primary image is not accidentally lazy-loaded.
* [ ] Image dimensions prevent layout shifts.
* [ ] Fonts are subset, compressed, and loaded deliberately.
* [ ] Third-party scripts have measured cost.
* [ ] Preload and prefetch are used selectively rather than indiscriminately.
* [ ] Browser caching is correct for immutable assets.
* [ ] HTML and user-specific responses are not cached incorrectly.
* [ ] Compression is enabled for suitable text assets.
* [ ] CDN behavior is verified in the deployed environment.
* [ ] Error pages and first-time visits are also performant.
* [ ] Long-running sessions are checked for memory leaks.
* [ ] Large lists use pagination, virtualization, or another appropriate strategy.

## Backend performance

* [ ] Latency is measured at p50, p95, and p99 rather than only average.
* [ ] Time is broken down across application, database, cache, queue, and external dependencies.
* [ ] Slow endpoints have profiles or traces.
* [ ] Database queries use realistic data volumes.
* [ ] Cache hit and miss behavior is measured.
* [ ] Cache misses do not overload the backing store.
* [ ] Connection pools are correctly sized.
* [ ] Serialization and payload size are measured.
* [ ] Compression does not consume disproportionate CPU.
* [ ] External calls are parallelized only when safe and beneficial.
* [ ] Batch and bulk endpoints exist where chatty APIs are a bottleneck.
* [ ] Background work is removed from synchronous request paths where appropriate.
* [ ] Cold-start behavior is tested.
* [ ] Geographic latency is tested from relevant regions.
* [ ] Performance regression gates exist for critical paths.

## Load testing

* [ ] Normal expected load is tested.
* [ ] Forecast peak load is tested.
* [ ] Sudden spike behavior is tested.
* [ ] Sustained soak behavior is tested.
* [ ] Recovery after overload is tested.
* [ ] Hot-user, hot-tenant, and hot-key scenarios are tested.
* [ ] Database connections do not exceed provider limits.
* [ ] Queue depth and processing lag are observed.
* [ ] Autoscaling activates early enough.
* [ ] Rate limiting behaves correctly under distributed load.
* [ ] Load generation itself does not invalidate the results.
* [ ] Test data and cleanup do not distort database performance.
* [ ] The system’s actual breaking point is understood.
* [ ] Capacity includes reasonable headroom.

---

# 14. Scalability and capacity

* [ ] Traffic and data-growth forecasts exist.
* [ ] Capacity is modeled for users, requests, storage, database rows, search documents, queue depth, emails, files, and third-party calls.
* [ ] Horizontal scaling does not depend on local process state.
* [ ] Sessions and locks work across multiple instances.
* [ ] Shared caches and stores have sufficient capacity.
* [ ] Database write scaling limits are understood.
* [ ] Read replicas are used safely if needed.
* [ ] Sharding or partitioning keys will not create obvious hotspots.
* [ ] Large tenants cannot starve small tenants.
* [ ] Per-tenant fairness or quotas exist where appropriate.
* [ ] Queue consumers can scale without duplicate unsafe processing.
* [ ] Backpressure prevents unbounded accumulation.
* [ ] Cache stampedes and thundering herds are mitigated.
* [ ] Scheduled jobs are spread or controlled.
* [ ] Object-store and CDN limits are known.
* [ ] Third-party provider quotas include launch and retry volume.
* [ ] Autoscaling maximums align with database and dependency limits.
* [ ] Capacity expansion has an owner and lead-time estimate.

---

# 15. Reliability and resilience

## Service objectives

* [ ] User-visible availability objectives are defined.
* [ ] Latency objectives are defined.
* [ ] Correctness and data-freshness objectives are defined.
* [ ] SLIs measure what users experience rather than only process uptime.
* [ ] Error budgets or equivalent release-risk criteria exist.
* [ ] Critical dependencies have explicit reliability assumptions.

## Failure handling

* [ ] Every external call has a timeout.
* [ ] Timeout hierarchies are coherent.
* [ ] Retries use exponential backoff and jitter.
* [ ] Retry storms are prevented.
* [ ] Circuit breakers or equivalent isolation exist where useful.
* [ ] Bulkheads prevent one dependency or tenant exhausting all resources.
* [ ] Optional features degrade without taking down core workflows.
* [ ] Dependency failure does not corrupt state.
* [ ] Queued work survives process restarts.
* [ ] Dead-letter queues or failure stores exist.
* [ ] Failed jobs can be inspected and replayed safely.
* [ ] Idempotency protects against replay.
* [ ] Duplicate and out-of-order events are handled.
* [ ] Graceful shutdown drains work.
* [ ] Deployments do not terminate long-running work unsafely.
* [ ] Resource exhaustion produces controlled rejection.
* [ ] The system recovers automatically after the limiting condition ends.
* [ ] Maintenance modes do not accidentally expose administrative behavior.
* [ ] Feature kill switches exist for risky integrations or expensive features.

## Dependency and regional failures

* [ ] Authentication-provider outage behavior is tested.
* [ ] Payment-provider outage behavior is tested.
* [ ] Email or notification-provider outage behavior is tested.
* [ ] Object-storage outage behavior is tested.
* [ ] Database failover behavior is understood.
* [ ] DNS and certificate failure scenarios are covered.
* [ ] Regional outage strategy is documented.
* [ ] Critical third parties have fallback, queuing, or manual recovery procedures.
* [ ] Retry duration does not exceed business validity windows.
* [ ] Reconciliation can detect missed or contradictory third-party events.
* [ ] Failure modes are reflected accurately to users.

---

# 16. Observability, logging, and alerting

A complete observability implementation generally combines correlated traces, metrics, and logs. ([OpenTelemetry][12])

## Logging

* [ ] Logs are structured.
* [ ] Log levels are used consistently.
* [ ] Requests have correlation or trace IDs.
* [ ] User, tenant, request, job, deployment, and dependency context is recorded safely.
* [ ] Passwords, tokens, secrets, payment data, and sensitive personal data are redacted.
* [ ] User-provided strings cannot forge log records.
* [ ] Exceptions include stack and causal context internally.
* [ ] Expected user errors do not create excessive noise.
* [ ] Security-sensitive actions are auditable.
* [ ] Administrative and impersonation actions are logged.
* [ ] Audit events are protected against unauthorized modification.
* [ ] Log retention and access controls are defined.
* [ ] Clock synchronization is reliable.

## Metrics

* [ ] Request rate, error rate, and latency are measured.
* [ ] CPU, memory, disk, network, connection pools, and thread/event-loop health are measured.
* [ ] Database latency, locks, connections, replication, and storage are measured.
* [ ] Cache hit rate, eviction, and errors are measured.
* [ ] Queue depth, age, throughput, retries, and dead letters are measured.
* [ ] Third-party latency, errors, quotas, and costs are measured.
* [ ] Authentication failures and suspicious activity are measured.
* [ ] Signup, activation, purchase, save, export, and other business-critical success rates are measured.
* [ ] Data freshness and background-job completion are measured.
* [ ] Metrics avoid uncontrolled high-cardinality dimensions.

## Tracing and diagnostics

* [ ] Distributed traces cross relevant service and queue boundaries.
* [ ] Frontend requests can be correlated with backend traces where appropriate.
* [ ] Trace sampling retains useful failure information.
* [ ] Slow critical paths can be diagnosed without adding a new deployment.
* [ ] Deploy versions and feature flags appear in telemetry.
* [ ] Database and external-call spans contain safe diagnostic metadata.
* [ ] Profiling can be enabled safely for difficult incidents.

## Dashboards and alerts

* [ ] A launch dashboard covers critical user journeys and dependencies.
* [ ] Dashboards show deployment markers.
* [ ] Alerts are based primarily on user-visible symptoms or SLO risk.
* [ ] Infrastructure alerts are actionable rather than merely informational.
* [ ] Every paging alert has an owner.
* [ ] Every paging alert links to a runbook.
* [ ] Alert thresholds have been tested.
* [ ] Alert delivery has been tested end to end.
* [ ] Alert noise and duplication are controlled.
* [ ] External synthetic checks validate public availability.
* [ ] Real-user monitoring captures frontend failures and performance.
* [ ] Status-page update criteria are defined.
* [ ] Security events generate appropriate alerts, not merely logs.

---

# 17. Testing and quality engineering

## Test layers

* [ ] Unit tests cover important business and transformation logic.
* [ ] Integration tests cover databases, queues, storage, authentication, and external adapters.
* [ ] Contract tests cover service and client compatibility.
* [ ] End-to-end tests cover critical user journeys.
* [ ] Visual regression tests cover high-value layouts and states.
* [ ] Accessibility tests run automatically and manually.
* [ ] Security tests include both automation and adversarial manual cases.
* [ ] Performance tests include frontend, API, database, and load behavior.
* [ ] Migration tests use realistic schemas and data.
* [ ] Backup-restoration tests are performed.
* [ ] Deployment and rollback are tested.
* [ ] Failure-injection tests cover critical dependencies.
* [ ] Browser and device testing follows the support matrix.

## Test quality

* [ ] Tests assert business outcomes rather than implementation trivia.
* [ ] Critical negative and authorization cases are covered.
* [ ] Tests use at least two users and two tenants where relevant.
* [ ] Tests are deterministic.
* [ ] Flaky tests are fixed or explicitly quarantined with an owner.
* [ ] Test failures cannot be ignored silently.
* [ ] Test data is isolated and cleaned up.
* [ ] Tests do not depend unnecessarily on execution order.
* [ ] Mocks accurately preserve critical provider semantics.
* [ ] Production-like integration tests exist for behavior that mocks cannot validate.
* [ ] Time-dependent tests control the clock.
* [ ] Concurrency tests exercise race-sensitive workflows.
* [ ] Property-based or fuzz testing is used for parsers and complex validation where valuable.
* [ ] Coverage is assessed by risk and behavior, not a vanity percentage.
* [ ] Every production incident or escaped critical bug receives a regression test where feasible.

## Release-candidate testing

* [ ] The exact production artifact is tested.
* [ ] Tests run with production-equivalent configuration.
* [ ] Database migrations are included.
* [ ] CDN, proxy, cookie, domain, and TLS behavior are tested in the deployed environment.
* [ ] Feature flags match the intended launch state.
* [ ] Third-party production credentials or sandbox equivalents are validated.
* [ ] Smoke tests run automatically after deployment.
* [ ] Critical paths are manually explored before release.
* [ ] A clean browser profile is used.
* [ ] Existing-user upgrade behavior is tested.
* [ ] Previous-version compatibility is tested during rolling deployment.

---

# 18. Accessibility audit

Target WCAG 2.2 AA unless a different contractual or legal standard has been established. WCAG 2.2 includes newer criteria covering focus obscuration, dragging alternatives, target size, redundant entry, consistent help, and accessible authentication. ([W3C][2])

## Structure and semantics

* [ ] The page has a correct language declaration.
* [ ] Headings form a meaningful hierarchy.
* [ ] Landmarks identify header, navigation, main, complementary, and footer regions appropriately.
* [ ] A skip link reaches main content.
* [ ] Lists, tables, forms, and buttons use native semantics where possible.
* [ ] Custom controls expose correct name, role, value, state, and relationships.
* [ ] DOM order matches meaningful reading and focus order.
* [ ] Reflow does not change the logical order.

## Keyboard and focus

* [ ] All functionality is available by keyboard.
* [ ] Focus is always visible.
* [ ] Focus is not obscured by sticky headers, overlays, or drawers.
* [ ] Focus order is logical.
* [ ] Modals trap focus appropriately and return it when closed.
* [ ] Menus and composite widgets use expected keyboard patterns.
* [ ] There are no keyboard traps.
* [ ] Disabled controls are understandable.
* [ ] Hover-only content can also be reached and dismissed by keyboard.
* [ ] Dragging interactions have a non-drag alternative.

## Forms and errors

* [ ] Every input has a programmatic and visible label.
* [ ] Required fields are communicated without relying only on color.
* [ ] Input purpose and autocomplete attributes are correct.
* [ ] Instructions precede the interaction they describe.
* [ ] Errors identify the relevant field and explain how to fix it.
* [ ] Error summaries are focusable and link to fields where useful.
* [ ] Validation is announced to assistive technology.
* [ ] Previously entered information is not unnecessarily requested again.
* [ ] Authentication does not require an unsupported cognitive-function test without an accessible alternative.
* [ ] Time limits can be extended where required.

## Visual presentation

* [ ] Normal text meets at least 4.5:1 contrast.
* [ ] Large text and meaningful graphical objects meet applicable contrast requirements.
* [ ] Information is not conveyed by color alone.
* [ ] Text can be enlarged to 200 percent without loss of content or functionality.
* [ ] Content reflows without two-dimensional scrolling at relevant narrow widths, except where inherently necessary.
* [ ] Text spacing overrides do not break content.
* [ ] Focus indicators have sufficient visibility.
* [ ] Touch targets meet the WCAG target-size requirement or a valid exception.
* [ ] Motion can be reduced.
* [ ] Flashing content is avoided or remains within safe thresholds.
* [ ] Zooming is not disabled.

WCAG 2.2 specifies 4.5:1 contrast for normal text and 3:1 for large text at Level AA. ([W3C][2])

## Images, audio, video, and charts

* [ ] Informative images have useful alternatives.
* [ ] Decorative images are hidden from assistive technology.
* [ ] Complex diagrams and charts have equivalent text or data.
* [ ] Prerecorded audio and video have captions or required alternatives.
* [ ] Audio description is provided where visual information is otherwise unavailable.
* [ ] Autoplaying sound can be stopped or controlled.
* [ ] Media controls are keyboard and screen-reader accessible.
* [ ] CAPTCHA has an accessible alternative.

## Dynamic applications

* [ ] Route changes announce the new page or context.
* [ ] Loading, success, failure, and background updates are announced appropriately.
* [ ] Toasts remain available long enough and do not contain the only copy of essential information.
* [ ] Infinite scrolling does not make navigation or content recovery impossible.
* [ ] Virtualized content retains accessible semantics.
* [ ] Screen-reader testing covers at least the critical flows.
* [ ] Automated accessibility scans run, but manual keyboard, zoom, contrast, and assistive-technology testing also occurs.

---

# 19. Browser, device, and responsive compatibility

## Support policy

* [ ] Supported browsers and minimum versions are documented.
* [ ] The policy reflects actual users, contracts, and business requirements.
* [ ] Desktop and mobile browsers are addressed separately.
* [ ] Embedded webviews are included where applicable.
* [ ] Unsupported browsers receive an understandable message only when necessary.
* [ ] Progressive enhancement or fallbacks exist for limited-availability APIs.
* [ ] Polyfills are maintained and loaded only where needed.

## Test matrix

Test representative versions of:

* Chrome desktop and Android.
* Safari macOS and iOS.
* Edge desktop.
* Firefox desktop and Android where material.
* Relevant in-app or embedded browsers.
* Touch-only and keyboard/mouse environments.

Audit:

* [ ] Layouts work from narrow mobile widths through large monitors.
* [ ] Portrait and landscape work where applicable.
* [ ] Notches and safe-area insets are handled.
* [ ] On-screen keyboards do not obscure focused controls.
* [ ] Hover-dependent behavior has touch alternatives.
* [ ] Pointer precision assumptions are appropriate.
* [ ] Browser zoom and operating-system scaling work.
* [ ] Browser autofill and password managers work.
* [ ] Cookie and storage restrictions do not break critical flows unexpectedly.
* [ ] Private-browsing behavior is acceptable.
* [ ] Tracking blockers do not disable core product functionality unnecessarily.
* [ ] Pop-up, clipboard, media, notification, and file APIs handle permission denial.
* [ ] Download and upload behavior works across supported platforms.
* [ ] Printing and PDF output work where offered.
* [ ] Hardware acceleration failures have a fallback where needed.
* [ ] Reduced-motion, dark-mode, and high-contrast preferences are respected where supported.
* [ ] Slow CPU, low memory, and unreliable network conditions are represented in testing.

---

# 20. SEO and discoverability

This section primarily applies to public content. Authenticated application pages should normally be excluded from indexing and protected by authentication.

## Crawlability and indexability

* [ ] Production does not retain staging `noindex` directives.
* [ ] Staging and confidential environments are password-protected or otherwise access-controlled.
* [ ] Intended public pages return `200`.
* [ ] Permanent redirects use an appropriate permanent status.
* [ ] Removed pages return `404` or `410` rather than misleading soft-404 content.
* [ ] Server errors return proper `5xx` statuses.
* [ ] Important content is present in rendered HTML that crawlers can process.
* [ ] Robots directives match intended indexing behavior.
* [ ] XML sitemaps contain canonical, indexable URLs.
* [ ] Sitemap generation updates automatically.
* [ ] Sitemap errors are monitored.
* [ ] Canonical URLs are self-consistent.
* [ ] HTTP/HTTPS, `www`/non-`www`, trailing slash, case, and parameter variants consolidate correctly.
* [ ] Pagination and faceted-navigation behavior do not create uncontrolled duplicate URL spaces.
* [ ] Search-result, filter, account, checkout, and internal utility pages are excluded where appropriate.

`robots.txt` controls crawler access; it is not a reliable mechanism for keeping a page out of search results. Confidential pages should be access-controlled, while intended non-indexed pages should use supported indexing directives. ([Google for Developers][13])

## On-page SEO

* [ ] Each indexable page has a unique, descriptive title.
* [ ] Meta descriptions are useful and page-specific.
* [ ] One clear primary heading describes the page.
* [ ] Heading hierarchy reflects document structure.
* [ ] URLs are stable, readable, and not unnecessarily parameterized.
* [ ] Internal links use descriptive anchor text.
* [ ] Important pages are reachable through normal internal navigation.
* [ ] Images have meaningful alt text where they convey content.
* [ ] Content directly answers the likely user intent.
* [ ] Pages do not consist mainly of generic, duplicated, or templated filler.
* [ ] Product and comparison claims are specific and supported.
* [ ] Author, organization, contact, and policy information provide appropriate trust signals.
* [ ] Structured data matches visible content and validates.
* [ ] Breadcrumbs are correct where used.
* [ ] International pages use correct locale signals and `hreflang` where applicable.
* [ ] Social-preview metadata produces correct titles, descriptions, and images.
* [ ] Broken links, redirect chains, and orphan pages are removed.
* [ ] Public performance meets the defined Core Web Vitals targets.

## Search operations

* [ ] Search Console or equivalent webmaster tooling is configured.
* [ ] Ownership is verified through an organizational account.
* [ ] Coverage, indexing, structured-data, and security issues are monitored.
* [ ] Crawl errors and unexpected indexed URLs are reviewed.
* [ ] Canonical selection is checked for key pages.
* [ ] Sitemap processing is reviewed after deployment.
* [ ] Analytics distinguish organic landing pages and conversions.
* [ ] Site migrations have URL maps and redirect validation.
* [ ] SEO-critical metadata has automated regression tests.

Google treats sitemaps as a discovery hint rather than a guarantee of crawling or indexing, and canonical signals must be internally consistent. ([Google for Developers][14])

---

# 21. Privacy, compliance, and legal readiness

Exact requirements depend on user location, business location, industry, data categories, contracts, and product behavior. Engineering should document implementation accurately and obtain jurisdiction-specific legal review where required; security standards do not replace that review. ([GitHub][15])

## Data governance

* [ ] A data inventory identifies personal, sensitive, confidential, and public data.
* [ ] Every collected field has a documented purpose.
* [ ] Collection is minimized.
* [ ] Data-sharing destinations are documented.
* [ ] Subprocessors and third-party SDKs are inventoried.
* [ ] Data residency and cross-border processing match commitments.
* [ ] Retention periods exist for primary data, logs, analytics, backups, support records, and derived data.
* [ ] Deletion mechanisms enforce those periods.
* [ ] User export, correction, restriction, and deletion workflows exist where required.
* [ ] Consent or preference records are auditable where applicable.
* [ ] Changes to policy or consent are versioned.
* [ ] Production data is not copied casually into development systems.
* [ ] Access to personal data is least-privileged and audited.
* [ ] Incident-response procedures include privacy and notification assessment.

## Policies and user controls

* [ ] The privacy policy describes actual current behavior.
* [ ] Terms of service reflect the current product and payment model.
* [ ] Cookie and tracking disclosures match deployed scripts.
* [ ] Consent choices are respected technically, not merely displayed.
* [ ] Withdrawing consent has a real effect.
* [ ] Non-essential tracking does not start prematurely where consent is required.
* [ ] User choices persist appropriately.
* [ ] “Reject” is not made materially harder than “accept” where equivalent choice is required.
* [ ] Marketing communication has appropriate opt-in or opt-out behavior.
* [ ] Unsubscribe links work promptly.
* [ ] Account deletion and subscription cancellation are discoverable.
* [ ] User-generated public content and privacy expectations are clear.
* [ ] AI training, model-provider use, or human review of user data is disclosed where relevant.
* [ ] Session replay and support-screen capture exclude sensitive fields.

## Legal and intellectual property

* [ ] Open-source licenses are inventoried and obligations are satisfied.
* [ ] Required notices and attributions are included.
* [ ] Fonts, images, icons, music, video, and datasets are licensed.
* [ ] Product names and claims do not create known trademark issues.
* [ ] User-uploaded content terms address ownership and permitted processing.
* [ ] Takedown and abuse-reporting procedures exist where relevant.
* [ ] Pricing, renewal, refund, trial, and cancellation representations match implementation.
* [ ] Accessibility, consumer, sector, and age-related obligations have been reviewed where relevant.
* [ ] Public security or compliance claims are supported by evidence.

---

# 22. Internationalization and localization

* [ ] Text is externalized from application logic.
* [ ] UI is tested with longer translations.
* [ ] Right-to-left layouts are supported if required.
* [ ] Unicode is handled end to end.
* [ ] User names are not constrained to inappropriate Western assumptions.
* [ ] Address, telephone, postal-code, and personal-name formats are locale-aware.
* [ ] Dates, times, time zones, daylight-saving transitions, and calendars are handled correctly.
* [ ] Numbers, decimal separators, and grouping are locale-aware.
* [ ] Currency values use correct precision and display.
* [ ] Currency conversion and exchange-rate timestamps are explicit where applicable.
* [ ] Pluralization uses locale-aware rules.
* [ ] String concatenation does not make translation grammatically impossible.
* [ ] Search and sorting use appropriate collation.
* [ ] Character limits account for multi-byte and grapheme behavior.
* [ ] Generated documents, email, notifications, and exports use the correct locale.
* [ ] Missing translations fall back safely.
* [ ] Translated public pages have appropriate canonical and locale metadata.
* [ ] Accessibility labels are translated.
* [ ] Legal copy can vary by jurisdiction where required.

---

# 23. Third-party integrations

For every external service:

* [ ] The business purpose is documented.
* [ ] Data sent and received is documented.
* [ ] Authentication scopes are minimal.
* [ ] Development and production credentials are separate.
* [ ] Secrets can be rotated.
* [ ] Requests have timeouts.
* [ ] Retries are bounded and safe.
* [ ] Rate and usage limits are known.
* [ ] Provider failures produce graceful behavior.
* [ ] Provider API versions are monitored.
* [ ] Deprecation notices have an owner.
* [ ] Responses and webhook payloads are validated.
* [ ] Duplicate, late, missing, and out-of-order events are handled.
* [ ] Integration health is observable.
* [ ] Costs and quota consumption are observable.
* [ ] Provider outage and account suspension procedures exist.
* [ ] Data-processing and subprocessor implications are documented.
* [ ] A replacement or degradation strategy exists for critical providers.

---

# 24. Email, SMS, push, and notifications

## Email infrastructure

* [ ] Sending domains are authenticated with SPF, DKIM, and an appropriate DMARC policy.
* [ ] Return-path and reply-to behavior is correct.
* [ ] Sender identity is recognizable.
* [ ] Transactional and marketing communication are classified correctly.
* [ ] Bounce and complaint handling exists.
* [ ] Unsubscribe behavior works.
* [ ] Suppression lists are respected.
* [ ] Email links point to the correct production domain.
* [ ] Reset and verification tokens expire and are single-use.
* [ ] Sensitive information is not unnecessarily placed in email.
* [ ] HTML email has a usable plain-text equivalent.
* [ ] Templates render correctly in representative clients.
* [ ] Delivery failures are retried without duplication.
* [ ] Email volume cannot be abused to create cost or harassment.

## Notifications

* [ ] User preferences are respected.
* [ ] Notification events are deduplicated.
* [ ] Notification order is sensible.
* [ ] Quiet hours and locale/time-zone behavior are correct where applicable.
* [ ] Sensitive notification content is suitable for lock screens.
* [ ] Push permission is requested in context rather than immediately.
* [ ] Permission denial does not break core functionality.
* [ ] Device-token lifecycle and invalidation are handled.
* [ ] Links inside notifications route correctly after login.
* [ ] Notification delivery and click-through are measured without collecting unnecessary personal data.

---

# 25. Payments, billing, and commerce

Where applicable:

* [ ] Card or payment data is delegated to an appropriate payment provider wherever possible.
* [ ] The application does not expand its payment-security scope unnecessarily.
* [ ] Product IDs, prices, discounts, taxes, and totals are calculated and validated server side.
* [ ] Currency and minor-unit handling are correct.
* [ ] Rounding is deterministic.
* [ ] Payment creation uses idempotency.
* [ ] Duplicate browser submissions cannot create duplicate charges.
* [ ] Payment-provider webhooks are signed and replay-protected.
* [ ] Entitlements are based on verified payment state, not a client redirect.
* [ ] Delayed and out-of-order provider events are handled.
* [ ] Payment success with entitlement failure is reconciled.
* [ ] Entitlement success with payment failure is reconciled.
* [ ] Refunds, partial refunds, chargebacks, disputes, and reversals are modeled.
* [ ] Subscription upgrade, downgrade, proration, renewal, grace, cancellation, and expiry behavior is tested.
* [ ] Free trials cannot be trivially replayed.
* [ ] Invoices and receipts contain correct business information.
* [ ] Taxes and location handling have been reviewed.
* [ ] Failed-payment communication is accurate.
* [ ] Administrative refund and entitlement tools are audited.
* [ ] Daily or periodic financial reconciliation exists.
* [ ] Fraud and velocity controls exist where required.
* [ ] Payment-provider outage behavior is safe.
* [ ] Payment secrets and dashboards have strong access controls.

---

# 26. Analytics, product telemetry, and experimentation

## Analytics implementation

* [ ] An event taxonomy exists.
* [ ] Event names and properties are documented.
* [ ] Events represent business outcomes rather than arbitrary clicks alone.
* [ ] SPA navigation is tracked correctly.
* [ ] Duplicate page views and conversions are prevented.
* [ ] Anonymous-to-authenticated identity merging is deliberate.
* [ ] Tenant and user identifiers are pseudonymous where possible.
* [ ] Sensitive information and free-form user content are excluded.
* [ ] Consent and privacy preferences are respected.
* [ ] Internal staff, bots, tests, and preview traffic are identifiable or excluded.
* [ ] UTM and attribution behavior is documented.
* [ ] Key funnel events are validated in production.
* [ ] Analytics failure cannot break the product.
* [ ] Event delivery has reasonable retry and offline behavior.
* [ ] Data retention is defined.
* [ ] Deletion requests propagate where required.
* [ ] Dashboards have owners and definitions.

## Experiments and flags

* [ ] Feature flags have owners and expiry dates.
* [ ] Old flags are removed.
* [ ] Flag evaluation failure has a safe default.
* [ ] Server and client see consistent variants where required.
* [ ] Experiment assignment is stable.
* [ ] Eligibility rules are documented.
* [ ] Guardrail metrics cover reliability, support, security, and revenue impact.
* [ ] Experiments do not violate consent or accessibility requirements.
* [ ] Emergency disablement is possible.
* [ ] Rollout percentages and audience targeting are auditable.
* [ ] Deployment and experiment changes are distinguishable in metrics.

---

# 27. CI/CD, deployment, and release engineering

## Pipeline

* [ ] Every production change passes through the controlled pipeline.
* [ ] Required checks run against the release commit.
* [ ] The tested artifact is the deployed artifact.
* [ ] Deployment environments require appropriate authorization.
* [ ] Deployment credentials are short-lived or tightly scoped.
* [ ] Secrets are not exposed to untrusted jobs.
* [ ] Infrastructure and application changes are coordinated.
* [ ] Deployment logs identify actor, artifact, configuration, and time.
* [ ] Releases are reproducible.
* [ ] A failed deployment stops automatically.
* [ ] Partial deployment is detected.
* [ ] Post-deployment smoke tests run automatically.
* [ ] Deployment markers enter observability systems.
* [ ] Release notes identify material user and operational changes.
* [ ] Database migrations have a separately visible result.

## Rollout strategy

* [ ] The rollout strategy is appropriate: all-at-once, rolling, canary, blue-green, or feature-flagged.
* [ ] Health criteria determine whether rollout continues.
* [ ] Canary traffic is representative enough to detect relevant failures.
* [ ] Metrics are compared against the previous version.
* [ ] Rollout can pause automatically or manually.
* [ ] Feature flags can separate code deployment from user exposure.
* [ ] Incompatible old and new application versions cannot run simultaneously.
* [ ] Background workers and web processes are deployed in a safe order.
* [ ] Long-running jobs are version-compatible.
* [ ] CDN and service-worker cache invalidation are included.
* [ ] Launch traffic and external campaigns are coordinated with capacity.

## Rollback and roll-forward

* [ ] Application rollback has been tested.
* [ ] Rollback time is within the operational requirement.
* [ ] The previous artifact remains available.
* [ ] Configuration rollback is supported.
* [ ] Feature disablement is faster than a full rollback where appropriate.
* [ ] Database changes are backward compatible or have a safe roll-forward strategy.
* [ ] Destructive data migrations are not assumed to be trivially reversible.
* [ ] Queued messages from a newer version will not break an older version.
* [ ] Rollback does not create duplicate transactions.
* [ ] Rollback ownership and authority are clear.
* [ ] User communication criteria exist for failed launches.

---

# 28. Backup, restoration, and disaster recovery

A backup that has not been restored successfully is not adequate release evidence.

## Backup coverage

* [ ] Every stateful production component is covered.
* [ ] Databases are backed up.
* [ ] Object storage and uploaded files are covered.
* [ ] Search indexes are reproducible or backed up appropriately.
* [ ] Configuration, secrets metadata, and infrastructure definitions are recoverable.
* [ ] Encryption keys have an independent recovery procedure.
* [ ] Backups are encrypted.
* [ ] Backup access is separated from ordinary production access.
* [ ] Backup deletion or tampering is constrained.
* [ ] Retention matches business and legal requirements.
* [ ] Cross-region or independent-location copies exist where risk warrants it.
* [ ] Backup jobs are monitored and alert on failure.

## Restoration

* [ ] Restoration has been tested recently.
* [ ] Restore tests use an isolated environment.
* [ ] Data integrity is validated after restoration.
* [ ] Application versions required to read restored data remain available.
* [ ] Point-in-time recovery is tested where supported.
* [ ] Partial restoration is understood.
* [ ] File and database restoration remain mutually consistent.
* [ ] Restoration runbooks include permissions, DNS, secrets, and third parties.
* [ ] Recovery time objective is measured.
* [ ] Recovery point objective is measured.
* [ ] Restoration does not overwrite the only good copy.
* [ ] Responsible operators can perform the procedure without undocumented knowledge.

## Disaster recovery

* [ ] Credible disaster scenarios are documented.
* [ ] Regional, account, credential, ransomware, accidental deletion, and provider-failure scenarios are considered.
* [ ] Recovery priorities are defined.
* [ ] Dependencies required during recovery are known.
* [ ] DNS and certificate changes are included.
* [ ] A disaster-recovery exercise has been performed.
* [ ] Customer and internal communication plans exist.
* [ ] The system can operate in a degraded mode where appropriate.
* [ ] Reconciliation procedures exist after restoration.

---

# 29. Operational readiness, support, and incident response

## Ownership

* [ ] Every production service has an owner.
* [ ] Every alert has an owner.
* [ ] On-call or escalation coverage matches business expectations.
* [ ] Vendor escalation contacts are recorded.
* [ ] Domain, certificate, cloud, payment, and email account owners are identified.
* [ ] Access does not depend on one employee’s personal account.
* [ ] Critical-account recovery methods are controlled and current.

## Runbooks

Runbooks should cover at least:

* Elevated errors.
* High latency.
* Database saturation.
* Queue backlog.
* Failed migrations.
* Authentication outage.
* Payment inconsistency.
* Email or notification outage.
* Object-storage failure.
* Certificate or DNS problem.
* Security incident.
* Data corruption.
* Backup restoration.
* Rollback.
* Third-party quota exhaustion.
* Unexpected cost spike.

Each runbook should include:

* Symptoms.
* Verification queries and dashboards.
* Immediate containment.
* Recovery steps.
* Rollback or kill switch.
* Escalation.
* User communication criteria.
* Post-incident reconciliation.

## Incident response

* [ ] Severity definitions exist.
* [ ] Incident commander and communication roles are defined.
* [ ] A secure incident channel and documentation method exist.
* [ ] Security, privacy, legal, and customer-support escalation paths exist.
* [ ] Evidence preservation is understood.
* [ ] Credential revocation and secret rotation can be performed quickly.
* [ ] Affected-user identification is possible.
* [ ] Status-page and customer-notification procedures exist.
* [ ] Post-incident reviews assign actions and owners.
* [ ] Incident exercises have been performed.
* [ ] Support staff cannot bypass identity verification casually.
* [ ] Support account-recovery procedures resist social engineering.
* [ ] Administrative data corrections are auditable and reversible where possible.

## Launch support

* [ ] Launch monitoring coverage is scheduled.
* [ ] Engineering, support, product, and operations know the launch time.
* [ ] Known issues and workarounds are documented.
* [ ] Customer-facing documentation is published.
* [ ] Support macros and escalation paths are prepared.
* [ ] Status page and incident contacts are ready.
* [ ] High-risk changes have a designated observation period.
* [ ] Launch success and abort criteria are explicit.

---

# 30. Cost, quotas, and operational economics

* [ ] Baseline monthly and per-user cost are estimated.
* [ ] Cost under expected peak traffic is estimated.
* [ ] Cost under retries, dependency failure, and abuse is estimated.
* [ ] Compute, database, storage, egress, logs, CDN, email, SMS, AI, media processing, and third-party API costs are included.
* [ ] Unit cost per request, job, document, minute, user, or tenant is measurable.
* [ ] Budgets and anomaly alerts are configured.
* [ ] Provider spending limits and quotas are understood.
* [ ] Log and trace retention will not grow without bound.
* [ ] User uploads have quotas and lifecycle rules.
* [ ] Background jobs have concurrency and cost caps.
* [ ] Serverless or autoscaling workloads have maximum limits.
* [ ] Expensive endpoints have rate and resource controls.
* [ ] Cache strategy considers both latency and cost.
* [ ] Data transfer between regions and providers is understood.
* [ ] Large customers cannot create negative unit economics unknowingly.
* [ ] Trial and free-tier abuse is constrained.
* [ ] Emergency cost-control switches exist.
* [ ] Cost attribution by environment, service, and tenant is available where useful.
* [ ] Decommissioned resources are removed promptly.

---

# 31. Conditional module: AI-enabled web applications

Where the application contains chat, generation, retrieval, agents, tools, code execution, or model-driven automation:

## Data and model boundaries

* [ ] User data sent to model providers is documented.
* [ ] Provider retention and training settings match product promises.
* [ ] Sensitive data is redacted or excluded.
* [ ] Tenant data cannot enter another tenant’s prompt, retrieval results, cache, memory, trace, or evaluation dataset.
* [ ] Retrieval applies authorization before returning documents to the model.
* [ ] Embeddings and vector-store records retain tenant and access-control metadata.
* [ ] Model and embedding versions are recorded.
* [ ] Model upgrades run against regression evaluations before rollout.

## Prompt injection and tool use

* [ ] External content is treated as untrusted instructions.
* [ ] A system prompt is not treated as an authorization boundary.
* [ ] Tool execution performs server-side user authorization at execution time.
* [ ] Tools expose the minimum required capability.
* [ ] High-impact actions require explicit confirmation or human approval.
* [ ] File, shell, browser, email, payment, and repository tools are sandboxed appropriately.
* [ ] Model output is validated before use as SQL, code, HTML, URLs, commands, or structured actions.
* [ ] Secrets are not inserted into model context unless strictly necessary and constrained.
* [ ] Tool results cannot inject new privileged actions without validation.
* [ ] Recursive agent activity has depth, time, token, and cost limits.
* [ ] The agent cannot silently expand its own permissions.
* [ ] All consequential actions have an audit trail.

## Product behavior

* [ ] The interface distinguishes generated content from verified facts where material.
* [ ] High-stakes results have appropriate review or validation.
* [ ] Hallucination and partial-failure states are handled.
* [ ] Structured-output parsing fails safely.
* [ ] Model refusal and provider outage have usable fallbacks.
* [ ] Prompt and output logs redact sensitive data.
* [ ] Rate, token, and monetary limits exist.
* [ ] Abuse and content-safety controls match the product.
* [ ] Evaluations cover quality, safety, security, latency, and cost.
* [ ] Release gates detect regressions across representative tasks.
* [ ] Users can delete model conversation history according to policy.
* [ ] Human review and feedback collection are disclosed where applicable.

---

# 32. Conditional module: PWA and offline behavior

* [ ] Manifest metadata, icons, names, and start URL are correct.
* [ ] Service-worker scope is no broader than intended.
* [ ] Cache names and versions are controlled.
* [ ] Application updates do not leave incompatible mixed asset versions.
* [ ] Users can recover from a stale or broken service worker.
* [ ] Authenticated sensitive responses are not persisted in public caches.
* [ ] Logout clears sensitive offline state.
* [ ] Tenant switching clears tenant-specific caches.
* [ ] Offline submissions are idempotent.
* [ ] Background sync cannot duplicate destructive operations.
* [ ] Offline UI distinguishes saved locally from saved remotely.
* [ ] Conflict resolution is defined.
* [ ] Notification permission is requested contextually.
* [ ] Install prompts are not assumed to work identically across browsers.
* [ ] Application behavior remains usable where installation APIs are unavailable.
* [ ] Storage eviction and quota failure are handled.

Some PWA-related browser APIs remain unavailable in parts of the major-browser set, so install and permission flows must be capability-tested rather than assumed. ([MDN Web Docs][16])

---

# 33. Conditional module: user-generated content and communities

* [ ] Content creation is rate-limited.
* [ ] Spam and automation controls exist.
* [ ] Public/private visibility rules are unambiguous.
* [ ] Users cannot publish another user’s private content through reference manipulation.
* [ ] HTML, Markdown, links, images, and attachments are sanitized.
* [ ] External links receive appropriate treatment.
* [ ] Abuse reporting is available.
* [ ] Moderation tools are permissioned and audited.
* [ ] Takedown and appeal workflows exist where needed.
* [ ] Block, mute, privacy, and deletion behavior is tested.
* [ ] Search indexing respects content visibility and deletion.
* [ ] Deleted content is removed from caches and indexes.
* [ ] Notification and mention abuse is limited.
* [ ] Moderators cannot access more personal data than necessary.
* [ ] Public profile defaults and discoverability are deliberate.
* [ ] Content-retention and account-deletion behavior are disclosed.

---

# Final release gates

## Automatic no-go conditions

A release should ordinarily be blocked when any of the following remains unresolved:

* An exploitable authentication or authorization defect.
* Cross-user or cross-tenant data access.
* Exposed secrets, credentials, or private storage.
* A known critical dependency or infrastructure vulnerability without a credible compensating control.
* Data corruption or irreversible data-loss risk.
* An untested destructive migration.
* Inability to restore critical data.
* A broken core user journey.
* Duplicate charging, incorrect entitlement, or unreconciled financial state.
* No safe rollback, roll-forward, or feature-disable path for a high-risk change.
* No production logging, monitoring, or ownership for the critical service.
* Expected launch load exceeds demonstrated capacity.
* Unbounded resource or third-party cost exposure.
* A core journey that cannot be completed by keyboard or required assistive technology.
* Privacy or security behavior that contradicts published claims.
* Production accidentally blocked from indexing when organic discovery is launch-critical.
* Confidential or staging content accidentally indexable or publicly accessible.
* Missing legal, payment, or account ownership required to operate the service.
* A critical alert or incident-response path that has never been tested.

## Conditional release with accepted risk

A non-blocking unresolved issue should have:

* Written impact and likelihood.
* A named accountable owner.
* A compensating control.
* User or operational workaround.
* Remediation date.
* Risk-acceptance authority.
* Expiry date.
* Monitoring that detects deterioration.
* A linked regression test or verification plan.

---

# Minimum release evidence pack

A senior engineer signing off a release should expect to see:

1. The exact release commit, artifact, configuration, and environment.
2. Current architecture, deployment, and sensitive-data-flow diagrams.
3. Critical user-journey test results.
4. Security threat model and ASVS coverage or equivalent control matrix.
5. SAST, dependency, secret, infrastructure, and dynamic scan results.
6. Manual authorization and business-logic test results.
7. Frontend and backend performance reports.
8. Load, spike, soak, and capacity results.
9. Accessibility report with manual keyboard and assistive-technology testing.
10. Browser and device compatibility matrix.
11. Database migration timing and rollback or roll-forward plan.
12. Backup and successful restoration evidence.
13. SBOM, build provenance, and artifact identity.
14. Production dashboards, alerts, and alert-delivery test.
15. Runbooks, escalation paths, and incident ownership.
16. Privacy/data inventory and third-party processor inventory.
17. SEO crawl/index validation for public pages.
18. Launch, canary, rollback, and user-communication plans.
19. Open-risk register with owners and expiry dates.
20. Formal go/no-go decision record.

A useful audit tracker schema is:

`ID | Area | Requirement | Applies? | Evidence | Result | Severity | Owner | Remediation | Retest | Risk exception | Exception expiry`

The key distinction is evidence. “Implemented,” “should work,” “the framework handles that,” and “the scanner found nothing” are not release evidence.

[1]: https://owasp.org/www-project-application-security-verification-standard/?utm_source=chatgpt.com "OWASP Application Security Verification Standard (ASVS)"
[2]: https://www.w3.org/TR/WCAG22/?utm_source=chatgpt.com "Web Content Accessibility Guidelines (WCAG) 2.2"
[3]: https://web.dev/articles/vitals?utm_source=chatgpt.com "Web Vitals | Articles"
[4]: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-218.pdf "Secure Software Development Framework (SSDF) Version 1.1: Recommendations for Mitigating the Risk of Software Vulnerabilities"
[5]: https://developer.mozilla.org/en-US/docs/Glossary/Baseline/Compatibility?utm_source=chatgpt.com "Baseline (compatibility) - Glossary - MDN Web Docs"
[6]: https://developers.google.com/search/docs/fundamentals/seo-starter-guide?utm_source=chatgpt.com "Search Engine Optimization (SEO) Starter Guide"
[7]: https://owasp.org/Top10/2025/0x00_2025-Introduction/?utm_source=chatgpt.com "Introduction - OWASP Top 10:2025"
[8]: https://owasp.org/www-project-api-security/?utm_source=chatgpt.com "OWASP API Security Project"
[9]: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html?utm_source=chatgpt.com "HTTP Security Response Headers Cheat Sheet"
[10]: https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/?utm_source=chatgpt.com "A10:2025 Mishandling of Exceptional Conditions ..."
[11]: https://slsa.dev/spec/v1.2/build-track-basics?utm_source=chatgpt.com "Build: Track Basics"
[12]: https://opentelemetry.io/docs/?utm_source=chatgpt.com "Documentation"
[13]: https://developers.google.com/search/docs/crawling-indexing/robots/intro?utm_source=chatgpt.com "Robots.txt Introduction and Guide | Google Search Central"
[14]: https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap?utm_source=chatgpt.com "Build and Submit a Sitemap | Google Search Central"
[15]: https://github.com/OWASP/ASVS/blob/master/5.0/en/0x23-V14-Data-Protection.md?utm_source=chatgpt.com "0x23-V14-Data-Protection.md - ASVS"
[16]: https://developer.mozilla.org/en-US/docs/Web/API/Window/beforeinstallprompt_event?utm_source=chatgpt.com "Window: beforeinstallprompt event - Web APIs - MDN Web Docs"

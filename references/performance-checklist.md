# Full-Stack Performance Checklist (audit · performance lens)

Detection + remediation cues for the `performance` lens beyond the FRONTEND
re-render smell + runtime keystroke pass. Covers the server side the static lens is
blind to: database (N+1 / indexing), network waterfalls, caching strategy,
bundle/assets, backend, and Core Web Vitals. Every finding needs a real `file:line`
or a measured locus. Source: vibecoder performance-audit.

### 1. Eliminate unnecessary component re-renders
*Area: Frontend Rendering & Re-render Control. Why it matters: Components that redraw when nothing they show has changed waste device power and make the interface feel sluggish, especially on phones.*

Scan my frontend for components that re-render more often than their displayed data actually changes. Wrap pure presentational components in a memoization boundary (such as React.memo or the framework equivalent) and confirm their props are referentially stable so the memoization actually takes effect. Pay special attention to components rendered inside loops or lists. After the change, verify nothing renders incorrectly and that the components now skip renders when their inputs are unchanged.

### 2. Memoize expensive computed values
*Area: Frontend Rendering & Re-render Control. Why it matters: Recalculating the same heavy result on every screen update burns time the browser could spend keeping things smooth.*

Find any place in my UI where a costly calculation (sorting, filtering, mapping large arrays, formatting, or derived aggregates) runs directly inside a component body on every render. Move each one into a memoized value keyed only on the specific inputs it depends on, so it recomputes solely when those inputs change. Double-check the dependency list is complete and correct to avoid stale results. Confirm the visible output is identical before and after.

### 3. Stabilize callbacks passed to children
*Area: Frontend Rendering & Re-render Control. Why it matters: Recreating functions on every render quietly forces child components to redraw, undoing other speed work you've done.*

Identify functions that are recreated on each render and passed down as props to child components or used as effect dependencies. Wrap them so their identity stays stable across renders unless their real dependencies change, and make sure those dependencies are listed correctly. Be careful not to capture stale values inside the stabilized function. After the change, verify the children stop re-rendering unnecessarily and behavior is unchanged.

### 4. Split bloated global state
*Area: Frontend Rendering & Re-render Control. Why it matters: When unrelated data lives in one big shared store, changing any part of it can re-render large chunks of your whole app.*

Review how global/shared state is structured in my app and find cases where a single store or context bundles unrelated concerns together. Split it so that consumers subscribe only to the specific slice they actually use, preventing unrelated updates from triggering broad re-renders. Where a context provider holds a large object, separate frequently-changing values from stable ones. Verify that updating one slice no longer re-renders components that don't depend on it.

### 5. Virtualize long scrolling lists
*Area: Frontend Rendering & Re-render Control. Why it matters: Rendering thousands of rows at once freezes the page; only the rows on screen need to exist.*

Locate any list, table, or feed in my app that can grow to hundreds or thousands of items and currently renders them all at once. Introduce list virtualization (windowing) so only the visible rows plus a small buffer are mounted in the DOM at any time. Preserve correct scroll height, keyboard navigation, and item sizing, including variable-height rows if present. Test with a large dataset and confirm scrolling stays smooth and memory use drops.

### 6. Debounce text input and search
*Area: Frontend Rendering & Re-render Control. Why it matters: Firing a search or filter on every keystroke hammers your server and makes typing feel laggy.*

Find input fields that trigger expensive work on every keystroke, such as live search, filtering, or autosave. Add debouncing so the action runs only after the user pauses typing for a sensible interval (around 250–400ms), and cancel any in-flight work that's been superseded. Keep the input itself fully responsive while debouncing only the downstream effect. Verify the expensive action now fires far less often without feeling unresponsive.

### 7. Throttle scroll and resize handlers
*Area: Frontend Rendering & Re-render Control. Why it matters: Scroll and resize events fire dozens of times per second, and heavy handlers on them stutter the page.*

Search for scroll, resize, mousemove, or similar high-frequency event handlers that run non-trivial logic on each event. Throttle them so they execute at most a few times per second, or better, route the work through requestAnimationFrame so it aligns with the browser's paint cycle. Ensure the handlers are also cleaned up properly when components unmount. Confirm the page stays smooth during fast scrolling and resizing.

### 8. Batch related state updates
*Area: Frontend Rendering & Re-render Control. Why it matters: Triggering several separate updates in a row can make the screen redraw multiple times when once would do.*

Look for places where multiple state updates happen in sequence within the same event or async callback, causing several render passes. Consolidate them so related changes are applied together in a single update, using your framework's batching mechanism or by combining the values into one state change. Pay attention to updates that span an await boundary, which often escape automatic batching. Verify the same final UI is produced with fewer render cycles.

### 9. Replace scroll listeners with observers
*Area: Frontend Rendering & Re-render Control. Why it matters: Watching elements via constant scroll math is wasteful; the browser can notify you only when visibility actually changes.*

Find code that uses scroll position math to detect when elements enter the viewport, become sticky, or should lazy-load. Replace it with IntersectionObserver so the browser efficiently reports visibility changes instead of you recalculating on every scroll event. Configure appropriate root margins and thresholds for the behavior you need, and disconnect observers on cleanup. Confirm the visibility-triggered behavior still fires at the right moments.

### 10. Move heavy computation to Web Workers
*Area: Frontend Rendering & Re-render Control. Why it matters: Big calculations on the main thread freeze the entire interface until they finish; a worker keeps the page alive.*

Identify any CPU-intensive work running on the main thread, such as parsing large files, image processing, heavy data transforms, or cryptography, that visibly blocks the UI. Move that work into a Web Worker so the main thread stays free to handle rendering and input. Pass data in and out via messages, and show a loading state while the worker runs. Verify the interface remains responsive during the computation and results come back correctly.

### 11. Break up long main-thread tasks
*Area: Frontend Rendering & Re-render Control. Why it matters: Any single task over ~50ms makes the page unresponsive to taps and clicks during that window.*

Profile my app for long tasks (over ~50ms) that block interaction, then locate the loops or synchronous routines responsible. Break them into smaller chunks that yield back to the browser between batches (using techniques like chunked processing with scheduling APIs or yielding to the event loop) so input stays responsive. Preserve correctness and final output across the chunked execution. Confirm the long tasks are gone and the app responds quickly during the work.

### 12. Memoize list items and stabilize keys
*Area: Frontend Rendering & Re-render Control. Why it matters: Without stable identity, lists re-render every row on any change, and unstable keys cause flicker and lost state.*

Examine how I render lists and verify each item uses a stable, unique key tied to its data identity rather than its array index. Memoize the individual item component so unchanged rows skip re-rendering when the list updates. Ensure props passed to each item are referentially stable. Test by updating, adding, and removing items, confirming only affected rows re-render and no row state is incorrectly reused.

### 13. Defer rendering offscreen components
*Area: Frontend Rendering & Re-render Control. Why it matters: Mounting heavy sections the user can't see yet slows the initial paint for no benefit.*

Find heavy components that mount immediately but sit offscreen or behind tabs, modals, and accordions the user may never open. Defer their rendering until they're actually needed or about to become visible, so they don't compete with the initial render. Use the framework's content-visibility, conditional mounting, or lazy boundaries as appropriate. Verify the initial view paints faster and deferred content appears correctly when triggered.

### 14. Add skeleton loading placeholders
*Area: Perceived Performance & Loading UX. Why it matters: Blank screens during loading feel broken; placeholders make waits feel shorter and intentional.*

Find views that show nothing (or a bare spinner) while data loads, leaving users staring at emptiness. Add skeleton placeholders that mirror the final layout's shape and size so the page feels alive and doesn't jump when real content arrives. Reserve the same dimensions the loaded content will occupy to avoid layout shift. Confirm the skeleton matches the real layout closely and transitions smoothly to the loaded state.

### 15. Apply optimistic UI updates
*Area: Perceived Performance & Loading UX. Why it matters: Waiting for the server before showing a result makes simple actions feel slow; showing it instantly feels snappy.*

Identify user actions (likes, toggles, adds, edits, deletes) that currently wait for the server response before updating the screen. Make them optimistic: update the UI immediately as if the action succeeded, then reconcile with the server result and roll back gracefully if it fails. Include clear error handling and a visible rollback so users aren't misled. Verify the happy path feels instant and failures restore the correct state.

### 16. Prefetch the next likely route
*Area: Perceived Performance & Loading UX. Why it matters: Loading a page's code and data only after the click adds a visible delay you can hide in advance.*

Determine which navigation paths users most commonly take next from each major screen. Prefetch the code bundle and, where safe, the data for those likely destinations when the user hovers a link or when the current page goes idle, so the next page opens almost instantly. Avoid prefetching on slow connections or data-saver mode. Confirm navigation feels faster without wasting bandwidth on unlikely routes.

### 17. Stream server-rendered HTML progressively
*Area: Perceived Performance & Loading UX. Why it matters: Making users wait for the whole page to assemble before seeing anything wastes time the browser could use.*

If my app renders pages on the server, check whether it buffers the entire response before sending. Switch to streaming so the browser receives and starts rendering the shell and above-the-fold content while slower sections are still being prepared. Use suspense-style boundaries or chunked transfer to flush content progressively. Verify users see meaningful content sooner and the full page still completes correctly.

### 18. Show instant feedback on interactions
*Area: Perceived Performance & Loading UX. Why it matters: A button that does nothing for half a second feels broken, even if the work is happening.*

Audit interactive elements (buttons, form submits, links to async actions) for any that give no immediate visual response when activated. Add instant feedback such as a pressed state, inline spinner, or disabled-with-label state the moment the user acts, before the async work resolves. Prevent duplicate submissions during the pending window. Confirm every interaction acknowledges the user within a frame or two.

### 19. Lazy-load below-the-fold page sections
*Area: Perceived Performance & Loading UX. Why it matters: Building parts of the page the user hasn't scrolled to yet delays everything they can actually see.*

Identify sections, widgets, and embeds that live below the fold and aren't needed for the first paint. Lazy-load them as the user approaches, so initial load only does the work required for what's immediately visible. Trigger loading slightly before they scroll into view to avoid visible pop-in. Verify the above-the-fold experience loads faster and lower sections appear seamlessly on scroll.

### 20. Prioritize above-the-fold content first
*Area: Perceived Performance & Loading UX. Why it matters: When everything loads at equal priority, the important visible stuff competes with things nobody's looking at yet.*

Review the loading order of my main pages and find cases where above-the-fold content competes with offscreen or non-critical resources for bandwidth and CPU. Reorder so the visible hero content, critical CSS, and primary data load first, while deferring or lowering the priority of everything else. Use resource priority hints and defer non-essential fetches. Confirm the first meaningful paint happens noticeably sooner.

### 21. Add route-level loading states
*Area: Perceived Performance & Loading UX. Why it matters: Navigating to a page that hangs silently makes users think the click didn't register.*

Check each route transition in my app for missing or abrupt loading states during navigation and data fetching. Add clear route-level loading indicators that appear immediately on navigation and hand off smoothly to the loaded page, avoiding flashes of empty or stale content. Keep the previous page interactive where possible until the new one is ready. Verify every navigation gives immediate, coherent feedback.

### 22. Preconnect to critical third-party origins
*Area: Perceived Performance & Loading UX. Why it matters: The browser wastes time setting up connections to outside services at the moment it needs them instead of ahead of time.*

List the third-party origins my app must contact early in page load (fonts, analytics, APIs, image CDNs, payment scripts). Add preconnect and dns-prefetch hints for the most critical ones so the DNS, TCP, and TLS handshakes happen ahead of the actual request. Limit this to genuinely critical origins to avoid wasting connections. Confirm the network waterfall shows earlier, faster connections to those origins.

### 23. Reserve space to avoid load shift
*Area: Perceived Performance & Loading UX. Why it matters: Content that pops in and shoves the page around causes misclicks and a janky, cheap feeling.*

Find elements that load asynchronously (images, ads, embeds, dynamically injected banners, late-arriving data) and currently cause the page to jump as they appear. Reserve their final dimensions up front with explicit sizing or aspect-ratio containers so surrounding content doesn't shift when they load. Apply this anywhere content size is known or estimable in advance. Verify the layout stays stable from first paint through full load.

### 24. Render a fast static shell first
*Area: Perceived Performance & Loading UX. Why it matters: Showing the app's frame instantly makes it feel loaded even while data is still arriving.*

Restructure my app's initial load so a lightweight static shell (header, navigation, layout chrome) renders almost immediately, independent of data fetching. Fill in data-dependent regions afterward as their content arrives, rather than blocking the whole page on the slowest request. Ensure the shell is cacheable and doesn't depend on user-specific data. Confirm users perceive the app as loaded within a moment of navigation.

### 25. Convert images to modern formats
*Area: Images, Fonts & Media. Why it matters: Old image formats are far larger than necessary, slowing every page that shows them and costing bandwidth.*

Audit the images my app serves and identify ones still in heavier formats like unoptimized PNG or JPEG. Convert them to modern formats such as WebP or AVIF with appropriate quality settings, and serve them with fallbacks for browsers that need them. Keep the originals as a fallback source where required. Verify image file sizes drop substantially with no visible quality loss and that fallbacks work.

### 26. Serve responsive image sizes
*Area: Images, Fonts & Media. Why it matters: Sending a huge desktop image to a phone wastes data and slows the load for no visual gain.*

Find images that are served at a single large size regardless of the device displaying them. Generate multiple resolutions and serve them with srcset and sizes (or the framework's responsive image component) so each device downloads only the resolution it needs. Account for high-density displays without over-serving. Confirm small screens fetch smaller files and the images stay crisp on every device.

### 27. Lazy-load images below the fold
*Area: Images, Fonts & Media. Why it matters: Downloading images the user hasn't scrolled to competes with the images they're actually looking at.*

Identify images that render below the fold but download eagerly during initial load. Add native lazy-loading (or an IntersectionObserver-based approach) so offscreen images fetch only as the user approaches them, while keeping above-the-fold and LCP images eager. Make sure the most important hero image is never lazy-loaded. Verify initial page weight drops and below-the-fold images still appear smoothly on scroll.

### 28. Compress and right-size large images
*Area: Images, Fonts & Media. Why it matters: Images that are physically larger than their display slot waste megabytes the user pays to download.*

Scan for images whose intrinsic dimensions are much larger than the space they're displayed in, or that are saved at excessive quality. Resize each to roughly the maximum size it's actually rendered at and apply sensible compression so the file matches its display purpose. Preserve enough resolution for high-density screens. Confirm total image payload shrinks significantly with no perceptible quality loss in the layout.

### 29. Set image dimensions to stop shift
*Area: Images, Fonts & Media. Why it matters: Images without declared size cause the page to lurch as they load, jolting whatever the user is reading.*

Find image elements that lack explicit width and height (or an aspect-ratio) and therefore cause layout shift as they load. Add intrinsic dimensions or aspect-ratio styling to every such image so the browser reserves the correct space before the image arrives. Apply this consistently across responsive images too. Verify the layout no longer jumps when images load and your layout-shift metric improves.

### 30. Subset and preload web fonts
*Area: Images, Fonts & Media. Why it matters: Large font files block text from showing and pull in characters your app never uses.*

Review the web fonts my app loads and identify oversized files or unused weights and character sets. Subset the fonts to only the glyphs, weights, and styles actually used, and preload the few that are critical for first paint. Drop any font variants that aren't referenced. Confirm font payload drops and primary text renders sooner without unnecessary downloads.

### 31. Use swap to avoid invisible text
*Area: Images, Fonts & Media. Why it matters: While a custom font loads, text can stay invisible, leaving users staring at a blank page.*

Check how my web fonts handle the loading period and find any that hide text until the font is ready (the invisible-text problem). Apply font-display: swap (or optional) so text renders immediately in a fallback and swaps to the custom font when available. Pair fallbacks with similar metrics to minimize the reflow when swapping. Verify text is visible immediately during font load and the swap is unobtrusive.

### 32. Lazy-load and poster-optimize video
*Area: Images, Fonts & Media. Why it matters: Auto-downloading video is one of the heaviest things a page can do and often runs before anyone presses play.*

Find video elements that preload or autoplay heavy content during initial load. Set them to load metadata only (or defer entirely until interaction), provide a lightweight poster image, and lazy-load offscreen videos as the user approaches. For background videos, use compressed, appropriately sized sources. Confirm initial load no longer pulls large video data and playback still starts promptly when requested.

### 33. Self-host critical third-party assets
*Area: Images, Fonts & Media. Why it matters: Pulling key scripts and fonts from outside servers adds extra connections and leaves your speed at their mercy.*

Identify critical third-party assets (fonts, small libraries, key scripts) that are fetched from external domains and add connection overhead or single points of failure to your load path. Where licensing allows, self-host the most critical of these so they load from your own origin over an already-open connection. Keep them cache-busted and updated. Confirm fewer cross-origin connections are needed for the critical path and load timing improves.

### 34. Inline tiny critical SVGs and icons
*Area: Images, Fonts & Media. Why it matters: Each separate request for a small icon adds round-trip delay that adds up across a page.*

Find small, critical SVG icons and graphics that are loaded as separate network requests on important pages. Inline the few that appear above the fold directly into the markup or a sprite so they render without extra round trips, while keeping larger or rarely-used graphics external. Avoid inlining large SVGs that would bloat the HTML. Verify the critical icons appear instantly with fewer requests.

### 35. Serve all static media via CDN
*Area: Images, Fonts & Media. Why it matters: Sending images and files from one distant server makes them slow for users far away.*

Check whether my static assets (images, fonts, scripts, downloads) are served directly from my application server or a single region. Move them behind a CDN so they're delivered from edge locations near each user with proper long-lived caching. Ensure correct cache headers and cache-busting on deploys. Confirm assets load faster for distant users and origin load decreases.

### 36. Code-split the app by route
*Area: JavaScript, Bundles & Build. Why it matters: Shipping the entire app's code on first load forces users to download pages they may never visit.*

Examine how my JavaScript is bundled and determine whether the whole app ships as one large bundle on first load. Introduce route-based code splitting so each page loads only its own code on demand, with the initial bundle limited to what the first view needs. Add suspense or loading boundaries around the lazy routes. Confirm the initial bundle shrinks substantially and routes load their code as visited.

### 37. Remove unused dependencies and dead code
*Area: JavaScript, Bundles & Build. Why it matters: Every unused library and orphaned file still gets shipped, bloating downloads for zero benefit.*

Audit my project for dependencies that are installed but no longer used, and for dead code paths that are never reached. Remove the unused packages and prune the dead code, confirming nothing still imports them. Watch for dependencies used only in one small place that could be dropped entirely. Verify the build still works, tests pass, and the bundle size decreases.

### 38. Tree-shake and dedupe the bundle
*Area: JavaScript, Bundles & Build. Why it matters: Importing whole libraries for one function, or shipping the same dependency twice, pads your download size.*

Inspect my bundle for whole-library imports where only a small part is used, and for duplicate copies of the same dependency at different versions. Switch to granular imports so unused code is tree-shaken away, and deduplicate the dependency tree so each library ships once. Confirm side-effect flags are set so tree-shaking is effective. Verify the bundle shrinks and the app behaves identically.

### 39. Analyze bundle composition for bloat
*Area: JavaScript, Bundles & Build. Why it matters: You can't fix what you can't see; most bloated bundles hide one or two oversized culprits.*

Run a bundle analysis on my build to visualize what's actually taking up space in the JavaScript I ship. Identify the largest modules and any surprisingly heavy dependencies, then recommend specific replacements, lazy-loading, or removals for the biggest offenders. Quantify the potential savings for each. Present the findings clearly so I can decide which to act on, then implement the agreed cuts.

### 40. Defer and async non-critical scripts
*Area: JavaScript, Bundles & Build. Why it matters: Scripts that block parsing freeze the page while they download and run, delaying everything visible.*

Find script tags and third-party snippets that block HTML parsing or run synchronously during load. Mark non-critical scripts as defer or async (or load them after interaction) so they no longer hold up rendering, while keeping any script the first paint truly depends on. Verify load order still works for scripts with dependencies. Confirm the page renders sooner and blocking time drops.

### 41. Minify JS, CSS, and HTML
*Area: JavaScript, Bundles & Build. Why it matters: Unminified code ships with comments and whitespace users download but never see.*

Verify that my production build minifies JavaScript, CSS, and HTML, and check whether any assets are slipping through unminified. Enable or fix minification across all output, and ensure compression (gzip or brotli) is applied at serve time on top of it. Confirm source maps are generated separately rather than shipped to users. Verify served asset sizes drop and the app still works in production mode.

### 42. Lazy-initialize heavy client libraries
*Area: JavaScript, Bundles & Build. Why it matters: Spinning up big libraries on page load slows startup even when the feature isn't used yet.*

Identify heavy client-side libraries (charts, editors, maps, video players, PDF viewers) that initialize on page load but power features the user may not immediately use. Defer importing and initializing each until its feature is actually triggered, so startup cost is paid only when needed. Show a brief loading state when the feature first opens. Confirm initial load is lighter and the deferred features still work on demand.

### 43. Replace heavy libraries with lighter ones
*Area: JavaScript, Bundles & Build. Why it matters: A bloated dependency for a simple job can dwarf the rest of your code in size.*

Review my dependencies for heavyweight libraries used for tasks that lighter alternatives or native browser APIs could handle (date handling, utility functions, animation, HTTP, validation). Propose specific lighter replacements and estimate the size savings for each. Implement the swaps that are low-risk, preserving the existing behavior and API surface where I depend on it. Verify functionality is unchanged and the bundle shrinks.

### 44. Hash filenames for long-term caching
*Area: JavaScript, Bundles & Build. Why it matters: Without content hashes, browsers either re-download unchanged files or serve stale ones after deploys.*

Check whether my static asset filenames include content hashes for cache-busting. Configure the build so each asset's filename changes only when its content changes, then serve those assets with long-lived immutable cache headers. Ensure the HTML references the hashed names and isn't itself over-cached. Confirm returning users skip re-downloading unchanged assets while always getting the latest version after a deploy.

### 45. Split vendor and app bundles
*Area: JavaScript, Bundles & Build. Why it matters: Bundling your code with rarely-changing libraries forces users to re-download everything on every update.*

Look at how my build groups code and determine whether my application code and third-party dependencies share the same bundle. Split stable vendor code into its own long-cached chunk separate from frequently-changing app code, so a deploy invalidates only what actually changed. Tune the chunking so it doesn't fragment into too many tiny requests. Confirm repeat visits after a deploy re-download less.

### 46. Eliminate render-blocking CSS on load
*Area: JavaScript, Bundles & Build. Why it matters: The browser won't show anything until all blocking CSS loads, so bloated stylesheets delay first paint.*

Identify CSS that blocks the first render, including large stylesheets and unused rules loaded up front. Inline the small set of critical above-the-fold styles and load the rest asynchronously so rendering isn't blocked waiting for the full stylesheet. Remove or defer CSS that the initial view doesn't need. Verify first paint happens sooner and the page isn't left unstyled during load.

### 47. Compress API responses in transit
*Area: Network & API Efficiency. Why it matters: Uncompressed JSON can be several times larger than it needs to be on the wire.*

Check whether my API responses are compressed in transit. Enable gzip or brotli compression on the server or edge for JSON and text responses above a small size threshold, and confirm the client negotiates it via Accept-Encoding. Avoid double-compressing already-compressed payloads. Verify response transfer sizes drop significantly and responses still parse correctly on the client.

### 48. Trim oversized API payloads
*Area: Network & API Efficiency. Why it matters: Endpoints that return far more data than the screen uses waste bandwidth and slow every request.*

Audit my API responses for payloads that include fields, nested objects, or rows the consuming screens don't actually use. Trim each endpoint to return only the data its callers need, adding field selection or sparse-fieldset support where different screens need different shapes. Avoid sending large blobs that could be fetched separately on demand. Verify payloads shrink and the UI still has everything it requires.

### 49. Parallelize independent async requests
*Area: Network & API Efficiency. Why it matters: Running independent requests one after another adds up their wait times instead of overlapping them.*

Find places where my code awaits multiple independent async operations sequentially, so each one's latency stacks on the last. Run independent requests concurrently (e.g., with Promise.all or equivalent) so their wait times overlap, while keeping genuinely dependent calls ordered. Add sensible error handling so one failure doesn't silently break the batch. Verify the combined operation finishes in roughly the time of the slowest request, not the sum.

### 50. Eliminate sequential request waterfalls
*Area: Network & API Efficiency. Why it matters: Each request that waits on the previous one's result chains delays into a long, slow load.*

Trace my app's data loading for waterfalls where one request must finish before the next can even start, chaining latency. Restructure so independent data is fetched in parallel, and where one request feeds another, consider fetching the combined data in a single round trip or moving the dependency to the server. Hoist data requirements up so they can start as early as possible. Verify the total load path has fewer sequential hops.

### 51. Deduplicate concurrent identical requests
*Area: Network & API Efficiency. Why it matters: Multiple components asking for the same data at once can fire the same request several times over.*

Identify cases where the same data can be requested multiple times concurrently (e.g., several components mounting at once or rapid re-triggers), causing duplicate in-flight requests. Add request deduplication so identical concurrent requests share a single underlying call and its result. Make sure cache keys correctly capture the request's parameters. Verify duplicate network calls disappear under concurrent access while data stays correct.

### 52. Paginate large API responses
*Area: Network & API Efficiency. Why it matters: Returning thousands of records in one response is slow to generate, transfer, and render.*

Find endpoints that return large unbounded collections in a single response. Add pagination (limit/offset or, preferably, cursor-based) so clients fetch data in manageable pages, and update the client to request and render pages incrementally. Include total-count or next-cursor metadata as needed for the UI. Verify large datasets load in fast, bounded chunks rather than one heavy response.

### 53. Add timeouts and retry with backoff
*Area: Network & API Efficiency. Why it matters: Requests that hang forever freeze features, and naive retries can stampede a struggling server.*

Audit my outbound requests for missing timeouts and unsafe retry behavior. Add sensible timeouts so no request hangs indefinitely, and implement retries with exponential backoff and jitter for transient failures, capping the number of attempts. Ensure non-idempotent requests aren't retried unsafely. Verify slow or failing dependencies degrade gracefully instead of hanging or overwhelming the backend.

### 54. Cache GET responses with validators
*Area: Network & API Efficiency. Why it matters: Re-fetching data that hasn't changed wastes a full round trip the browser could skip.*

Review my read-only API endpoints for missing HTTP caching. Add ETag or Last-Modified validators and appropriate Cache-Control directives so clients and intermediaries can revalidate cheaply and skip transferring unchanged bodies (via 304 responses). Choose caching rules that respect user-specific or sensitive data. Verify repeat reads of unchanged resources avoid re-downloading the full payload.

### 55. Use stale-while-revalidate on the client
*Area: Network & API Efficiency. Why it matters: Making users wait for fresh data when slightly older data exists makes the app feel slower than it is.*

Identify client data fetches where showing cached data immediately while refreshing in the background would improve perceived speed. Adopt a stale-while-revalidate strategy so cached results render instantly and a background fetch updates them, with clear handling when the refresh changes the data. Set sensible staleness windows per data type. Verify revisited screens appear instantly and quietly update when newer data arrives.

### 56. Batch many small requests together
*Area: Network & API Efficiency. Why it matters: Dozens of tiny requests carry more overhead than payload and clog the connection.*

Find patterns where my client fires many small requests in quick succession (e.g., per-item lookups in a list). Batch them into fewer combined requests where the API supports it, or add a batching endpoint that accepts multiple keys and returns them together. Preserve correct mapping of results back to each caller. Verify the number of requests drops sharply while the data returned stays complete and correct.

### 57. Reuse connections with keep-alive
*Area: Network & API Efficiency. Why it matters: Opening a brand-new connection for every request adds handshake delay each time.*

Check whether my server-to-server and outbound HTTP calls open a fresh connection per request instead of reusing them. Enable HTTP keep-alive and connection pooling on outbound clients so connections are reused across requests, reducing handshake overhead. Tune pool size and idle timeouts to match load. Verify outbound request latency drops and connection churn decreases under sustained traffic.

### 58. Move reads to the edge
*Area: Network & API Efficiency. Why it matters: Fetching cacheable data from one central server is slow for users far from it.*

Identify read-heavy, cacheable responses that are currently served from a single origin region. Move them to edge caching or edge functions so users are served from a nearby location, with correct cache keys and invalidation for any personalized variation. Keep uncacheable, user-specific paths on the origin. Verify global read latency improves and origin load drops for cacheable content.

### 59. Add a client-side request cache
*Area: Network & API Efficiency. Why it matters: Re-fetching the same data as users navigate back and forth repeats work the app already did.*

Review how my client refetches data when users revisit screens or navigate back and forth, and find cases where it re-requests identical data unnecessarily. Introduce a client-side cache (or adopt a data-fetching library that provides one) keyed by request parameters, with sensible freshness and invalidation rules. Ensure mutations correctly invalidate affected cache entries. Verify revisiting screens reuses cached data and avoids redundant requests.

### 60. Add a server cache for hot data
*Area: Caching Strategy. Why it matters: Recomputing or re-querying the same popular data on every request wastes your server's time.*

Identify expensive read operations on the server (heavy queries, external API calls, costly computations) whose results are requested frequently and change infrequently. Add a server-side cache layer in front of them with appropriate keys and TTLs, so repeated requests are served from cache instead of redoing the work. Handle cache misses and concurrent population safely. Verify hot endpoints get faster and backend load for them drops.

### 61. Set correct Cache-Control headers
*Area: Caching Strategy. Why it matters: Wrong caching headers either make browsers re-fetch everything or serve dangerously stale content.*

Audit the Cache-Control headers across my responses and find assets that are under-cached (re-fetched needlessly) or dynamic data that's over-cached (served stale). Set correct directives per resource type: long immutable caching for hashed static assets, short or revalidated caching for dynamic data, and no-store for sensitive responses. Confirm private vs shared cache scope is set appropriately. Verify caching behavior matches each resource's real volatility.

### 62. Cache expensive computed results
*Area: Caching Strategy. Why it matters: Repeating the same costly calculation for identical inputs burns CPU you could reclaim.*

Find pure, deterministic functions on the server or client that are called repeatedly with the same inputs and are expensive to compute. Add memoization or a keyed result cache so repeated calls with identical inputs return the stored result, with bounded size to avoid unbounded memory growth. Ensure the cache is only used for genuinely pure computations. Verify repeated calls get faster without stale or incorrect results.

### 63. Choose sensible cache TTLs
*Area: Caching Strategy. Why it matters: Caches that expire too soon barely help, and ones that expire too late serve outdated data.*

Review the expiration times on my caches and find TTLs that are arbitrary, too short to be effective, or too long for how fast the data changes. Tune each TTL to balance freshness against hit rate based on the data's real update frequency, and document the reasoning. Consider longer TTLs paired with explicit invalidation for data that changes on known events. Verify cache hit rates improve without serving unacceptably stale data.

### 64. Invalidate caches on writes
*Area: Caching Strategy. Why it matters: A cache that isn't cleared when data changes will confidently serve the wrong answer.*

Trace my caches for cases where underlying data can change without the corresponding cache entry being invalidated, risking stale reads. Add invalidation (or targeted updates) triggered by the relevant writes so cached data stays consistent with the source of truth. Prefer precise key-based invalidation over clearing everything. Verify that updating data promptly reflects in subsequent reads while unaffected cache entries survive.

### 65. Add an in-memory cache layer
*Area: Caching Strategy. Why it matters: Hitting the database or external services for the same data repeatedly is far slower than memory.*

Identify frequently accessed, slow-to-fetch data that would benefit from a fast in-memory cache (such as Redis or an in-process cache for single instances). Introduce the cache layer for those reads with clear keys, TTLs, and a safe miss-and-populate path, falling back to the source on cache failure. Be mindful of consistency across multiple server instances. Verify the cached reads are dramatically faster and source-system load drops.

### 66. Cache rendered pages or fragments
*Area: Caching Strategy. Why it matters: Rebuilding the same HTML for every visitor wastes server effort on content that rarely changes.*

Find server-rendered pages or fragments whose output is identical (or nearly so) across many users and changes infrequently. Cache the rendered output and serve it directly, regenerating on a schedule or on content change, while keeping personalized regions dynamic via holes or client-side hydration. Ensure cache keys account for meaningful variations like locale. Verify these pages serve much faster and rendering load decreases.

### 67. Warm caches for hot paths
*Area: Caching Strategy. Why it matters: The first user after a cache expires pays the full slow cost; warming spares them.*

Identify predictable hot paths where a cold cache causes a slow first request (after deploys, expirations, or scheduled clears). Add cache warming that proactively populates those entries before users hit them, such as on startup or just before known expiry. Keep warming cheap and limited to genuinely hot keys. Verify users rarely encounter the cold-cache penalty on these paths.

### 68. Add a service worker asset cache
*Area: Caching Strategy. Why it matters: Without local caching, returning visitors re-download your app shell every single time.*

Determine whether my app uses a service worker to cache its shell and static assets for repeat visits. Add (or refine) a service worker with a sensible caching strategy that serves the app shell and assets from local cache while keeping them updated, and handle versioning so stale caches are cleared on deploy. Avoid caching sensitive or rapidly-changing API data inappropriately. Verify repeat visits load near-instantly and update correctly after a release.

### 69. Index frequently queried columns
*Area: Database & Data Layer. Why it matters: Without indexes, the database scans entire tables to answer common queries, which gets slower as data grows.*

Examine my most frequent and slowest database queries and identify columns used in WHERE filters, JOINs, and ORDER BY that lack supporting indexes. Add appropriate indexes for those access patterns, choosing column order to match how the data is queried. Avoid over-indexing columns that are rarely filtered or frequently written. Verify the targeted queries use the new indexes (via the query planner) and run substantially faster.

### 70. Fix N+1 query patterns
*Area: Database & Data Layer. Why it matters: Loading a list and then querying once per item explodes into hundreds of round trips that crush performance.*

Hunt for N+1 query patterns where my code loads a collection and then issues a separate query for each item's related data. Replace them with eager loading, a JOIN, or a single batched query that fetches all the related data at once. Watch for N+1s hidden inside loops, serializers, and template rendering. Verify the number of queries per request drops dramatically and the endpoint speeds up.

### 71. Select only needed columns
*Area: Database & Data Layer. Why it matters: Pulling every column when you need a few wastes I/O, memory, and network on data you discard.*

Find queries that select all columns (SELECT *) or fetch wide rows when only a few fields are actually used. Narrow them to select only the needed columns, which also enables more efficient index-only access in some cases. Be careful to keep any columns the code actually depends on downstream. Verify the queries transfer less data and run faster without missing fields.

### 72. Add composite indexes for filters
*Area: Database & Data Layer. Why it matters: Queries that filter on several columns at once need a matching multi-column index to stay fast.*

Identify queries that filter or sort on multiple columns together but rely only on single-column indexes (or none). Add composite indexes whose column order matches the query's filter and sort pattern, so the database can satisfy the whole predicate efficiently. Order columns by selectivity and equality-before-range rules. Verify the multi-column queries now use the composite index and avoid scanning or sorting large result sets.

### 73. Switch to cursor-based pagination
*Area: Database & Data Layer. Why it matters: Skipping past thousands of rows with OFFSET gets slower the deeper users page, eventually crawling.*

Find paginated queries that use large OFFSET values, which force the database to scan and discard everything before the requested page. Convert them to cursor- (keyset-) based pagination that seeks directly using an indexed sort key, so deep pages stay fast. Update the API and client to pass and use the cursor. Verify pagination performance stays constant regardless of how deep the user goes.

### 74. Profile and fix slow queries
*Area: Database & Data Layer. Why it matters: A handful of slow queries usually cause most of the pain, and you can't fix them until you find them.*

Use my database's slow-query log or timing data to find the queries consuming the most total time, then run their execution plans to see what's slow. For each top offender, diagnose the cause (missing index, full scan, bad join order, large sort) and apply the specific fix. Prioritize by total impact, not just single-query duration. Verify each fixed query's plan improves and its runtime drops.

### 75. Cache repeated read queries
*Area: Database & Data Layer. Why it matters: Asking the database the same question over and over wastes capacity better spent on real work.*

Identify read queries that run very frequently with the same or few distinct parameters and return data that changes slowly. Add a caching layer in front of them with keys based on the query parameters and TTLs matched to the data's volatility, plus invalidation on relevant writes. Ensure cache misses populate safely under concurrency. Verify database query volume for these reads drops sharply and response times improve.

### 76. Batch inserts and updates
*Area: Database & Data Layer. Why it matters: Writing rows one at a time multiplies round-trip and transaction overhead enormously.*

Find code that performs many individual INSERT or UPDATE statements in a loop where a single batched operation would work. Replace them with bulk/batched writes (multi-row inserts, batch updates, or a single statement) inside an appropriate transaction. Chunk very large batches to avoid oversized statements or long locks. Verify write-heavy operations complete far faster with fewer round trips.

### 77. Add covering indexes for hot reads
*Area: Database & Data Layer. Why it matters: When an index contains every column a query needs, the database skips touching the table entirely.*

Identify hot read queries that hit an index but still have to fetch additional columns from the table rows. Where worthwhile, extend the index to cover all the columns those queries need (a covering index) so they can be answered from the index alone. Weigh the added write and storage cost against the read benefit. Verify the targeted queries become index-only and run faster.

### 78. Materialize expensive aggregation queries
*Area: Database & Data Layer. Why it matters: Recomputing heavy reports and counts on every request can hammer the database for the same answer.*

Find expensive aggregate queries (large GROUP BY, complex reports, dashboard counts) that run often but whose inputs change relatively slowly. Precompute them into a materialized view or a summary table refreshed on a schedule or on relevant changes, and read from that instead. Keep the refresh strategy appropriate to how fresh the numbers must be. Verify the dashboards and reports load quickly and stop overloading the database.

### 79. Use database connection pooling
*Area: Database & Data Layer. Why it matters: Opening a new database connection per request is expensive and can exhaust the database under load.*

Check whether my app opens a fresh database connection per request or operation instead of reusing a pool. Configure a properly sized connection pool so connections are reused, with limits tuned to the database's capacity and the app's concurrency. In serverless or high-fan-out setups, ensure pooling works correctly (e.g., via a pooler). Verify connection overhead drops and the database isn't overwhelmed by connection churn under load.

### 80. Avoid loading whole tables into memory
*Area: Database & Data Layer. Why it matters: Pulling an entire large table into the app to filter or count in code is slow and can exhaust memory.*

Find places where my code loads large query results or whole tables into memory to filter, sort, count, or aggregate in application code. Push that work down into the database query (WHERE, ORDER BY, GROUP BY, COUNT) so only the needed results come back, and stream rather than buffer where large results are unavoidable. Verify memory use drops and these operations run faster by letting the database do the heavy lifting.

### 81. Denormalize critical read paths
*Area: Database & Data Layer. Why it matters: Joining many tables for the hottest reads can be slower than storing a little redundant data.*

Identify read paths that are extremely hot but require expensive multi-table JOINs to assemble. For the most critical of these, consider selectively denormalizing by storing the needed fields together or maintaining a precomputed read model, accepting controlled redundancy for speed. Add the logic to keep the duplicated data consistent on writes. Verify the hot reads get faster while writes still keep the denormalized data correct.

### 82. Route reads to a replica
*Area: Database & Data Layer. Why it matters: When reads and writes share one database, heavy read traffic can starve the writes that matter.*

Assess whether my read traffic is heavy enough to be competing with writes on a single database instance. Route appropriate read-only queries to a read replica so the primary is freed up for writes, while keeping reads that need the very latest data on the primary. Account for replication lag in the routing decisions. Verify read load shifts off the primary and overall throughput improves without serving unacceptably stale reads.

### 83. Partition or archive huge tables
*Area: Database & Data Layer. Why it matters: Tables that grow without bound slow every query and operation that touches them over time.*

Find tables that have grown very large and are slowing queries, indexing, and maintenance. Introduce partitioning by a natural key (such as time) so queries prune to relevant partitions, and archive or roll off old data that's rarely accessed into cheaper storage. Ensure queries and indexes align with the partition scheme. Verify queries against recent data speed up and table maintenance becomes more manageable.

### 84. Add database query timeouts
*Area: Database & Data Layer. Why it matters: A single runaway query can lock resources and drag down the whole app for everyone.*

Check whether my database queries can run unbounded, risking a single slow query tying up connections and degrading the whole system. Add statement timeouts at the query or connection level so long-running queries are cut off before they cause cascading slowdowns. Set limits appropriate to each query class, with longer allowances only for known heavy jobs. Verify runaway queries are terminated safely without harming normal traffic.

### 85. Offload slow work to background jobs
*Area: Backend, Server & Concurrency. Why it matters: Making users wait through emails, image processing, or exports inside the request makes the app feel frozen.*

Identify slow or non-essential work done synchronously inside request handling (sending emails, processing images/files, generating exports, calling slow third parties). Move it to a background job queue so the request returns quickly while the work runs asynchronously, with status tracking or notifications as needed. Ensure jobs are retryable and idempotent. Verify the user-facing requests return fast and the deferred work completes reliably out of band.

### 86. Stream large responses instead of buffering
*Area: Backend, Server & Concurrency. Why it matters: Building a huge response fully in memory before sending it is slow and can crash the server under load.*

Find endpoints that assemble large responses (big exports, reports, file downloads, long lists) entirely in memory before sending. Convert them to stream the response incrementally so data flows to the client as it's produced, keeping memory flat regardless of size. Apply backpressure-aware streaming for very large outputs. Verify large responses start arriving sooner, use far less memory, and don't destabilize the server.

### 87. Replace blocking I/O with async
*Area: Backend, Server & Concurrency. Why it matters: Synchronous I/O ties up the server while it waits, so it can handle far fewer users at once.*

Audit my server code for synchronous/blocking I/O (file reads, network calls, or blocking library calls) on the request path that stalls the worker while it waits. Replace it with non-blocking async equivalents so the server can handle other work during I/O waits, and move unavoidable blocking work to a worker pool. Verify throughput under concurrency improves and requests stop blocking each other on I/O.

### 88. Reduce serverless cold starts
*Area: Backend, Server & Concurrency. Why it matters: A function that has to boot from scratch makes the first user wait noticeably longer.*

If my app runs on serverless functions, identify those with slow cold starts hurting first-request latency. Reduce cold-start cost by trimming the deployment bundle and dependencies, deferring heavy initialization, reusing connections across invocations, and using provisioned concurrency or keep-warm for latency-critical functions. Move one-time setup outside the handler so it's reused. Verify cold-start latency drops and warm invocations stay fast.

### 89. Profile and optimize hot paths
*Area: Backend, Server & Concurrency. Why it matters: Most slowness concentrates in a few code paths; optimizing blindly elsewhere wastes effort.*

Profile my server under realistic load to find the hottest code paths and biggest time sinks, rather than guessing. For the top offenders, identify the specific cause (redundant work, inefficient algorithms, excessive allocations, repeated I/O) and apply targeted optimizations. Re-profile after each change to confirm real improvement and catch regressions. Verify the hot paths measurably speed up and overall latency improves.

### 90. Pool and reuse expensive resources
*Area: Backend, Server & Concurrency. Why it matters: Recreating database clients, HTTP agents, or parsers per request adds avoidable overhead every time.*

Find expensive resources (database clients, HTTP agents, parsers, compiled templates, encryption contexts) that are created fresh per request instead of reused. Initialize them once and share them safely across requests via pooling or module-level singletons, respecting thread/async safety. Ensure they're properly closed on shutdown and recreated if they fail. Verify per-request overhead drops and resource creation no longer shows up in profiles.

### 91. Add a circuit breaker for slow deps
*Area: Backend, Server & Concurrency. Why it matters: When a dependency gets slow, piling requests onto it can drag your whole app down with it.*

Identify external dependencies whose slowness or failures could cascade into my app, exhausting threads or connections while everyone waits. Add a circuit breaker that trips when a dependency is failing or too slow, fast-failing or serving a fallback until it recovers, with timeouts and limited concurrency to that dependency. Verify that a degraded dependency no longer drags down unrelated parts of the app and recovers cleanly.

### 92. Rate-limit to protect under load
*Area: Backend, Server & Concurrency. Why it matters: Without limits, a traffic spike or abusive client can overwhelm your server and take it down for everyone.*

Assess whether my API endpoints are protected against being overwhelmed by bursts, abusive clients, or runaway loops. Add rate limiting (per client/IP/key) on the most expensive and public endpoints so excessive traffic is throttled before it degrades service for everyone, returning clear limit responses. Tune limits to real usage and protect critical paths first. Verify the server stays healthy under spikes and legitimate users are unaffected.

### 93. Compress and cache server templates
*Area: Backend, Server & Concurrency. Why it matters: Re-reading and re-parsing templates or config on every request repeats work that never changes.*

Check whether my server re-reads or re-compiles templates, configuration, or schema definitions on each request instead of once at startup. Cache the parsed/compiled forms in memory and reuse them, reloading only when the source actually changes. Ensure the cached versions are correctly invalidated on legitimate updates. Verify per-request work drops by skipping repeated parsing and the responses are unchanged.

### 94. Gracefully degrade non-critical features
*Area: Backend, Server & Concurrency. Why it matters: When one optional feature breaks or slows, it shouldn't take the whole page down with it.*

Identify non-critical features (recommendations, related items, third-party widgets, analytics) whose failure or slowness currently risks breaking or delaying the whole page. Make them degrade gracefully so the core experience renders even if these fail, by isolating them with timeouts, fallbacks, and error boundaries. Avoid letting optional data block critical rendering. Verify the page stays fast and functional when a non-critical feature is slow or unavailable.

### 95. Add real-user performance monitoring
*Area: Measurement, Monitoring & Budgets. Why it matters: Lab tests miss what real users on real devices and networks actually experience.*

Set up real-user monitoring (RUM) that captures Core Web Vitals and key timings from actual visitors across devices and networks, not just lab tests. Report the metrics (LCP, CLS, INP, TTFB) so I can see real-world distributions and regressions over time, segmented by page and device class. Keep the monitoring lightweight so it doesn't itself hurt performance. Verify real user data flows in and surfaces the slowest pages and worst experiences.

### 96. Run Lighthouse and fix top issues
*Area: Measurement, Monitoring & Budgets. Why it matters: An automated audit quickly surfaces concrete, prioritized performance problems you can act on.*

Run a Lighthouse (or equivalent) performance audit on my key pages and collect the specific opportunities and diagnostics it reports. Prioritize the highest-impact issues (render-blocking resources, oversized images, unused code, layout shift, slow server response) and implement fixes for the top ones. Re-run the audit after changes to confirm the score and metrics improve. Present the before/after so the gains are clear.

### 97. Reduce Largest Contentful Paint
*Area: Measurement, Monitoring & Budgets. Why it matters: LCP measures how fast the main content shows up, and slow LCP is what makes a site feel slow to load.*

Measure my pages' Largest Contentful Paint and identify what the LCP element is and why it's slow (slow server response, render-blocking resources, late-loading or unoptimized hero image, or client-side rendering delay). Apply targeted fixes such as preloading and optimizing the LCP image, prioritizing its delivery, cutting render-blocking work, and speeding up the initial response. Verify LCP drops below the recommended threshold on key pages.

### 98. Reduce Cumulative Layout Shift
*Area: Measurement, Monitoring & Budgets. Why it matters: Content that jumps around as the page loads frustrates users and causes accidental clicks.*

Measure Cumulative Layout Shift on my pages and find every source of unexpected movement: images and embeds without reserved space, late-loading fonts that reflow text, dynamically injected banners or ads, and content inserted above existing elements. Fix each by reserving space, stabilizing fonts, and avoiding layout-shifting insertions. Verify CLS falls into the good range and the page stays visually stable through load.

### 99. Improve Interaction to Next Paint
*Area: Measurement, Monitoring & Budgets. Why it matters: INP measures how quickly the page responds to taps and clicks, which is what makes an app feel responsive.*

Measure Interaction to Next Paint and find the interactions with the worst responsiveness, then trace the long tasks and heavy event handlers causing the delay. Reduce input-handler work, break up long tasks, defer non-urgent work off the interaction path, and minimize re-render cost so the UI responds within a frame or two. Verify INP improves into the good range for the most common interactions.

### 100. Set a performance budget in CI
*Area: Measurement, Monitoring & Budgets. Why it matters: Without an automated guardrail, speed quietly erodes as features pile up over time.*

Establish performance budgets for key metrics (bundle size, LCP, total page weight, request counts) based on my current baseline and targets. Wire them into CI so a build that regresses past the budget fails or flags a warning, preventing silent performance erosion as the app grows. Set realistic thresholds and clear failure messages. Verify the check runs on each change and actually catches regressions before they ship.

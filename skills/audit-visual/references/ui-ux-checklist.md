# UI/UX Depth Checklist (audit-visual)

Extra-depth checklist to pull from during a review — especially the areas the
4-pass protocol covers more thinly: **WCAG 2.1 AA accessibility (45-56)**,
responsive depth (11-20), forms UX (67-76), feedback systems (77-86), and
navigation + data patterns (87-100). The design-system / typography / motion items
(1-44) mostly overlap the existing passes — use them as a coverage backstop, not a
replacement for the principled gates. Source: vibecoder ui-audit.

### 1. Establish a Design Token System
*Area: Design System & Visual Foundations. Why it matters: Centralizing colors, spacing, and sizing into reusable variables stops your UI from drifting into inconsistency as it grows, and lets you restyle the entire app from one place instead of hunting through every file.*

Audit my codebase for every hardcoded color, font-size, spacing value, and border-radius currently used inline or scattered across components. Consolidate them into a single source of truth using CSS custom properties (or my framework's theme config) organized into tiers — primitive tokens (raw values), semantic tokens (intent-based like `--color-surface`), and component tokens. Replace the hardcoded values throughout the app with references to these tokens without changing the current visual appearance. Then give me a short summary of how many values you consolidated and where the token definitions now live.

### 2. Build a Semantic Color System
*Area: Design System & Visual Foundations. Why it matters: Naming colors by their job (surface, danger, muted) rather than their hue lets you support dark mode, theming, and rebrands later without touching a single component.*

Review how color is currently applied across my interface and map every usage to a semantic role rather than a literal value — for example `--color-background`, `--color-text-primary`, `--color-text-muted`, `--color-border`, `--color-accent`, `--color-success`, `--color-warning`, and `--color-danger`. Build out this semantic palette with appropriate values, ensuring each text-on-background pairing meets a contrast ratio of at least 4.5:1. Refactor components to consume these semantic tokens instead of raw hex codes. Confirm the visual result is unchanged and flag any colors that currently fail contrast.

### 3. Define a Consistent Spacing Scale
*Area: Design System & Visual Foundations. Why it matters: Random margins and paddings make an interface feel sloppy; a mathematical spacing scale creates visual rhythm that reads as "designed" even to people who can't name why.*

Examine the padding, margin, and gap values used throughout my UI and identify the inconsistencies. Establish a spacing scale based on a consistent base unit (typically a 4px or 8px grid) with named steps, and refactor the layout so all spacing snaps to this scale. Pay special attention to vertical rhythm between stacked elements and the internal padding of cards, buttons, and inputs, so related elements feel grouped and unrelated ones feel separated. Summarize which spacing values you removed and what they were replaced with.

### 4. Create an Elevation Shadow System
*Area: Design System & Visual Foundations. Why it matters: A layered shadow scale communicates which elements float above others, giving your flat interface a believable sense of depth and hierarchy.*

Review how I'm currently using box-shadows and borders to separate elements. Design a cohesive elevation system with 3–5 tiers (e.g. resting, raised, overlay, modal) where each tier uses subtle, layered shadows — combining a tight ambient shadow with a softer, more diffuse one rather than a single harsh drop shadow. Apply the appropriate elevation tier to cards, dropdowns, popovers, and modals so stacking context is visually obvious. Make sure the shadows look natural against my current background color and stay subtle rather than heavy.

### 5. Standardize the Border Radius Scale
*Area: Design System & Visual Foundations. Why it matters: Mismatched corner roundness is a subtle but pervasive sign of an unpolished app; one consistent radius scale instantly makes everything feel like it belongs together.*

Find every border-radius value across my components and note where they diverge. Define a small radius scale (for example: none, sm, md, lg, and full for pills/avatars) and decide on a sensible default for interactive elements like buttons and inputs. Apply the scale consistently so that nested elements use a slightly smaller radius than their containers, to avoid the awkward "corner gap" effect. Report the values you standardized on and where each tier is now used.

### 6. Strengthen Overall Visual Hierarchy
*Area: Design System & Visual Foundations. Why it matters: When everything competes for attention, nothing stands out; deliberate hierarchy guides the eye to what matters first and makes your interface effortless to scan.*

Analyze a few of my key screens and evaluate whether the single most important element on each is clearly the most prominent. Adjust size, weight, color contrast, and spacing so there's an obvious primary, secondary, and tertiary visual tier on every screen — the primary action or heading should draw the eye first, and supporting content should recede. Reduce competing emphasis by muting secondary text, de-emphasizing repeated UI chrome, and giving primary actions stronger visual weight. Walk me through the hierarchy changes you made on each screen and why.

### 7. Polish All Button Interaction States
*Area: Design System & Visual Foundations. Why it matters: Buttons are the most-touched element in any app, and missing hover, active, focus, loading, or disabled states make them feel broken or unresponsive.*

Audit my button components and check whether each variant fully handles default, hover, active/pressed, focus-visible, disabled, and loading states. Implement any missing states with smooth transitions — hover should give clear feedback, active should feel tactile (e.g. a subtle scale or shade shift), focus-visible should show an accessible outline, disabled should look unmistakably non-interactive, and loading should show a spinner while preventing double-submission. Ensure these states are consistent across every button variant (primary, secondary, ghost, destructive). Confirm all states are keyboard-reachable and the transitions feel responsive, not sluggish.

### 8. Design Helpful Empty States
*Area: Design System & Visual Foundations. Why it matters: Blank screens when there's no data yet confuse and discourage new users; a thoughtful empty state guides them toward their first meaningful action.*

Find every place in my app that renders a list, table, or collection and check what shows when that data is empty. For each, design a proper empty state with a brief explanation of what would normally appear here, a clear primary call-to-action to create the first item, and optionally a simple illustration or icon to make it feel intentional rather than broken. Distinguish between a true empty state (nothing created yet) and a no-results state (filters returned nothing), since they need different messaging. Show me each empty state you added and where it appears.

### 9. Unify the App's Iconography
*Area: Design System & Visual Foundations. Why it matters: Mixing icon styles, weights, and sizes makes an interface feel cobbled together; a single consistent icon set is one of the fastest ways to look professional.*

Review all the icons currently used across my interface and identify inconsistencies in style, stroke weight, size, and source. Standardize on a single icon library with a consistent visual style, and define a small set of allowed icon sizes that align to my spacing scale. Ensure icons sitting next to text are optically aligned and sized relative to the adjacent font-size, and that interactive icons have accessible labels. List which icons you swapped and the standard sizes you established.

### 10. Run a Full Consistency Audit
*Area: Design System & Visual Foundations. Why it matters: Small inconsistencies accumulate invisibly until an app feels "off" without anyone knowing why; a systematic sweep catches them all at once.*

Do a systematic pass across my entire interface looking specifically for visual inconsistencies: differing font sizes for the same type of content, varying padding on similar components, inconsistent capitalization in labels and headings, mismatched corner radii, and one-off colors that don't fit the palette. Compile a categorized list of every inconsistency you find with its location. Then fix the clear-cut cases by aligning them to the established design system, and flag any judgment calls for me to decide. Prioritize the fixes that will have the most visible impact.

### 11. Audit Mobile and Tablet Breakpoints
*Area: Layout & Responsive Design. Why it matters: Most real users are on phones, and a layout that only looks right on a desktop monitor silently loses a huge share of your audience.*

Test my interface at common viewport widths — roughly 360px (small phone), 768px (tablet), 1024px (small laptop), and 1440px (desktop) — and identify everything that breaks or looks awkward at each size. Look for content overflowing its container, text becoming unreadable, touch targets getting too small, layouts failing to reflow, and excessive empty space on large screens. Fix the issues using a mobile-first responsive approach with a consistent set of breakpoints, preferring flexible layouts (flexbox/grid with sensible wrapping) over fixed pixel widths. Give me a before/after summary of what was broken at each breakpoint.

### 12. Eliminate Horizontal Scroll on Mobile
*Area: Layout & Responsive Design. Why it matters: An unexpected sideways scrollbar on mobile is one of the most common and most amateur-looking bugs, and it usually comes from a single overflowing element.*

There may be unwanted horizontal scrolling on smaller screens. Systematically hunt down any element wider than the viewport — common culprits are fixed widths, large unwrapped tables, oversized images, negative margins, long unbroken strings, and elements whose padding pushes them past 100% width. Identify the specific offending elements and fix them using techniques like `max-width: 100%`, `overflow-wrap`, responsive table patterns, and box-sizing corrections. Verify no horizontal scroll remains at 360px width and report what was causing it.

### 13. Build a Flexible Responsive Grid
*Area: Layout & Responsive Design. Why it matters: A proper grid system makes layouts morph gracefully across screen sizes without hand-tuning every component, and keeps content aligned to invisible guidelines that read as polished.*

Look at how my main content areas are laid out and replace any rigid or manually-positioned layouts with a flexible grid approach. Use CSS Grid with `repeat(auto-fit, minmax(...))` for card collections so items reflow naturally as the screen narrows, and use a consistent max-width content container that centers on large screens to prevent lines from stretching too wide. Ensure consistent gutters that tie back to my spacing scale. Show me which layouts you converted and how they now behave as the viewport changes.

### 14. Enlarge Mobile Touch Targets
*Area: Layout & Responsive Design. Why it matters: Buttons and links that are easy to click with a mouse are often frustratingly hard to tap with a thumb, causing mis-taps that make your app feel clumsy on phones.*

Audit all interactive elements — buttons, links, icon buttons, checkboxes, form controls — and check that each has a touch target of at least 44x44px on mobile, even if its visible size is smaller. Increase the tappable area where needed using padding or pseudo-element hit areas without necessarily enlarging the visual element, and ensure adjacent tap targets have enough spacing to prevent accidental taps. Pay particular attention to small icon buttons, close buttons, and items in dense lists. Report which elements were below the threshold and how you expanded them.

### 15. Eliminate Cumulative Layout Shift
*Area: Layout & Responsive Design. Why it matters: Content that jumps around as the page loads — pushing the button you were about to tap — is jarring, hurts your Google ranking, and signals a low-quality build.*

Identify sources of layout shift in my app where elements move after initial render. Common causes include images and embeds without reserved dimensions, web fonts causing reflow, dynamically injected banners, and content that pops in after data loads. Fix these by setting explicit width/height or aspect-ratio on media, reserving space for asynchronously-loaded content with correctly-sized skeleton placeholders, and using `font-display` strategies that minimize reflow. Tell me where the shifts were occurring and what you did to stabilize each one.

### 16. Respect Mobile Safe Area Insets
*Area: Layout & Responsive Design. Why it matters: On modern phones with notches and home indicators, content and fixed bars can get cut off or overlapped without accounting for the device's safe areas.*

Check whether my app accounts for mobile safe areas on devices with notches, rounded corners, and home indicators. Add support for `env(safe-area-inset-*)` so that fixed headers, bottom navigation bars, floating action buttons, and full-bleed content respect these insets and never get obscured by system UI. Ensure the viewport meta tag is configured with `viewport-fit=cover` so the insets are available. Show me which fixed or edge-anchored elements you adjusted.

### 17. Build a Smart Sticky Header
*Area: Layout & Responsive Design. Why it matters: A header that stays accessible but gets out of the way while scrolling gives users constant navigation without sacrificing precious vertical space on mobile.*

Improve my main navigation header's scroll behavior. Make it sticky so navigation is always reachable, but implement a "hide on scroll down, reveal on scroll up" pattern so it maximizes content space while scrolling through long pages. Add a subtle background blur or solid background plus a faint shadow only once the user has scrolled away from the top, so it sits cleanly over content. Ensure the behavior is smooth, doesn't cause layout shift, and degrades gracefully where the page is too short to scroll.

### 18. Balance Content Density and Whitespace
*Area: Layout & Responsive Design. Why it matters: Cramped interfaces overwhelm users while sparse ones waste their time scrolling; getting density right is what makes an app feel calm and confident.*

Evaluate the information density across my key screens and judge whether they feel cramped, too sparse, or well-balanced. Adjust spacing, line-height, and grouping so related elements are visually clustered and there's enough breathing room around important content to let it stand out, without forcing excessive scrolling for routine tasks. Consider where a denser layout actually helps power users (like data tables) versus where generous whitespace improves focus (like forms and reading). Explain the density decisions you made on each screen.

### 19. Use Container Queries for Components
*Area: Layout & Responsive Design. Why it matters: Components that morph to their own container — not just the whole screen — can be reused anywhere (sidebar, main area, modal) and always look right, a major upgrade over viewport-only responsiveness.*

Identify reusable components in my app that should look different based on how much space they're given rather than the overall screen size — for example a card that should stack vertically in a narrow sidebar but lay out horizontally in a wide main column. Refactor these to use CSS container queries so they respond to their parent container's width instead of the viewport. Establish the container context properly and define sensible internal breakpoints. Show me which components became container-aware and how they now morph.

### 20. Untangle Z-Index Stacking Issues
*Area: Layout & Responsive Design. Why it matters: When modals hide behind content, dropdowns get clipped, or tooltips appear under headers, it's usually a tangled z-index mess that makes the app feel buggy.*

Audit my app for z-index and stacking context problems — places where overlays appear behind other content, dropdowns get clipped by `overflow: hidden` parents, or modals don't sit above everything else. Establish a documented z-index scale with named layers (e.g. base, dropdown, sticky, overlay, modal, toast, tooltip) instead of arbitrary large numbers, and refactor components to use it. Fix clipping issues by rendering overlays in a portal at the document root where appropriate. List the stacking conflicts you found and how you resolved the layering.

### 21. Establish a Modular Type Scale
*Area: Typography & Readability. Why it matters: Arbitrary font sizes make text feel chaotic; a mathematically related type scale creates harmony and makes it obvious which text is a heading, body, or caption.*

Audit every font-size used across my app and consolidate them into a coherent modular type scale derived from a consistent ratio (for example a 1.25 major-third scale) anchored to a sensible base body size of around 16px. Define named tiers — display, h1–h4, body-large, body, small, and caption — and map each piece of text content to the appropriate tier based on its role. Refactor components to use these tiers instead of one-off sizes. Report the scale you established and how many distinct sizes you eliminated.

### 22. Add Fluid Responsive Typography
*Area: Typography & Readability. Why it matters: Headlines that look great on desktop are often too big on mobile (or vice versa); fluid type scales smoothly between screen sizes so it's always proportionate.*

Make my typography scale fluidly between screen sizes instead of jumping at breakpoints. Use CSS `clamp()` for headings and large display text so font-size interpolates smoothly between a minimum (mobile) and maximum (desktop) value based on viewport width, with sensible bounds so text never gets uncomfortably small or large. Apply this primarily to large headings where the size difference matters most, keeping body text at a stable, readable size. Show me which text styles you made fluid and the min/max values you chose.

### 23. Optimize Reading Line Length
*Area: Typography & Readability. Why it matters: Lines of text that stretch too wide are genuinely hard to read because the eye loses its place; constraining the measure and tuning line-height dramatically improves comprehension.*

Review the readability of body text and long-form content throughout my app. Constrain the line length (measure) of paragraph text to roughly 60–75 characters using a max-width in `ch` units so lines don't stretch uncomfortably wide on large screens. Set line-height appropriately — looser (around 1.5–1.6) for body copy and tighter for large headings — and ensure adequate spacing between paragraphs. Identify where text was running too wide or sitting too cramped and show me the adjustments.

### 24. Optimize Web Font Loading
*Area: Typography & Readability. Why it matters: Poorly loaded web fonts cause either invisible text or an ugly flash as fonts swap, both of which hurt the first impression and perceived speed.*

Examine how my web fonts are loaded and optimize the strategy to prevent invisible text and minimize layout shift. Preload the critical fonts used above the fold, use `font-display: swap` (or `optional` for non-essential fonts), subset fonts to only the characters and weights actually used, and self-host or use a performant source rather than render-blocking external requests. Provide a well-matched system font fallback in the font stack to reduce the visual jump when the web font loads. Summarize the loading optimizations and which fonts you preloaded.

### 25. Tune Text Color and Contrast
*Area: Typography & Readability. Why it matters: Light-gray-on-white "minimalist" text might look elegant in a mockup but is unreadable for many users in real conditions; proper contrast is both an accessibility requirement and a quality signal.*

Audit all text colors in my interface against their backgrounds for sufficient contrast. Ensure normal body text meets at least a 4.5:1 contrast ratio and large text meets at least 3:1, fixing any "low-contrast gray" text that fails. At the same time, establish a deliberate text-color hierarchy — primary, secondary/muted, and disabled — where even the muted tier remains legible. Report every text color that failed contrast, its location, and the accessible value you replaced it with.

### 26. Fix Semantic Heading Structure
*Area: Typography & Readability. Why it matters: Using heading tags for their visual size instead of their meaning breaks screen readers, SEO, and document outline; decoupling the two lets you style freely while staying correct.*

Review my heading markup and ensure headings follow a logical, sequential structure — a single h1 per page, no skipped levels, and headings used to convey document hierarchy rather than chosen for their font size. Decouple semantics from styling so I can have a small-but-important heading or a large-but-secondary one by applying type-scale classes independently of the heading level. Fix any pages where the heading outline is broken or where non-heading text is faking a heading. Show me the corrected outline for each page.

### 27. Handle Text Overflow Gracefully
*Area: Typography & Readability. Why it matters: Real user data — long names, emails, titles — overflows and breaks layouts that looked perfect with placeholder text; handling overflow prevents embarrassing visual bugs in production.*

Find places where dynamic text content could overflow or break the layout when it's longer than expected — long user names, email addresses, titles, file names, and unbroken strings. Apply appropriate handling per context: truncate with an ellipsis and a tooltip/title for single-line constraints, clamp multi-line text to a set number of lines with `-webkit-line-clamp`, and use `overflow-wrap: anywhere` for content like URLs that must wrap. Test each with deliberately long strings. Show me which elements you hardened against overflow.

### 28. Format Numbers, Dates, and Currency
*Area: Typography & Readability. Why it matters: Raw, unformatted numbers and timestamps look unfinished and are hard to read; locale-aware formatting makes data instantly scannable and trustworthy.*

Audit how numbers, currency, dates, and times are displayed across my app. Replace raw values with properly formatted output using `Intl.NumberFormat` and `Intl.DateTimeFormat` — thousands separators on large numbers, consistent currency formatting, human-friendly relative times ("3 hours ago") where appropriate, and clear absolute dates elsewhere. Right-align numeric columns in tables and use tabular figures so digits line up. Show me every place where formatting was improved.

### 29. Add Refined Typographic Details
*Area: Typography & Readability. Why it matters: Tiny typographic touches — proper quotes, non-breaking spaces, optimized rendering — separate a thrown-together interface from one that feels crafted by someone who cares.*

Add a layer of typographic polish across my text content. Replace straight quotes and apostrophes with proper curly typographic ones, use non-breaking spaces to keep related words and units together (preventing awkward single-word orphans), enable kerning and ligatures with `text-rendering: optimizeLegibility`, and use proper en/em dashes where appropriate. Prevent widows and orphans in headings where it looks awkward. Tell me which typographic refinements you applied and where they're most visible.

### 30. Standardize Text Casing and Labels
*Area: Typography & Readability. Why it matters: Mixing "Sign up", "Sign Up", and "SIGN UP" across buttons and labels looks careless; one consistent casing convention makes the whole interface feel intentional.*

Audit all UI labels, button text, headings, menu items, and form labels for inconsistent capitalization. Decide on and apply a consistent casing convention — typically sentence case for most UI text since it's friendlier and more readable, reserving title case or uppercase for specific deliberate uses. Apply casing through the actual content rather than CSS `text-transform` where the underlying text matters for accessibility and copy-paste. List the inconsistencies you found and the convention you standardized on.

### 31. Run a Full Performance Audit
*Area: Performance & Loading Speed. Why it matters: You can't fix what you can't see; a structured audit reveals exactly which assets and code are making your app feel slow before you start optimizing blindly.*

Perform a comprehensive performance audit of my app and identify the biggest opportunities for improvement. Analyze bundle size and what's contributing most to it, identify render-blocking resources, find large unoptimized images, check for expensive re-renders or long JavaScript tasks, and evaluate the loading sequence of critical content. Prioritize the findings by estimated user-facing impact versus effort to fix. Give me a ranked list of the top performance issues with a brief explanation of each and a recommended fix, before making any changes.

### 32. Shrink the JavaScript Bundle
*Area: Performance & Loading Speed. Why it matters: Every kilobyte of JavaScript must be downloaded, parsed, and executed before your app becomes interactive; trimming the bundle is one of the highest-impact speed wins.*

Analyze my JavaScript bundle and reduce its size. Identify large dependencies that could be replaced with lighter alternatives or removed entirely, find code that's imported but never used (dead code), check for duplicate dependencies, and look for heavy libraries being fully imported when only a small part is needed so they can be tree-shaken or imported granularly. Quantify the size of the biggest contributors before and after. Show me what you removed or replaced and the resulting bundle size reduction.

### 33. Add Route-Based Code Splitting
*Area: Performance & Loading Speed. Why it matters: Loading the entire app's code upfront is wasteful when a user only needs the current page; splitting code per route makes the initial load dramatically faster.*

Implement code splitting so users only download the JavaScript needed for what they're currently viewing. Split the bundle at the route level using dynamic imports with lazy loading, and additionally lazy-load heavy components that aren't needed immediately (modals, complex editors, charts, anything below the fold). Add appropriate loading fallbacks (skeletons or spinners) so the experience stays smooth during chunk loading, and consider prefetching the next likely route. Show me which routes and components you split out and the impact on the initial bundle.

### 34. Optimize and Modernize All Images
*Area: Performance & Loading Speed. Why it matters: Images are usually the largest assets on any page, and serving oversized, outdated formats is the single most common cause of slow-loading apps.*

Audit every image in my app and optimize them comprehensively. Serve modern formats like WebP or AVIF with appropriate fallbacks, generate and serve responsively-sized images using `srcset`/`sizes` so phones don't download desktop-sized files, add `loading="lazy"` to below-the-fold images while eager-loading critical above-the-fold ones, and always specify width/height (or aspect-ratio) to prevent layout shift. Compress images to a sensible quality without visible degradation. Report the total image weight before and after and which images were the worst offenders.

### 35. Implement Content-Aware Loading Skeletons
*Area: Performance & Loading Speed. Why it matters: A blank screen or spinner while data loads makes wait time feel longer; skeleton screens that mirror incoming content make the app feel faster even when it isn't.*

Replace blank loading states and generic spinners with skeleton screens for my main data-driven views. Design skeletons that closely match the shape and layout of the actual content that will appear (cards, list rows, text blocks, avatars) so the transition to real content is seamless and doesn't cause layout shift. Add a subtle shimmer or pulse animation to signal active loading, and ensure skeletons appear instantly while data is fetched. Show me which loading states you upgraded to skeletons.

### 36. Virtualize Long Scrolling Lists
*Area: Performance & Loading Speed. Why it matters: Rendering thousands of rows or items at once freezes the browser; virtualization renders only what's visible, keeping even massive lists buttery smooth.*

Find any lists, tables, or feeds in my app that can grow long enough to render hundreds or thousands of DOM nodes, and implement windowing/virtualization so only the visible items (plus a small buffer) are rendered to the DOM. Preserve smooth scrolling, correct scrollbar sizing, and keyboard navigation, and handle variable-height items if present. Make sure dynamic content, selection state, and accessibility still work correctly within the virtualized container. Tell me which lists you virtualized and the rough node-count reduction.

### 37. Eliminate Unnecessary Component Re-renders
*Area: Performance & Loading Speed. Why it matters: Components that re-render when nothing relevant changed waste the user's CPU and make interactions feel laggy; pruning them keeps the UI snappy under load.*

Profile my app for unnecessary re-renders where components update even though their relevant data hasn't changed. Identify the causes — new object/array/function references created on every render, overly broad state or context updates, missing memoization — and fix them with memoization of expensive computations and stable references for props and callbacks, without over-memoizing trivial components. Be careful to fix actual measured problems rather than adding memoization everywhere. Show me the re-render hotspots you found and how you resolved each.

### 38. Cache and Dedupe Data Fetching
*Area: Performance & Loading Speed. Why it matters: Re-fetching the same data on every navigation wastes bandwidth and makes the app feel sluggish; smart caching makes revisited screens load instantly.*

Improve how my app fetches and caches data so it doesn't redundantly re-request the same information. Implement a caching strategy that serves cached data instantly while revalidating in the background (stale-while-revalidate), deduplicates simultaneous identical requests, and caches responses with sensible expiration. Show cached content immediately on revisit rather than a fresh loading state. Describe the caching approach you implemented and which data fetches now benefit from it.

### 39. Add Optimistic UI Updates
*Area: Performance & Loading Speed. Why it matters: Waiting for the server to confirm every action — a like, a toggle, a delete — makes the app feel slow; optimistic updates make interactions feel instant.*

Identify user actions in my app that currently wait for a server round-trip before updating the UI (toggling, liking, adding to a list, editing, deleting) and convert appropriate ones to optimistic updates. Update the UI immediately to reflect the intended outcome, send the request in the background, and gracefully roll back with a clear error message if it fails. Make sure the rollback is reliable and that rapid repeated actions are handled correctly. Show me which actions you made optimistic and how failures are handled.

### 40. Prefetch Data on User Intent
*Area: Performance & Loading Speed. Why it matters: Loading data only after a user clicks adds a noticeable delay; prefetching when they show intent (hovering a link) makes the next screen appear to load instantly.*

Add intent-based prefetching so content for a likely next destination starts loading before the user commits. Prefetch route code and/or data when a user hovers or focuses a link or button for a brief moment, or when a link scrolls into the viewport, so navigation feels instantaneous. Be conservative to avoid wasting bandwidth on unlikely targets, and avoid prefetching on slow connections or when data-saver is enabled. Show me where you added prefetching and the heuristics you used.

### 41. Debounce and Throttle Costly Handlers
*Area: Performance & Loading Speed. Why it matters: Firing a search request or heavy calculation on every keystroke or scroll event overwhelms the app; debouncing and throttling smooth these out without losing responsiveness.*

Find event handlers in my app that run expensive operations too frequently — search-as-you-type firing a request per keystroke, scroll or resize handlers doing heavy work on every event, autosave triggering constantly. Apply debouncing to actions that should wait for the user to pause (like search input, ideally around 300ms) and throttling to actions that should run at a controlled rate during continuous events (like scroll). Ensure the final state is always captured on the trailing edge. Tell me which handlers you optimized and the strategy for each.

### 42. Optimize the Critical Rendering Path
*Area: Performance & Loading Speed. Why it matters: How quickly users see meaningful content depends on the order resources load; prioritizing what's needed for the first paint makes the app feel fast from the very first moment.*

Optimize my app's critical rendering path so meaningful content appears as fast as possible. Inline or prioritize the critical CSS needed for above-the-fold content, defer non-critical CSS and JavaScript, add `preconnect`/`dns-prefetch` resource hints for critical third-party origins, and ensure the most important content isn't blocked behind less important resources. Eliminate render-blocking requests where possible. Walk me through the loading-sequence changes and their expected effect on time-to-first-meaningful-paint.

### 43. Audit Third-Party Script Performance
*Area: Performance & Loading Speed. Why it matters: Analytics, chat widgets, and embeds can quietly add seconds to your load time and block the main thread; auditing them often reveals easy, high-impact wins.*

Audit all third-party scripts in my app — analytics, tag managers, chat widgets, embeds, fonts, and trackers — and assess their performance cost. For each, determine whether it can be loaded lazily, deferred until after interaction, loaded only on pages that need it, or removed if it's not earning its weight. Load non-essential scripts asynchronously and after the main content, and sandbox heavy embeds. Give me a list of every third-party script, its rough performance cost, and the optimization you applied.

### 44. Load Critical Content First
*Area: Performance & Loading Speed. Why it matters: Loading everything at once delays the content users actually came for; a prioritized strategy shows the important stuff immediately and fills in the rest progressively.*

Restructure how my pages load so the most important content is fetched and displayed first, with secondary content loading progressively afterward. Prioritize above-the-fold and primary data, then stream in or lazy-load below-the-fold sections, secondary widgets, and supplementary data. Avoid blocking the primary content render on slow or non-essential requests, and show the page shell immediately. Describe the loading priority you established and which content now loads progressively.

### 45. Run a Full Accessibility Audit
*Area: Accessibility & Inclusivity. Why it matters: Accessibility is often legally required and ethically right — and it overlaps heavily with general usability, so fixing it makes the app better for everyone.*

Conduct a thorough accessibility audit of my app against WCAG 2.1 AA standards. Check color contrast, keyboard navigability, focus management, semantic HTML and landmark structure, form labeling, image alt text, ARIA usage, heading hierarchy, and screen-reader experience. Compile the issues into a prioritized list categorized by severity, noting which are quick fixes versus larger efforts. Present the findings and recommended remediations before making changes so I understand the current state.

### 46. Make Everything Keyboard Navigable
*Area: Accessibility & Inclusivity. Why it matters: Many users — including power users and those with motor disabilities — navigate entirely by keyboard, and an app that traps or excludes them is fundamentally broken for that audience.*

Ensure my entire app is fully operable by keyboard alone. Verify every interactive element is reachable and activatable via Tab/Enter/Space, that the tab order follows a logical reading sequence, that custom interactive components (dropdowns, modals, tabs, menus, sliders) implement expected keyboard interactions (arrow keys, Escape, Home/End per ARIA patterns), and that there are no keyboard traps. Add visible focus styling so keyboard users can always see where they are. Test each major flow by keyboard and report what you fixed.

### 47. Add Clear Visible Focus Indicators
*Area: Accessibility & Inclusivity. Why it matters: Removing focus outlines for aesthetics makes an app unusable for keyboard users; well-designed focus indicators can be both beautiful and accessible.*

Audit focus visibility across my app and ensure every interactive element shows a clear, attractive focus indicator when navigated to by keyboard. Use `:focus-visible` so the indicator appears for keyboard users without cluttering the experience for mouse users, and design the indicator to be highly visible against any background (a sufficiently thick, high-contrast outline or ring with appropriate offset). Never remove focus outlines without providing an equally clear replacement. Show me where focus was invisible or removed and how you restored it accessibly.

### 48. Make Forms Fully Accessible
*Area: Accessibility & Inclusivity. Why it matters: Forms are where accessibility most often fails, and an inaccessible form can completely block a user from signing up, paying, or contacting you.*

Audit all forms in my app for accessibility. Ensure every input has a properly associated `<label>` (not just a placeholder), that related fields are grouped with fieldset/legend where appropriate, that errors are programmatically associated with their fields via `aria-describedby` and announced to screen readers, that required fields are properly indicated, and that the form is fully keyboard operable. Ensure validation errors are perceivable without relying on color alone. Show me each form's accessibility issues and the fixes applied.

### 49. Use Proper Semantic HTML
*Area: Accessibility & Inclusivity. Why it matters: Generic divs for everything force assistive technology to guess at meaning; semantic HTML gives screen readers a clear map of the page and often improves SEO for free.*

Review my markup and replace non-semantic `<div>`/`<span>` soup with appropriate semantic HTML elements where they convey meaning — `<nav>`, `<main>`, `<header>`, `<footer>`, `<article>`, `<section>`, `<aside>`, `<button>` (for actions, never a clickable div), `<a>` (for navigation), lists for list content, and so on. Add ARIA landmarks only where native semantics aren't sufficient. Ensure there's exactly one `<main>` and a logical landmark structure. Tell me the key structural elements you corrected and why.

### 50. Add Meaningful Image Alt Text
*Area: Accessibility & Inclusivity. Why it matters: Images without alt text are invisible to screen reader users and hurt SEO, while decorative images with unnecessary alt text add noise; getting this right serves both audiences.*

Audit every image, icon, and graphic in my app for appropriate alternative text. Provide concise, meaningful alt text for images that convey information (describing the content and purpose, not "image of"), mark purely decorative images with empty alt (`alt=""`) or appropriate ARIA so screen readers skip them, and ensure functional images like icon buttons have accessible labels describing their action. Don't be redundant where adjacent text already describes the image. Show me how you classified and labeled each image.

### 51. Respect Reduced Motion Preferences
*Area: Accessibility & Inclusivity. Why it matters: Animations that delight some users can cause genuine nausea, dizziness, or distraction for others; honoring their system preference is a simple, respectful necessity.*

Add support for users who've requested reduced motion at the system level. Wrap non-essential animations and transitions in a `prefers-reduced-motion: reduce` media query that either removes them or replaces them with a near-instant, subtle alternative (like a simple fade instead of large movement). Pay particular attention to parallax, auto-playing motion, large transforms, and looping animations, while preserving essential motion that communicates meaning. Tell me which animations you made motion-safe and how they behave when reduced motion is on.

### 52. Announce Dynamic Changes to Screen Readers
*Area: Accessibility & Inclusivity. Why it matters: When content updates without a page reload — toasts, validation, search results, status changes — screen reader users miss it entirely unless you announce it.*

Identify dynamic content updates in my app that happen without a full page change and aren't currently announced to screen readers — toast notifications, form validation results, search result counts, loading completions, and live status updates. Implement ARIA live regions (`aria-live` with appropriate politeness, or roles like `status`/`alert`) so these changes are announced appropriately without overwhelming the user. Avoid over-announcing rapidly changing content. Show me which updates you made perceivable and the politeness level chosen for each.

### 53. Build Fully Accessible Modals
*Area: Accessibility & Inclusivity. Why it matters: Modals are notorious accessibility traps — focus escapes, screen readers read the background, Escape doesn't work — and fixing them is essential since modals gate important actions.*

Audit my modal and dialog components for accessibility and fix them to follow the ARIA dialog pattern. Ensure focus moves into the modal when it opens and is trapped within it while open, that focus returns to the triggering element when it closes, that Escape closes it, that the background content is inert and hidden from screen readers (`aria-hidden`/inert), and that the dialog has an accessible name via `aria-labelledby`. Prevent background scrolling while open. Show me the accessibility gaps in my modals and how you closed them.

### 54. Don't Rely on Color Alone
*Area: Accessibility & Inclusivity. Why it matters: Conveying status purely through color (red = error, green = success) excludes colorblind users and anyone in poor lighting; pairing color with text or icons makes meaning universal.*

Find every place in my app where meaning is communicated through color alone — error/success states, status badges, chart series, required-field indicators, links distinguished only by color. Add a redundant non-color cue to each: an icon, a text label, a pattern, an underline for links, or a shape, so the meaning is perceivable without relying on color perception. Keep the color as a reinforcing signal, not the only one. List each color-only signal you found and the additional cue you added.

### 55. Add a Skip-To-Content Link
*Area: Accessibility & Inclusivity. Why it matters: Keyboard and screen reader users otherwise have to tab through the entire navigation on every page load; a skip link is a tiny addition that hugely improves their experience.*

Add a "skip to main content" link as the very first focusable element on the page that lets keyboard and screen reader users bypass the repeated header and navigation. Style it to be visually hidden until it receives keyboard focus, at which point it becomes clearly visible, and ensure activating it moves focus to the main content landmark. If there are other large repeated blocks, consider additional skip links. Confirm it works and tell me where focus lands when activated.

### 56. Fix Page Titles and Language
*Area: Accessibility & Inclusivity. Why it matters: Missing or generic page titles and language attributes confuse screen readers, hurt SEO, and make browser tabs useless; fixing them is quick and broadly beneficial.*

Ensure every page/route in my app has a unique, descriptive document title that reflects its content and updates correctly on client-side navigation, and that the `<html lang>` attribute is set correctly (and updated for any multilingual content). Make titles follow a consistent, useful pattern (e.g. specific page name first, then app name) so browser tabs, history, and bookmarks are meaningful. Verify titles announce correctly to screen readers on navigation. Show me the title pattern you implemented and confirm the language attributes.

### 57. Add Small Purposeful Micro-Interactions
*Area: Motion & Micro-interactions. Why it matters: Small, responsive animations on hover, tap, and state changes make an interface feel alive and give users satisfying feedback that their actions registered.*

Add tasteful micro-interactions throughout my app to make it feel responsive and alive. Focus on interactive elements: subtle scale or color shifts on button press, smooth transitions on hover, gentle feedback when toggling switches or checkboxes, and satisfying confirmation animations on successful actions. Keep them fast (typically 150–250ms), purposeful, and consistent in their easing, enhancing usability rather than decorating for its own sake. Respect reduced-motion preferences. Show me which interactions you added and the timing/easing conventions you established.

### 58. Standardize Animation Timing and Easing
*Area: Motion & Micro-interactions. Why it matters: Animations with mismatched speeds and easing curves feel chaotic; a shared motion system makes every transition feel like part of the same considered experience.*

Audit all the animations and transitions in my app and standardize them into a coherent motion system. Define a small set of duration tokens (e.g. fast ~150ms, base ~250ms, slow ~400ms) and easing curves (a default ease for most transitions, an ease-out for entrances, an ease-in for exits) and apply them consistently, replacing arbitrary or linear timings. Match duration to the distance and importance of the movement. Tell me the motion tokens you established and which animations you brought in line.

### 59. Implement Smooth Page Transitions
*Area: Motion & Micro-interactions. Why it matters: Abrupt jumps between pages feel jarring and disorienting; smooth transitions provide spatial continuity that helps users understand how they moved through the app.*

Add smooth transitions between page/route changes in my app so navigation feels continuous rather than abrupt. Implement subtle enter/exit animations (such as a quick fade or directional slide) that give a sense of spatial relationship between views, keeping them fast enough not to slow navigation. Ensure scroll position is handled sensibly and that transitions don't block interaction or cause layout shift. Respect reduced-motion settings. Show me the transition pattern you implemented and how it behaves between key screens.

### 60. Animate Value and State Changes
*Area: Motion & Micro-interactions. Why it matters: When a number, progress bar, or status changes instantly, users can miss it; animating the change draws the eye and helps them perceive what updated.*

Find places where values or states change abruptly and would benefit from animation — counters and statistics, progress bars, expanding/collapsing sections, and items appearing or disappearing from lists. Add smooth transitions: count numbers up to their new value, animate progress fills, smoothly expand/collapse height (or use a CSS grid/clip technique to avoid janky height animations), and animate list insertions and removals so they don't pop jarringly. Keep these subtle and quick. Show me which state changes you animated.

### 61. Refine Hover and Focus Feedback
*Area: Motion & Micro-interactions. Why it matters: Clear, consistent feedback on hover and focus tells users what's interactive before they click, reducing hesitation and making the interface feel responsive and learnable.*

Audit hover and focus feedback across all interactive elements in my app and make it consistent and clear. Ensure every clickable element gives obvious visual feedback on hover (cursor change plus a subtle color, background, or elevation shift) and an equivalent clear state on keyboard focus, so users can always tell what's interactive. Make sure non-interactive elements don't falsely appear clickable, and that touch devices (which have no hover) still get clear active feedback. Tell me where feedback was missing or inconsistent and how you standardized it.

### 62. Add Tasteful Scroll-Triggered Animations
*Area: Motion & Micro-interactions. Why it matters: Subtle entrance animations as content scrolls into view add a sense of polish and guide attention, making long pages feel dynamic and considered.*

Add subtle scroll-triggered reveal animations to content as it enters the viewport on longer pages, using an Intersection Observer for performance rather than scroll event listeners. Keep the effect understated — a gentle fade and slight upward movement is usually enough — and ensure each element animates only once, doesn't delay content readability, and doesn't cause layout shift. Critically, make the content fully visible and functional even when reduced motion is requested or JavaScript fails. Show me where you added reveals and how they degrade gracefully.

### 63. Smooth the Loading-To-Content Transition
*Area: Motion & Micro-interactions. Why it matters: A harsh swap from loading state to real content is jarring; a smooth transition makes data appearing feel natural and reinforces perceived speed.*

Improve the transitions between loading states and loaded content throughout my app. When skeletons or spinners are replaced by real content, cross-fade or smoothly transition rather than abruptly swapping, and avoid sudden layout shifts as content fills in by reserving correct space beforehand. Ensure fast responses don't cause a jarring flash of loading state (consider a small delay before showing a spinner, and a minimum display duration once shown). Show me which loading transitions you smoothed.

### 64. Improve Drag-And-Drop Interface Affordances
*Area: Motion & Micro-interactions. Why it matters: Drag-and-drop is powerful but invisible without clear cues; good affordances tell users what's draggable, where it can go, and what will happen when they drop.*

If my app has any drag-and-drop or reorderable interfaces, improve their affordances and feedback. Make draggable elements clearly indicate they can be dragged (grab cursor, drag handle, subtle hover cue), show a clear visual representation while dragging, highlight valid drop targets and indicate the insertion point, and animate items smoothly into their new positions on drop. Ensure there's also a keyboard-accessible way to reorder for accessibility. Show me which drag interactions you enhanced and the cues you added.

### 65. Add Mobile Gesture Support
*Area: Motion & Micro-interactions. Why it matters: On touch devices, users expect to swipe, pull, and drag; supporting these natural gestures makes a web app feel native rather than like a desktop site squeezed onto a phone.*

Enhance my app's touch experience by adding appropriate mobile gestures where they'd feel natural — swipe to dismiss or reveal actions on list items, swipe between tabs or carousel slides, and pull-to-refresh on primary feeds. Implement them with smooth, finger-tracking motion and clear visual feedback, sensible thresholds, and the ability to cancel mid-gesture. Ensure gestures don't conflict with native browser behaviors like back-swipe or scrolling. Tell me which gestures you added and where.

### 66. Add Subtle Success Moments
*Area: Motion & Micro-interactions. Why it matters: Acknowledging when users complete something meaningful — finishing onboarding, hitting a milestone — creates an emotional high point that builds attachment to your product.*

Identify meaningful completion moments in my app — finishing onboarding, completing a first key action, reaching a milestone, successfully submitting something important — and add a subtle moment of delight to acknowledge them. This could be a brief satisfying animation, a checkmark that draws itself, a gentle confetti burst for major milestones, or an encouraging confirmation message, calibrated so it feels rewarding without being annoying or slowing the user down. Reserve the bigger moments for genuinely significant achievements. Show me which moments you enhanced and how.

### 67. Add Real-Time Inline Validation
*Area: Forms & Inputs. Why it matters: Making users submit a form just to discover their errors is frustrating; validating as they go and confirming valid input reduces errors and abandonment.*

Improve my forms with helpful inline validation. Validate fields at the right moment — generally on blur (when leaving a field) and then on change once an error is shown, rather than aggressively on every keystroke from the start — and show clear, specific error messages directly beside the relevant field. Confirm valid input where helpful (e.g. a subtle checkmark) and reflect the submit state appropriately. Ensure errors are accessible and announced. Show me which forms you improved and the validation timing you used.

### 68. Write Clear Helpful Error Messages
*Area: Forms & Inputs. Why it matters: Vague errors like "Invalid input" leave users stuck; specific, friendly messages that explain how to fix the problem dramatically improve form completion.*

Audit all the error and validation messages in my app and rewrite the unhelpful ones. Make each message specific (what exactly is wrong), constructive (how to fix it), and human (friendly, not robotic or blaming) — for example replace "Invalid input" with "Please enter a valid email address like name@example.com". Avoid technical jargon and error codes in user-facing copy, and place messages where the user is looking. Show me the worst offenders and the improved messaging you wrote for each.

### 69. Polish Input Field Design and States
*Area: Forms & Inputs. Why it matters: Inputs are where users spend real effort, and unclear states, cramped sizing, or missing focus feedback make data entry feel tedious and error-prone.*

Refine the design and interaction states of all my form inputs for clarity and comfort. Ensure inputs have adequate size and padding for comfortable typing and tapping, a clear visible label (not relying on placeholder as label), distinct and accessible states for default/focus/filled/error/disabled, appropriate input types and `inputmode` for mobile keyboards, and sensible autocomplete attributes. Make the focus state prominent and the error state unmistakable. Tell me which input improvements you applied across the form components.

### 70. Add Smart Input Masking and Formatting
*Area: Forms & Inputs. Why it matters: Letting users type phone numbers, card numbers, or dates in any format leads to errors; smart formatting guides them and reduces mistakes without feeling restrictive.*

Add intelligent input formatting and masking to fields that benefit from it — phone numbers, credit card numbers, dates, currency amounts, and similar structured inputs. Format the value as the user types (e.g. grouping card digits, adding phone number separators) while keeping the underlying stored value clean, and guide them with the expected pattern without blocking legitimate entry. Handle paste and editing gracefully. Show me which inputs you added formatting to and how each behaves.

### 71. Add Form Autosave and Recovery
*Area: Forms & Inputs. Why it matters: Losing a half-filled form to an accidental refresh is infuriating and a common reason users give up; autosave protects their work and their patience.*

Add autosave and draft recovery to my longer or important forms so users don't lose their work. Periodically and on-change save form state (debounced) to a draft, show a subtle "saving/saved" indicator so users trust it's working, and restore the draft if they navigate away and return or accidentally refresh. Warn before discarding unsaved changes on navigation. Be mindful of what's appropriate to persist (avoid storing sensitive fields insecurely). Show me which forms got autosave and how recovery works.

### 72. Improve Multi-Step Form Experience
*Area: Forms & Inputs. Why it matters: Long forms feel daunting as a single wall of fields; breaking them into clear steps with visible progress reduces anxiety and increases completion.*

If I have any long or complex forms, improve them by breaking them into a logical multi-step flow with a clear progress indicator showing total steps and current position. Validate each step before advancing, preserve entered data when moving backward and forward, allow editing previous steps, and make the final step a clear review-and-submit. Keep related fields grouped per step and don't lose data on accidental navigation. Show me how you structured the steps and the progress indication.

### 73. Upgrade Select and Dropdown Inputs
*Area: Forms & Inputs. Why it matters: Native selects are clunky for long or searchable lists, and poorly built custom ones break keyboard access; getting these right matters because they're everywhere.*

Improve the select and dropdown inputs in my app. For long option lists, add search/filtering within the dropdown; for multi-selection, show selected items clearly as removable chips; and ensure all custom dropdowns are fully keyboard accessible (arrow keys, type-ahead, Enter, Escape) and screen-reader friendly following the combobox/listbox ARIA pattern. Ensure they position correctly without getting clipped and work well on mobile. Tell me which dropdowns you upgraded and the capabilities you added.

### 74. Improve Password Field UX
*Area: Forms & Inputs. Why it matters: Password fields are a frequent point of friction and failed sign-ups; small improvements like a visibility toggle and clear requirements meaningfully reduce abandonment.*

Improve all password input fields in my app following modern best practices. Add a show/hide visibility toggle, display password requirements clearly and ideally validate them in real time with a simple strength indicator, allow password managers to work correctly (proper autocomplete attributes, no blocking paste), and on signup consider whether a "confirm password" field is even necessary when a visibility toggle is present. Provide clear feedback without being punitive. Show me the password UX improvements you made.

### 75. Add Input Hints and Affordances
*Area: Forms & Inputs. Why it matters: Users often hesitate at form fields unsure what's expected; helper text, examples, and clear optional/required indicators remove that uncertainty and speed completion.*

Add clarifying affordances to my form fields where users might be uncertain what to enter. Provide concise helper text or examples for fields with specific format or content expectations, clearly distinguish required from optional fields (and be consistent about which you mark), add character counters where there are length limits, and use placeholder text correctly as a hint rather than as the label. Keep guidance concise and only where it adds value. Show me which fields you clarified and how.

### 76. Clarify Form Submission Feedback
*Area: Forms & Inputs. Why it matters: After hitting submit, uncertainty about whether it worked leads to double-submissions and anxiety; clear submission states and outcomes give users confidence.*

Improve the feedback during and after form submission across my app. While submitting, disable the submit button and show a loading state to prevent double-submission; on success give clear confirmation and a sensible next step (redirect, success message, or reset); and on failure show a clear error that preserves the user's entered data so they don't have to re-type everything. Handle slow networks and partial failures gracefully. Show me how each form now communicates its submission outcome.

### 77. Build a Toast Notification System
*Area: Feedback & System States. Why it matters: Without a consistent way to confirm actions and surface alerts, users are left guessing whether things worked; a good notification system provides reliable, non-intrusive feedback.*

Implement a consistent toast/notification system for transient feedback across my app. Support distinct types (success, error, warning, info) with appropriate styling and icons, auto-dismiss after a sensible duration (with errors persisting longer or until dismissed), allow manual dismissal, stack multiple notifications cleanly, and position them consistently without blocking important content. Make them accessible via ARIA live regions and pausable on hover. Replace any ad-hoc alerts with this system. Show me the notification system and where it's now used.

### 78. Handle Loading, Empty, Error, Success States
*Area: Feedback & System States. Why it matters: Every data-driven view has four states — loading, empty, error, and success — and apps that only design the "happy path" feel broken the moment anything else happens.*

Go through every data-fetching view in my app and ensure all four key states are properly designed and handled: loading (skeleton or spinner), empty (no data yet, with guidance), error (something went wrong, with a retry option), and success (the actual content). Right now some views likely only handle the success case and break or show nothing otherwise. Implement the missing states consistently so no view ever leaves the user staring at a blank or frozen screen. Show me which views were missing states and what you added.

### 79. Add Graceful Error Boundaries
*Area: Feedback & System States. Why it matters: One component crashing shouldn't take down your entire app into a blank white screen; error boundaries contain failures and offer users a way to recover.*

Add error boundaries around the major sections of my app so that if a component throws an unexpected error, it's caught and displays a friendly fallback UI with a recovery option (retry, reload, or go back) instead of crashing the whole interface into a blank screen. Scope boundaries sensibly so a failure in one area doesn't take down unrelated parts, log the error for debugging, and avoid exposing raw technical error details to users. Show me where you placed boundaries and what the fallback looks like.

### 80. Confirm Destructive and Irreversible Actions
*Area: Feedback & System States. Why it matters: A misclicked delete that can't be undone destroys user trust instantly; confirmation (or better, undo) for destructive actions prevents catastrophic mistakes.*

Audit my app for destructive or irreversible actions — deleting, removing, overwriting, canceling, bulk operations — and ensure each has appropriate friction so users don't trigger them accidentally. For significant actions add a confirmation dialog that clearly states the consequence and what's being affected (naming the specific item), with the confirm button labeled by the action ("Delete project") rather than a generic "OK". Style destructive confirm buttons distinctly. Where feasible, prefer an undo pattern over a confirmation prompt. Show me which actions you protected and how.

### 81. Add Undo for Reversible Actions
*Area: Feedback & System States. Why it matters: Undo is more forgiving and less annoying than constant confirmation prompts — it lets users move fast while still recovering from mistakes, a hallmark of polished software.*

Implement an undo pattern for appropriate user actions in my app — deletions, edits, status changes, and bulk operations — as a more elegant alternative to confirmation dialogs where suitable. When the user performs the action, apply it immediately but show a brief toast with an "Undo" option for several seconds that reverses it if clicked. Ensure the undo reliably restores the exact previous state, and handle the case where the user navigates away. Show me which actions now support undo and how long the window lasts.

### 82. Handle Offline and Network Errors
*Area: Feedback & System States. Why it matters: Users on flaky mobile connections will inevitably lose network, and an app that silently fails or hangs feels broken; clear offline handling keeps it trustworthy.*

Make my app handle network failures and offline conditions gracefully. Detect when the user goes offline and show a clear, non-alarming indicator, queue or disable actions that require connectivity, and automatically recover when the connection returns. For failed requests, distinguish network errors from server errors in the messaging, and offer a retry. Avoid infinite spinners that hang forever — always time out with a clear error and recovery path. Show me how the app now responds to offline and failed-request scenarios.

### 83. Show Progress for Long Operations
*Area: Feedback & System States. Why it matters: When an action takes more than a moment — uploads, processing, generation — a frozen UI makes users assume it's broken; clear progress keeps them informed and patient.*

Find operations in my app that can take more than a couple of seconds — file uploads, data processing, report generation, batch actions, AI generation — and add clear progress feedback. Use a determinate progress bar with percentage where progress is measurable, an indeterminate indicator with descriptive status text where it isn't, and communicate what's happening ("Uploading 3 of 10…"). Keep the UI responsive and, where possible, allow cancellation. Show me which long operations now have progress feedback and what kind.

### 84. Improve Perceived Performance Everywhere
*Area: Feedback & System States. Why it matters: How fast an app feels often matters more than how fast it actually is; perception techniques make the experience feel instant even when real work is happening behind the scenes.*

Apply perceived-performance techniques throughout my app so it feels faster regardless of actual speed. Respond to user input instantly even if the result takes time (immediate visual acknowledgment of taps and clicks), show skeletons that match incoming content, optimistically reflect actions before server confirmation, prioritize rendering visible content first, and avoid blocking the UI during background work. Eliminate any moments where the app appears frozen or unresponsive. Tell me which perception improvements you applied and where they'll be most felt.

### 85. Add Contextual Help and Tooltips
*Area: Feedback & System States. Why it matters: Users hit moments of confusion at specific spots in any interface; well-placed contextual help answers their question right where it arises, reducing frustration and support requests.*

Identify spots in my app where users might be confused or need clarification — unfamiliar terms, icon-only buttons, complex features, fields with non-obvious requirements — and add contextual help. Use accessible tooltips for brief clarifications (triggered by hover and keyboard focus, not hover-only), info popovers for longer explanations, and inline helper text where appropriate. Ensure tooltips are positioned to stay on-screen, are dismissible, and don't trap or obscure content. Show me where you added contextual help and what form each takes.

### 86. Standardize Status and State Indicators
*Area: Feedback & System States. Why it matters: When "active", "pending", and "error" states look different in every part of the app, users have to relearn the visual language constantly; a consistent system makes status instantly readable.*

Audit how status and state are visually communicated across my app — badges, pills, dots, and labels for things like active/inactive, online/offline, success/pending/failed, read/unread — and unify them into a consistent system. Establish a standard set of status styles (color plus icon plus label, never color alone) and apply them uniformly everywhere status appears, so the same state always looks the same. Ensure they're accessible and distinguishable. Show me the status system you established and where you applied it.

### 87. Clarify Primary Navigation Structure
*Area: Navigation & Information Architecture. Why it matters: If users can't quickly figure out where things are and where they currently are, the whole app feels confusing regardless of how good individual screens look.*

Evaluate my app's primary navigation for clarity and improve it. Ensure the main navigation items are clearly labeled in user-friendly language, that the current location is always obvious through an active state, that the structure is shallow and logical (related items grouped, important destinations easy to reach), and that it works well on both desktop and mobile. Remove or consolidate redundant or rarely-used items cluttering the primary nav. Walk me through the navigation issues you found and the structural improvements you made.

### 88. Add a Command Palette
*Area: Navigation & Information Architecture. Why it matters: Power users love being able to jump anywhere and do anything from the keyboard; a command palette (Cmd/Ctrl+K) is a beloved feature that makes an app feel fast and modern.*

Add a command palette to my app, invoked with Cmd/Ctrl+K (and an accessible button), that lets users quickly search and jump to pages, find content, and trigger common actions from anywhere. Include fuzzy search across navigable destinations and key commands, full keyboard navigation (arrow keys, Enter, Escape), recent or suggested items when empty, and clear grouping of result types. Make it fast and accessible. Show me what's searchable and actionable through the palette and how it's wired up.

### 89. Show Clear Active Location Indicators
*Area: Navigation & Information Architecture. Why it matters: Users constantly need to know "where am I?" and without clear active states in navigation, they lose their bearings and feel disoriented.*

Ensure my app always clearly indicates the user's current location within the navigation. Add or improve active-state styling on navigation items, sidebar links, tabs, and breadcrumbs so the current page/section is unmistakable, and make sure these active states update correctly during client-side navigation including for nested routes (a parent section should show active when a child page is open). Make the active indication accessible (e.g. `aria-current`). Show me where active indication was missing or wrong and how you fixed it.

### 90. Add Breadcrumbs for Deep Navigation
*Area: Navigation & Information Architecture. Why it matters: In apps with nested sections, users get lost and struggle to navigate back up; breadcrumbs show the path and provide quick escape routes to parent levels.*

If my app has hierarchical or deeply nested sections, add breadcrumb navigation to show users where they are in the hierarchy and let them jump back to any ancestor level. Generate breadcrumbs accurately from the route/content hierarchy, make each level clickable except the current page, truncate gracefully on small screens, and use proper semantic markup with `aria-label` for accessibility. Don't add breadcrumbs where the hierarchy is too shallow to warrant them. Show me where you added breadcrumbs and how they're generated.

### 91. Improve In-App Search Experience
*Area: Navigation & Information Architecture. Why it matters: When users search, they're expressing clear intent, and a slow or unhelpful search experience frustrates them at a high-stakes moment; great search makes the app feel capable.*

Improve the search experience in my app. Add helpful affordances like search-as-you-type with debounced queries, clear loading and empty/no-results states (with suggestions when nothing matches), result highlighting of matched terms, recent searches, and full keyboard support. Make the search input prominent and easy to invoke, handle typos forgivingly where possible, and ensure results are relevant and scannable. Show me the search improvements you made and how the experience flows from query to result.

### 92. Fix Scroll Position and Back Behavior
*Area: Navigation & Information Architecture. Why it matters: Losing your scroll position when navigating back — being dumped at the top of a long list you were halfway through — is a deeply frustrating bug that makes browsing feel hostile.*

Fix scroll and back-navigation behavior in my app. Ensure that when users navigate back to a previous page (especially long, scrollable lists or feeds), their scroll position is restored where they left off, while new navigations to fresh pages start at the top. Make sure the browser back/forward buttons behave intuitively and that any in-app back buttons go somewhere sensible. Preserve relevant state (filters, expanded sections) across back navigation where appropriate. Show me which navigation behaviors you corrected.

### 93. Add Useful Keyboard Shortcuts
*Area: Navigation & Information Architecture. Why it matters: Keyboard shortcuts let frequent users fly through common tasks, and even casual users appreciate small ones; they signal that an app respects its users' efficiency.*

Add thoughtful keyboard shortcuts for common actions in my app to speed up frequent users. Implement shortcuts for high-value actions (creating new items, saving, searching, navigating between key views, closing dialogs with Escape) following conventional patterns where they exist, ensure they don't conflict with browser or assistive-technology shortcuts or fire while typing in inputs, and provide a discoverable shortcuts help dialog (commonly triggered by "?"). Show me which shortcuts you added and how users can discover them.

### 94. Reduce Friction in Key Flows
*Area: Navigation & Information Architecture. Why it matters: The number of steps and decisions between a user's intent and its completion directly determines how usable an app feels; removing unnecessary friction is one of the highest-leverage improvements possible.*

Pick my app's most important user flows (such as signing up, creating the core object, and completing the primary task) and analyze each step for friction. Identify unnecessary steps, redundant confirmations, premature requests for information, and points of confusion, then streamline the flow — combining or removing steps, deferring non-essential decisions, applying smart defaults, and reducing required input. Don't sacrifice clarity or safety for brevity. Walk me through each flow's friction points and the specific streamlining you applied.

### 95. Make Data Tables Genuinely Usable
*Area: Data Display & Tables. Why it matters: Tables are where users do real work with data, and a table that can't sort, scrolls awkwardly, or loses its headers makes that work painful; a well-built table is a productivity multiplier.*

Upgrade the data tables in my app for real-world usability. Add column sorting with clear indicators, make headers sticky so they stay visible while scrolling long tables, handle horizontal overflow gracefully on small screens (such as a responsive card layout or a clearly-indicated scroll region rather than breaking the layout), ensure adequate row height and cell padding for scannability, and support row hover highlighting. Keep it keyboard and screen-reader accessible with proper table semantics. Show me the table improvements you applied.

### 96. Add Powerful Filtering and Sorting
*Area: Data Display & Tables. Why it matters: As data grows, users need to slice it down to what's relevant; robust filtering and sorting turn an overwhelming list into a tool they can actually use.*

Add comprehensive filtering and sorting to my app's data-heavy views. Provide intuitive filter controls appropriate to the data (search, category/status filters, date ranges, multi-select facets), allow combining multiple filters, clearly show which filters are active with easy removal, and reflect filter/sort state in the URL so it's shareable and survives refresh. Always provide a clear empty/no-results state with a way to reset filters. Show me the filtering and sorting capabilities you added and how state is preserved.

### 97. Add Pagination or Infinite Scroll
*Area: Data Display & Tables. Why it matters: Loading thousands of records at once is slow and overwhelming; the right strategy keeps things fast and digestible while matching how users actually browse the data.*

Implement an appropriate strategy for handling large datasets in my list and table views — either traditional pagination (better for tasks where users need to reference specific pages, navigate precisely, and know the total) or infinite scroll / "load more" (better for exploratory, feed-like browsing). Whichever fits, make it performant, show clear loading indicators for additional pages, handle the end-of-list state, and preserve position on back-navigation. Tell me which approach you chose for each view and why it fits.

### 98. Polish Charts and Data Visualization
*Area: Data Display & Tables. Why it matters: Charts communicate at a glance what raw numbers can't, but poorly designed ones mislead or confuse; clear, well-labeled visualizations make your data instantly understandable and trustworthy.*

Review any charts and data visualizations in my app and improve their clarity and design. Ensure each chart is the right type for the data and the question it answers, has clear labels, axes, and legends, uses an accessible and consistent color scheme (distinguishable without color alone, with sufficient contrast), and handles empty and loading states, and is responsive on mobile. Add helpful interactivity like tooltips on hover/focus where it aids understanding, and avoid chart-junk that distracts from the data. Show me which visualizations you improved and how.

### 99. Add Bulk Selection and Actions
*Area: Data Display & Tables. Why it matters: Forcing users to act on items one at a time is tedious when they need to manage many; bulk selection and actions respect their time and make the app feel powerful.*

Add multi-select and bulk actions to my list and table views where users may need to act on multiple items at once. Implement row selection with checkboxes plus a "select all" (clarifying whether it selects the current page or the full dataset), show a clear contextual action bar when items are selected indicating how many are chosen, and offer relevant bulk operations (delete, update status, export, move) with appropriate confirmation for destructive ones. Maintain selection sensibly across interactions. Show me where you added bulk actions and which operations are supported.

### 100. Add Data Export and Sharing
*Area: Data Display & Tables. Why it matters: Users often need to get their data out — into a spreadsheet, a report, or a shareable link — and an app that traps data inside it feels limiting; easy export builds confidence and utility.*

Add data export and sharing capabilities to the relevant views in my app. Allow users to export the data they're viewing in useful formats (such as CSV for tabular data, respecting current filters and sorting), generate the file cleanly with proper headers and formatting, give feedback during export of large datasets, and where appropriate offer shareable links or print-friendly views. Ensure exports only include data the user is authorized to access. Show me which views now support export/sharing and the formats offered.

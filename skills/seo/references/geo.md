---
name: seo-geo
description: >
  Optimize content for AI Overviews (formerly SGE), ChatGPT web search,
  Perplexity, and other AI-powered search experiences. Generative Engine
  Optimization (GEO) analysis including brand mention signals, AI crawler
  accessibility, llms.txt compliance, passage-level citability scoring, and
  platform-specific optimization. Use when user says "AI Overviews", "SGE",
  "GEO", "AI search", "LLM optimization", "Perplexity", "AI citations",
  "ChatGPT search", "AI visibility", "AEO", "answer engine optimization",
  "LLMO", "LLM optimization", "optimize for ChatGPT", "optimize for Perplexity",
  "zero-click search", "LLM mentions", or "optimize for Claude/Gemini".
  (Consolidates former seo-geo-aeo and ai-seo skills.)
user-invokable: true
argument-hint: "[url]"
license: MIT
metadata:
  author: AgriciDaniel
  version: "1.7.0"
  category: seo
---

# AI Search / GEO Optimization (February 2026)

## Key Statistics

| Metric | Value | Source |
|--------|-------|--------|
| AI Overviews reach | 1.5 billion users/month across 200+ countries | Google |
| AI Overviews query coverage | 50%+ of all queries | Industry data |
| AI-referred sessions growth | 527% (Jan-May 2025) | SparkToro |
| ChatGPT weekly active users | 900 million | OpenAI |
| Perplexity monthly queries | 500+ million | Perplexity |

## AI Mode & query fan-out (added 2026-07-04)

Google **AI Mode** (conversational search tab, Gemini + search index + Knowledge Graph) is now a
first-class surface alongside AI Overviews. Google confirms it uses **query fan-out**: the engine
decomposes a query into related subqueries/subtopics and retrieves per-passage across them. GEO
implications (these are checks, not new disciplines — the AI-Optimization-Guide calibration below
still governs):

- **Cover the fan-out, not just the head term.** A page competing for a topic must answer the
  subquestions AI Mode fans out to (the FAQ-coverage audit below is the mechanism — mine real
  subquestions, verify per-passage answers).
- **Passage self-containment matters more.** Each H2/H3 section should stand alone: question-shaped
  heading → direct answer in the first sentences → verifiable fact. AI Mode lifts passages, not pages.
- **Zero-click reality (calibrate expectations):** ~68% of US searches Jan–Apr 2026 ended without an
  external click; when an AI Overview is present, top-organic CTR drops ~60% (≈28.5%→11.2%).
  Cited-in-AI brands still earn ~35% more clicks than uncited competitors — measure presence-in-answers
  (Ahrefs Brand Radar lane), not rank alone. *(Aggregator-sourced stats, medium confidence — re-verify
  before citing to a client.)*

**Operational check — Cloudflare AI-bot default block (HIGH priority for our stack):** Cloudflare
now blocks AI crawlers **by default** on proxied zones. DD/RH/TS/HR sites all sit behind Cloudflare —
robots.txt allowing GPTBot/ClaudeBot/PerplexityBot means nothing if the CDN 403s them first. Every
GEO audit on a Cloudflare-proxied site MUST verify actual bot reachability (fetch as the bot UA or
check CF dashboard AI-crawler settings + logs), not just robots.txt text. A silent CF block is a
critical finding.

## Critical Insight: Brand Mentions > Backlinks

**Brand mentions correlate 3x more strongly with AI visibility than backlinks.**
(Ahrefs December 2025 study of 75,000 brands)

| Signal | Correlation with AI Citations |
|--------|------------------------------|
| YouTube mentions | ~0.737 (strongest) |
| Reddit mentions | High |
| Wikipedia presence | High |
| LinkedIn presence | Moderate |
| Domain Rating (backlinks) | ~0.266 (weak) |

**Only 11% of domains** are cited by both ChatGPT and Google AI Overviews for the same query, so platform-specific optimization is essential.

---

## Calibration: what Google itself says are NOT ranking levers

Google published official guidance — the **AI Optimization Guide, 2026-05-15**
(`https://developers.google.com/search/docs/fundamentals/ai-optimization-guide`). Read it before
over-investing. It states plainly: AEO/GEO are **not separate disciplines — they are SEO** (AI
features run on core ranking + quality systems). It explicitly lists as **myths / not required**:

| Over-invested "AEO hack" | Google's position | Our stance |
|---|---|---|
| Structured data / schema as an AI-ranking lever | Not required to appear in AI features | Keep schema for rich-result eligibility + entity clarity; **don't treat it as an AEO ranking boost** |
| `llms.txt` & special AI markup | Not used by Google AI features | Fine to publish for tidiness; **stop counting it as a GEO win** (it's "medium effort" below, but low actual impact) |
| Content chunking for AI | No requirement | Write naturally; good H2/H3 structure already does this |
| Rewriting content just for AI | Discouraged | Write for humans; SEO fundamentals carry over |

**Core message:** "Is SEO still relevant for generative AI search? Yes." AI features are rooted
in core ranking + quality systems — Google AI uses the search index; ChatGPT does a web search
then summarizes. So **traditional SEO + E-E-A-T + earned brand presence (off-page) are the real
levers.** The biggest AEO wins are the cheap on-page ones (answer-first blocks, question headings,
cited stats) plus third-party presence — not schema/llms.txt theater. Treat the llms.txt and
schema items later in this doc as hygiene, not growth.

---

## FAQ coverage audit — answer the real questions (for AI citations)

AI engines cite pages that directly answer the questions people actually ask. Don't invent FAQs —
mine the real ones and verify the page covers them.

**Workflow (per page/topic):**
1. **Harvest real questions** for the topic:
   - Google SERP **"People Also Ask"** for the primary keyword (expand 2-3 levels).
   - **AlsoAsked** / **AnswerThePublic** (question trees), **Reddit/Quora** threads, and the
     **GSC 8+ word query** export (see `references/google.md` — these ARE the question-shaped
     queries you already get impressions for).
   - DataForSEO (if available): `serp` PAA extraction; Ahrefs "Questions" filter on the keyword.
2. **Diff against the page:** list the harvested questions, mark each as Covered / Partial / Missing
   in the page's body + FAQ block.
3. **Close gaps:** add a 4-6 item FAQ where each answer is **answer-first (≤40-60w, self-contained,
   quotable)** — that passage is what AI lifts. Add `FAQPage` JSON-LD (AI-citation benefit; not a
   Google rich-result lever for commercial sites — see calibration above).
4. **Re-check** the highest-impression "near-miss" questions (position 8-20) first — fastest wins.

This is the active version of `blog-post-contract.md §4.5` (real-question ideation). `/review seo`
with the keyword map fed in will flag FAQ/keyword gaps; this workflow is how you fill them.

---

## GEO Analysis Criteria (Updated)

### 1. Citability Score (25%)

**Optimal passage length: 134-167 words** for AI citation.

**Strong signals:**
- Clear, quotable sentences with specific facts/statistics
- Self-contained answer blocks (can be extracted without context)
- Direct answer in first 40-60 words of section
- Claims attributed with specific sources
- Definitions following "X is..." or "X refers to..." patterns
- Unique data points not found elsewhere

**Weak signals:**
- Vague, general statements
- Opinion without evidence
- Buried conclusions
- No specific data points

### 2. Structural Readability (20%)

**92% of AI Overview citations come from top-10 ranking pages**, but 47% come from pages ranking below position 5, demonstrating different selection logic.

**Strong signals:**
- Clean H1->H2->H3 heading hierarchy
- Question-based headings (matches query patterns)
- Short paragraphs (2-4 sentences)
- Tables for comparative data
- Ordered/unordered lists for step-by-step or multi-item content
- FAQ sections with clear Q&A format

**Weak signals:**
- Wall of text with no structure
- Inconsistent heading hierarchy
- No lists or tables
- Information buried in paragraphs

### 3. Multi-Modal Content (15%)

Content with multi-modal elements sees **156% higher selection rates**.

**Check for:**
- Text + relevant images
- Video content (embedded or linked)
- Infographics and charts
- Interactive elements (calculators, tools)
- Structured data supporting media

### 4. Authority & Brand Signals (20%)

**Strong signals:**
- Author byline with credentials
- Publication date and last-updated date
- Citations to primary sources (studies, official docs, data)
- Organization credentials and affiliations
- Expert quotes with attribution
- Entity presence in Wikipedia, Wikidata
- Mentions on Reddit, YouTube, LinkedIn

**Weak signals:**
- Anonymous authorship
- No dates
- No sources cited
- No brand presence across platforms

### 5. Technical Accessibility (20%)

**AI crawlers do NOT execute JavaScript.** Server-side rendering is critical.

**Check for:**
- Server-side rendering (SSR) vs client-only content
- AI crawler access in robots.txt
- llms.txt file presence and configuration
- RSL 1.0 licensing terms

---

## AI Crawler Detection

Check `robots.txt` for these AI crawlers:

| Crawler | Owner | Purpose |
|---------|-------|---------|
| GPTBot | OpenAI | ChatGPT web search |
| OAI-SearchBot | OpenAI | OpenAI search features |
| ChatGPT-User | OpenAI | ChatGPT browsing |
| ClaudeBot | Anthropic | Claude web features |
| PerplexityBot | Perplexity | Perplexity AI search |
| CCBot | Common Crawl | Training data (often blocked) |
| anthropic-ai | Anthropic | Claude training |
| Bytespider | ByteDance | TikTok/Douyin AI |
| cohere-ai | Cohere | Cohere models |

**Recommendation:** Allow GPTBot, OAI-SearchBot, ClaudeBot, PerplexityBot for AI search visibility. Block CCBot and training crawlers if desired.

---

## llms.txt Standard

The emerging **llms.txt** standard provides AI crawlers with structured content guidance.

**Location:** `/llms.txt` (root of domain)

**Format:**
```
# Title of site
> Brief description

## Main sections
- Page title: Description
- Another page: Description

## Optional: Key facts
- Fact 1
- Fact 2
```

**Check for:**
- Presence of `/llms.txt`
- Structured content guidance
- Key page highlights
- Contact/authority information

---

## RSL 1.0 (Really Simple Licensing)

New standard (December 2025) for machine-readable AI licensing terms.

**Backed by:** Reddit, Yahoo, Medium, Quora, Cloudflare, Akamai, Creative Commons

**Check for:** RSL implementation and appropriate licensing terms.

---

## Platform-Specific Optimization

| Platform | Key Citation Sources | Optimization Focus |
|----------|---------------------|-------------------|
| **Google AI Overviews** | Top-10 ranking pages (92%) | Traditional SEO + passage optimization |
| **ChatGPT** | Wikipedia (47.9%), Reddit (11.3%) | Entity presence, authoritative sources |
| **Perplexity** | Reddit (46.7%), Wikipedia | Community validation, discussions |
| **Bing Copilot** | Bing index, authoritative sites | Bing SEO, IndexNow |

---

## Output

Generate `GEO-ANALYSIS.md` with:

1. **GEO Readiness Score: XX/100**
2. **Platform breakdown** (Google AIO, ChatGPT, Perplexity scores)
3. **AI Crawler Access Status** (which crawlers allowed/blocked)
4. **llms.txt Status** (present, missing, recommendations)
5. **Brand Mention Analysis** (presence on Wikipedia, Reddit, YouTube, LinkedIn)
6. **Passage-Level Citability** (optimal 134-167 word blocks identified)
7. **Server-Side Rendering Check** (JavaScript dependency analysis)
8. **Top 5 Highest-Impact Changes**
9. **Schema Recommendations** (for AI discoverability)
10. **Content Reformatting Suggestions** (specific passages to rewrite)

---

## Quick Wins

1. Add "What is [topic]?" definition in first 60 words
2. Create 134-167 word self-contained answer blocks
3. Add question-based H2/H3 headings
4. Include specific statistics with sources
5. Add publication/update dates
7. Allow key AI crawlers in robots.txt

## Medium Effort

1. Create `/llms.txt` file
2. Add author bio with credentials + Wikipedia/LinkedIn links
3. Ensure server-side rendering for key content
4. Build entity presence on Reddit, YouTube
5. Add comparison tables with data

## High Impact

1. Create original research/surveys (unique citability)
2. Build Wikipedia presence for brand/key people
3. Establish YouTube channel with content mentions
5. Develop unique tools or calculators

## DataForSEO Integration (Optional)

If DataForSEO MCP tools are available, use `ai_optimization_chat_gpt_scraper` to check what ChatGPT web search returns for target queries (real GEO visibility check) and `ai_opt_llm_ment_search` with `ai_opt_llm_ment_top_domains` for LLM mention tracking across AI platforms.

## Error Handling

| Scenario | Action |
|----------|--------|
| URL unreachable (DNS failure, connection refused) | Report the error clearly. Do not guess site content. Suggest the user verify the URL and try again. |
| AI crawlers blocked by robots.txt | Report exactly which crawlers are blocked and which are allowed. Provide specific robots.txt directives to add for enabling AI search visibility. |
| No llms.txt found | Note the absence and provide a ready-to-use llms.txt template based on the site's content structure. |
| No structured data detected | Report the gap and provide specific schema recommendations (Article, Organization, Person) for improving AI discoverability. |

---

## Absorbed from seo-geo-aeo

The seo-geo-aeo skill provided a full audit workflow producing DOCX/PDF reports with detailed scoring across SEO, GEO, and AEO dimensions. Its unique contributions -- the multi-page crawl methodology, AEO-specific signal analysis, report generation pipeline, and scoring rubric -- are preserved below.

### Scope Confirmation

Before starting an audit, confirm with the user:
> "Would you like a **Quick Audit** (top priority issues and scores -- takes 1-2 minutes) or a **Full Audit** (comprehensive analysis across all dimensions -- takes 5-10 minutes)?"

Only skip this if the user's message already contains a clear choice.

### Multi-Page Crawl Methodology

**Phase 2a -- Homepage fetch and site discovery:**
- Fetch provided URL first. Extract navigation links, internal links, build a map of existing pages (About, Team, Services, Case Studies, Blog, FAQ, Contact).
- Fetch in parallel: `{domain}/robots.txt` and `{domain}/sitemap.xml`.

**Phase 2b -- Crawl key pages:**
- Quick Audit: Homepage plus up to 6 high-signal pages.
- Full Audit: Crawl as many pages as possible. Priority: About/Team, Services, Case Studies/Portfolio, Blog (index + recent posts), Contact, FAQ, individual service/product pages, all remaining content-rich sitemap pages.
- Skip only: Privacy Policy, Terms of Service, login/account pages, thank-you pages, paginated archives beyond page 2.

### AEO Signals (Answer Engine Optimization)

AEO optimizes for featured snippets, People Also Ask boxes, and voice search.

**Featured Snippet Eligibility:**
- Direct answer paragraphs: key question answered in 40-60 words right below a question-phrased heading
- Definition patterns: "X is..." sentence for core topic
- List content: numbered steps or bulleted lists for list snippets
- Table content: comparison tables for table snippets

**Structured Answer Formats:**
- FAQ schema markup with correctly structured questions and answers
- HowTo schema for step-by-step process content
- Question-phrased headings using natural language ("How does X work?", "What is Y?")
- SpeakableSpecification markup for voice-friendly sections

**Voice Search Readiness:**
- Conversational language and natural phrasing
- Long-tail question coverage (who/what/when/where/why/how)
- Local signals if applicable (NAP data, local schema, location mentions)

### Scoring Rubric (1-10 per dimension)

- **1-3**: Critical issues -- site is likely penalized or invisible
- **4-5**: Below average -- significant missed opportunities
- **6-7**: Decent foundation -- specific improvements needed
- **8-9**: Strong -- minor refinements available
- **10**: Exemplary -- model implementation

### DOCX/PDF Report Generation Pipeline

After analysis, generate both `.docx` and `.pdf` reports automatically.

**Setup:**
```bash
node -e "require('docx')" 2>/dev/null || npm install docx
```

**Report design system:**
- Navy header/cover: `1B2A4A`
- Accent blue: `2563EB`
- Score green (8-10): `16A34A`, amber (5-7): `D97706`, red (1-4): `DC2626`
- Light gray alternating rows: `F8F9FA`, borders: `E2E8F0`
- Typography: Arial throughout (Title 36pt, H1 24pt, H2 18pt, H3 14pt, body 11pt)
- Page setup: US Letter, 1-inch margins

**Report structure:**
1. Cover page (navy background, score table with color-coded cells)
2. Executive summary (shaded box + scores table)
3. Pages audited (URL, page type, notes)
4. SEO analysis (Technical On-Page, Content Quality, Structured Data)
5. GEO analysis (E-E-A-T Assessment, Content for AI Synthesis, Technical GEO)
6. AEO analysis (Featured Snippet Eligibility, Structured Answer Formats, Voice Search Readiness)
7. Priority recommendations matrix (color-coded: Critical red, High orange, Medium amber, Quick Win green)
8. What's working well (green-tinted table with specific evidence)
9. Glossary (Full Audit only)

**Validation and conversion:**
```bash
python <SKILL_DIR>/scripts/office/validate.py <output.docx>
python <SKILL_DIR>/scripts/office/soffice.py --headless --convert-to pdf <output.docx> --outdir <output_dir>/
```

### GEO-Specific Signals (from seo-geo-aeo)

**Content for AI Synthesis:**
- Factual density: specific facts, statistics, or data that AI engines could cite
- Clear claims: core argument stated plainly at the top
- Source citation: references to external authoritative sources
- Comprehensiveness: fully addresses topic without leaving key questions unanswered
- Entity clarity: brand/person/place named clearly and consistently
- Originality signals: clear point of view, original data, unique perspective

**Technical GEO:**
- Structured data depth beyond basic schema (Author, Dataset, ClaimReview, SpeakableSpecification)
- Clean crawlability: no excessive JavaScript-only rendering blocking AI crawlers
- sameAs / brand entity links: social profile links strengthening entity graph

---

## Absorbed from ai-seo

The ai-seo skill provided a comprehensive AI search optimization framework. Its unique contributions -- the Three Pillars strategy, Princeton GEO research data, content type optimization guides, monitoring tools, and AI visibility audit methodology -- are preserved below.

### The Three Pillars of AI SEO

```
1. Structure (make it extractable)
2. Authority (make it citable)
3. Presence (be where AI looks)
```

### Pillar 1: Structure -- Make Content Extractable

AI systems extract passages, not pages. Every key claim should work as a standalone statement.

**Content block patterns:**
- **Definition blocks** for "What is X?" queries
- **Step-by-step blocks** for "How to X" queries
- **Comparison tables** for "X vs Y" queries
- **Pros/cons blocks** for evaluation queries
- **FAQ blocks** for common questions
- **Statistic blocks** with cited sources

**Structural rules:**
- Lead every section with a direct answer (do not bury it)
- Keep key answer passages to 40-60 words (optimal for snippet extraction)
- Use H2/H3 headings that match how people phrase queries
- Tables beat prose for comparison content
- Numbered lists beat paragraphs for process content

### Pillar 2: Authority -- Princeton GEO Research (KDD 2024)

Studied across Perplexity.ai, ranked 9 optimization methods:

| Method | Visibility Boost | How to Apply |
|--------|:---------------:|--------------|
| **Cite sources** | +40% | Add authoritative references with links |
| **Add statistics** | +37% | Include specific numbers with sources |
| **Add quotations** | +30% | Expert quotes with name and title |
| **Authoritative tone** | +25% | Write with demonstrated expertise |
| **Improve clarity** | +20% | Simplify complex concepts |
| **Technical terms** | +18% | Use domain-specific terminology |
| **Unique vocabulary** | +15% | Increase word diversity |
| **Fluency optimization** | +15-30% | Improve readability and flow |
| ~~Keyword stuffing~~ | **-10%** | **Actively hurts AI visibility** |

**Best combination:** Fluency + Statistics = maximum boost. Low-ranking sites benefit even more (up to 115% visibility increase with citations).

### Pillar 3: Presence -- Be Where AI Looks

AI systems do not just cite your website -- they cite where you appear.

**Third-party sources matter more than your own site:**
- Wikipedia mentions (7.8% of all ChatGPT citations)
- Reddit discussions (1.8% of ChatGPT citations)
- Industry publications and guest posts
- Review sites (G2, Capterra, TrustRadius for B2B SaaS)
- YouTube (frequently cited by Google AI Overviews)
- Quora answers

**Actions:**
- Ensure Wikipedia page is accurate and current
- Participate authentically in Reddit communities
- Get featured in industry roundups and comparison articles
- Maintain updated profiles on relevant review platforms
- Create YouTube content for key how-to queries

### AI Visibility Audit Methodology

**Step 1 -- Check AI Answers for Key Queries:**
Test 10-20 important queries across Google AI Overview, ChatGPT, and Perplexity. Record whether you are cited, and who else is.

**Step 2 -- Analyze Citation Patterns:**
When competitors get cited and you do not, examine: content structure (extractability), authority signals, freshness, schema markup, third-party presence.

**Step 3 -- Content Extractability Check:**
For each priority page verify: clear definition in first paragraph, self-contained answer blocks, statistics with sources, comparison tables, FAQ section, schema markup, expert attribution, recent update date, heading structure matching query patterns, AI bots allowed in robots.txt.

### Content Types That Get Cited Most

| Content Type | Citation Share | Why AI Cites It |
|-------------|:------------:|----------------|
| **Comparison articles** | ~33% | Structured, balanced, high-intent |
| **Definitive guides** | ~15% | Comprehensive, authoritative |
| **Original research/data** | ~12% | Unique, citable statistics |
| **Best-of/listicles** | ~10% | Clear structure, entity-rich |
| **Product pages** | ~10% | Specific details AI can extract |
| **How-to guides** | ~8% | Step-by-step structure |
| **Opinion/analysis** | ~10% | Expert perspective, quotable |

**Underperformers:** Generic blog posts without structure, thin product pages, gated content, content without dates/attribution, PDF-only content.

### AI SEO for Specific Content Types

**SaaS Product Pages:** Clear product description in first paragraph, feature comparison tables, specific metrics (not "blazing fast"), customer count with numbers, pricing transparency, FAQ section.

**Blog Content:** One clear target query per post, definition in first paragraph, original data/expert quotes, "Last updated" date, author bio with credentials, internal links to related pages.

**Comparison/Alternative Pages:** Structured comparison tables, fair and balanced, specific criteria with ratings, updated pricing and feature data.

**Documentation / Help Content:** Step-by-step with numbered lists, code examples, HowTo schema, screenshots with alt text, clear prerequisites and outcomes.

### AI Visibility Monitoring Tools

| Tool | Coverage | Best For |
|------|----------|----------|
| **Otterly AI** | ChatGPT, Perplexity, Google AI Overviews | Share of AI voice tracking |
| **Peec AI** | ChatGPT, Gemini, Perplexity, Claude, Copilot+ | Multi-platform monitoring at scale |
| **ZipTie** | Google AI Overviews, ChatGPT, Perplexity | Brand mention + sentiment tracking |
| **LLMrefs** | ChatGPT, Perplexity, AI Overviews, Gemini | SEO keyword to AI visibility mapping |

### DIY AI Monitoring (No Tools)

Monthly manual check:
1. Pick your top 20 queries
2. Run each through ChatGPT, Perplexity, and Google
3. Record: Are you cited? Who is? What page?
4. Log in a spreadsheet, track month-over-month

### Common AI SEO Mistakes

- Ignoring AI search entirely (45% of Google searches show AI Overviews)
- Treating AI SEO as separate from traditional SEO
- Writing for AI, not humans
- No freshness signals (undated content loses to dated content)
- Gating all content (AI cannot access gated content)
- Ignoring third-party presence
- No structured data
- Keyword stuffing (actively reduces AI visibility by 10%)
- Blocking AI bots in robots.txt
- Generic content without data
- Not monitoring AI visibility

### Schema Markup for AI Discoverability

| Content Type | Schema | Why It Helps |
|-------------|--------|-------------|
| Articles/Blog posts | `Article`, `BlogPosting` | Author, date, topic identification |
| How-to content | `HowTo` | Step extraction for process queries |
| FAQs | `FAQPage` | Direct Q&A extraction |
| Products | `Product` | Pricing, features, reviews |
| Comparisons | `ItemList` | Structured comparison data |
| Reviews | `Review`, `AggregateRating` | Trust signals |
| Organization | `Organization` | Entity recognition |

### AI Platform Source Selection

| Platform | How It Works | Source Selection |
|----------|-------------|----------------|
| **Google AI Overviews** | Summarizes top-ranking pages | Strong correlation with traditional rankings |
| **ChatGPT (with search)** | Searches web, cites sources | Wider range, not just top-ranked |
| **Perplexity** | Always cites sources with links | Authoritative, recent, well-structured |
| **Gemini** | Google's AI assistant | Google index + Knowledge Graph |
| **Copilot** | Bing-powered AI search | Bing index + authoritative sources |
| **Claude** | Brave Search (when enabled) | Training data + Brave search results |

For platform-specific ranking factors, see `references/platform-ranking-factors.md` and `references/content-patterns.md`.

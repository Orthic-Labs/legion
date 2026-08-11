# Method — reddit

Loaded when `ResearchRoute.methods` contains `reddit`. This is a composable Research method, not a delegated skill and not a catalog entry.

## Purpose

Use Reddit research to surface observed user language, complaints, objections, product comparisons, niche trends, and falsifying counterexamples from subreddit discussions.

## Source discipline

- Reddit search results and third-party summaries are leads. Evidence requires the actual thread or comment to be opened and the relevant passage located.
- Prefer diversified sampling over viral-only sampling: include top, new, controversial, low-score, unanswered, and dissenting material when relevant.
- Preserve subreddit, thread URL, post/comment locator, author pseudonym if necessary, date, score/comment context, and retrieval date.
- Report counts across sampled posts or comments. Do not claim population percentages from subreddit samples.
- Collapse cross-posts, bot reposts, quoted duplicates, and linked mirrors into one independence cluster.
- Treat Reddit as qualitative audience evidence unless the route and data justify stronger claims.

## Query design

Construct queries from the frozen subject and method combination:

- pain language: `"struggling with"`, `"anyone else"`, `"I don't understand"`, `"why is"`;
- evaluation language: `"vs"`, `"alternative"`, `"switch from"`, `"worth it"`;
- trust language: `"scam"`, `"privacy"`, `"safe"`, `"refund"`, `"support"`;
- workflow language: `"how do you"`, `"what do you use"`, `"best way to"`.

Use platform operators or provider-specific filters only through the approved provider for the route.

## Output pattern

Render:

1. sampled subreddits, query terms, date range, and sample count;
2. repeated themes with counts and evidence IDs;
3. exact language worth preserving, with quote/paraphrase labels;
4. competitor or tool mentions, separated from sentiment;
5. dissenting or minority views;
6. sampling gaps and what would overturn the finding.

Do not quote out of context, treat one viral thread as a trend, or mine for validation only.

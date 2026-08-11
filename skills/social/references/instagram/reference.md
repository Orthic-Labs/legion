---
name: instagram-pro
description: >
  Instagram workflow per brand: content calendar, post review, performance analysis, growth strategy.
  Use when user says "/instagram", "IG", "Instagram strategy", "IG content calendar", "review my IG",
  "why isn't IG working", "IG performance", "Reels strategy". Requires IG Graph API for live analytics
  (todo.md P0) — without it, creation + manual-data analysis only.
---

# Instagram

## Status
- Content calendar + creation: works now
- **Live analytics: use `agent-browser` CLI** to navigate IG dashboard while user is logged in (preferred — DOM snapshot, no inline screenshots)
- Bulk historical exports + publishing: needs IG Graph API MCP (todo.md P0)

## Live analytics via agent-browser (preferred path, works today)

`agent-browser` is the Rust CLI + Chrome-for-Testing daemon (~7.6× cheaper per snapshot than Playwright MCP). User must be logged into Instagram in the Chrome-for-Testing profile (run `agent-browser --profile Default open https://www.instagram.com/` once to seed cookies). Then:

```bash
# 1. Profile + dashboard
agent-browser open "https://www.instagram.com/<username>/" && agent-browser wait 3000 && agent-browser snapshot -i

# 2. Professional Dashboard → Insights (click via @ref from the snapshot above)
agent-browser click @e<N>          # the dashboard link
agent-browser snapshot              # account-level DOM with numbers parsable inline

# 3. Per-post insights
agent-browser open "https://www.instagram.com/p/<shortcode>/" && agent-browser click "View insights" && agent-browser snapshot

# 4. Reels overview (if available)
agent-browser open "https://www.instagram.com/reels/audience/" && agent-browser snapshot

# 5. Stories: dashboard → Stories tab, snapshot per slide

# 6. For chart visualizations that don't appear in DOM, capture as image and Read it:
agent-browser screenshot /tmp/ig_chart.png
# Then in the conversation: use the Read tool on /tmp/ig_chart.png so Claude can reason about the chart visually.
```

If agent-browser fails (2FA, account locked, layout change): fall back to user-provided screenshots OR the IG Graph API token path (todo.md P0).

If the daemon throws "version mismatch" on Windows: `taskkill //F //IM agent-browser-win32-x64.exe && rm ~/.agent-browser/default.{port,pid,version,stream}` then retry.

**Always read on-screen numbers back to the user** before analyzing — lets them flag if agent-browser grabbed stale or wrong panels.

## Always start with
1. `/brand <DD|RH|SS>`
2. **Identify task:** strategy / calendar / single post / performance review / Reels-specific

## Tasks

### Content calendar (weekly/monthly)
Ask: posting frequency, content mix, themes/launches.

Default mix:
| Brand | Reels | Carousel | Single | Story |
|---|---|---|---|---|
| RH | 4/wk | 2/wk | 0 | daily 3-5 |
| DD | 3/wk | 1/wk | 1/wk | 2-3/wk |
| SS | 2/wk | 3/wk | 2/wk | 2/wk |

Output: 7- or 30-day grid with topic, format, hook, CTA, hashtag set, posting time.

### Single post creation
1. Topic + format
2. Hook test (first frame for Reel, first slide for carousel, first line for caption)
3. Caption: hook → 2-3 body lines → CTA OR question (never both)
4. Hashtags: 5-15 mid-tail in first comment
5. Generate via /marketing-design or /social youtube for Reel

### Performance review (with screenshots/exports)
Analyze:
- Reach vs followers (>20% healthy, <5% punished)
- Saves + shares (best signal — not likes)
- Profile visits / reach
- Follow rate / profile visits
- Comments-to-likes ratio
- Story exit rate per slide

Pattern-match last 30 posts:
- Top 3 by saves: common element?
- Bottom 3: what killed them?
- Off-brand vs on-brand: which performs better? (data > theory)

### Growth strategy
- Audit current state
- Identify ONE bottleneck (reach? CTR? bio? content-market fit?)
- 4-week experiment to test the fix

## Hashtag strategy
- 5-15 in FIRST COMMENT (clean caption)
- Mix: 30% brand/community, 50% mid-tail (10k-100k posts), 20% topic-broad
- Rotate sets weekly to avoid shadow-ban patterns

## Posting times (US-skewed)
- RH: 7-9am ET weekdays + Sun 8pm
- DD: 12-2pm ET weekdays + Sat 10am
- SS: 8-10pm ET Tue/Thu/Sun

## Why IG doesn't work for new accounts (cold truth)
- < 1k followers: algo barely shows posts to non-followers
- Reels = only path to non-follower reach
- Need 30+ posts of consistent quality before judging
- Hashtags help discovery, don't 10× small accounts
- Comments + DMs from your audience > follower count

## Output

Calendar:
```markdown
## IG Calendar — [brand] — [week of date]
| Day | Time | Format | Topic | Hook | CTA | Hashtag set |
| Mon | 8am | Reel | ... | ... | ... | Set A |
```

Review:
```markdown
## IG Review — [brand] — [period]

### Scorecard
- Reach: X% of followers (target 20%+)
- Save rate: X per 1k reach
- Profile visit → follow: X%
- Comments-to-likes: 1:X

### What worked (top 3)
- [post] — [why]

### What didn't (bottom 3)
- [post] — [why]

### One bottleneck to fix
[Specific change]

### Test plan (4 weeks)
- W1: ...
- W2: ...
```

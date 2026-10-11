# Instagram

## Status
- Content calendar + creation: works from the brand card and the user's inputs.
- Live analytics: needs a host browser or platform-data capability. Neither is declared by this package (missing: `browser`, `social-data`). Without one, ask the user for Insights screenshots or exports and analyze those.
- Bulk historical exports and publishing: need a host `social-data` or `social-scheduler` capability (missing from this package). Without one, the user posts manually.

## Live analytics (only if the host provides it)

If the host provides a browser capability and the user is logged in to the account, read the Professional Dashboard → Insights panels the user names. Read-only; do not change settings, post, or reply.

- Read every on-screen number back to the user before analyzing, so they can flag a stale or wrong panel.
- Charts that are not in the page text: use an image the user supplies.
- If the browser capability fails (2FA, locked account, layout change), fall back to user-provided screenshots or exports.

## Always start with
1. `/brand <brand-code>`
2. **Identify task:** strategy / calendar / single post / performance review / Reels-specific

## Tasks

### Content calendar (weekly/monthly)
Ask: posting frequency, content mix, themes/launches.

Content mix: take the per-format cadence (Reels, carousels, single posts, Stories) from the brand card loaded via `/brand`. If the card sets none, propose a starting mix and label it an untested assumption to check against the account's own data.

Output: 7- or 30-day grid with topic, format, hook, CTA, hashtag set, posting time.

### Single post creation
1. Topic + format
2. Hook test (first frame for Reel, first slide for carousel, first line for caption)
3. Caption: hook → 2-3 body lines → CTA OR question (never both)
4. Hashtags: 5-15 mid-tail in first comment
5. Generate via `/designer static` for the visual, or the YouTube reference for a Reel script

### Performance review (with screenshots/exports)
Analyze:
- Reach vs followers (compare with the brand's own history; avoid fixed benchmarks presented as fact)
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
- Audit current state from the data the user supplies
- Identify ONE bottleneck (reach? CTR? bio? content-market fit?)
- 4-week experiment to test the fix

## Hashtag strategy
- 5-15 in FIRST COMMENT (clean caption)
- Mix: 30% brand/community, 50% mid-tail (10k-100k posts), 20% topic-broad
- Rotate sets weekly to avoid shadow-ban patterns

## Posting times
Take the posting windows from the brand card and the audience's timezone. If the card has none, propose windows and label them hypotheses to test against the account's own insights.

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
- Reach: X% of followers (vs the account's own baseline)
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

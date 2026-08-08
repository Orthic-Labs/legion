---
name: design-app-stub
description: Routing stub — product/app UI belongs to the /app skill, not /designer static.
---

# Routing stub — product/application UI

**For product UI, dashboards, admin panels, SaaS tools, or any interactive application screen, use `/designer`.**

This file is a routing stub only. The canonical instructions for functional app UI (intent-first exploration,
domain-specific palette, token architecture, elevation system, interaction states, craft mandate) live in the
`/designer` skill (app-UI surface).

> `/designer static` does not own product UI. If you landed here from a `/designer static` invocation with an app/dashboard
> request, stop and route to `/designer` instead.

The only design-router-specific note: when `/designer static` is invoked for a static ad creative that must
*depict* an app UI (e.g. an OG image showing a screenshot mock), render the screen as a soft glow or blurred
background rather than a faithful recreation. See `references/marketing.md` and the video-pipeline rule on
`compose_with.screenComposite` for the compositing pattern.

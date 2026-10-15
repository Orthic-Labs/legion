# Browser automation

Use `legion script qa/qa-functional --url <loopback-url> --actions <actions.json>` for `waitFor`, `click`, `hover`, `type`, `press`, & DOM/ARIA/style assertions; add `screenshot` only in `kind = "visual"` scenarios. Use `legion script qa/qa-shot --url <loopback-url> --out <file>` for app viewport only, in visual scenarios. Shared runners use headless Chrome/Edge via raw CDP; do not add Playwright or Puppeteer. QA mode is loopback-only, deterministic, & enabled by project env plus `?qa=1`.

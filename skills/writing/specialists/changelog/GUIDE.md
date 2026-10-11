---
name: writing-changelog
description: Automatically creates user-facing changelogs from git commits by analyzing commit history, categorizing changes, and transforming technical commits into clear, customer-friendly release notes. Turns hours of manual changelog writing into minutes of automated generation.
---

# Changelog Generator

This skill transforms technical git commits into polished, user-friendly changelogs that your customers and users will actually understand and appreciate.

## When to Use This Skill

- Preparing release notes for a new version
- Creating weekly or monthly product update summaries
- Documenting changes for customers
- Writing changelog entries for app store submissions
- Generating update notifications
- Creating internal release documentation
- Maintaining a public changelog/product updates page

## What This Skill Does

1. **Scans Git History**: Analyzes commits from a specific time period or between versions
2. **Categorizes Changes**: Groups commits into logical categories (features, improvements, bug fixes, breaking changes, security)
3. **Translates Technical → User-Friendly**: Converts developer commits into customer language
4. **Formats Professionally**: Creates clean, structured changelog entries
5. **Filters Noise**: Excludes internal commits (refactoring, tests, etc.)
6. **Follows Best Practices**: Applies changelog guidelines and your brand voice

## Procedure

1. **Set the range.** Use the dates or the two refs the user gives (for example `v2.4.0..HEAD`). Run from the repository root. If no range is given, ask for one.
2. **Read the commits.** Run `git log <range> --no-merges --pretty=format:'%h %s'`, or `git log --since="<date>" --until="<date>" --no-merges --pretty=format:'%h %s'` for a date window.
3. **Group by type.** Use the commit prefix or subject: `feat` → New features; `fix` → Fixes; `perf` or user-visible `refactor` → Improvements; `security` → Security; a `!` marker or `BREAKING CHANGE` → Breaking changes. Drop `chore`, `test`, `ci`, `docs`-only and internal-only commits.
4. **Rewrite each kept commit** as one customer-facing line: what the user can now do, or what stopped going wrong. Never publish hashes or raw commit subjects.
5. **Check the result.** Every bullet traces to at least one commit in the range. If the range is empty, say so and stop; do not invent entries.

### Basic Usage

From your project repository:

```
Create a changelog from commits since last release
```

```
Generate changelog for all commits from the past week
```

```
Create release notes for version 2.5.0
```

### With Specific Date Range

```
Create a changelog for all commits between March 1 and March 15
```

### With Custom Guidelines

```
Create a changelog for commits since v2.4.0, using my changelog 
guidelines from the project's style file (if it has one)
```

## Example

**User**: "Create a changelog for commits from the past 7 days"

**Output**:
```markdown
# Updates - Week of March 10, 2024

## ✨ New Features

- **Team Workspaces**: Create separate workspaces for different 
  projects. Invite team members and keep everything organized.

- **Keyboard Shortcuts**: Press ? to see all available shortcuts. 
  Navigate faster without touching your mouse.

## 🔧 Improvements

- **Faster Sync**: Files now sync 2x faster across devices
- **Better Search**: Search now includes file contents, not just titles

## 🐛 Fixes

- Fixed issue where large images wouldn't upload
- Resolved timezone confusion in scheduled posts
- Corrected notification badge count
```

## Tips

- Run from your git repository root
- Specify date ranges for focused changelogs
- If the project has a changelog style file, follow it for consistent formatting
- Review and adjust the generated changelog before publishing
- Save output to the project's changelog file, after review

## Related Use Cases

- Creating GitHub release notes
- Writing app store update descriptions
- Generating email updates for users
- Creating social media announcement posts


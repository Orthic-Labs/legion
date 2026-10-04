# Architecture reference map

Use this directory when a change crosses module boundaries, introduces a dependency,
changes failure handling, adds tests, or changes documentation/build workflow. Start with
the narrowest page that answers the question, then follow links only when the change needs
them.

- [Progressive design](progressive-design.md): preserve current shape, add abstraction only
  when evidence requires it.
- [Dependency injection](dependency-injection.md): make lifetimes and test seams explicit.
- [Errors & recovery](errors.md): model failures at boundaries and preserve context.
- [Behavior-focused testing](testing.md): test outcomes with deterministic collaborators.
- [Progressive docs loading](docs-loading.md): route documentation by task and load only
  relevant pages.
- [Build loop](build-loop.md): keep build, test, run, output, and version checks repeatable.

The parent [architecture reference](../architecture.md) remains the entry point. These
pages add concrete methods; they do not select an architecture acronym or authorize tools,
dependencies, signing, uploads, or external orchestration.

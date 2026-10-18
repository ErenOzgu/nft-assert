# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/), versions follow [SemVer](https://semver.org/).

## Unreleased

### Added
- `check --github-annotations` prints one `::error` workflow command per failed expectation, so GitHub Actions shows
  the failure (with the deciding rule from the trace) on the pull request. A spec path inside `$GITHUB_WORKSPACE` is
  made relative, which is what GitHub needs to attach the note to the file.
- `docs/design-notes.md`: why the tool is built the way it is, what was tried and rejected, how the mutation check was
  done, and the questions this design usually draws.
- `ROADMAP.md`: the next small steps, in order.

### Changed
- Releases: a commit that adds a numbered heading to this file releases that version (the Release workflow tests, builds and
  makes the tag itself). Pushing a `vX.Y.Z` tag or running the workflow by hand still works.

## 0.1.0 - 2026-10-18

First release: `check`, `matrix`, `diff` and `cleanup`; real network namespaces, a sanity pass before the ruleset is
loaded, rule tracing for failed expectations, JUnit, Markdown and JSON reports.

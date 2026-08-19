# Contributing to portcullis

Small contributions are welcome and there is no expectation that you read the
whole codebase first. This document is short on purpose.

## Getting set up

```bash
git clone https://github.com/sushantlokhande14/portcullis
cd portcullis
cargo test --workspace
```

That is the whole setup. There is no code generation step, no database, and no
network access in the test suite. If `cargo test` passes you have a working
environment.

Before opening a PR, run what CI runs:

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Where to start

**Adding a detector to `portcullis-scan` is the easiest useful change.** Each
one is a pattern, an enum variant, and a test. You do not need to understand the
proxy, the policy engine, or MCP itself.

- `secret.rs` for a credential format that is not yet recognised
- `injection.rs` for an injection phrasing
- `unicode.rs` for a covert channel

Issues labelled `good first issue` are mostly of this shape and each one names
the file to edit.

## Two rules that will trip you up

**Build credential fixtures at runtime, never as literals.**

```rust
// Yes
let token = fixture(&["AKIA", "IOSFODNN7EXAMPLE"]);

// No: GitHub push protection will reject the whole push
let token = "AKIAIOSFODNN7EXAMPLE";
```

A credential scanner's fixtures are by construction shaped exactly like real
credentials, and other people's scanners cannot tell that yours are fake. This
already happened once during development. The `fixture` helper in
`secret.rs` exists for it.

**A new detector needs a negative test, not just a positive one.**

A detector that fires on ordinary output gets switched off, and a detector that
is switched off has zero recall. So a PR adding a pattern should also add a
realistic sample that must *not* match. The existing suites have a
`realistic_tool_output_stays_quiet` test for exactly this; extend it.

## Style

The code aims for a particular thing that is worth naming: **comments explain
why, not what.** A comment that restates the line above it is noise; a comment
recording the alternative that was rejected and the reason is the thing that
saves the next reader an hour. If you find yourself writing "increments the
counter", delete it. If you can write "counted here rather than in the caller,
because the caller can bail out early and the metric has to include those",
keep it.

Other conventions:

- `unsafe` is forbidden workspace-wide.
- Public items are documented. CI builds docs with warnings denied.
- Test names are sentences. `a_closed_connection_wakes_waiters_instead_of_hanging`
  tells you what broke; `test_upstream_3` does not.
- Errors name the thing that failed and, where possible, what to do about it.

## Commits and pull requests

- One logical change per commit. Separate a fix from the test that proves it if
  they read better apart.
- Commit messages explain the reasoning, not just the diff. The body is where a
  tradeoff belongs.
- Draft PRs are fine and encouraged for anything you want feedback on early.

## Reporting a security issue

Please do not open a public issue for a vulnerability in portcullis itself. See
[SECURITY.md](SECURITY.md).

A gap in a *detector*, on the other hand, is an ordinary issue and a very
welcome one. The detectors are documented as heuristics and their limits are not
secrets; discussing them openly is how they improve.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

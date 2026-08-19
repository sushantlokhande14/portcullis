# portcullis

**A policy-enforcing gateway for the Model Context Protocol.**

[![CI](https://github.com/sushantlokhande14/portcullis/actions/workflows/ci.yml/badge.svg)](https://github.com/sushantlokhande14/portcullis/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange)](https://www.rust-lang.org)

When an agent connects to an MCP server, two things happen that nothing is
checking. Every tool the server exposes becomes callable by the model, and every
byte the server returns is spliced straight into the model's context. The first
is an authorization problem. The second is an injection problem, and it is the
one that gets overlooked, because tool output looks like data right up until the
model reads it as instructions.

portcullis sits in the middle. Your client points at portcullis instead of at
the real servers. It speaks MCP in both directions, presents several upstream
servers as one, and applies policy to every `tools/call` that crosses it.

```
  MCP client                  portcullis                   upstream servers
 (Claude Code,   <-- MCP -->   policy       <-- MCP -->   (filesystem, github,
  Cursor, Zed)                 scanners                     postgres, ...)
                               rate limits
                               audit log
```

## What it actually does

**Refuses calls policy did not permit.** Rules match on tool name, upstream
server, and argument values. The default is deny.

**Reads tool output before the model does.** Credentials are redacted.
Instruction-shaped text is fenced as untrusted data. Text hidden in Unicode tag
characters is decoded, judged by the same rules as visible text, and stripped.

**Writes down what happened.** One JSONL record per decision, with the deciding
rule, argument digests, and scanner findings.

**Explains itself.** `portcullis explain` tells you what a policy would do to a
call without starting anything.

## Quickstart

```bash
git clone https://github.com/sushantlokhande14/portcullis
cd portcullis
cargo build --release
```

Point it at your servers in `portcullis.toml`, then check what your policy does
before you run anything:

```bash
cargo run -p portcullis-cli -- explain --tool fs__read_file --args '{"path":"/home/u/.ssh/id_rsa"}'
```

```
call    fs / fs__read_file
args    {"path":"/home/u/.ssh/id_rsa"}

-> [ 0] deny-credential-paths            deny  applied
   [ 1] deny-dotenv-files                deny  not reached
   [ 2] deny-path-traversal              deny  not reached
   [ 3] allow-filesystem-reads           allow not reached
   ...

decision deny by policy rule "deny-credential-paths": Never read or write the
directories that hold long-lived credentials
```

Then run the gateway. It speaks MCP over stdio, so it drops into any client's
server configuration in place of the server it fronts:

```bash
portcullis run --config portcullis.toml --policy policies/default.toml
```

Other commands: `validate --strict` for CI, `scan` to run the detectors over a
file or stdin, `servers` to list what a config declares.

## Writing policy

Rules are evaluated top to bottom and the first one that applies decides.

```toml
version = 1
default = "deny"

[[rule]]
id = "deny-credential-paths"
description = "Never read or write the directories that hold long-lived credentials"
tools = ["fs__*"]
action = "deny"
when = [{ arg = "path", matches = "(^|/)\\.(ssh|aws|gnupg)(/|$)" }]

[[rule]]
id = "allow-filesystem-reads"
tools = ["fs__read_*", "fs__list_*"]
action = "allow"
```

Full syntax is in [docs/policy-reference.md](docs/policy-reference.md).
`policies/default.toml` is a worked starting point, and CI fails if it ever
produces a validation warning.

One thing worth knowing before you write your first rule: **an absent argument
makes a condition false**, so a deny rule keyed on `path` does not fire on a
call that omits `path`. That is why the default has to be `deny`. The policy
reference covers this properly, and `validate` warns about the cases where it
bites.

## What this does not do

Honesty about limits is part of the design, because the failure mode for a tool
like this is someone trusting it further than it goes and loosening their real
controls to match.

- **The injection detectors are heuristics.** They match phrasings that
  circulate publicly. Natural language has unbounded paraphrase, and anyone who
  reads `crates/portcullis-scan/src/injection.rs` can write around them. Policy
  is the structural control; the scanners are a signal on top of it.
- **Resources and prompts are not mediated yet.** They are refused rather than
  forwarded, because forwarding would put content in the model's context that no
  policy inspected. See [issue tracker](https://github.com/sushantlokhande14/portcullis/issues).
- **Non-text content is not inspected.** Images and audio pass through and are
  recorded as uninspected, not as clean.
- **A shell tool defeats everything.** No argument pattern reliably separates a
  safe command from an unsafe one. The shipped policy denies shell tools
  outright and says why.

[docs/threat-model.md](docs/threat-model.md) is the long version.

## Layout

| Crate | What it owns |
| --- | --- |
| `portcullis-core` | JSON-RPC 2.0 and MCP types, stdio transport |
| `portcullis-policy` | Rule model, matchers, decision engine, loading |
| `portcullis-scan` | Credential, injection, and Unicode detectors |
| `portcullis-proxy` | Upstream lifecycle, aggregation, enforcement, audit |
| `portcullis-cli` | The `portcullis` binary |

The dependency direction is one-way, `core` at the bottom. Nothing in `core` or
`scan` knows what a proxy is, which is what lets both be tested against plain
values.

## Contributing

Contributions are genuinely welcome, and the project is arranged to make small
ones easy.

**The scanners are the best place to start.** Each detector in
`portcullis-scan` is a self-contained pattern with its own fixtures. Adding one
means adding a regex, a variant, and a test, and needs no understanding of the
proxy at all. Issues labelled [`good first
issue`](https://github.com/sushantlokhande14/portcullis/labels/good%20first%20issue)
are mostly of this shape.

Read [CONTRIBUTING.md](CONTRIBUTING.md) first; it is short, and it explains the
one rule that trips people up (test fixtures for credentials are built at
runtime, never written as literals, because push protection will reject them).

## License

Dual licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you state otherwise, any contribution you intentionally
submit for inclusion shall be dual licensed as above, without additional terms.

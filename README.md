# portcullis

**A policy-enforcing gateway for the Model Context Protocol.**

When an agent connects to an MCP server, two things happen that nobody is
checking. Every tool the server exposes becomes callable by the model, and every
byte the server returns is spliced directly into the model's context. The first
is an authorization problem. The second is an injection problem, and it is the
one that gets overlooked, because tool output looks like data right up until the
model reads it as instructions.

portcullis sits in the middle. Your client points at portcullis instead of at
the real servers. portcullis speaks MCP in both directions, aggregates the
upstream servers behind one endpoint, and applies policy to every `tools/call`
that crosses it, in both directions.

```
  MCP client                 portcullis                    upstream servers
 (Claude Code,   <-- MCP -->  policy       <-- MCP -->   (filesystem, github,
  Cursor, Zed)                scanners                     postgres, ...)
                              rate limits
                              audit log
```

## Status

Early. The workspace is being built up in public, one reviewable stage at a
time. See [the roadmap](#roadmap) for what has landed.

## Why this exists

The MCP threat model is unusual because the dangerous input arrives through a
channel the user trusts. A README fetched by a `web.fetch` tool, a row returned
by a database tool, or an issue body returned by a GitHub tool is attacker
influenced content that lands in the same context window as the system prompt.
An agent with filesystem read and network write in the same session can be
talked into moving one to the other.

portcullis does not try to solve that with a smarter model. It solves the part
that is a plumbing problem: deny the calls that policy never permitted, strip
the credentials that should not be in a transcript, flag the tool output that is
shaped like an instruction, and write down everything that happened.

## Design principles

- **Fail closed.** An unparseable policy is a startup failure, not a warning. An
  unmatched tool call takes the configured default, and that default is `deny`
  in the shipped example policy.
- **Passthrough by default for everything else.** portcullis intercepts the
  methods it understands and forwards the rest untouched, including unknown
  fields, so it does not become the reason a new protocol revision breaks.
- **Every decision is explainable.** A denial names the rule that produced it.
  `portcullis explain` answers "what would happen if the agent called this"
  without starting a server.
- **No unsafe code.** `unsafe_code = "forbid"` at the workspace root.

## Roadmap

- [x] Workspace, licensing, and lint policy
- [ ] JSON-RPC 2.0 and MCP protocol types
- [ ] stdio transport
- [ ] Policy rules, matchers, and decision engine
- [ ] Credential and prompt-injection scanners
- [ ] Upstream lifecycle and multi-server tool aggregation
- [ ] Enforcement, redaction, and rate limiting
- [ ] Audit log
- [ ] CLI
- [ ] End-to-end tests and CI

## Contributing

Contributions are welcome, and the project is deliberately structured to make
them easy. The scanners in particular are a good place to start: each detector
is a self-contained rule with its own test fixtures, so adding one does not
require understanding the proxy. See `CONTRIBUTING.md` once it lands, and the
issues labelled `good first issue`.

## License

Dual licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

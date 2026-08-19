# Architecture

## Crate graph

```
portcullis-core  <-- portcullis-policy
      ^          <-- portcullis-scan
      |          <-- portcullis-proxy  <-- portcullis-cli
```

One direction only. `core` owns the wire format and knows nothing about policy;
`policy` and `scan` know nothing about proxies. That is what lets the entire
policy language be tested against plain JSON values and every detector against
plain strings, with no server, no process, and no protocol setup.

## The path of a call

1. The client sends `tools/call` with a published name like `fs__read_file`.
2. The registry maps that to an upstream and the name that upstream uses.
3. Policy evaluates against the upstream name, the published tool name, and the
   arguments. First matching rule decides; no match takes the default.
4. A denial returns immediately, as an `isError` result naming the rule. The
   upstream is never contacted.
5. An allowed call is forwarded with the name rewritten back to the upstream's.
6. The result is scanned: Unicode neutralisation first, then injection detection
   over both visible and recovered text, then credential redaction.
7. An audit record is written.

Step 6's ordering is the load-bearing part. Scanning for injection before
neutralising Unicode would let a payload hidden in tag characters pass, because
the injection detectors would only see the innocent visible sentence.

## Decisions worth knowing about

**Denials are tool results, not protocol errors.** A JSON-RPC error is absorbed
by the client library and the model often never learns why its call failed, so
it retries. An `isError` result lands in the context and the agent can act on it.

**Unknown fields are preserved.** Every type that is deserialised and
re-serialised carries a flattened `extra` map, and content blocks with an
unrecognised `type` are passed through verbatim. Round-trip tests assert byte
equality against payloads containing fields this build does not model.

**The transport frames by hand.** `read_line` grows without bound, which for a
process reading from servers it did not write is memory exhaustion. The reader
enforces a line limit and resynchronises after an oversized line, so one bad
response does not break every later message on the connection.

**Requests are matched by id through a pending table**, not serialised behind a
mutex on the stream, so one slow upstream does not stall calls to the others.

**Startup is all-or-nothing.** A gateway that came up with two of its three
servers would present a tool list quietly different from its configuration.

## Known gaps

These are real and tracked, not hidden:

- **Resources and prompts are refused, not mediated.** Forwarding them would put
  content in the model's context that no policy inspected.
- **Upstream `tools/list_changed` notifications are not forwarded**, which is
  why the handshake advertises `listChanged: false`.
- **Rate limits are not yet expressible in policy files.** The limiter exists
  and is tested; wiring it to a `rate_limit` key on a rule is open work.
- **OpenTelemetry export.** Spans use `tracing` with GenAI-convention field
  names, but there is no OTLP exporter yet.
- **Non-text content is uninspected.**

Each of these is a reasonable contribution. See the issue tracker.

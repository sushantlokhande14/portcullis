# Policy reference

A policy is an ordered list of rules plus a default. Evaluating a call walks the
rules top to bottom; the first rule that applies decides, and if none does, the
default decides.

Check any policy without running anything:

```bash
portcullis validate --strict policies/default.toml
portcullis explain --tool fs__read_file --args '{"path":"/etc/passwd"}'
```

## Document

```toml
version = 1        # schema version; a future version is refused, not guessed at
default = "deny"   # applied when no rule matches. Keep this deny; see below.
```

Unknown top-level keys are a load error. A policy file is security
configuration, and a typo must not silently produce something other than what
was written.

## Rules

```toml
[[rule]]
id = "deny-credential-paths"          # required, unique; quoted in denials and audit
description = "..."                   # optional, shown to the model on a denial
tools = ["fs__*", "gh__create_*"]     # required, at least one glob
servers = ["fs"]                      # optional; omit to apply to every upstream
action = "deny"                       # allow | deny
when = [ ... ]                        # optional conditions, all must hold
```

Duplicate ids are an error: an audit record naming a rule that occurs twice does
not identify what decided the call.

### Tool patterns

Globs, matched against the **published** name, which is `server__tool` by
default.

| Pattern | Meaning |
| --- | --- |
| `fs__read_file` | exactly that tool |
| `fs__*` | every tool on the `fs` upstream |
| `*__search` | a `search` tool on any upstream |
| `gh__create_?` | one character where the `?` is |
| `*` | everything |

Matching is case-sensitive. There is no escape character.

## Conditions

Each entry in `when` names one argument path and exactly one predicate. Naming
none or two is a load error that quotes the offending keys.

**All conditions must hold** for the rule to apply. Within a single condition, a
wildcard path may select several values and the condition holds if **any** of
them satisfies the predicate. A rule denying writes under `/etc` fires when one
path out of fifty is under `/etc`.

### Predicates

| Key | Holds when |
| --- | --- |
| `equals` | the value equals this JSON value exactly |
| `one_of` | the value equals one of these |
| `contains` | the value is a string containing this substring |
| `matches` | the value is a string matching this regex |
| `glob` | the value is a string matching this glob |
| `gt` / `lt` | the value is a number strictly above / below this |
| `exists` | the path selects at least one value, including an explicit null |

Add `not = true` to invert. `exists = false` is shorthand for a negated
presence check.

```toml
when = [
  { arg = "path", matches = "(^|/)\\.(ssh|aws)(/|$)" },
  { arg = "recursive", equals = true },
  { arg = "mode", one_of = ["w", "a"] },
  { arg = "limit", gt = 1000.0 },
  { arg = "files.*.path", contains = "/etc/" },
  { arg = "force", exists = true },
]
```

### Argument paths

Dotted, with `*` as a wildcard segment.

| Path | Selects |
| --- | --- |
| `path` | the top-level `path` argument |
| `options.recursive` | a nested field |
| `files.0.name` | the first array element's `name` |
| `files.*.path` | every element's `path` |
| `` (empty) | the whole arguments object |

## Rate limits

A limit may be written on an `allow` rule, and one may be written for the whole
session:

```toml
session_rate_limit = { max = 500, per_seconds = 60 }

[[rule]]
id = "allow-github-drafting"
tools = ["gh__create_issue", "gh__comment_*"]
action = "allow"
rate_limit = { max = 10, per_seconds = 300 }
```

`max` is both the ceiling and the burst allowance: ten calls immediately, then
one every thirty seconds as the bucket refills. Refill is continuous rather than
per-window, so twice the limit cannot land across a window boundary.

**The budget belongs to the rule, not the tool.** The example above grants ten
calls per five minutes across all four tools together. For a separate budget per
tool, write a narrower rule, which also makes the intent readable.

A limited call is refused with a message that says it is *temporary*, unlike a
policy denial, and gives a retry-after. The message names whichever budget
actually ran out, so a call a rule allowed but the session limit stopped points
at the session limit rather than at the rule.

A limit on a `deny` rule is inert, since a deny rule refuses every call anyway.
That is a `rate-limit-on-deny` warning rather than an error. A `max` or
`per_seconds` of zero is a load error: writing `max = 0` to mean "never" is
indistinguishable at runtime from a bucket that has not refilled, so use
`action = "deny"`, where the refusal names the rule.

## The two things that bite

### An absent argument makes a condition false

A rule saying "deny when `path` contains `..`" does **not** fire on a call that
omits `path`. Nothing was selected, so nothing contains `..`.

This is why `default = "deny"` is not a style preference. Under default-deny the
call falls through and is refused anyway. Under default-allow it sails past
every deny rule that could not evaluate. `validate` warns when the default is
`allow`, and the warning explains this.

### Negation over an absent argument is vacuously true

```toml
{ arg = "force", not = true, equals = true }   # "force is not true"
```

This also holds when the call omits `force` entirely, which is logically correct
and rarely what the author meant. Pair it with a presence check:

```toml
when = [
  { arg = "force", exists = true },
  { arg = "force", not = true, equals = true },
]
```

`validate` emits `vacuous-negation` for the unpaired form.

## Ordering

First-match-wins means a broad `allow` near the top silently shadows every
narrower `deny` below it:

```toml
[[rule]]
id = "allow-all-reads"
tools = ["fs__*"]
action = "allow"

[[rule]]
id = "deny-ssh"        # never reached
tools = ["fs__read_file"]
action = "deny"
```

Put deny rules for credential material first. `validate` reports the
unreachable cases it can prove, and it is deliberately conservative: it only
flags an earlier unconditional, unscoped rule whose patterns visibly cover a
later one, because a false "this rule is dead" would train you to ignore the
warning.

## Validation diagnostics

| Code | Severity | Meaning |
| --- | --- | --- |
| `duplicate-rule-id` | error | two rules share an id, so audit cannot attribute a decision |
| `unreachable-rule` | warning | an earlier rule already covers this one |
| `vacuous-negation` | warning | a negated condition with no companion presence check |
| `default-allow` | warning | the default forwards anything unmatched |
| `rate-limit-on-deny` | warning | a limit on a rule that refuses every call, so the limit is inert |

`validate --strict` exits non-zero on warnings, for use in CI.

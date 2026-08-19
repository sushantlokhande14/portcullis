# Threat model

This document says what portcullis defends against, what it does not, and where
the honest gaps are. It is written to be read by someone deciding whether to
rely on this, so it leads with the limits.

## The shape of the problem

An MCP session has an unusual property: the dangerous input arrives through a
channel the user explicitly trusted. A user configures a GitHub server because
they want their agent to read issues. The issue *body* is written by whoever
opened it. The user vouched for the server; nobody vouched for its contents.

Two things follow from every tool the agent can reach:

1. **The call may be harmful.** `delete_repository` is one token away from
   `list_repositories` in the model's output distribution.
2. **The result may be an instruction.** Text returned by a tool lands in the
   same context window as the system prompt, and the model has no reliable way
   to tell one from the other.

The combination is what makes this worth solving. An agent with a read tool and
a write tool, in the same session, can be talked into moving data from one to
the other by a string it read on the way past.

## What portcullis defends against

**Unauthorized tool calls.** Policy is evaluated before the call is forwarded,
and there is a test asserting a denied call never reaches the upstream at all,
not merely that the client saw an error. This is the only *structural* control
in the project. Everything below is defence in depth on top of it.

**Credential propagation.** Provider-format detectors run over arguments on the
way out and results on the way back. This narrows two real paths: an agent
pasting a `.env` file into an issue body, and a secret in a tool result being
copied onward into transcripts, traces, and log aggregators.

**Covert-channel injection.** Text hidden in the Unicode tag block is decoded,
judged by the injection detectors, and stripped. This one is not a heuristic:
there is no legitimate reason for a tool result to contain those characters, so
detection is decidable. Bidi overrides are handled the same way.

**Runaway loops.** Token-bucket limits bound how many times a permitted call can
happen, which is a different question from whether it is permitted once.

**Forensics.** Every decision is recorded with the deciding rule, an argument
digest, and scanner findings.

## What portcullis does not defend against

**Injection phrasings nobody anticipated.** The injection detectors match
patterns that circulate publicly. Natural language paraphrases without bound,
and an attacker who reads `injection.rs` can write around it in an afternoon.
These findings are a signal for the audit log and a trigger for fencing, not a
filter you can rely on.

**A model that ignores the fence.** `annotate` mode wraps untrusted content in a
marker saying it is data. A sufficiently persuasive payload can talk a model
past a banner as easily as past a rule. It moves the odds.

**Anything a shell tool can do.** A shell tool is every other tool at once, and
no argument pattern separates a safe command from an unsafe one. The shipped
policy denies shell tools and says so in a comment. If you allow one, the rest
of your policy is advisory.

**Content in non-text blocks.** Images and audio are forwarded untouched.
Steganographic payloads are a real gap. They are reported as uninspected rather
than counted as clean, because a scanner that has not looked at something must
not claim it is safe.

**Resources and prompts.** Not mediated. They are refused rather than forwarded,
which is the honest state: forwarding would put content in the context that no
policy inspected. This is tracked as open work.

**A hostile upstream server.** portcullis assumes the servers you configured are
the ones you meant to configure. A malicious server can lie in its tool
annotations, return anything it likes, and describe its tools misleadingly.
Policy still bounds what it can be *asked* to do, which is the useful half.

**The gateway's own host.** Anyone who can edit your policy file, replace the
binary, or read the audit log has already won. portcullis does not defend its
own configuration.

## Design decisions that follow

**Default deny.** An absent argument makes a condition false, so a call crafted
to omit the argument a deny rule inspects will not match that rule. Under
default-allow it would then be forwarded. Default-deny is what makes deny rules
meaningful rather than advisory, and `validate` warns when the default is set
the other way.

**Denials are visible to the model.** A denial returns an `isError` result
naming the rule, rather than a protocol error the model never sees. An agent
that cannot tell why a call failed retries it. The rule id is a label the
operator wrote, not a secret.

**Fail closed on configuration, fail open on telemetry.** An unparseable policy
stops the gateway from starting. A failed audit write is logged and swallowed,
because a full disk should not take out the gateway, and the audit log is a
record of decisions rather than part of making them.

**Unknown things are preserved, not dropped.** Unrecognised protocol fields and
content types pass through intact. A gateway that quietly deletes what it does
not understand is a gateway that breaks on the next protocol revision.

## Reporting

Gaps in detectors are ordinary issues and are welcome. Vulnerabilities in
portcullis itself go through [SECURITY.md](../SECURITY.md).

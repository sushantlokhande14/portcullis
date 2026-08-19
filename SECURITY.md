# Security policy

## Reporting a vulnerability in portcullis

Please report privately through [GitHub Security
Advisories](https://github.com/sushantlokhande14/portcullis/security/advisories/new)
rather than opening a public issue.

Include what you were running, what you expected, and what happened. A proof of
concept helps but is not required to start a conversation.

This is a personal project maintained in spare time, so treat any timeline as
best effort rather than a commitment. You will get an acknowledgement; if a fix
takes a while, you will get an explanation of why.

## What counts as a vulnerability here

A bug that lets a call bypass policy, causes a denial to be forwarded anyway, or
makes the gateway leak a credential it was supposed to redact.

## What does not

**A phrasing the injection detectors miss is not a vulnerability.** Those
detectors are documented heuristics over natural language, their limits are
stated in the README and the threat model, and they are not a security boundary.
Report a missed phrasing as an ordinary issue; it is a welcome contribution and
discussing it in public is how the detectors improve.

The same goes for anything already listed under "What portcullis does not defend
against" in [docs/threat-model.md](docs/threat-model.md). Those are known and
documented limits, not undisclosed weaknesses. If you think one of them is
described too generously, that is worth an issue too.

## Supported versions

The `main` branch. There are no released versions yet.

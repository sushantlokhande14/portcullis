## What this changes

<!-- One or two sentences. -->

## Why

<!-- The reasoning. If you rejected an alternative approach, this is the place
     to say which and why; that context is worth more than the diff. -->

## Checklist

- [ ] `cargo fmt --all`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] New public items are documented

If this adds or changes a detector:

- [ ] A positive test showing it fires
- [ ] A negative test with realistic, non-malicious content that must not match
- [ ] Any credential-shaped fixture is assembled at runtime, not written as a
      literal (see CONTRIBUTING.md)

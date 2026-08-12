# Contributing to GAIT

Thanks for considering a contribution. This project accepts
contributions **only through GitHub pull requests**. There is no
submission form, no account system, and no other channel — identity,
history, and review all live on GitHub, by design.

## What's welcome

- **New patterns**, describing a real, documented implant/backdoor
  behaviour, cited from a technical source (a vendor advisory, a CVE
  write-up, a threat-intel report — not a news summary of one).
- **Corrections to existing patterns**, especially if you have direct
  evidence (packet captures, honeypot logs, your own analysis) that a
  field is wrong or a `verified: assumed` field can be upgraded to
  `clear`.
- **Improvements to `validate.py` or `engine.py`**: bug fixes, new
  input formats, better false-positive handling. Open an issue first
  for anything beyond a small fix, so we don't duplicate effort.

## What's not a good fit

- Patterns based purely on IPs, hashes, or domains, with no behavioural
  description. That's what most other threat-intel feeds already do
  well — GAIT exists to capture what survives when those rot.
- Patterns you can't cite a public technical source for. If you found
  something yourself (e.g. on your own network or honeypot), describe
  the behaviour you observed directly as the source, but be explicit
  that it's a first-hand observation, not a published advisory.

## Before you open a PR

1. Read `SCHEMA.md`. It documents every field, what it means, and how
   it's validated.
2. Write the pattern's `description` in your own words. Do not copy
   sentences from the advisory you're citing — summarise the behaviour,
   and let `source.url` carry the reader to the original text. This
   matters for copyright, and it also forces a real understanding of
   what you're encoding rather than a transcription.
3. Mark every behavioural field `verified: "clear"` only if you can
   point to where, in the cited source, that exact fact is stated. If
   you're inferring or estimating, use `verified: "assumed"` — an
   honest, incomplete pattern is more useful than a confident, wrong
   one.
4. Run the validator locally before opening the PR:

   ```bash
   python3 validate.py patterns/your-new-pattern.yaml
   ```

   Fix every error. Read every warning — they usually mean the pattern
   as written will never fire, or will fire on everything.

## Pull request checklist

- [ ] File is named `patterns/<id>.yaml`, matching the `id` field inside it.
- [ ] `validate.py` passes with no errors.
- [ ] `source.url` points to a real, technical, publicly accessible page.
- [ ] `description` is written in your own words, not copied from the source.
- [ ] Every field marked `verified: "clear"` is genuinely stated in the source, not inferred.
- [ ] PR description states, briefly, what makes this behaviour distinctive (why these fields, why these weights).

## Review process

This is currently a single-maintainer project. Expect review to focus
on:

- whether the cited source actually supports what's `verified: "clear"`,
- whether `confidence_weight` values are reasonable relative to how
  distinctive and hard-to-fake each trait is,
- whether the pattern is specific enough to be useful without being so
  narrow it will never match real traffic.

Disagreements about weighting are normal and welcome in the PR
discussion — there's no single objectively correct weight for most
fields, and the goal is a pattern that's honest about its own
confidence, not one that scores perfectly on paper.

## Licensing

By submitting a pull request, you agree that your contribution is
licensed under the same MIT license as the rest of this project (see
`LICENSE`).

## Code contributions

The same PR-only process applies to `validate.py`, `engine.py`, and
`fake_implant.py`. If you're adding a new schema field, update
`SCHEMA.md` and `validate.py`'s `BEHAVIOR_FIELDS` together, in the same
PR — a field that exists in one but not the other will confuse the next
contributor.

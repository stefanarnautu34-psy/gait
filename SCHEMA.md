# Pattern schema

Every pattern is a single YAML file in `patterns/`. This document
describes every field. `validate.py` enforces everything described here;
if the two ever disagree, `validate.py` is the source of truth and this
file has a bug.

Field-level conventions used throughout:

- **`confidence_weight`** (0.0–1.0, required on every behavioural field):
  how much this field should count toward the match score, relative to
  the other fields in the pattern. Higher means "this trait is
  distinctive and hard for an attacker to change." A field with weight
  `0.0` is accepted but contributes nothing to scoring — a warning, not
  an error, since it may be there for documentation purposes.
- **`verified`** (`"clear"` or `"assumed"`, required on every behavioural
  field): whether this value was read directly and unambiguously from
  the source material (`clear`), or inferred / estimated and still
  needs confirmation (`assumed`). A field cannot be marked `clear` if it
  has no real value — that combination is rejected as a contradiction.
- Any field can be left unknown. Depending on the field's type, "unknown"
  is spelled `null`, `"unknown"`, or an empty list — see each field below.
  An unknown field is excluded from scoring entirely; it is not treated
  as a mismatch.

## Top-level (metadata) fields

| Field | Required | Type | Notes |
|---|---|---|---|
| `id` | yes | string | kebab-case (`lowercase-words-with-hyphens`). Should match the filename. |
| `name` | yes | string | Human-readable name of the implant/family. |
| `family` | yes | string | Malware/implant family name, used to group related patterns. |
| `cve` | no | string | Format `CVE-YYYY-NNNN...`, if one applies. |
| `version` | yes | integer ≥ 1 | Bump on every meaningful revision of this pattern. |
| `created` | yes | date `YYYY-MM-DD` | |
| `updated` | yes | date `YYYY-MM-DD` | Must not be earlier than `created`. |
| `author` | yes | string | Who wrote this pattern. |
| `source` | yes | object | See below. |
| `description` | yes | string | Free text, in your own words — see the copyright note below. Aim for enough detail to be useful as a standalone reference (40+ characters; a one-line description triggers a warning). |
| `severity` | yes | enum | One of `low`, `medium`, `high`, `critical`. Informational only, does not affect scoring. |
| `behavior` | yes | object | See "Behavioural fields" below. Must contain at least one field. |
| `scoring` | yes | object | See "Scoring" below. |

### `source`

```yaml
source:
  name: "VulnCheck"
  url: "https://example.com/advisory"
  published: "2026-08-05"   # optional
```

`name` and `url` are required. `url` must be a valid `http(s)://` link.
Always cite the original technical source, not a news summary of it —
the more technical the source, the more fields you'll be able to fill in
with `verified: clear` instead of guessing.

### A note on writing `description`

Write it in your own words. Do not copy-paste sentences from the
advisory or article you're citing — summarise the behaviour as you
understand it, and let `source.url` carry the reader to the original for
exact wording. This keeps every pattern clear of copyright issues and
forces you to actually understand the behaviour you're encoding, not
just transcribe it.

## Behavioural fields

All fields live under `behavior:`. Every field you include needs
`confidence_weight` and `verified`, plus whatever value keys are listed
below. You do not need to include every field — a pattern with three or
four well-evidenced fields is more useful than one with nine guessed
ones.

| Field | Value shape | Unknown spelling | Meaning |
|---|---|---|---|
| `connection_direction` | `value:` one of `outbound`, `inbound`, `bidirectional`, `unknown` | `"unknown"` | Which way the implant initiates traffic. |
| `trigger` | `value:` one of `boot`, `scheduled`, `periodic`, `on_demand`, `unknown` | `"unknown"` | What starts the implant's activity. |
| `dns_lookup_before` | `value:` boolean | `"unknown"` | Whether the implant resolves a domain before connecting, or talks to a hardcoded IP. Note how `engine.py` checks it: a DNS answer is matched to a flow by destination IP inside a time window, which is correlation, not authoritative domain-to-flow attribution. A domain with several A records, a CDN, or a busy resolver can all weaken that link, and an unrelated lookup for the same IP shortly before the connection will satisfy it. Read a match as "a lookup for this address preceded the connection", not as "this implant resolved this name". |
| `payload_size_bytes` | `min:`, `max:` (integers, either may be `null`) | both `null` | Expected size range of the connection's initial payload, in bytes. |
| `auth_present` | `value:` boolean | `"unknown"` | Whether the C2 channel authenticates the client, at the application level. Document it when the source says so, but note that `engine.py` reports this field as unevaluable from network telemetry: flow records do not show application-level authentication. It costs coverage and contributes nothing to the score. |
| `transport_encryption` | `value:` boolean | `"unknown"` | Whether the channel is encrypted in transit. This one the IDS can check, by the protocol it identifies. Distinct from `auth_present`: a TLS connection can be anonymous, and cleartext HTTP can carry a bearer token. If a source says "communicates over HTTPS", it is describing this field, not the one above. |
| `destination_asn_hint` | `value:` list of ASNs (numbers or `"AS12345"` strings) | `[]` | Known hosting ASN(s) for the C2 infrastructure, if documented. |
| `process_name_pattern` | `value:` a regular expression string; optional `note:` | `null` or `""` | Process name to look for in host telemetry (e.g. Falco). Kept short and simple — see the ReDoS note below. |
| `c2_port_hint` | `value:` list of integers, 1–65535 | `[]` | Known C2 port(s). |
| `beacon_interval_seconds` | `value:` number > 0; optional `tolerance_seconds:` | `null` | How often the implant phones home, and how much jitter is acceptable around that figure. |

Example of a single field, fully written out:

```yaml
beacon_interval_seconds:
  value: 35
  tolerance_seconds: 5
  confidence_weight: 0.65
  verified: "clear"
```

### A note on `process_name_pattern` and ReDoS

This field is matched with Python's `re` module against process names
seen in host telemetry. Regular expressions can be constructed to run in
exponential time on certain inputs (catastrophic backtracking, aka
ReDoS). `validate.py` rejects:

- expressions longer than a small fixed length (process names are
  short; a long expression is a red flag, not a legitimate need),
- expressions containing nested quantifiers such as `(a+)+` or `(a*)*`,
  the classic ReDoS shape.

Keep these expressions simple: an anchor and a literal or two
(`^kworker`) is almost always enough. If your case genuinely needs
something more elaborate, open an issue before assuming the validator
is wrong.

## `scoring`

```yaml
scoring:
  method: "weighted_sum"
  threshold_alert: 0.7
```

| Field | Required | Notes |
|---|---|---|
| `method` | yes | Currently only `weighted_sum` is supported. |
| `threshold_alert` | yes | Number in `(0.0, 1.0]`. The engine flags a candidate as a match when its score reaches this value. `validate.py` warns if the sum of weights of your `clear`/valued fields can never reach this threshold — meaning the pattern could never alert as written. |

## Validating a pattern

```bash
python3 validate.py patterns/your-pattern.yaml
```

Use `--strict` to treat warnings as errors (useful in CI before merging
a PR), and `--json` for machine-readable output.

`validate.py` will, among other things:

- reject unknown fields (typos, or fields not yet in this schema),
- reject a field marked `verified: clear` with no actual value,
- warn if a pattern has fewer than three fields with real values (high
  false-positive risk),
- warn if no field is marked `clear` at all (the whole pattern is
  guesswork),
- warn if the sum of weights of your known fields can never reach
  `threshold_alert`.

Warnings do not block a merge on their own, but they're worth reading —
they usually point at a pattern that will either never fire or fire on
everything.

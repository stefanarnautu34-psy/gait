# GAIT — General Adaptive Implant Tracker

An open, versioned library of **behavioural** detection patterns for
IoT/network implants and backdoors, plus a small engine that matches
those patterns against real traffic logs (Suricata `eve.json`, optionally
enriched with Falco process telemetry).

GAIT does not rely on indicators that change easily (a specific IP, a
file hash). It describes *how an implant behaves*: when it starts, how
often it phones home, whether it authenticates, what ports it prefers.
Those traits are much harder for an attacker to change without rebuilding
the implant itself.

This is closer to knowledge-based / heuristic detection than to anomaly
detection: it does not learn a baseline from your network, it compares
observed traffic against patterns written from public research (CVEs,
vendor advisories, threat intel write-ups).

## Status

Early stage, single maintainer. One complete pattern
(`ENDLESSDOORS / Zbtlink AX3000`, CVE-2026-66747) is included as a
reference implementation. The engine has been validated against real
home-network traffic (Suricata, ~99k connections) with zero false
positives, and against a simulated implant beacon with a perfect match.
It has not yet been validated against a real-world compromise.

Treat this as a research and detection-engineering aid, not a finished
production security product.

## Why this exists

Static indicators (IPs, hashes, domains) rot fast. A router backdoor's
*behaviour* — booting silently, beaconing on a fixed interval, skipping
DNS, talking to a fixed port with no authentication — tends to survive
across campaigns and rebrands longer than any single IP ever will.

GAIT tries to capture that behaviour in a small, readable YAML format
that a human can write from a technical advisory, and that a machine
can score against real traffic.

## How it works

```
             write pattern from a technical source
                          |
                          v
patterns/*.yaml  --->  validate.py  --->  engine.py  --->  JSON lines output
(behavioural           (checks the         (scores real       (score, matched/
 description)           pattern is          traffic against     mismatched/
                         well-formed)        every pattern)      unevaluable fields)
```

1. **Patterns** (`patterns/*.yaml`) describe a known implant's behaviour:
   direction, boot trigger, DNS usage, payload size, authentication,
   destination ASN, process name, C2 ports, beacon interval. Each field
   carries a `confidence_weight` (how much it should count toward the
   score) and a `verified` flag (`clear` — read directly from the source,
   or `assumed` — inferred, to be confirmed).

2. **`validate.py`** checks that a pattern file is well-formed: valid
   field types, weights in range, no contradictions (e.g. a field marked
   `clear` with no actual value), and rejects regular expressions that
   could cause catastrophic backtracking (ReDoS) if used in
   `process_name_pattern`.

3. **`engine.py`** reads a Suricata `eve.json` log (and, optionally, a
   Falco JSON log for process telemetry), groups connections into
   candidates (same source, destination, port), and scores each
   candidate against every pattern. The score is the weight of *matched*
   fields divided by the weight of *fields that could actually be
   evaluated from the data you gave it* — fields the logs can't speak to
   are excluded from the score, not counted as a miss. A separate
   `coverage` value tells you how much of the pattern was testable at
   all, so a perfect score on a thin pattern isn't mistaken for a
   perfect score on a well-evidenced one.

Output is JSON lines, one match per line, so it can be tailed into
Wazuh (or any other log pipeline) as just another log source, or
consumed by any script.

## What this is not

- **Not an IDS.** GAIT does not capture packets and has no network
  listener. It reads logs that an existing IDS (Suricata today; other
  formats may be added later) has already produced. You need Suricata,
  or a compatible log source, already running.
- **Not anomaly detection.** It does not learn what "normal" looks like
  on your network. It compares traffic against explicit, hand-written
  patterns. A pattern that is wrong or incomplete will produce wrong or
  incomplete results — the tool is only as good as the patterns in it.
- **Not a verdict.** A match is a lead, not a conviction. Every alert
  should be reviewed by a human before any action is taken.

## Getting started

Requirements: Python 3.9+, [PyYAML](https://pypi.org/project/PyYAML/).

```bash
pip install pyyaml
```

Validate a pattern:

```bash
python3 validate.py patterns/endlessdoors-zbtlink-ax3000.yaml
```

Score your traffic against every pattern in the library:

```bash
python3 engine.py \
  --patterns patterns/ \
  --suricata /var/log/suricata/eve.json \
  --local-net 192.168.0.0/24
```

Only alerts above each pattern's threshold are printed by default.
Add `--all` to see every candidate that was scored, including those
below the threshold — useful when tuning a new pattern or checking for
false positives on your own traffic before trusting an alert.

Add process telemetry from Falco, if you have it:

```bash
python3 engine.py \
  --patterns patterns/ \
  --suricata /var/log/suricata/eve.json \
  --falco /var/log/falco/events.log \
  --local-net 192.168.0.0/24
```

Feed the output into Wazuh as a new log source (`<localfile>` with
`log_format json`) and write custom rules on top of the `gait.*` fields,
the same way you would integrate any other JSON-producing tool.

### Testing the engine without a real implant

`fake_implant.py`, in this repository, is a small standalone script that
simulates the beacon behaviour described in the ENDLESSDOORS pattern
(fixed interval, fixed port, cleartext, no DNS). It exists purely so you
can verify the engine actually detects something on your own setup,
without needing a real compromise to test against. It is not part of the
detection library itself.

```bash
python3 fake_implant.py <fake-C2-host> <port> --count 8
```

Point it at a listener you control (e.g. `ncat -lk -p 7000` on a second
machine), then run the engine against your Suricata log to confirm it
scores the simulated traffic correctly.

## Contributing patterns

New patterns are contributed exclusively through GitHub pull requests.
There is no submission form and no account system: identity and review
history are handled entirely by GitHub. See `CONTRIBUTING.md` and
`SCHEMA.md` before opening a PR.

## Security and privacy

- `engine.py` and `validate.py` make no network connections and send no
  telemetry anywhere. They read the local files you point them at and
  write output to the local file (or stdout) you specify. Read the
  source — it's short enough to audit yourself.
- Pattern contributions go through `validate.py`, which rejects
  regular expressions that could cause catastrophic backtracking, before
  they can be merged or run against your traffic.
- No user accounts, no API keys, no personal data of any kind are
  collected by this project.

## Disclaimer

This software is provided "as is", without warranty of any kind — see
`LICENSE`. GAIT is a detection-engineering aid, not a certified security
product. A match does not prove compromise, and the absence of a match
does not prove safety. Always verify findings independently and apply
your own judgement before acting on any alert produced by this tool.

## License

MIT — see `LICENSE`.

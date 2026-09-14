#!/usr/bin/env python3
"""
selftest.py - does the engine still catch a beacon, and does it stay quiet
otherwise?

Both halves matter. On 2026-09-14 the engine reported 56 alerts on 50k
connections of ordinary home traffic, every one of them false: a pattern could
reach score 1.0 on generic fields alone (outbound, encrypted, preceded by DNS),
because the score is computed only over the fields the logs can speak to. One
"alert" was AdGuard checking for updates; four more were daily update checks
whose intervals happened to land inside a tolerance of +/- 1h48m. The fix
requires at least one discriminant field before anything alerts, and tightened
the beacon check.

This test pins both directions down. A change that silences the false
positives by silencing everything fails cases A, B and F just as loudly as a
regression fails C, D and E.

Two patterns are used, because the two halves need isolating:

  P1  generic + c2_port_hint + beacon   an uncommon port is itself
                                        discriminant, so P1 can alert on the
                                        port alone. That is intended.
  P2  generic + beacon, no port         the shape of the real Ted pattern,
                                        where only the rhythm can carry an
                                        alert. The cases that test the beacon
                                        logic use P2 on port 443, so nothing
                                        else can do the work for it.

Runs on synthetic flows: no network, no root.

    python3 testdata/selftest.py
    python3 testdata/selftest.py --engine engine/engine.py --keep
"""

import argparse
import json
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta
from pathlib import Path

SRC = "192.168.88.115"
LOCAL_NET = "192.168.88.0/24"

P1_ID = "selftest-port-and-beacon"
P2_ID = "selftest-beacon-only"

P1 = """\
id: selftest-port-and-beacon
name: Selftest - uncommon port plus beacon
family: Selftest
version: 1
created: '2026-09-14'
updated: '2026-09-14'
author: GAIT selftest
source:
  name: selftest
  url: https://example.invalid/selftest
  published: '2026-09-14'
description: >-
  Synthetic pattern for testdata/selftest.py. Lists an uncommon C2 port, so it
  can alert on the port alone; used for the cases that check the engine still
  detects something, not for the cases that check it stays quiet.
severity: low
behavior:
  connection_direction:
    value: outbound
    confidence_weight: 0.6
    verified: clear
  c2_port_hint:
    value: [4444]
    confidence_weight: 0.7
    verified: clear
  beacon_interval_seconds:
    value: 3600
    confidence_weight: 0.8
    verified: clear
scoring:
  method: weighted_sum
  threshold_alert: 0.7
"""

P2 = """\
id: selftest-beacon-only
name: Selftest - generic fields plus beacon
family: Selftest
version: 1
created: '2026-09-14'
updated: '2026-09-14'
author: GAIT selftest
source:
  name: selftest
  url: https://example.invalid/selftest
  published: '2026-09-14'
description: >-
  Synthetic pattern for testdata/selftest.py, deliberately shaped like the real
  Ted backdoor pattern: everything generic except the beacon interval. Only the
  rhythm can carry an alert here, which is what makes it useful for testing the
  beacon checks in isolation.
severity: low
behavior:
  connection_direction:
    value: outbound
    confidence_weight: 0.6
    verified: clear
  auth_present:
    value: true
    confidence_weight: 0.75
    verified: clear
  beacon_interval_seconds:
    value: 3600
    confidence_weight: 0.8
    verified: clear
scoring:
  method: weighted_sum
  threshold_alert: 0.7
"""

P3_ID = "selftest-long-beacon"

P3 = """\
id: selftest-long-beacon
name: Selftest - twelve hour beacon
family: Selftest
version: 1
created: '2026-09-14'
updated: '2026-09-14'
author: GAIT selftest
source:
  name: selftest
  url: https://example.invalid/selftest
  published: '2026-09-14'
description: >-
  Synthetic pattern for testdata/selftest.py with the same twelve-hour interval
  the real Ted backdoor pattern declares. It exists to test the tolerance cap:
  15 percent of 43200 seconds is a window almost two hours wide either side,
  which is how four ordinary daily update checks were read as beacons.
severity: low
behavior:
  connection_direction:
    value: outbound
    confidence_weight: 0.6
    verified: clear
  auth_present:
    value: true
    confidence_weight: 0.75
    verified: clear
  beacon_interval_seconds:
    value: 43200
    confidence_weight: 0.8
    verified: clear
scoring:
  method: weighted_sum
  threshold_alert: 0.7
"""


# label, pattern id to assert on, dest ip, port, app proto,
# offsets in seconds, expected alert, why the case exists
CASES = [
    ("A  perfect beacon on an uncommon port",
     P1_ID, "203.0.113.10", 4444, "failed",
     [0, 3600, 7200, 10800, 14400], True,
     "the thing the engine exists to find"),

    ("B  jittered beacon on an uncommon port",
     P1_ID, "203.0.113.11", 4444, "failed",
     [0, 3580, 7220, 10790, 14410], True,
     "a real implant is not a metronome; fake_implant.py jitters on purpose"),

    ("C  three connections, plausible median",
     P2_ID, "203.0.113.12", 443, "tls",
     [0, 48915, 97830], False,
     "the actual 14.09 false positive: two gaps are two similar numbers, "
     "not a rhythm"),

    ("D  five connections, irregular",
     P2_ID, "203.0.113.13", 443, "tls",
     [0, 3600, 9000, 11000, 19000], False,
     "several daily jobs started at one boot used to read as a beacon"),

    ("E  regular rhythm, wrong interval",
     P2_ID, "203.0.113.14", 443, "tls",
     [0, 600, 1200, 1800, 2400], False,
     "10 minutes is not 60; a capped tolerance must not swallow the difference"),

    ("F  regular rhythm on a common port",
     P2_ID, "203.0.113.15", 443, "tls",
     [0, 3600, 7200, 10800, 14400], True,
     "the overcorrection check: a genuine rhythm is discriminant even on 443, "
     "so tightening the beacon must not have blinded the engine"),

    ("G  daily job, 1.6h off a 12h beacon",
     P3_ID, "203.0.113.16", 443, "tls",
     [0, 48915, 97830, 146745, 195660], False,
     "5715s off target: inside the old 15 percent window (+/-6480s), outside "
     "the 900s cap. This is the shape of all four real false positives"),

    ("H  12h beacon, 6 minutes off",
     P3_ID, "203.0.113.17", 443, "tls",
     [0, 43560, 87120, 130680, 174240], True,
     "360s off target is within any sane cap; a real implant that drifts a "
     "little must still be caught"),
]


def write_eve(path):
    base = datetime(2026, 9, 14, 8, 0, 0)
    rows = []
    for _, _, ip, port, proto, offsets, _, _ in CASES:
        for off in offsets:
            ts = (base + timedelta(seconds=off)).strftime(
                "%Y-%m-%dT%H:%M:%S.000000+0000")
            rows.append({
                "timestamp": ts,
                "event_type": "flow",
                "src_ip": SRC,
                "dest_ip": ip,
                "dest_port": port,
                "proto": "TCP",
                "app_proto": proto,
                "flow": {"bytes_toserver": 512, "bytes_toclient": 900,
                         "pkts_toserver": 5, "pkts_toclient": 5},
            })
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n",
                    encoding="utf-8")


def run_engine(engine, patterns_dir, eve, out):
    cmd = [sys.executable, str(engine),
           "--patterns", str(patterns_dir),
           "--suricata", str(eve),
           "--local-net", LOCAL_NET,
           "--all",
           "--output", str(out)]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if not out.exists():
        print("engine produced no output file", file=sys.stderr)
        print(proc.stderr, file=sys.stderr)
        return None
    return [json.loads(l) for l in out.read_text(encoding="utf-8").splitlines()
            if l.strip()]


def main():
    ap = argparse.ArgumentParser(description="GAIT engine self-test")
    ap.add_argument("--engine", default=None,
                    help="path to engine.py (default: ../engine/engine.py)")
    ap.add_argument("--keep", action="store_true",
                    help="keep the generated files and say where they are")
    args = ap.parse_args()

    here = Path(__file__).resolve().parent
    engine = Path(args.engine) if args.engine else here.parent / "engine" / "engine.py"
    if not engine.is_file():
        print(f"engine not found at {engine}", file=sys.stderr)
        return 2

    tmp = Path(tempfile.mkdtemp(prefix="gait-selftest-"))
    pdir = tmp / "patterns"
    pdir.mkdir()
    (pdir / "p1.yaml").write_text(P1, encoding="utf-8")
    (pdir / "p2.yaml").write_text(P2, encoding="utf-8")
    (pdir / "p3.yaml").write_text(P3, encoding="utf-8")
    eve = tmp / "eve.json"
    write_eve(eve)

    records = run_engine(engine, pdir, eve, tmp / "out.json")
    if records is None:
        return 2

    # (pattern id, dest ip) -> verdict
    seen = {}
    for r in records:
        seen[(r["gait"]["pattern_id"], r["observation"]["dest_ip"])] = r["gait"]

    failures = 0
    print(f"engine: {engine}")
    print(f"{len(CASES)} case(s), synthetic flows only\n")

    for label, pid, ip, _, _, _, expect, why in CASES:
        g = seen.get((pid, ip))
        got = bool(g and g["alert"])
        ok = got == expect
        if not ok:
            failures += 1
        print(f"  [{'ok' if ok else 'FAIL'}] {label}")
        print(f"         pattern {pid}")
        print(f"         expected alert={expect}, got alert={got}"
              f"{'' if g else ' (no record produced)'}")
        if g:
            print(f"         score={g['score']} coverage={g['coverage']} "
                  f"discriminant={g['discriminant_fields']}")
            if not ok:
                print(f"         reason: {g['alert_reason']}")
        print(f"         why: {why}")
        print()

    if args.keep:
        print(f"generated files kept in {tmp}")

    if failures:
        print(f"{failures} of {len(CASES)} case(s) FAILED")
        return 1
    print(f"all {len(CASES)} case(s) passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

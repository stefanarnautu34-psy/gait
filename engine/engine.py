#!/usr/bin/env python3
"""
GAIT - General Adaptive Implant Tracker
engine.py - matches observed network activity against behavioural patterns.

Usage:
    python3 engine.py --patterns patterns/ --suricata /var/log/suricata/eve.json
    python3 engine.py --patterns patterns/ --suricata eve.json --falco falco.log \\
        --output matches.json
    python3 engine.py --patterns patterns/ --suricata eve.json --all --pretty

Output is JSON lines (one object per line), ready to be picked up by Wazuh
through a <localfile> block with log_format json, or by any other tool.

Exit codes:
    0 = ran successfully, nothing scored above the threshold
    1 = ran successfully, at least one match above the threshold
    2 = usage error

This script reads local files only. It makes no network connections and sends
no telemetry anywhere. It does not require root.
"""

import argparse
import ipaddress
import json
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is missing. Install it with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


ENGINE_VERSION = "0.2"

# Field verdicts
MATCH = "match"
MISMATCH = "mismatch"
UNEVALUABLE = "unevaluable"

# Patterns arrive through pull requests, so a hostile regex must not be able to
# hang a run. Expressions are length-capped and rejected when they contain
# nested quantifiers; subjects are truncated because process names are short and
# catastrophic backtracking needs a long subject to bite.
MAX_REGEX_LENGTH = 200
MAX_SUBJECT_LENGTH = 256
NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*]")

# Suricata application protocol values.
ENCRYPTED_PROTOCOLS = {"tls", "ssh", "quic", "dtls"}
CLEARTEXT_PROTOCOLS = {"http", "ftp", "telnet", "smtp", "dns", "smb", "nfs",
                       "irc", "snmp", "sip", "rdp", "mqtt"}
# "failed" and "unknown" mean Suricata could not identify the protocol. That is
# not evidence of anything, and treating it as evidence of cleartext was a real
# source of false positives.
UNIDENTIFIED_PROTOCOLS = {"failed", "unknown"}

# Fields that are true of the implant but true of almost everything else too.
# "outbound TLS after a DNS lookup" describes a backdoor and it describes a
# browser, so a pattern that matches only on these has not identified anything.
# They still contribute to the score; they just cannot carry an alert alone.
GENERIC_FIELDS = {
    "connection_direction",
    "auth_present",
    "transport_encryption",
    "dns_lookup_before",
    "trigger",
    "payload_size_bytes",
}

# Ports so widely used that finding one in a pattern's C2 list says nothing
# about this particular connection.
COMMON_PORTS = {80, 443, 53, 22, 123, 8080, 8443}

# Beacon sanity limits. Three connections give two intervals, which is not a
# rhythm - it is two numbers that happen to be similar. And a percentage
# tolerance on a 12-hour interval opens a window hours wide, wide enough for
# any daily update check to fall into.
MIN_BEACON_GAPS = 3          # so at least 4 connections
MAX_BEACON_TOLERANCE = 900.0  # seconds, 15 minutes either side at most
MAX_BEACON_SPREAD = 0.25      # max(gap)-min(gap) must stay within 25% of median


def is_discriminant(field, entry):
    """Did this matched field actually narrow anything down?

    Generic fields never do. c2_port_hint does only when the port it matched is
    not one everything else uses: a pattern listing 443 matches all of HTTPS.
    """
    if field in GENERIC_FIELDS:
        return False
    if field == "c2_port_hint":
        port = entry.get("observed_port")
        return port is not None and port not in COMMON_PORTS
    return True


# ---------------------------------------------------------------------------
# Pattern loading
# ---------------------------------------------------------------------------

def load_patterns(path):
    files = []
    p = Path(path)
    if p.is_file():
        files = [p]
    elif p.is_dir():
        files = sorted(list(p.rglob("*.yaml")) + list(p.rglob("*.yml")))

    patterns = []
    for f in files:
        try:
            data = yaml.safe_load(f.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            print(f"[warning] skipping {f}: {exc}", file=sys.stderr)
            continue
        if isinstance(data, dict) and data.get("behavior"):
            data["_file"] = str(f)
            patterns.append(data)
        else:
            print(f"[warning] {f} does not look like a valid pattern, skipped",
                  file=sys.stderr)
    return patterns


def safe_compile(expression):
    """
    Compile a regex coming from a pattern file, refusing shapes that are known
    to backtrack catastrophically. Returns (compiled, error_message).
    """
    if len(expression) > MAX_REGEX_LENGTH:
        return None, f"expression longer than {MAX_REGEX_LENGTH} characters, refused"
    if NESTED_QUANTIFIER_RE.search(expression):
        return None, "expression contains nested quantifiers, refused"
    try:
        return re.compile(expression), None
    except re.error as exc:
        return None, f"invalid regular expression: {exc}"


# ---------------------------------------------------------------------------
# Log reading
# ---------------------------------------------------------------------------

def parse_ts(value):
    """Suricata writes ISO8601 with an offset. Returns a UNIX timestamp."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    try:
        txt = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(txt)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return None


def read_json_lines(path):
    """Read a JSON lines file, tolerating corrupt lines."""
    bad = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    bad += 1
    except OSError as exc:
        print(f"[error] cannot read {path}: {exc}", file=sys.stderr)
        return
    if bad:
        print(f"[warning] {bad} unreadable line(s) in {path}", file=sys.stderr)


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


IP_IN_TEXT = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class Telemetry:
    """Everything extracted from the logs, normalised."""

    def __init__(self):
        self.flows = []            # observed connections
        self.dns_answers = []      # (timestamp, resolved_ip, name)
        self.has_dns_visibility = False
        self.processes = []        # {"name": ..., "peers": set(ip)}
        self.has_process_visibility = False
        self.host_boot_ts = None   # only known when the user supplies it

    def processes_for(self, dest_ip):
        """
        Processes tied to this destination address.

        Falco reports per host, not per flow. When an event carries the network
        peer (fd.name, fd.sip) the correlation is exact. When it does not, the
        best we have is host-wide, which is flagged as weak so it cannot inflate
        every candidate on the host equally.
        """
        strict = sorted({p["name"] for p in self.processes if dest_ip in p["peers"]})
        if strict:
            return strict, True
        return sorted({p["name"] for p in self.processes}), False


def load_suricata(path, tel):
    """Pull flows, DNS answers and application hints out of eve.json."""
    for ev in read_json_lines(path):
        etype = ev.get("event_type")

        if etype == "dns":
            tel.has_dns_visibility = True
            ts = parse_ts(ev.get("timestamp"))
            dns = ev.get("dns", {})
            name = dns.get("rrname")
            # v2 format (answers list) and v1 format (rdata inline)
            answers = dns.get("answers") or []
            for a in answers:
                rdata = a.get("rdata")
                if rdata and _is_ip(rdata):
                    tel.dns_answers.append((ts, rdata, a.get("rrname") or name))
            if not answers and dns.get("rdata") and _is_ip(dns.get("rdata")):
                tel.dns_answers.append((ts, dns["rdata"], name))

        elif etype == "flow":
            flow = ev.get("flow", {})
            start = parse_ts(flow.get("start")) or parse_ts(ev.get("timestamp"))
            tel.flows.append({
                "ts": start,
                "src_ip": ev.get("src_ip"),
                "dest_ip": ev.get("dest_ip"),
                "src_port": ev.get("src_port"),
                "dest_port": ev.get("dest_port"),
                "proto": ev.get("proto"),
                "app_proto": ev.get("app_proto") or flow.get("app_proto"),
                "bytes_toserver": flow.get("bytes_toserver"),
                "bytes_toclient": flow.get("bytes_toclient"),
                "pkts_toserver": flow.get("pkts_toserver"),
            })


def load_falco(path, tel):
    """
    Pull process names out of Falco events (JSON lines) and, where present, the
    address the process was talking to. Useful field names vary per rule, so
    several are checked.
    """
    for ev in read_json_lines(path):
        fields = ev.get("output_fields") or {}
        name = fields.get("proc.name") or fields.get("proc_name")
        exe = fields.get("proc.exepath")
        if not name and exe:
            name = Path(exe).name
        if not name:
            continue

        tel.has_process_visibility = True
        peers = set()
        for key in ("fd.name", "fd.sip", "fd.rip", "fd.cip"):
            val = fields.get(key)
            if isinstance(val, str):
                for found in IP_IN_TEXT.findall(val):
                    if _is_ip(found):
                        peers.add(found)
        tel.processes.append({"name": name, "peers": peers})
        if exe and Path(exe).name != name:
            tel.processes.append({"name": Path(exe).name, "peers": peers})


# ---------------------------------------------------------------------------
# Candidate grouping
# ---------------------------------------------------------------------------

class Candidate:
    """
    A candidate is every connection between the same source and destination on
    the same port. An implant phoning home produces exactly that shape: one
    pair, repeated over time.
    """

    def __init__(self, src_ip, dest_ip, dest_port, proto):
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.proto = proto
        self.flows = []

    def add(self, flow):
        self.flows.append(flow)

    @property
    def key(self):
        return f"{self.src_ip}->{self.dest_ip}:{self.dest_port}/{self.proto}"

    @property
    def timestamps(self):
        return sorted(f["ts"] for f in self.flows if f["ts"] is not None)

    def payload_sizes(self):
        return [f["bytes_toserver"] for f in self.flows
                if isinstance(f["bytes_toserver"], int)]

    def app_protos(self):
        return {str(f["app_proto"]).lower() for f in self.flows if f["app_proto"]}

    def intervals(self):
        ts = self.timestamps
        return [round(b - a, 2) for a, b in zip(ts, ts[1:])] if len(ts) > 1 else []


def is_local(ip, local_nets):
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return False
    if local_nets:
        return any(addr in net for net in local_nets)
    return addr.is_private or addr.is_loopback or addr.is_link_local


def is_non_unicast(ip, local_nets):
    """
    True for addresses that cannot be a command-and-control endpoint: broadcast,
    multicast, unspecified and reserved ranges.

    Routers, printers and discovery protocols emit steady, regularly timed
    traffic to broadcast addresses on every network. Left in, that traffic looks
    like a beacon and produces false positives regardless of vendor.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return True

    if addr.is_multicast or addr.is_unspecified or addr.is_reserved:
        return True
    if addr.version == 4:
        if str(addr) == "255.255.255.255":
            return True
        # Directed broadcast of any network the user declared.
        for net in local_nets or []:
            if net.version == 4 and net.prefixlen < 31 and addr == net.broadcast_address:
                return True
        # Without a declared network we cannot know the real prefix, so fall back
        # to the common case: a final octet of 255 on a /24-style network.
        if not local_nets and int(addr) & 0xFF == 0xFF:
            return True
    return False


def build_candidates(tel, local_nets, min_flows):
    groups = {}
    for f in tel.flows:
        if not f["src_ip"] or not f["dest_ip"]:
            continue
        k = (f["src_ip"], f["dest_ip"], f["dest_port"], f["proto"])
        if k not in groups:
            groups[k] = Candidate(*k)
        groups[k].add(f)

    out = []
    dropped_broadcast = 0
    dropped_internal = 0
    for cand in groups.values():
        if len(cand.flows) < min_flows:
            continue
        if is_non_unicast(cand.dest_ip, local_nets):
            dropped_broadcast += 1
            continue
        src_local = is_local(cand.src_ip, local_nets)
        dst_local = is_local(cand.dest_ip, local_nets)
        # Traffic entirely within the LAN is out of scope: neither endpoint is
        # the internet, so it is neither C2 (outbound) nor an attacker reaching
        # a local listener (inbound). Both of THOSE are kept, even though one
        # has a local destination - an external source calling a local port is
        # exactly the DARKLANTERN scenario. Dropping every local-destination
        # candidate here used to make inbound patterns unmatchable no matter
        # what the traffic looked like (found 15.09.2026 via code review).
        if src_local and dst_local:
            dropped_internal += 1
            continue
        out.append(cand)

    if dropped_broadcast:
        print(f"[info] {dropped_broadcast} broadcast/multicast destination(s) ignored",
              file=sys.stderr)
    if dropped_internal:
        print(f"[info] {dropped_internal} purely internal candidate(s) ignored",
              file=sys.stderr)
    return out


# ---------------------------------------------------------------------------
# Field evaluators
# ---------------------------------------------------------------------------
# Each returns (verdict, explanation). UNEVALUABLE means "the logs cannot tell
# us", NOT "it does not match". Keeping those apart is the whole point: a high
# score drawn from two testable fields is not worth the same as one drawn from
# eight.

def ev_connection_direction(block, cand, tel, ctx):
    expected = block.get("value")
    # Candidates with both endpoints local are dropped in build_candidates, so
    # a local destination here always means an external source reached it.
    observed = "inbound" if is_local(cand.dest_ip, ctx["local_nets"]) else "outbound"
    if expected == "bidirectional":
        return MATCH, "pattern accepts either direction"
    if expected == observed:
        return MATCH, f"observed {observed}"
    return MISMATCH, f"expected {expected}, observed {observed}"


def ev_trigger(block, cand, tel, ctx):
    expected = block.get("value")
    if expected != "boot":
        return UNEVALUABLE, f"trigger '{expected}' cannot be derived from these logs"
    if tel.host_boot_ts is None:
        return UNEVALUABLE, "host boot time unknown, pass --boot-time to check this"
    first = cand.timestamps[0] if cand.timestamps else None
    if first is None:
        return UNEVALUABLE, "connections carry no timestamps"
    delta = first - tel.host_boot_ts
    if 0 <= delta <= ctx["boot_window"]:
        return MATCH, f"first connection {int(delta)}s after boot"
    return MISMATCH, f"first connection {int(delta)}s after boot"


def ev_dns_lookup_before(block, cand, tel, ctx):
    expected = block.get("value")
    if not isinstance(expected, bool):
        return UNEVALUABLE, "pattern states no value"
    if not tel.has_dns_visibility:
        return UNEVALUABLE, "no DNS events in the logs, no visibility"

    first = cand.timestamps[0] if cand.timestamps else None
    window = ctx["dns_window"]
    resolved = False
    matched_name = None
    for ts, ip, name in tel.dns_answers:
        if ip != cand.dest_ip:
            continue
        if first is None or ts is None or (0 <= first - ts <= window):
            resolved = True
            matched_name = name
            break

    if resolved == expected:
        note = (f"preceding DNS answer found ({matched_name})" if resolved
                else "no DNS answer for this address, connection went to a fixed IP")
        return MATCH, note
    note = (f"preceding DNS answer found ({matched_name}), pattern expects none"
            if resolved else "no preceding DNS answer, pattern expects one")
    return MISMATCH, note


def ev_payload_size_bytes(block, cand, tel, ctx):
    lo, hi = block.get("min"), block.get("max")
    if lo is None and hi is None:
        return UNEVALUABLE, "pattern states no range"
    sizes = cand.payload_sizes()
    if not sizes:
        return UNEVALUABLE, "logs carry no payload sizes"
    median = statistics.median(sizes)
    if (lo is None or median >= lo) and (hi is None or median <= hi):
        return MATCH, f"median {median} bytes, inside the range"
    return MISMATCH, f"median {median} bytes, outside the range {lo}-{hi}"


def ev_transport_encryption(block, cand, tel, ctx):
    """Is the channel encrypted in transit? This the IDS can actually tell us."""
    expected = block.get("value")
    if not isinstance(expected, bool):
        return UNEVALUABLE, "pattern states no value"

    protos = cand.app_protos()
    if not protos:
        return UNEVALUABLE, "no application protocol detected"

    encrypted = protos & ENCRYPTED_PROTOCOLS
    cleartext = protos & CLEARTEXT_PROTOCOLS
    if encrypted:
        observed = True
    elif cleartext:
        observed = False
    else:
        # Only 'failed'/'unknown' left: Suricata could not identify the protocol.
        # An absence of information, not evidence of cleartext.
        return UNEVALUABLE, (f"protocol not identified by the IDS "
                             f"({sorted(protos)}), cannot tell encrypted from not")

    verdict = MATCH if observed == expected else MISMATCH
    return verdict, f"protocols observed: {sorted(protos)}"


def ev_auth_present(block, cand, tel, ctx):
    """Always unevaluable from network telemetry alone, and that is the point.

    This used to read any encrypted protocol as "authentication present" and any
    cleartext one as absent. Those are different things. TLS says nothing about
    whether the application authenticates: a connection can be encrypted and
    anonymous, or cleartext and carrying a bearer token. The two patterns in the
    library that set this field mean application-level authentication in both
    cases - Ted's hardcoded API token in a User-token header, DARKLANTERN's
    unauthenticated 19-byte probe - and neither is visible in flow records.

    The heuristic was not merely imprecise, it manufactured matches: on
    2026-09-14 auth_present matched on plain TLS in every one of the Ted false
    positives. Reporting honestly that we cannot check it costs coverage, which
    is exactly the signal coverage exists to give. Patterns that really mean
    "the channel is encrypted" should use transport_encryption instead.
    """
    if not isinstance(block.get("value"), bool):
        return UNEVALUABLE, "pattern states no value"
    return UNEVALUABLE, ("application-level authentication is not visible in "
                         "network flow records; use transport_encryption if the "
                         "pattern meant encryption in transit")


def ev_destination_asn_hint(block, cand, tel, ctx):
    wanted = block.get("value") or []
    if not wanted:
        return UNEVALUABLE, "pattern states no ASN"
    asn = ctx["asn_map"].get(cand.dest_ip)
    if asn is None:
        return UNEVALUABLE, "destination ASN unknown, no mapping supplied"
    norm = {str(a).upper().lstrip("AS") for a in wanted}
    if str(asn).upper().lstrip("AS") in norm:
        return MATCH, f"ASN {asn} is in the pattern list"
    return MISMATCH, f"ASN {asn} is not in the pattern list"


def ev_process_name_pattern(block, cand, tel, ctx):
    expression = block.get("value")
    if not expression:
        return UNEVALUABLE, "pattern states no expression"
    if not tel.has_process_visibility:
        return UNEVALUABLE, "no process telemetry available (Falco not supplied)"

    rx, err = safe_compile(expression)
    if rx is None:
        return UNEVALUABLE, err

    names, strict = tel.processes_for(cand.dest_ip)
    hits = [p for p in names if rx.search(p[:MAX_SUBJECT_LENGTH])]

    if not strict:
        # Host-level correlation only: the process cannot be tied to this
        # connection. Counting that as a match would hand the same points to
        # every candidate on the host.
        if ctx["loose_process"] and hits:
            return MATCH, (f"processes on host: {hits[:5]} "
                           "(weak, host-level correlation)")
        return UNEVALUABLE, ("process telemetry carries no network peer, "
                             "cannot tie any process to this connection")

    if hits:
        return MATCH, f"process tied to {cand.dest_ip}: {hits[:5]}"
    return MISMATCH, (f"processes tied to {cand.dest_ip}: {names[:5]}, "
                      "none of them match")


def ev_c2_port_hint(block, cand, tel, ctx):
    ports = block.get("value") or []
    if not ports:
        return UNEVALUABLE, "pattern states no ports"
    if cand.dest_port in ports:
        if cand.dest_port in COMMON_PORTS:
            return MATCH, (f"destination port {cand.dest_port} is in the pattern "
                           "list, but it is a common port and narrows nothing down")
        return MATCH, f"destination port {cand.dest_port} is in the pattern list"
    return MISMATCH, f"destination port {cand.dest_port} is not in the pattern list"


def ev_beacon_interval_seconds(block, cand, tel, ctx):
    expected = block.get("value")
    if not isinstance(expected, (int, float)) or isinstance(expected, bool):
        return UNEVALUABLE, "pattern states no interval"

    # A percentage tolerance is fine for short intervals and far too loose for
    # long ones: 15% of 12 hours is a window almost two hours wide either way,
    # which any once-a-day service can wander into. Cap it.
    tol = block.get("tolerance_seconds")
    if isinstance(tol, (int, float)) and not isinstance(tol, bool):
        tol = float(tol)
    else:
        tol = min(max(1.0, expected * 0.15), MAX_BEACON_TOLERANCE)

    gaps = cand.intervals()
    needed = max(ctx["min_beacons"] - 1, MIN_BEACON_GAPS)
    if len(gaps) < needed:
        return UNEVALUABLE, (f"only {len(gaps) + 1} connection(s), need at least "
                             f"{needed + 1} to establish a rhythm")

    median = statistics.median(gaps)

    # A real beacon keeps time. Several services started together at boot
    # produce near-identical medians across unrelated destinations, which is
    # what a wide tolerance mistakes for a rhythm. Require the intervals to be
    # tight relative to their own median before trusting the median at all.
    spread = (max(gaps) - min(gaps)) / median if median else float("inf")
    if spread > MAX_BEACON_SPREAD:
        return UNEVALUABLE, (f"intervals are not regular enough to be a beacon "
                             f"(median {round(median, 1)}s, spread "
                             f"{round(spread * 100)}% of the median over "
                             f"{len(gaps)} interval(s))")

    detail = (f"median interval {round(median, 1)}s, expected {expected}s "
              f"+/- {round(tol, 1)}s, spread {round(spread * 100)}% over "
              f"{len(gaps)} interval(s)")
    if abs(median - expected) <= tol:
        return MATCH, detail
    return MISMATCH, detail


EVALUATORS = {
    "connection_direction": ev_connection_direction,
    "trigger": ev_trigger,
    "dns_lookup_before": ev_dns_lookup_before,
    "payload_size_bytes": ev_payload_size_bytes,
    "auth_present": ev_auth_present,
    "transport_encryption": ev_transport_encryption,
    "destination_asn_hint": ev_destination_asn_hint,
    "process_name_pattern": ev_process_name_pattern,
    "c2_port_hint": ev_c2_port_hint,
    "beacon_interval_seconds": ev_beacon_interval_seconds,
}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def score_candidate(pattern, cand, tel, ctx):
    """
    score = weight of matched fields / weight of testable fields.

    Fields the logs cannot speak to drop out of the calculation entirely, but
    they are reported through 'coverage' so a high score is never mistaken for
    strong evidence.

    Matched fields are also split into discriminant and generic. A pattern can
    reach score 1.0 on generic fields alone - outbound, encrypted, preceded by
    DNS - which is a description of ordinary traffic, not of an implant. The
    alert decision in build_record() therefore requires at least one
    discriminant match as well.
    """
    matched, mismatched, skipped = [], [], []
    w_match = w_eval = w_total = 0.0

    for field, block in (pattern.get("behavior") or {}).items():
        fn = EVALUATORS.get(field)
        if fn is None or not isinstance(block, dict):
            continue
        weight = block.get("confidence_weight")
        weight = float(weight) if isinstance(weight, (int, float)) \
            and not isinstance(weight, bool) else 0.0
        w_total += weight

        try:
            verdict, note = fn(block, cand, tel, ctx)
        except Exception as exc:  # one broken field must not stop the run
            verdict, note = UNEVALUABLE, f"internal error while evaluating: {exc}"

        entry = {
            "field": field,
            "weight": weight,
            "verified": block.get("verified"),
            "note": note,
        }
        if field == "c2_port_hint":
            entry["observed_port"] = cand.dest_port
        if verdict == MATCH:
            entry["discriminant"] = is_discriminant(field, entry)
            matched.append(entry)
            w_match += weight
            w_eval += weight
        elif verdict == MISMATCH:
            mismatched.append(entry)
            w_eval += weight
        else:
            skipped.append(entry)

    score = (w_match / w_eval) if w_eval else 0.0
    coverage = (w_eval / w_total) if w_total else 0.0
    discriminant = [m["field"] for m in matched if m.get("discriminant")]
    return {
        "score": round(score, 3),
        "coverage": round(coverage, 3),
        "discriminant_fields": discriminant,
        "matched": matched,
        "mismatched": mismatched,
        "unevaluable": skipped,
    }


def compute_evidence(outcome):
    """How well sourced are the fields that matched?

    Weighted by confidence_weight rather than counted, because a `clear` field
    the pattern considers decisive should move this more than a `clear` field
    it considers incidental. Floors at 0.75: `assumed` means the source implied
    it rather than stated it, which is weaker provenance, not worthless.
    """
    matched = outcome["matched"]
    if not matched:
        return 0.75
    w_total = sum(m["weight"] for m in matched) or 1.0
    w_clear = sum(m["weight"] for m in matched if m.get("verified") == "clear")
    return round(0.75 + 0.25 * (w_clear / w_total), 3)


def compute_confidence(outcome, evidence):
    """How well the evidence supports the observation. Deliberately says
    nothing about whether it deserves an alert.

    Those are separate questions and were briefly conflated here: an earlier
    version multiplied this by 0.25 when no discriminant field matched, which
    punished the same situation twice, since `alert` already goes false for it.
    It also gave the wrong answer. A pattern that matches perfectly on fields
    the logs could all test has been confirmed as well as it can be; that the
    pattern happens to contain nothing distinguishing is a fact about the
    pattern, not a reason to distrust the observation.

    So: confidence answers "does the evidence hold up", alert answers "is any
    of it specific enough to act on". Read them together - has_discriminant is
    in the record for exactly that.

    Heuristic and uncalibrated: 0.8 is not an 80% probability of compromise.
    """
    return round(min(1.0, max(0.0, outcome["score"] * outcome["coverage"] * evidence)), 3)


def build_record(pattern, cand, outcome, threshold, require_discriminant=True):
    ts = cand.timestamps
    gaps = cand.intervals()
    sizes = cand.payload_sizes()

    evidence = compute_evidence(outcome)
    over_threshold = outcome["score"] >= threshold
    has_discriminant = bool(outcome["discriminant_fields"])
    alert = over_threshold and (has_discriminant or not require_discriminant)

    if not over_threshold:
        reason = "score below threshold"
    elif alert:
        reason = "score above threshold, discriminant evidence present" \
            if has_discriminant else "score above threshold (discriminant check disabled)"
    else:
        reason = ("score above threshold but every matched field is generic "
                  "(outbound / encrypted / DNS / common port), so nothing "
                  "distinguishes this from ordinary traffic")

    return {
        "timestamp": datetime.fromtimestamp(
            ts[-1] if ts else 0, tz=timezone.utc).isoformat(),
        "gait": {
            "engine_version": ENGINE_VERSION,
            "pattern_id": pattern.get("id"),
            "pattern_name": pattern.get("name"),
            "family": pattern.get("family"),
            "cve": pattern.get("cve"),
            "severity": pattern.get("severity"),
            "score": outcome["score"],
            "threshold": threshold,
            "alert": alert,
            "alert_reason": reason,
            "coverage": outcome["coverage"],
            "evidence": evidence,
            "confidence": compute_confidence(outcome, evidence),
            "has_discriminant": has_discriminant,
            "discriminant_fields": outcome["discriminant_fields"],
            "matched_fields": [m["field"] for m in outcome["matched"]],
            "mismatched_fields": [m["field"] for m in outcome["mismatched"]],
            "unevaluable_fields": [m["field"] for m in outcome["unevaluable"]],
            "detail": {
                "matched": outcome["matched"],
                "mismatched": outcome["mismatched"],
                "unevaluable": outcome["unevaluable"],
            },
        },
        "observation": {
            "src_ip": cand.src_ip,
            "dest_ip": cand.dest_ip,
            "dest_port": cand.dest_port,
            "proto": cand.proto,
            "flow_count": len(cand.flows),
            "first_seen": datetime.fromtimestamp(
                ts[0], tz=timezone.utc).isoformat() if ts else None,
            "last_seen": datetime.fromtimestamp(
                ts[-1], tz=timezone.utc).isoformat() if ts else None,
            "median_interval_seconds": round(statistics.median(gaps), 2) if gaps else None,
            "median_payload_bytes": statistics.median(sizes) if sizes else None,
            "app_protocols": sorted(cand.app_protos()),
        },
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_nets(values):
    nets = []
    for v in values or []:
        try:
            nets.append(ipaddress.ip_network(v, strict=False))
        except ValueError:
            print(f"[warning] invalid network ignored: {v}", file=sys.stderr)
    return nets


def load_asn_map(path):
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return {str(k): v for k, v in data.items()} if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[warning] cannot read the ASN map: {exc}", file=sys.stderr)
        return {}


def main():
    ap = argparse.ArgumentParser(
        description="Match observed network activity against GAIT patterns.")
    ap.add_argument("--patterns", required=True,
                    help="a pattern file or a directory of patterns")
    ap.add_argument("--suricata", help="Suricata eve.json")
    ap.add_argument("--falco", help="Falco JSON output log")
    ap.add_argument("--asn-map", help="optional JSON file mapping {ip: asn}")
    ap.add_argument("--output", help="write results here instead of stdout")
    ap.add_argument("--local-net", action="append",
                    help="local network, repeatable, e.g. 192.168.1.0/24")
    ap.add_argument("--boot-time",
                    help="host boot time in ISO8601, enables the trigger=boot check")
    ap.add_argument("--min-flows", type=int, default=2,
                    help="minimum connections before a pair becomes a candidate")
    ap.add_argument("--min-beacons", type=int, default=3,
                    help="minimum connections before an interval is calculated")
    ap.add_argument("--dns-window", type=int, default=60,
                    help="seconds to look back when correlating DNS answers")
    ap.add_argument("--boot-window", type=int, default=300,
                    help="seconds after boot that still count as boot-triggered")
    ap.add_argument("--threshold", type=float,
                    help="override the threshold declared in the pattern")
    ap.add_argument("--min-coverage", type=float, default=0.0,
                    help="drop matches below this coverage ratio")
    ap.add_argument("--loose-process", action="store_true",
                    help="accept host-level process correlation even when Falco "
                         "cannot tie the process to the connection")
    ap.add_argument("--allow-generic-only", action="store_true",
                    help="alert even when every matched field is generic "
                         "(outbound / encrypted / DNS / common port); off by "
                         "default because it fires on ordinary traffic")
    ap.add_argument("--all", action="store_true",
                    help="report matches below the threshold as well")
    ap.add_argument("--pretty", action="store_true",
                    help="indented JSON, easier to read by hand")
    ap.add_argument("--version", action="version",
                    version=f"GAIT engine {ENGINE_VERSION}")
    args = ap.parse_args()

    if not args.suricata and not args.falco:
        print("At least one source is required: --suricata or --falco.",
              file=sys.stderr)
        return 2

    patterns = load_patterns(args.patterns)
    if not patterns:
        print(f"No valid patterns found at '{args.patterns}'.", file=sys.stderr)
        return 2

    tel = Telemetry()
    if args.suricata:
        load_suricata(args.suricata, tel)
    if args.falco:
        load_falco(args.falco, tel)
    if args.boot_time:
        tel.host_boot_ts = parse_ts(args.boot_time)
        if tel.host_boot_ts is None:
            print("[warning] --boot-time could not be parsed, ignored", file=sys.stderr)

    ctx = {
        "local_nets": parse_nets(args.local_net),
        "asn_map": load_asn_map(args.asn_map),
        "dns_window": args.dns_window,
        "boot_window": args.boot_window,
        "min_beacons": args.min_beacons,
        "loose_process": args.loose_process,
    }

    candidates = build_candidates(tel, ctx["local_nets"], args.min_flows)
    print(f"[info] {len(tel.flows)} connections, {len(candidates)} candidates, "
          f"{len(patterns)} pattern(s)", file=sys.stderr)

    records = []
    for pattern in patterns:
        thr = args.threshold
        if thr is None:
            thr = (pattern.get("scoring") or {}).get("threshold_alert", 0.7)
        for cand in candidates:
            outcome = score_candidate(pattern, cand, tel, ctx)
            if outcome["coverage"] < args.min_coverage:
                continue
            if outcome["score"] >= thr or args.all:
                records.append(build_record(
                    pattern, cand, outcome, thr,
                    require_discriminant=not args.allow_generic_only))

    records.sort(key=lambda r: r["gait"]["score"], reverse=True)

    lines = [json.dumps(r, ensure_ascii=False,
                        indent=2 if args.pretty else None) for r in records]
    text = "\n".join(lines) + ("\n" if lines else "")
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"[info] {len(records)} record(s) written to {args.output}",
              file=sys.stderr)
    else:
        sys.stdout.write(text)

    alerts = sum(1 for r in records if r["gait"]["alert"])
    generic = sum(1 for r in records
                  if not r["gait"]["alert"]
                  and r["gait"]["score"] >= r["gait"]["threshold"])
    print(f"[info] {alerts} alert(s)", file=sys.stderr)
    if generic:
        print(f"[info] {generic} match(es) scored above the threshold on generic "
              f"fields only and did not alert (see alert_reason)", file=sys.stderr)
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())

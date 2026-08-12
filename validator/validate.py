#!/usr/bin/env python3
"""
GAIT - General Adaptive Implant Tracker
validate.py - schema validator for behavioural pattern files.

Usage:
    python3 validate.py patterns/
    python3 validate.py patterns/endlessdoors-zbtlink-ax3000.yaml
    python3 validate.py patterns/ --strict     # treat warnings as errors
    python3 validate.py patterns/ --json       # machine-readable output for CI

Exit codes:
    0 = every file is valid
    1 = at least one file was rejected
    2 = usage error (missing path, unreadable YAML)

This script reads local files only. It makes no network connections and
sends no telemetry anywhere.
"""

import argparse
import json
import re
import sys
from datetime import date, datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML is missing. Install it with: pip install pyyaml", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# Schema definition. Single source of truth for what a pattern may contain.
# New fields go here, not into scattered if-branches further down.
# ---------------------------------------------------------------------------

SCHEMA_VERSION = "1.0"

ID_RE = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
URL_RE = re.compile(r"^https?://\S+$")

SEVERITY_VALUES = {"low", "medium", "high", "critical"}
VERIFIED_VALUES = {"clear", "assumed"}
SCORING_METHODS = {"weighted_sum"}

# Values that mean "we have no data", as opposed to a real observation.
UNKNOWN_MARKERS = (None, "unknown", "")

# Untrusted patterns come in through pull requests, so a hostile or careless
# regex must not be able to hang an engine run. Length caps plus a nested
# quantifier check keep catastrophic backtracking out of the library.
MAX_REGEX_LENGTH = 200
NESTED_QUANTIFIER_RE = re.compile(r"\([^)]*[+*][^)]*\)\s*[+*]")

REQUIRED_META = [
    "id", "name", "family", "version", "created", "updated",
    "author", "source", "description", "severity",
]

OPTIONAL_META = ["cve", "references", "tags", "schema_version"]

REQUIRED_SOURCE_KEYS = ["name", "url"]
OPTIONAL_SOURCE_KEYS = ["published"]

# Behavioural field specification.
#   kind   = the value shape expected for this field
#   enum   = permitted values (only for kind="enum")
#   extra  = additional keys allowed inside the field block
BEHAVIOR_FIELDS = {
    "connection_direction": {
        "kind": "enum",
        "enum": {"outbound", "inbound", "bidirectional", "unknown"},
    },
    "trigger": {
        "kind": "enum",
        "enum": {"boot", "scheduled", "periodic", "on_demand", "unknown"},
    },
    "dns_lookup_before": {
        "kind": "bool",
    },
    "payload_size_bytes": {
        "kind": "range",
    },
    "auth_present": {
        "kind": "bool",
    },
    "destination_asn_hint": {
        "kind": "asn_list",
    },
    "process_name_pattern": {
        "kind": "regex",
        "extra": ["note"],
    },
    "c2_port_hint": {
        "kind": "port_list",
    },
    "beacon_interval_seconds": {
        "kind": "interval",
        "extra": ["tolerance_seconds"],
    },
}

COMMON_FIELD_KEYS = {"confidence_weight", "verified"}


# ---------------------------------------------------------------------------
# Result of validating a single file
# ---------------------------------------------------------------------------

class Result:
    def __init__(self, path):
        self.path = str(path)
        self.errors = []
        self.warnings = []
        self.pattern_id = None

    def err(self, where, msg):
        self.errors.append({"field": where, "message": msg})

    def warn(self, where, msg):
        self.warnings.append({"field": where, "message": msg})

    @property
    def ok(self):
        return not self.errors

    def as_dict(self):
        return {
            "file": self.path,
            "id": self.pattern_id,
            "valid": self.ok,
            "errors": self.errors,
            "warnings": self.warnings,
        }


# ---------------------------------------------------------------------------
# Shared checks
# ---------------------------------------------------------------------------

def is_unknown(value):
    """True when the value means 'no data', not 'a real observation'."""
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return value in UNKNOWN_MARKERS


def check_date(res, key, value):
    if isinstance(value, (date, datetime)):
        return value if isinstance(value, date) else value.date()
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%Y-%m-%d").date()
        except ValueError:
            pass
    res.err(key, "invalid date, expected format is YYYY-MM-DD")
    return None


def check_weight(res, field, block):
    w = block.get("confidence_weight")
    if w is None:
        res.err(f"behavior.{field}.confidence_weight", "required key is missing")
        return None
    if isinstance(w, bool) or not isinstance(w, (int, float)):
        res.err(f"behavior.{field}.confidence_weight", "must be a number")
        return None
    if not 0.0 <= float(w) <= 1.0:
        res.err(f"behavior.{field}.confidence_weight",
                f"value {w} is outside the range 0.0 - 1.0")
        return None
    if float(w) == 0.0:
        res.warn(f"behavior.{field}.confidence_weight",
                 "weight is 0.0, this field contributes nothing to the score")
    return float(w)


def check_verified(res, field, block):
    v = block.get("verified")
    if v is None:
        res.err(f"behavior.{field}.verified", "required key is missing")
        return None
    if v not in VERIFIED_VALUES:
        res.err(f"behavior.{field}.verified",
                f"invalid value '{v}', allowed: {sorted(VERIFIED_VALUES)}")
        return None
    return v


# ---------------------------------------------------------------------------
# Value validation, per field kind
# ---------------------------------------------------------------------------

def validate_value(res, field, spec, block):
    """Check the field value. Returns True when the value is a real observation."""
    kind = spec["kind"]
    loc = f"behavior.{field}"

    if kind == "range":
        lo, hi = block.get("min"), block.get("max")
        for name, val in (("min", lo), ("max", hi)):
            if val is not None and (isinstance(val, bool) or not isinstance(val, int)):
                res.err(f"{loc}.{name}", "must be an integer or null")
                return False
            if isinstance(val, int) and not isinstance(val, bool) and val < 0:
                res.err(f"{loc}.{name}", "cannot be negative")
                return False
        if lo is None and hi is None:
            return False
        if lo is not None and hi is not None and lo > hi:
            res.err(loc, f"min ({lo}) is greater than max ({hi})")
            return False
        return True

    if kind == "interval":
        val = block.get("value")
        tol = block.get("tolerance_seconds")
        if is_unknown(val):
            return False
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            res.err(f"{loc}.value", "must be a number or 'unknown'")
            return False
        if val <= 0:
            res.err(f"{loc}.value", "interval must be positive")
            return False
        if tol is not None:
            if isinstance(tol, bool) or not isinstance(tol, (int, float)) or tol < 0:
                res.err(f"{loc}.tolerance_seconds", "must be a number >= 0")
                return False
            if tol >= val:
                res.warn(f"{loc}.tolerance_seconds",
                         "tolerance is greater than or equal to the interval, "
                         "which makes a match almost certain")
        return True

    # everything below carries its observation under the 'value' key
    if "value" not in block:
        res.err(f"{loc}.value", "required key is missing")
        return False
    val = block["value"]

    if kind == "enum":
        if val == "unknown":
            return False
        if val not in spec["enum"]:
            res.err(f"{loc}.value",
                    f"invalid value '{val}', allowed: {sorted(spec['enum'])}")
            return False
        return True

    if kind == "bool":
        if val == "unknown" or val is None:
            return False
        if not isinstance(val, bool):
            res.err(f"{loc}.value", "must be true, false or 'unknown'")
            return False
        return True

    if kind == "regex":
        if is_unknown(val):
            return False
        if not isinstance(val, str):
            res.err(f"{loc}.value", "must be a string")
            return False
        if len(val) > MAX_REGEX_LENGTH:
            res.err(f"{loc}.value",
                    f"expression is longer than {MAX_REGEX_LENGTH} characters; "
                    "process names are short, so a long expression is a red flag")
            return False
        if NESTED_QUANTIFIER_RE.search(val):
            res.err(f"{loc}.value",
                    "nested quantifiers such as (a+)+ can cause catastrophic "
                    "backtracking and are not accepted")
            return False
        try:
            re.compile(val)
        except re.error as exc:
            res.err(f"{loc}.value", f"invalid regular expression: {exc}")
            return False
        return True

    if kind == "asn_list":
        if val is None or val == "unknown":
            return False
        if not isinstance(val, list):
            res.err(f"{loc}.value", "must be a list (an empty list is allowed)")
            return False
        for item in val:
            if isinstance(item, int) and not isinstance(item, bool):
                if item <= 0:
                    res.err(f"{loc}.value", f"invalid ASN: {item}")
                    return False
            elif isinstance(item, str):
                if not re.match(r"^(AS)?\d+$", item.strip(), re.IGNORECASE):
                    res.warn(f"{loc}.value",
                             f"'{item}' does not look like an ASN "
                             "(expected AS15169 or 15169)")
            else:
                res.err(f"{loc}.value", f"invalid list entry: {item!r}")
                return False
        return len(val) > 0

    if kind == "port_list":
        if val is None or val == "unknown":
            return False
        if not isinstance(val, list):
            res.err(f"{loc}.value", "must be a list of ports")
            return False
        for item in val:
            if isinstance(item, bool) or not isinstance(item, int):
                res.err(f"{loc}.value", f"invalid port: {item!r}")
                return False
            if not 1 <= item <= 65535:
                res.err(f"{loc}.value", f"port outside the range 1-65535: {item}")
                return False
        return len(val) > 0

    res.err(loc, f"unknown field kind in schema: {kind}")
    return False


# ---------------------------------------------------------------------------
# Section validation
# ---------------------------------------------------------------------------

def validate_meta(res, data):
    for key in REQUIRED_META:
        if key not in data or data[key] in (None, ""):
            res.err(key, "required key is missing")

    known = set(REQUIRED_META) | set(OPTIONAL_META) | {
        "behavior", "scoring", "verification"}
    for key in data:
        if key not in known:
            res.warn(key, "unknown key, the engine will ignore it")

    pid = data.get("id")
    if isinstance(pid, str):
        res.pattern_id = pid
        if not ID_RE.match(pid):
            res.err("id", "must be kebab-case (lowercase letters, digits, hyphens)")
    elif pid is not None:
        res.err("id", "must be a string")

    cve = data.get("cve")
    if cve is not None and (not isinstance(cve, str) or not CVE_RE.match(cve)):
        res.err("cve", "expected format is CVE-YYYY-NNNN")

    ver = data.get("version")
    if ver is not None:
        if isinstance(ver, bool) or not isinstance(ver, int) or ver < 1:
            res.err("version", "must be an integer >= 1")

    sev = data.get("severity")
    if sev is not None and sev not in SEVERITY_VALUES:
        res.err("severity", f"invalid value, allowed: {sorted(SEVERITY_VALUES)}")

    created = check_date(res, "created", data["created"]) if data.get("created") else None
    updated = check_date(res, "updated", data["updated"]) if data.get("updated") else None
    if created and updated and updated < created:
        res.err("updated", "'updated' is earlier than 'created'")

    src = data.get("source")
    if src is not None:
        if not isinstance(src, dict):
            res.err("source", "must be a block containing name and url")
        else:
            for key in REQUIRED_SOURCE_KEYS:
                if not src.get(key):
                    res.err(f"source.{key}", "required key is missing")
            url = src.get("url")
            if isinstance(url, str) and not URL_RE.match(url):
                res.err("source.url", "must be a valid http(s) URL")
            if src.get("published"):
                check_date(res, "source.published", src["published"])
            for key in src:
                if key not in REQUIRED_SOURCE_KEYS + OPTIONAL_SOURCE_KEYS:
                    res.warn(f"source.{key}", "unknown key inside the source block")

    desc = data.get("description")
    if isinstance(desc, str) and len(desc.strip()) < 40:
        res.warn("description",
                 "description is very short and will be hard to use as a reference")


def validate_behavior(res, data):
    behavior = data.get("behavior")
    if behavior is None:
        res.err("behavior", "required section is missing")
        return
    if not isinstance(behavior, dict) or not behavior:
        res.err("behavior", "must contain at least one behavioural field")
        return

    known_count = 0
    clear_count = 0
    total_weight = 0.0

    for field, block in behavior.items():
        spec = BEHAVIOR_FIELDS.get(field)
        if spec is None:
            res.err(f"behavior.{field}",
                    "unknown field, see SCHEMA.md for the full list")
            continue
        if not isinstance(block, dict):
            res.err(f"behavior.{field}",
                    "must be a block containing value and confidence_weight")
            continue

        allowed = COMMON_FIELD_KEYS | set(spec.get("extra", []))
        allowed |= {"min", "max"} if spec["kind"] == "range" else {"value"}
        for key in block:
            if key not in allowed:
                res.warn(f"behavior.{field}.{key}", "unknown key, it will be ignored")

        weight = check_weight(res, field, block)
        verified = check_verified(res, field, block)

        before = len(res.errors)
        has_value = validate_value(res, field, spec, block)
        value_was_invalid = len(res.errors) > before

        if has_value:
            known_count += 1
            if weight:
                total_weight += weight
        if verified == "clear":
            clear_count += 1
            # If the value was already reported as invalid, do not pile a second
            # error onto the same field.
            if not has_value and not value_was_invalid:
                res.err(f"behavior.{field}",
                        "marked 'clear' but carries no real value; a field "
                        "without data must be marked 'assumed'")

    if known_count == 0:
        res.err("behavior",
                "no field carries a real value, this pattern cannot detect anything")
    elif known_count < 3:
        res.warn("behavior",
                 f"only {known_count} field(s) carry a real value, "
                 "high risk of false positives")
    if clear_count == 0:
        res.warn("behavior",
                 "no field is marked 'clear', the whole pattern is assumed")

    threshold = (data.get("scoring") or {}).get("threshold_alert")
    if isinstance(threshold, (int, float)) and not isinstance(threshold, bool):
        if total_weight and total_weight < threshold:
            res.warn("scoring.threshold_alert",
                     f"the weights of fields carrying real values sum to "
                     f"{total_weight:.2f}, below the threshold ({threshold}), "
                     "so this pattern can never raise an alert")


def validate_scoring(res, data):
    scoring = data.get("scoring")
    if scoring is None:
        res.err("scoring", "required section is missing")
        return
    if not isinstance(scoring, dict):
        res.err("scoring", "must be a block containing method and threshold_alert")
        return

    method = scoring.get("method")
    if method is None:
        res.err("scoring.method", "required key is missing")
    elif method not in SCORING_METHODS:
        res.err("scoring.method",
                f"unsupported method '{method}', allowed: {sorted(SCORING_METHODS)}")

    thr = scoring.get("threshold_alert")
    if thr is None:
        res.err("scoring.threshold_alert", "required key is missing")
    elif isinstance(thr, bool) or not isinstance(thr, (int, float)):
        res.err("scoring.threshold_alert", "must be a number")
    elif not 0.0 < float(thr) <= 1.0:
        res.err("scoring.threshold_alert", "must be within the range (0.0, 1.0]")
    elif float(thr) < 0.3:
        res.warn("scoring.threshold_alert",
                 "very low threshold, expect false positives")

    for key in scoring:
        if key not in {"method", "threshold_alert"}:
            res.warn(f"scoring.{key}", "unknown key, it will be ignored")


def validate_file(path):
    res = Result(path)
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        res.err("file", f"cannot read the file: {exc}")
        return res

    try:
        data = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        res.err("file", f"invalid YAML: {exc}")
        return res

    if not isinstance(data, dict):
        res.err("file", "the file must contain a YAML mapping at the top level")
        return res

    validate_meta(res, data)
    validate_scoring(res, data)
    validate_behavior(res, data)

    stem = Path(path).stem
    if res.pattern_id and stem != res.pattern_id:
        res.warn("id", f"file name ('{stem}') differs from id ('{res.pattern_id}')")

    return res


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def collect_files(target):
    p = Path(target)
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted(list(p.rglob("*.yaml")) + list(p.rglob("*.yml")))
    return []


def print_human(results, strict):
    ok = fail = 0
    for r in results:
        passed = r.ok and not (strict and r.warnings)
        status = "PASS" if passed else "FAIL"
        if passed:
            ok += 1
        else:
            fail += 1
        print(f"[{status}] {r.path}")
        for e in r.errors:
            print(f"         error    {e['field']}: {e['message']}")
        for w in r.warnings:
            marker = "error  " if strict else "warning"
            print(f"         {marker}  {w['field']}: {w['message']}")
    print()
    print(f"Total: {len(results)} file(s), {ok} passed, {fail} rejected.")


def main():
    ap = argparse.ArgumentParser(
        description="Schema validator for GAIT behavioural patterns.")
    ap.add_argument("target", help="a .yaml file or a directory of patterns")
    ap.add_argument("--strict", action="store_true",
                    help="treat warnings as errors")
    ap.add_argument("--json", action="store_true", dest="as_json",
                    help="machine-readable output, for CI pipelines")
    args = ap.parse_args()

    files = collect_files(args.target)
    if not files:
        print(f"No YAML files found at '{args.target}'.", file=sys.stderr)
        return 2

    results = [validate_file(f) for f in files]
    failed = [r for r in results
              if not r.ok or (args.strict and r.warnings)]

    if args.as_json:
        print(json.dumps({
            "schema_version": SCHEMA_VERSION,
            "checked": len(results),
            "failed": len(failed),
            "strict": args.strict,
            "results": [r.as_dict() for r in results],
        }, indent=2, ensure_ascii=False))
    else:
        print_human(results, args.strict)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

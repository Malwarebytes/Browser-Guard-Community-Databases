#!/usr/bin/env python3
"""
Fetch AdGuard's antiadblock.txt and convert it into a Browser Guard-consumable JSON manifest.

Reads the raw filter list from AdGuardTeam/AdguardFilters and writes:
  antiadblock/antiadblock.txt          - raw source, verbatim
  antiadblock/antiadblock.mbgc.json    - converted manifest

Rules the converter handles:
  ||host^, ||host^$options            -> DNR block rule
  @@||host^, @@||host^$options        -> DNR allow rule
  hosts##selector                     -> cosmetic hide entry per host
  hosts#@#selector                    -> cosmetic hide-exception entry per host
  hosts#?#selector                    -> cosmetic extended-hide entry per host
  hosts#$#css                         -> css-inject entry per host
  hosts#%#//scriptlet('name', ...)    -> scriptlet entry per host
  !#if / !#endif / !+ NOT_PLATFORM    -> platform gate for Chromium MV3

Rules the converter records but skips:
  #%# inline JS (not the //scriptlet form) - would need a per-rule injection channel
  $$html-filter                            - needs filterResponseData
  $replace=                                - needs filterResponseData
  trusted-* scriptlets                     - need signed rulesets
  $redirect=                               - pending Chromium bug 461824106
"""

import argparse
import ast
import datetime as dt
import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Iterable

ANTIADBLOCK_URL = (
    "https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/BaseFilter/sections/antiadblock.txt"
)

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "antiadblock"
RAW_PATH = OUTPUT_DIR / "antiadblock.txt"
MANIFEST_PATH = OUTPUT_DIR / "antiadblock.json"

# Chromium MV3 is the primary target; Firefox MV3 shares the same rule shape
# but omits webtransport/webbundle resource types (see mv3_helpers.py:7).
PLATFORM_FLAGS = {
    "adguard": True,
    "adguard_ext_chromium": True,
    "adguard_ext_chromium_mv3": True,
    "ext_chromium": True,
    "ext_chromium_mv3": True,
    "adguard_ext_firefox": False,
    "adguard_ext_safari": False,
    "adguard_ext_edge": False,
    "adguard_ext_android_cb": False,
    "adguard_ext_opera": False,
    "adguard_app_ios": False,
    "adguard_app_windows": False,
    "adguard_app_mac": False,
    "adguard_app_android": False,
    "ext_ublock": False,
    "ext_opera": False,
    "mv3": True,
    "ext_ff": False,
}

DNR_RESOURCES = {
    "main_frame", "sub_frame", "stylesheet", "script", "image", "font",
    "object", "xmlhttprequest", "ping", "csp_report", "media", "websocket",
    "webtransport", "webbundle",
}
ADG_TO_DNR = {
    "document": "main_frame",
    "subdocument": "sub_frame",
    "xhr": "xmlhttprequest",
    "css": "stylesheet",
}

SCRIPTLET_UNSUPPORTED_PREFIXES = ("trusted-",)


def _safe_eval_bool(node: ast.AST) -> bool:
    """Evaluate a whitelisted subset of a Python AST: bool constants, `and`/`or`, `not`."""
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.BoolOp):
        values = [_safe_eval_bool(v) for v in node.values]
        if isinstance(node.op, ast.And):
            return all(values)
        if isinstance(node.op, ast.Or):
            return any(values)
        raise ValueError(f"unsupported BoolOp: {type(node.op).__name__}")
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _safe_eval_bool(node.operand)
    raise ValueError(f"unsupported node: {type(node).__name__}")


def download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "browserguard-community-databases"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


class PreprocessorGate:
    """
    Evaluates AdGuard preprocessor directives (`!#if`, `!#endif`, `!+ NOT_PLATFORM(...)`,
    `!+ PLATFORM(...)`) so we only keep lines that apply to Chromium MV3.

    The full AdGuard directive grammar is richer than this; we implement the subset
    that appears in antiadblock.txt: single-token flags, `!`, `&&`, `||`, parens.
    """

    def __init__(self):
        # Stack of (condition_result, seen_true) for nested !#if blocks.
        self._stack = []
        # PLATFORM/NOT_PLATFORM applies to the immediately-following rule only.
        self._one_shot_gate = None

    def _eval_flag_expr(self, expr: str) -> bool:
        # Substitute identifiers with 'True'/'False' python literals, then walk the
        # AST rejecting any node that isn't a boolean op / constant / unary-not.
        # This avoids `eval` on upstream-controlled strings even after substitution.
        def sub(match: re.Match) -> str:
            ident = match.group(0)
            return "True" if PLATFORM_FLAGS.get(ident, False) else "False"

        expr = re.sub(r"[A-Za-z_][A-Za-z0-9_]*", sub, expr)
        expr = expr.replace("&&", " and ").replace("||", " or ").replace("!", " not ")
        try:
            tree = ast.parse(expr, mode="eval")
            return bool(_safe_eval_bool(tree.body))
        except (SyntaxError, ValueError):
            return False

    def _current_allows(self) -> bool:
        return all(entry[0] for entry in self._stack)

    def feed(self, line: str) -> tuple[bool, bool]:
        """
        Returns (is_directive, keep_next_content_line).
        The second value is only meaningful when is_directive is False;
        directives themselves are consumed and never emitted.
        """
        stripped = line.strip()
        if stripped.startswith("!#if"):
            cond = stripped[len("!#if"):].strip()
            if cond.startswith("(") and cond.endswith(")"):
                cond = cond[1:-1]
            self._stack.append((self._eval_flag_expr(cond), True))
            return True, False
        if stripped.startswith("!#endif"):
            if self._stack:
                self._stack.pop()
            return True, False
        if stripped.startswith("!#else"):
            if self._stack:
                cond, seen = self._stack[-1]
                self._stack[-1] = (not cond, seen)
            return True, False
        if stripped.startswith("!+"):
            payload = stripped[2:].strip()
            # A `!+` line can carry compound hints (`NOT_OPTIMIZED PLATFORM(...)`).
            # Only PLATFORM/NOT_PLATFORM affect our platform gating; unknown hints
            # (NOT_OPTIMIZED, HINT, etc.) are informational and must NOT gate the next rule.
            m = re.search(r"(NOT_PLATFORM|PLATFORM)\s*\(([^)]*)\)", payload)
            if not m:
                return True, False
            kind, args = m.group(1), m.group(2)
            flags = [a.strip() for a in args.split(",") if a.strip()]
            any_match = any(PLATFORM_FLAGS.get(f, False) for f in flags)
            self._one_shot_gate = (not any_match) if kind == "NOT_PLATFORM" else any_match
            return True, False
        if stripped.startswith("!"):
            # regular comment
            return True, False

        # Content line
        if self._one_shot_gate is not None:
            allowed = self._one_shot_gate and self._current_allows()
            self._one_shot_gate = None
            return False, allowed
        return False, self._current_allows()


def parse_domain_list(head: str) -> tuple[list[str], list[str]]:
    """Split a comma-separated cosmetic-rule domain list into includes/excludes."""
    includes, excludes = [], []
    if not head:
        return includes, excludes
    for token in head.split(","):
        token = token.strip()
        if not token:
            continue
        if token.startswith("~"):
            excludes.append(token[1:])
        else:
            includes.append(token)
    return includes, excludes


def tokenize_scriptlet_args(body: str) -> tuple[str, list[str]]:
    """
    Parse `'name', 'arg1', 'arg2'` from inside //scriptlet(...).
    Handles single or double quotes, backslash escapes, and unquoted numeric-ish args.
    """
    tokens: list[str] = []
    i, n = 0, len(body)
    while i < n:
        while i < n and body[i] in " \t\r\n,":
            i += 1
        if i >= n:
            break
        if body[i] in ("'", '"'):
            quote = body[i]
            i += 1
            buf = []
            while i < n and body[i] != quote:
                if body[i] == "\\" and i + 1 < n:
                    buf.append(body[i + 1])
                    i += 2
                else:
                    buf.append(body[i])
                    i += 1
            tokens.append("".join(buf))
            if i < n:
                i += 1
        else:
            j = i
            while j < n and body[j] != ",":
                j += 1
            tokens.append(body[i:j].strip())
            i = j
    if not tokens:
        return "", []
    return tokens[0], tokens[1:]


def parse_network_options(options: str) -> tuple[list[str], list[str], list[str], bool, dict]:
    """
    Split network-rule `$options` into (resource_types, initiator_domains, excluded_domains,
    third_party_only, extras) where extras carries flags like redirect=, replace=, etc.
    """
    resources: list[str] = []
    include_domains: list[str] = []
    exclude_domains: list[str] = []
    third_party_only = False
    first_party_only = False
    extras = {}
    if not options:
        return resources, include_domains, exclude_domains, third_party_only, extras

    for opt in options.split(","):
        opt = opt.strip()
        if not opt:
            continue
        if opt == "third-party":
            third_party_only = True
            continue
        if opt == "~third-party":
            first_party_only = True
            continue
        if opt.startswith("domain="):
            for d in opt[len("domain="):].split("|"):
                d = d.strip()
                if not d:
                    continue
                if d.startswith("~"):
                    exclude_domains.append(d[1:])
                else:
                    include_domains.append(d)
            continue
        if "=" in opt:
            k, v = opt.split("=", 1)
            extras[k] = v
            continue
        if opt.startswith("~"):
            extras.setdefault("negated_resources", []).append(opt[1:])
            continue
        mapped = ADG_TO_DNR.get(opt, opt)
        if mapped in DNR_RESOURCES:
            resources.append(mapped)
        else:
            extras.setdefault("unknown", []).append(opt)

    if first_party_only:
        extras["first_party_only"] = True
    return resources, include_domains, exclude_domains, third_party_only, extras


def build_dnr_rule(rule_id: int, filter_expr: str, is_allow: bool) -> tuple[dict | None, str | None]:
    """
    Build a DNR rule from either `||host^$options` (domain-format) or
    `/path/pattern$options` (path/URL-format). Returns (rule, skip_reason).
    Exactly one is non-None.
    """
    body = filter_expr[2:] if is_allow else filter_expr  # strip @@
    parts = body.split("$", 1)
    pattern = parts[0]
    options = parts[1] if len(parts) > 1 else ""

    if pattern.startswith("||"):
        url_filter = pattern
    elif pattern.startswith("/") or pattern.startswith(".") or pattern.startswith("-") or "://" in pattern:
        # Path-format (ABP): pass the pattern through as-is; DNR treats bare separators
        # (`^`, `|`, `*`) with the same semantics.
        url_filter = pattern
    else:
        return None, "unsupported: non-domain network pattern"

    if pattern.startswith("/") and pattern.endswith("/"):
        return None, "unsupported: regex network pattern"

    resources, include_doms, exclude_doms, third_party, extras = parse_network_options(options)

    if "redirect" in extras or "redirect-rule" in extras:
        return None, "pending: $redirect Chromium bug 461824106"
    if "replace" in extras:
        return None, "unsupported: $replace"
    if "csp" in extras:
        return None, "unsupported: $csp"

    condition: dict = {"urlFilter": url_filter}
    if include_doms:
        condition["initiatorDomains"] = include_doms
    if exclude_doms:
        condition["excludedInitiatorDomains"] = exclude_doms
    if resources:
        condition["resourceTypes"] = resources
    if third_party:
        condition["domainType"] = "thirdParty"
    elif extras.get("first_party_only"):
        condition["domainType"] = "firstParty"

    action = {"type": "allow" if is_allow else "block"}
    priority = 50 if is_allow else 40
    return {"id": rule_id, "priority": priority, "action": action, "condition": condition}, None


def find_cosmetic_separator(line: str) -> tuple[str, int] | None:
    """
    Return (separator, position) of the first cosmetic/scriptlet separator in line, or None.
    Order matters: check longer/more-specific separators first.
    """
    candidates = [
        "#%#//scriptlet(", "#@%#//scriptlet(",
        "#%#", "#$?#", "#$#", "#@$#", "#?#", "#@#", "##",
        "$$",
    ]
    best: tuple[str, int] | None = None
    for sep in candidates:
        idx = line.find(sep)
        if idx == -1:
            continue
        if best is None or idx < best[1]:
            best = (sep, idx)
    return best


def convert(raw_text: str) -> dict:
    counts = {
        "network": 0,
        "network_exception": 0,
        "cosmetic_hide": 0,
        "cosmetic_exception": 0,
        "cosmetic_extended": 0,
        "css_inject": 0,
        "scriptlet": 0,
        "skipped": 0,
    }
    network_rules: list[dict] = []
    cosmetic_hide: dict[str, list[str]] = {}
    cosmetic_exceptions: dict[str, list[str]] = {}
    cosmetic_extended: dict[str, list[str]] = {}
    css_inject: dict[str, list[str]] = {}
    scriptlets: list[dict] = []
    skipped: list[dict] = []

    gate = PreprocessorGate()
    rule_id = 1

    for raw_line in raw_text.splitlines():
        is_directive, keep = gate.feed(raw_line)
        if is_directive:
            continue
        line = raw_line.strip()
        if not line:
            continue
        if not keep:
            skipped.append({"rule": line, "reason": "platform-gated (not chromium mv3)"})
            counts["skipped"] += 1
            continue

        sep = find_cosmetic_separator(line)

        if sep is None:
            # Network rule.
            is_allow = line.startswith("@@")
            filter_expr = line
            rule, reason = build_dnr_rule(rule_id, filter_expr, is_allow)
            if rule is None:
                skipped.append({"rule": line, "reason": reason or "unsupported network rule"})
                counts["skipped"] += 1
                continue
            network_rules.append(rule)
            rule_id += 1
            counts["network_exception" if is_allow else "network"] += 1
            continue

        sep_str, pos = sep
        head = line[:pos]
        body = line[pos + len(sep_str):]
        includes, excludes = parse_domain_list(head)

        if sep_str == "$$":
            skipped.append({"rule": line, "reason": "unsupported: $$ html-filter"})
            counts["skipped"] += 1
            continue

        if sep_str == "#@%#//scriptlet(":
            skipped.append({"rule": line, "reason": "unsupported: scriptlet exception (#@%#)"})
            counts["skipped"] += 1
            continue

        if sep_str == "#%#//scriptlet(":
            if not body.endswith(")"):
                skipped.append({"rule": line, "reason": "malformed scriptlet"})
                counts["skipped"] += 1
                continue
            name, args = tokenize_scriptlet_args(body[:-1])
            if not name:
                skipped.append({"rule": line, "reason": "scriptlet missing name"})
                counts["skipped"] += 1
                continue
            if any(name.startswith(prefix) for prefix in SCRIPTLET_UNSUPPORTED_PREFIXES):
                skipped.append({"rule": line, "reason": f"unsupported: trusted scriptlet '{name}'"})
                counts["skipped"] += 1
                continue
            scriptlets.append({
                "domains": includes,
                "excludeDomains": excludes,
                "scriptlet": name,
                "args": args,
            })
            counts["scriptlet"] += 1
            continue

        if sep_str == "#%#":
            skipped.append({"rule": line, "reason": "unsupported: inline JS (#%#)"})
            counts["skipped"] += 1
            continue

        if sep_str in ("#$#", "#$?#"):
            for host in includes or ["*"]:
                css_inject.setdefault(host, []).append(body)
            counts["css_inject"] += 1
            continue

        if sep_str == "#@$#":
            skipped.append({"rule": line, "reason": "unsupported: css-inject exception (#@$#)"})
            counts["skipped"] += 1
            continue

        if sep_str == "#?#":
            for host in includes or ["*"]:
                cosmetic_extended.setdefault(host, []).append(body)
            counts["cosmetic_extended"] += 1
            continue

        if sep_str == "#@#":
            for host in includes or ["*"]:
                cosmetic_exceptions.setdefault(host, []).append(body)
            counts["cosmetic_exception"] += 1
            continue

        if sep_str == "##":
            for host in includes or ["*"]:
                cosmetic_hide.setdefault(host, []).append(body)
            counts["cosmetic_hide"] += 1
            continue

        skipped.append({"rule": line, "reason": f"unhandled separator {sep_str}"})
        counts["skipped"] += 1

    host_index: dict[str, dict] = {}
    for idx, entry in enumerate(scriptlets):
        for host in entry["domains"] or ["*"]:
            host_index.setdefault(host, {"scriptlets": [], "cosmetic": False, "cssInject": False})
            host_index[host]["scriptlets"].append(idx)
    for host in cosmetic_hide:
        host_index.setdefault(host, {"scriptlets": [], "cosmetic": False, "cssInject": False})["cosmetic"] = True
    for host in cosmetic_extended:
        host_index.setdefault(host, {"scriptlets": [], "cosmetic": False, "cssInject": False})["cosmetic"] = True
    for host in cosmetic_exceptions:
        host_index.setdefault(host, {"scriptlets": [], "cosmetic": False, "cssInject": False})["cosmetic"] = True
    for host in css_inject:
        host_index.setdefault(host, {"scriptlets": [], "cosmetic": False, "cssInject": False})["cssInject"] = True

    return {
        "counts": counts,
        "network_rules_dnr": network_rules,
        "cosmetic": {
            "hide": cosmetic_hide,
            "hide_extended": cosmetic_extended,
            "exceptions": cosmetic_exceptions,
            "css_inject": css_inject,
        },
        "scriptlets": scriptlets,
        "hostIndex": host_index,
        "skipped": skipped,
    }


def build_manifest(raw_text: str, source_url: str) -> dict:
    converted = convert(raw_text)
    upstream_sha256 = hashlib.sha256(raw_text.encode("utf-8")).hexdigest()
    manifest = {
        "source": "AdguardTeam/AdguardFilters/BaseFilter/sections/antiadblock.txt",
        "source_url": source_url,
        "fetched_at": dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z",
        "upstream_sha256": upstream_sha256,
        **converted,
    }
    return manifest


def write_outputs(raw_text: str, manifest: dict) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    RAW_PATH.write_text(raw_text, encoding="utf-8")
    with MANIFEST_PATH.open("w", encoding="utf-8") as fp:
        json.dump(manifest, fp, indent=2, sort_keys=True)
        fp.write("\n")


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-url", default=ANTIADBLOCK_URL,
                        help="Override upstream URL (useful for local testing).")
    parser.add_argument("--input-file",
                        help="Read raw list from a local file instead of downloading. "
                             "The manifest will still record --source-url as the origin.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print counts to stdout, do not write files.")
    args = parser.parse_args(list(argv))

    if args.input_file:
        raw_text = Path(args.input_file).read_text(encoding="utf-8")
    else:
        raw_bytes = download(args.source_url)
        raw_text = raw_bytes.decode("utf-8")

    manifest = build_manifest(raw_text, args.source_url)

    if args.dry_run:
        print(json.dumps(manifest["counts"], indent=2))
        return 0

    write_outputs(raw_text, manifest)
    print(f"Wrote {RAW_PATH} ({len(raw_text):,} bytes)")
    print(f"Wrote {MANIFEST_PATH}")
    print("Counts:")
    for key, value in manifest["counts"].items():
        print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

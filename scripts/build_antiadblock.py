#!/usr/bin/env python3
"""
Fetch AdGuard filter sections and convert them into a Browser Guard-consumable JSON manifest.

Reads two upstream sections from AdGuardTeam/AdguardFilters, in this order:
  BaseFilter/sections/antiadblock.txt   (source name: antiadblock)
  BaseFilter/sections/specific.txt      (source name: specific)

and writes:
  antiadblock/antiadblock.txt          - raw antiadblock source, verbatim bytes
  antiadblock/specific.txt             - raw specific source, verbatim bytes
  antiadblock/antiadblock.json         - merged converted manifest
  antiadblock/NOTICE                   - GPL-3.0 attribution and provenance for both files

The manifest's `sources[]` array is the authoritative, ordered provenance record: one
entry per source, each carrying exactly its provenance fields (`name`, `source`,
`source_url`, `upstream_commit`, `upstream_sha256`) and nothing else. Per-source conversion
counts live in `counts_by_source`, keyed by source name, so provenance and counts never get
conflated. The legacy top-level provenance fields (`source`, `source_url`, `upstream_commit`,
`upstream_sha256`) describe the antiadblock source only and are retained for backward
compatibility with existing consumers; `fetched_at` stays top-level and reflects the build
run. For anything beyond the antiadblock source, read `sources[]`.

Sources are converted independently (each with a fresh PreprocessorGate) and then merged in
source order:
  * network_rules_dnr : deduped by exact (action, condition); each rule tagged with `source`;
                        ids renumbered 1..N over the merged list. The first source to emit a
                        condition keeps the source tag and position; a later duplicate only
                        raises the retained priority to the maximum seen (so a later
                        `$important` duplicate is not silently downgraded).
  * cosmetic maps     : unioned per host in source order, without duplicate selector strings;
                        hide/exception collisions on the same host are retained (both kept).
  * scriptlets        : deduped by (scriptlet, args, sorted domains, sorted excludeDomains);
                        each tagged with `source`.
  * hostIndex         : rebuilt from the merged data.
  * skipped           : concatenated in source order; each tagged with `source`.

Counts come in two independent shapes:
  * counts            : merged totals. Cosmetic counts are unique *logical* rules in source
                        order (a multi-domain cosmetic line counts once; an exactly repeated
                        logical rule counts once), never per-host selector expansion. DNR,
                        scriptlet, and skipped totals are the sizes of the final emitted
                        collections after dedupe.
  * counts_by_source  : each source's own pre-merge `convert()` counters, verbatim, keyed by
                        source name. These are per-rule-line logical counts and are not
                        affected by cross-source dedupe.

The `preprocessor_audit` block records, per source and as ordered global distinct tables,
every distinct `!#if` expression (with its Chromium result and any unknown flags), every
distinct `!+` hint (with result / informational status), the ignored `!#include` and
`!#safari_cb_affinity` directives, and the unclosed/unmatched conditional counts.

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
  unknown $options, negated $options       - explicitly skipped (see unknown-option histogram)
"""

import argparse
import ast
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import sys
import urllib.request
from pathlib import Path
from typing import Iterable

USER_AGENT = "browserguard-community-databases"

UPSTREAM_REPO = "AdguardTeam/AdguardFilters"
UPSTREAM_LICENSE_URL = "https://github.com/" + UPSTREAM_REPO + "/blob/master/LICENSE"
RAW_URL_TEMPLATE = "https://raw.githubusercontent.com/" + UPSTREAM_REPO + "/{ref}/{path}"
COMMITS_API_URL = "https://api.github.com/repos/" + UPSTREAM_REPO + "/commits"

# Ordered list of sources to fetch, convert, and merge. Order is authoritative: it drives
# merge precedence (first source wins id/host ordering) and the sources[] array order.
SOURCES: list[tuple[str, str]] = [
    ("antiadblock", "BaseFilter/sections/antiadblock.txt"),
    ("specific", "BaseFilter/sections/specific.txt"),
]
SOURCE_PATHS = {name: path for name, path in SOURCES}

# The legacy top-level provenance describes this source only.
LEGACY_SOURCE_NAME = "antiadblock"

UNPINNED_COMMIT = "unpinned (commit resolution unavailable at build time)"

REPO_ROOT = Path(__file__).resolve().parent.parent
OUTPUT_DIR = REPO_ROOT / "antiadblock"
MANIFEST_PATH = OUTPUT_DIR / "antiadblock.json"
NOTICE_PATH = OUTPUT_DIR / "NOTICE"


def raw_path_for(name: str) -> Path:
    """Raw-byte output path for a source: antiadblock/<name>.txt."""
    return OUTPUT_DIR / f"{name}.txt"


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

# Network options that are known, non-resource modifiers handled explicitly elsewhere
# (either consumed into the rule or used to reject it). Any option not covered here and
# not a DNR resource type is treated as unknown and skips the rule.
KNOWN_VALUE_OPTIONS = {"domain", "redirect", "redirect-rule", "replace", "csp", "important"}

SCRIPTLET_UNSUPPORTED_PREFIXES = ("trusted-",)

# A valid cosmetic domain-list token: a hostname, optionally negated with `~`, allowing
# wildcard TLDs (example.*) and leading wildcards (*.example.com). This is used to decide
# whether text before a `#...#` separator is really a domain list (cosmetic rule) rather
# than, say, a URL fragment that merely contains `##`.
_DOMAIN_TOKEN_RE = re.compile(
    r"^~?(?:\*\.)?(?:[A-Za-z0-9_*-]+\.)*[A-Za-z0-9_*-]+(?:\.\*)?$"
)


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
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read()


def resolve_upstream_commit(path: str) -> str | None:
    """Latest commit sha touching the given upstream section file, or None if unavailable."""
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        # Raises the Actions rate limit from 60/hr to 1000/hr.
        headers["Authorization"] = f"Bearer {token}"
    url = f"{COMMITS_API_URL}?path={path}&per_page=1"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        sha = payload[0]["sha"]
        if not isinstance(sha, str) or not sha:
            raise ValueError("commits API returned no usable sha")
        return sha
    except Exception as exc:
        # Deliberately broad: a daily blocklist refresh must not fail on a GitHub API
        # hiccup, and a null commit in the manifest keeps the degradation auditable.
        print(f"warning: could not resolve upstream commit for {path} ({exc}); recording null",
              file=sys.stderr)
        return None


@dataclasses.dataclass(frozen=True)
class Provenance:
    """
    Single source of truth for where one source's raw bytes came from.

    The manifest's sources[] array and the shared NOTICE file are rendered from these
    instances so they can never disagree about the commit, the hash, or the fetch time.
    """

    name: str
    source: str
    source_url: str
    upstream_commit: str | None
    upstream_sha256: str
    fetched_at: str

    @classmethod
    def record(cls, name: str, path: str, raw_bytes: bytes, source_url: str,
               upstream_commit: str | None, fetched_at: str) -> "Provenance":
        return cls(
            name=name,
            source=f"{UPSTREAM_REPO}/{path}",
            source_url=source_url,
            upstream_commit=upstream_commit,
            upstream_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            fetched_at=fetched_at,
        )

    def source_fields(self) -> dict:
        """Per-source provenance block for the manifest's sources[] array."""
        return {
            "name": self.name,
            "source": self.source,
            "source_url": self.source_url,
            "upstream_sha256": self.upstream_sha256,
            "upstream_commit": self.upstream_commit,
        }

    def legacy_fields(self) -> dict:
        """Legacy top-level provenance (antiadblock source only)."""
        return {
            "source": self.source,
            "source_url": self.source_url,
            "upstream_sha256": self.upstream_sha256,
            "upstream_commit": self.upstream_commit,
        }

    def notice_block(self) -> str:
        return f"""\
{self.name}.txt in this release is an unmodified, byte-for-byte copy of:

    {self.source}
    {self.source_url}
    upstream commit: {self.upstream_commit or UNPINNED_COMMIT}
    sha256:          {self.upstream_sha256}"""


def render_notice(provenances: list[Provenance], fetched_at: str) -> str:
    """Render one NOTICE covering every raw source file, from the Provenance objects."""
    blocks = "\n\n".join(p.notice_block() for p in provenances)
    return f"""\
{blocks}

Each file above is distributed under the GNU General Public License v3.0:
    {UPSTREAM_LICENSE_URL}

The upstream section files carry no in-file license header, which is why this
notice accompanies them. The files themselves are left untouched so that the
sha256 values above stay verifiable against AdGuard's originals.

antiadblock.json is a derived work produced from the above by
scripts/build_antiadblock.py, and is likewise GPL-3.0.

Generated {fetched_at}. Do not edit by hand.
"""


class PreprocessorGate:
    """
    Evaluates AdGuard preprocessor directives (`!#if`, `!#endif`, `!#else`,
    `!+ NOT_PLATFORM(...)`, `!+ PLATFORM(...)`) so we only keep lines that apply to
    Chromium MV3.

    The full AdGuard directive grammar is richer than this; we implement the subset
    that appears in these sections: single-token flags, `!`, `&&`, `||`, parens.

    A detailed audit is accumulated for the manifest, all ordered-unique:
      * if_expressions   : each distinct `!#if` expression -> {result, unknown_flags}
                           where result is the Chromium-MV3 evaluation and unknown_flags
                           lists identifiers not in PLATFORM_FLAGS (which default False).
      * plus_hints       : each distinct `!+` hint -> {result, informational} where a hint
                           with no PLATFORM/NOT_PLATFORM is informational (does not gate) and
                           result is the one-shot gate it would impose on the next rule.
      * ignored          : distinct ignored structural directives (`!#include`,
                           `!#safari_cb_affinity`).
      * unclosed_if      : `!#if` blocks still open when the source ends.
      * unmatched_endif  : `!#endif` seen with no open `!#if`.
      * unmatched_else   : `!#else` seen with no open `!#if`.

    A fresh gate is used per source so audit tables never leak across sources.
    """

    def __init__(self):
        # Stack of (condition_result, seen_true) for nested !#if blocks.
        self._stack = []
        # PLATFORM/NOT_PLATFORM applies to the immediately-following rule only.
        self._one_shot_gate = None
        # Audit accumulators (ordered-unique via dict keys).
        self.if_expressions: dict[str, dict] = {}
        self.plus_hints: dict[str, dict] = {}
        self.ignored_directives: dict[str, None] = {}
        self.unmatched_endif = 0
        self.unmatched_else = 0

    @staticmethod
    def _flag_idents(expr: str) -> list[str]:
        """Distinct, order-preserving identifiers that aren't boolean keywords."""
        out: dict[str, None] = {}
        for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", expr):
            if ident in ("and", "or", "not", "True", "False"):
                continue
            out.setdefault(ident, None)
        return list(out)

    def _eval_flag_expr(self, expr: str) -> bool:
        # Substitute identifiers with 'True'/'False' python literals, then walk the
        # AST rejecting any node that isn't a boolean op / constant / unary-not.
        # This avoids `eval` on upstream-controlled strings even after substitution.
        # Unknown identifiers default to False.
        def sub(match: re.Match) -> str:
            ident = match.group(0)
            return "True" if PLATFORM_FLAGS.get(ident, False) else "False"

        expr = re.sub(r"[A-Za-z_][A-Za-z0-9_]*", sub, expr)
        expr = expr.replace("&&", " and ").replace("||", " or ").replace("!", " not ").strip()
        try:
            tree = ast.parse(expr, mode="eval")
            return bool(_safe_eval_bool(tree.body))
        except (SyntaxError, ValueError):
            return False

    def _current_allows(self) -> bool:
        return all(entry[0] for entry in self._stack)

    def unclosed_if(self) -> int:
        """Count of `!#if` blocks still open (call after feeding all lines)."""
        return len(self._stack)

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
            result = self._eval_flag_expr(cond)
            if cond not in self.if_expressions:
                unknown = [f for f in self._flag_idents(cond) if f not in PLATFORM_FLAGS]
                self.if_expressions[cond] = {"result": result, "unknown_flags": unknown}
            self._stack.append((result, True))
            return True, False
        if stripped.startswith("!#endif"):
            if self._stack:
                self._stack.pop()
            else:
                self.unmatched_endif += 1
            return True, False
        if stripped.startswith("!#else"):
            if self._stack:
                cond, seen = self._stack[-1]
                self._stack[-1] = (not cond, seen)
            else:
                self.unmatched_else += 1
            return True, False
        if stripped.startswith("!#include") or stripped.startswith("!#safari_cb_affinity"):
            # Structural directives we deliberately ignore for MV3; record for audit.
            self.ignored_directives.setdefault(stripped, None)
            return True, False
        if stripped.startswith("!+"):
            payload = stripped[2:].strip()
            # A `!+` line can carry compound hints (`NOT_OPTIMIZED PLATFORM(...)`).
            # Only PLATFORM/NOT_PLATFORM affect our platform gating; unknown hints
            # (NOT_OPTIMIZED, HINT, etc.) are informational and must NOT gate the next rule.
            m = re.search(r"(NOT_PLATFORM|PLATFORM)\s*\(([^)]*)\)", payload)
            if not m:
                self.plus_hints.setdefault(payload, {"result": None, "informational": True})
                return True, False
            kind, args = m.group(1), m.group(2)
            flags = [a.strip() for a in args.split(",") if a.strip()]
            any_match = any(PLATFORM_FLAGS.get(f, False) for f in flags)
            gate = (not any_match) if kind == "NOT_PLATFORM" else any_match
            self.plus_hints.setdefault(payload, {"result": gate, "informational": False})
            self._one_shot_gate = gate
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


def is_valid_domain_head(head: str) -> bool:
    """
    True if `head` is empty or a valid comma-separated domain list (each token a hostname,
    optionally `~`-negated, allowing wildcard TLDs like `example.*` and `*.example.com`).

    Used to reject false cosmetic matches: text before a `#...#` separator that is not a
    real domain list (e.g. a URL fragment that merely contains `##`) must not be treated
    as a cosmetic rule.
    """
    head = head.strip()
    if not head:
        return True
    for token in head.split(","):
        token = token.strip()
        if not token:
            # Trailing/empty token (e.g. "a,") is not a valid domain list.
            return False
        if not _DOMAIN_TOKEN_RE.match(token):
            return False
    return True


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
    third_party_only, extras) where extras carries flags like redirect=, replace=, important,
    plus `unknown[]` and `negated[]` lists for options we refuse to handle.
    """
    resources: list[str] = []
    include_domains: list[str] = []
    exclude_domains: list[str] = []
    third_party_only = False
    first_party_only = False
    extras: dict = {}
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
        if opt == "important":
            extras["important"] = True
            continue
        if opt == "csp":
            extras["csp"] = True
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
            if k in KNOWN_VALUE_OPTIONS:
                extras[k] = v
            else:
                extras.setdefault("unknown", []).append(opt)
            continue
        if opt.startswith("~"):
            # Negated resource/option: not representable as a DNR condition; reject.
            extras.setdefault("negated", []).append(opt)
            continue
        mapped = ADG_TO_DNR.get(opt, opt)
        if mapped in DNR_RESOURCES:
            resources.append(mapped)
        else:
            extras.setdefault("unknown", []).append(opt)

    if first_party_only:
        extras["first_party_only"] = True
    return resources, include_domains, exclude_domains, third_party_only, extras


def _split_pattern_options(body: str) -> tuple[str, str]:
    """
    Split a network rule body into (pattern, options).

    A network regex literal is `/.../` possibly followed by `$options`. A `$` *inside* the
    regex must not be read as the options separator: find the closing unescaped `/` first
    and only treat a following `$` as the start of options. For non-regex patterns, split
    on the first `$` as before.
    """
    if body.startswith("/"):
        i = 1
        n = len(body)
        while i < n:
            if body[i] == "\\" and i + 1 < n:
                i += 2
                continue
            if body[i] == "/":
                rest = body[i + 1:]
                # A regex literal is the whole pattern in slashes: the closing unescaped
                # slash is the end of the pattern, with nothing after it or only `$options`.
                # A slash with other trailing path characters (e.g. `/ads/banner`) is an
                # ABP path-format pattern, not a regex, so keep scanning / fall through.
                if rest == "":
                    return body, ""
                if rest.startswith("$"):
                    return body[: i + 1], rest[1:]
            i += 1
        # Not a well-formed regex literal; fall through to plain split.
    parts = body.split("$", 1)
    return parts[0], (parts[1] if len(parts) > 1 else "")


def build_dnr_rule(rule_id: int, filter_expr: str, is_allow: bool) -> tuple[dict | None, str | None]:
    """
    Build a DNR rule from either `||host^$options` (domain-format) or
    `/path/pattern$options` (path/URL-format). Returns (rule, skip_reason).
    Exactly one is non-None.
    """
    body = filter_expr[2:] if is_allow else filter_expr  # strip @@
    pattern, options = _split_pattern_options(body)

    if not pattern:
        return None, "unsupported: empty network pattern"

    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) >= 2:
        # Regex literal (may contain `$`, `##`, etc.): not expressible as a DNR urlFilter.
        return None, "unsupported: regex network pattern"

    if pattern.startswith("||"):
        url_filter = pattern
    elif pattern.startswith("/") or pattern.startswith(".") or pattern.startswith("-") or "://" in pattern:
        # Path-format (ABP): pass the pattern through as-is; DNR treats bare separators
        # (`^`, `|`, `*`) with the same semantics.
        url_filter = pattern
    else:
        return None, "unsupported: non-domain network pattern"

    resources, include_doms, exclude_doms, third_party, extras = parse_network_options(options)

    if extras.get("unknown"):
        return None, "unsupported: unknown option(s) " + ",".join(extras["unknown"])
    if extras.get("negated"):
        return None, "unsupported: negated option(s) " + ",".join(extras["negated"])
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
    # Priority tiers: allow (50) > important block (45) > plain block (40). $important
    # raises a block above plain blocks so it wins among blocks, but allow rules still
    # outrank it, matching AdGuard's exception-over-blocking precedence.
    if is_allow:
        priority = 50
    elif extras.get("important"):
        priority = 45
    else:
        priority = 40
    return {"id": rule_id, "priority": priority, "action": action, "condition": condition}, None


def find_cosmetic_separator(line: str) -> tuple[str, int] | None:
    """
    Return (separator, position) of the first cosmetic/scriptlet separator in line, or None.
    Order matters: check longer/more-specific separators first.

    A match is only accepted when the text before the separator is empty or a valid
    comma-separated domain list; otherwise the `#` is incidental (e.g. inside a URL) and
    the line is left for the network-rule path.
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
        if not is_valid_domain_head(line[:idx]):
            # Not a cosmetic rule: head is not a domain list. Keep looking in case a
            # later-but-valid separator exists, but do not accept this one.
            continue
        if best is None or idx < best[1]:
            best = (sep, idx)
    return best


def convert(raw_text: str) -> dict:
    """Convert one source's raw text into an unmerged, single-source result bundle."""
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
    unknown_options: dict[str, int] = {}
    network_rules: list[dict] = []
    cosmetic_hide: dict[str, list[str]] = {}
    cosmetic_exceptions: dict[str, list[str]] = {}
    cosmetic_extended: dict[str, list[str]] = {}
    css_inject: dict[str, list[str]] = {}
    scriptlets: list[dict] = []
    skipped: list[dict] = []

    # Ordered-unique logical cosmetic rule signatures, per category. One source line is one
    # logical rule regardless of how many hosts it expands to; an exactly repeated logical
    # rule collapses to a single signature. Merge uses these to count unique logical rules in
    # source order, independent of the per-host selector maps above.
    cosmetic_sigs: dict[str, dict[tuple, None]] = {
        "hide": {},
        "hide_extended": {},
        "exceptions": {},
        "css_inject": {},
    }

    def record_cosmetic_sig(category: str, includes: list[str], excludes: list[str],
                            selector: str) -> None:
        sig = (tuple(includes), tuple(excludes), selector)
        cosmetic_sigs[category].setdefault(sig, None)

    gate = PreprocessorGate()
    rule_id = 1

    def record_unknown(reason: str | None) -> None:
        """Tally unknown/negated options from a skip reason into the histogram."""
        if not reason:
            return
        prefix = None
        if reason.startswith("unsupported: unknown option(s) "):
            prefix = "unsupported: unknown option(s) "
        elif reason.startswith("unsupported: negated option(s) "):
            prefix = "unsupported: negated option(s) "
        if prefix is None:
            return
        for opt in reason[len(prefix):].split(","):
            opt = opt.strip()
            if opt:
                unknown_options[opt] = unknown_options.get(opt, 0) + 1

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
                record_unknown(reason)
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
            record_cosmetic_sig("css_inject", includes, excludes, body)
            for host in includes or ["*"]:
                css_inject.setdefault(host, []).append(body)
            counts["css_inject"] += 1
            continue

        if sep_str == "#@$#":
            skipped.append({"rule": line, "reason": "unsupported: css-inject exception (#@$#)"})
            counts["skipped"] += 1
            continue

        if sep_str == "#?#":
            record_cosmetic_sig("hide_extended", includes, excludes, body)
            for host in includes or ["*"]:
                cosmetic_extended.setdefault(host, []).append(body)
            counts["cosmetic_extended"] += 1
            continue

        if sep_str == "#@#":
            record_cosmetic_sig("exceptions", includes, excludes, body)
            for host in includes or ["*"]:
                cosmetic_exceptions.setdefault(host, []).append(body)
            counts["cosmetic_exception"] += 1
            continue

        if sep_str == "##":
            record_cosmetic_sig("hide", includes, excludes, body)
            for host in includes or ["*"]:
                cosmetic_hide.setdefault(host, []).append(body)
            counts["cosmetic_hide"] += 1
            continue

        skipped.append({"rule": line, "reason": f"unhandled separator {sep_str}"})
        counts["skipped"] += 1

    return {
        "counts": counts,
        "unknown_options": unknown_options,
        "network_rules_dnr": network_rules,
        "cosmetic": {
            "hide": cosmetic_hide,
            "hide_extended": cosmetic_extended,
            "exceptions": cosmetic_exceptions,
            "css_inject": css_inject,
        },
        "cosmetic_signatures": {
            category: list(sigs) for category, sigs in cosmetic_sigs.items()
        },
        "scriptlets": scriptlets,
        "skipped": skipped,
        "preprocessor_audit": {
            "if_expressions": [
                {"expr": expr, "result": info["result"], "unknown_flags": info["unknown_flags"]}
                for expr, info in gate.if_expressions.items()
            ],
            "plus_hints": [
                {"hint": hint, "result": info["result"], "informational": info["informational"]}
                for hint, info in gate.plus_hints.items()
            ],
            "ignored_directives": list(gate.ignored_directives),
            "unclosed_if": gate.unclosed_if(),
            "unmatched_endif": gate.unmatched_endif,
            "unmatched_else": gate.unmatched_else,
        },
    }


def _condition_key(action: dict, condition: dict) -> str:
    """Stable key for a DNR rule by exact action + condition (order-insensitive)."""
    return json.dumps({"action": action, "condition": condition}, sort_keys=True)


def _union_cosmetic(target: dict[str, list[str]], source_map: dict[str, list[str]]) -> None:
    """Union a per-host selector map into target in order, skipping duplicate strings."""
    for host, selectors in source_map.items():
        bucket = target.setdefault(host, [])
        seen = set(bucket)
        for sel in selectors:
            if sel not in seen:
                bucket.append(sel)
                seen.add(sel)


def _scriptlet_key(entry: dict) -> tuple:
    return (
        entry["scriptlet"],
        tuple(entry["args"]),
        tuple(sorted(entry["domains"])),
        tuple(sorted(entry["excludeDomains"])),
    )


def merge_sources(converted: list[tuple[str, dict]]) -> dict:
    """
    Merge per-source conversion results in source order.

    `converted` is a list of (source_name, convert()-result) in the authoritative order.
    """
    merged_counts = {
        "network": 0,
        "network_exception": 0,
        "cosmetic_hide": 0,
        "cosmetic_exception": 0,
        "cosmetic_extended": 0,
        "css_inject": 0,
        "scriptlet": 0,
        "skipped": 0,
    }
    counts_by_source: dict[str, dict] = {}
    unknown_options: dict[str, int] = {}

    # Preprocessor audit: per-source blocks plus ordered global distinct tables.
    audit_by_source: dict[str, dict] = {}
    audit_if: dict[str, dict] = {}      # expr -> {result, unknown_flags}
    audit_plus: dict[str, dict] = {}    # hint -> {result, informational}
    audit_ignored: dict[str, None] = {}

    # Unique logical cosmetic rule signatures across all sources, in source order, per
    # category. These drive the merged cosmetic counts; the per-host maps below are the
    # emitted output and may expand one logical rule across many hosts.
    cosmetic_sig_seen: dict[str, dict[tuple, None]] = {
        "hide": {},
        "hide_extended": {},
        "exceptions": {},
        "css_inject": {},
    }

    network_rules: list[dict] = []
    seen_conditions: dict[str, int] = {}
    cosmetic_hide: dict[str, list[str]] = {}
    cosmetic_extended: dict[str, list[str]] = {}
    cosmetic_exceptions: dict[str, list[str]] = {}
    css_inject: dict[str, list[str]] = {}
    scriptlets: list[dict] = []
    seen_scriptlets: set[tuple] = set()
    skipped: list[dict] = []

    for name, result in converted:
        counts_by_source[name] = dict(result["counts"])
        for opt, n in result["unknown_options"].items():
            unknown_options[opt] = unknown_options.get(opt, 0) + n

        audit = result["preprocessor_audit"]
        audit_by_source[name] = audit
        for item in audit["if_expressions"]:
            audit_if.setdefault(item["expr"],
                                {"result": item["result"], "unknown_flags": item["unknown_flags"]})
        for item in audit["plus_hints"]:
            audit_plus.setdefault(item["hint"],
                                  {"result": item["result"], "informational": item["informational"]})
        for directive in audit["ignored_directives"]:
            audit_ignored.setdefault(directive, None)

        # DNR: dedupe by exact action+condition. The first source to emit a condition keeps
        # the source tag and position; a later duplicate only raises the retained priority to
        # the maximum seen, so a later $important duplicate is not downgraded.
        for rule in result["network_rules_dnr"]:
            key = _condition_key(rule["action"], rule["condition"])
            if key in seen_conditions:
                existing = network_rules[seen_conditions[key]]
                if rule["priority"] > existing["priority"]:
                    existing["priority"] = rule["priority"]
                continue
            seen_conditions[key] = len(network_rules)
            is_allow = rule["action"].get("type") == "allow"
            merged = {
                "priority": rule["priority"],
                "action": rule["action"],
                "condition": rule["condition"],
                "source": name,
            }
            network_rules.append(merged)
            merged_counts["network_exception" if is_allow else "network"] += 1

        _union_cosmetic(cosmetic_hide, result["cosmetic"]["hide"])
        _union_cosmetic(cosmetic_extended, result["cosmetic"]["hide_extended"])
        _union_cosmetic(cosmetic_exceptions, result["cosmetic"]["exceptions"])
        _union_cosmetic(css_inject, result["cosmetic"]["css_inject"])

        # Count unique logical cosmetic rules in source order (not per-host expansion).
        for category, sigs in result["cosmetic_signatures"].items():
            for sig in sigs:
                cosmetic_sig_seen[category].setdefault(tuple(sig), None)

        for entry in result["scriptlets"]:
            key = _scriptlet_key(entry)
            if key in seen_scriptlets:
                continue
            seen_scriptlets.add(key)
            scriptlets.append({**entry, "source": name})

        for item in result["skipped"]:
            skipped.append({**item, "source": name})

    # Renumber DNR ids 1..N over the merged, deduped list.
    for new_id, rule in enumerate(network_rules, start=1):
        rule["id"] = new_id
    # Reorder keys for stable, readable output (id first).
    network_rules = [
        {"id": r["id"], "priority": r["priority"], "action": r["action"],
         "condition": r["condition"], "source": r["source"]}
        for r in network_rules
    ]

    # Cosmetic merged counts are unique logical rules, not per-host selector expansion.
    merged_counts["cosmetic_hide"] = len(cosmetic_sig_seen["hide"])
    merged_counts["cosmetic_extended"] = len(cosmetic_sig_seen["hide_extended"])
    merged_counts["cosmetic_exception"] = len(cosmetic_sig_seen["exceptions"])
    merged_counts["css_inject"] = len(cosmetic_sig_seen["css_inject"])
    # DNR, scriptlet, and skipped merged counts come from the final emitted collections.
    merged_counts["scriptlet"] = len(scriptlets)
    merged_counts["skipped"] = len(skipped)

    # Rebuild hostIndex from the merged data.
    host_index: dict[str, dict] = {}

    def ensure(host: str) -> dict:
        return host_index.setdefault(host, {"scriptlets": [], "cosmetic": False, "cssInject": False})

    for idx, entry in enumerate(scriptlets):
        for host in entry["domains"] or ["*"]:
            ensure(host)["scriptlets"].append(idx)
    for host in cosmetic_hide:
        ensure(host)["cosmetic"] = True
    for host in cosmetic_extended:
        ensure(host)["cosmetic"] = True
    for host in cosmetic_exceptions:
        ensure(host)["cosmetic"] = True
    for host in css_inject:
        ensure(host)["cssInject"] = True

    preprocessor_audit = {
        "by_source": audit_by_source,
        "if_expressions": [
            {"expr": expr, "result": info["result"], "unknown_flags": info["unknown_flags"]}
            for expr, info in audit_if.items()
        ],
        "plus_hints": [
            {"hint": hint, "result": info["result"], "informational": info["informational"]}
            for hint, info in audit_plus.items()
        ],
        "ignored_directives": list(audit_ignored),
    }

    return {
        "counts": merged_counts,
        "counts_by_source": counts_by_source,
        "unknown_options": unknown_options,
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
        "preprocessor_audit": preprocessor_audit,
    }


def build_manifest(converted: list[tuple[str, dict]], provenances: list[Provenance],
                   fetched_at: str) -> dict:
    merged = merge_sources(converted)
    prov_by_name = {p.name: p for p in provenances}
    legacy = prov_by_name.get(LEGACY_SOURCE_NAME)
    legacy_fields = legacy.legacy_fields() if legacy else {}

    manifest = {
        **legacy_fields,
        "fetched_at": fetched_at,
        "sources": [p.source_fields() for p in provenances],
        **merged,
    }
    return manifest


def write_outputs(raws: list[tuple[str, bytes]], manifest: dict,
                  provenances: list[Provenance], fetched_at: str) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, raw_bytes in raws:
        raw_path_for(name).write_bytes(raw_bytes)
    with MANIFEST_PATH.open("w", encoding="utf-8") as fp:
        json.dump(manifest, fp, indent=2, sort_keys=True)
        fp.write("\n")
    NOTICE_PATH.write_text(render_notice(provenances, fetched_at), encoding="utf-8")


def _parse_name_value(items: list[str] | None, flag: str) -> dict[str, str]:
    """Parse repeatable NAME=VALUE CLI args into a dict, validating NAME is a known source."""
    out: dict[str, str] = {}
    for item in items or []:
        if "=" not in item:
            raise SystemExit(f"error: {flag} expects NAME=VALUE, got {item!r}")
        name, value = item.split("=", 1)
        name = name.strip()
        if name not in SOURCE_PATHS:
            raise SystemExit(
                f"error: {flag} unknown source {name!r}; known: {', '.join(SOURCE_PATHS)}")
        out[name] = value
    return out


def acquire_source(name: str, path: str, input_file: str | None, source_url_override: str | None,
                   fetched_at: str) -> tuple[bytes, Provenance]:
    """
    Obtain one source's raw bytes and provenance.

    Priority: explicit --input-file (local, byte-preserving read) > explicit --source-url
    (download) > resolve path-specific commit and download pinned (falling back to master).
    """
    upstream_commit: str | None = None
    if input_file is not None:
        raw_bytes = Path(input_file).read_bytes()
        source_url = source_url_override or RAW_URL_TEMPLATE.format(ref="master", path=path)
    elif source_url_override is not None:
        raw_bytes = download(source_url_override)
        source_url = source_url_override
    else:
        # Resolve the commit before fetching. The other order is racy: an upstream push
        # between the two calls would record a sha describing bytes we do not have.
        upstream_commit = resolve_upstream_commit(path)
        source_url = (RAW_URL_TEMPLATE.format(ref=upstream_commit, path=path)
                      if upstream_commit else RAW_URL_TEMPLATE.format(ref="master", path=path))
        raw_bytes = download(source_url)

    provenance = Provenance.record(name, path, raw_bytes, source_url, upstream_commit, fetched_at)
    return raw_bytes, provenance


def print_preprocessor_audit(audit: dict) -> None:
    """Print the merged preprocessor audit to stderr (every run, including dry-run)."""
    print("Preprocessor audit this run:", file=sys.stderr)

    if_exprs = audit.get("if_expressions", [])
    print(f"  !#if expressions ({len(if_exprs)} distinct):", file=sys.stderr)
    for item in if_exprs:
        unknown = item.get("unknown_flags") or []
        suffix = f" unknown_flags={','.join(unknown)}" if unknown else ""
        print(f"    [{'keep' if item['result'] else 'drop'}] {item['expr']}{suffix}",
              file=sys.stderr)

    plus = audit.get("plus_hints", [])
    print(f"  !+ hints ({len(plus)} distinct):", file=sys.stderr)
    for item in plus:
        if item.get("informational"):
            status = "informational"
        else:
            status = "keep-next" if item["result"] else "drop-next"
        print(f"    [{status}] {item['hint']}", file=sys.stderr)

    ignored = audit.get("ignored_directives", [])
    print(f"  ignored directives ({len(ignored)} distinct):", file=sys.stderr)
    for directive in ignored:
        print(f"    {directive}", file=sys.stderr)

    by_source = audit.get("by_source", {})
    for name, src_audit in by_source.items():
        print(
            f"  {name}: unclosed_if={src_audit.get('unclosed_if', 0)} "
            f"unmatched_endif={src_audit.get('unmatched_endif', 0)} "
            f"unmatched_else={src_audit.get('unmatched_else', 0)}",
            file=sys.stderr,
        )


def main(argv: Iterable[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input-file", action="append", metavar="NAME=PATH",
                        help="Read a source's raw bytes from a local file instead of downloading. "
                             "Repeatable. NAME is one of: " + ", ".join(SOURCE_PATHS) + ".")
    parser.add_argument("--source-url", action="append", metavar="NAME=URL",
                        help="Override a source's upstream URL. Repeatable. NAME is one of: "
                             + ", ".join(SOURCE_PATHS) + ".")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print counts to stdout, do not write files.")
    args = parser.parse_args(list(argv))

    input_files = _parse_name_value(args.input_file, "--input-file")
    source_urls = _parse_name_value(args.source_url, "--source-url")

    fetched_at = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    raws: list[tuple[str, bytes]] = []
    provenances: list[Provenance] = []
    converted: list[tuple[str, dict]] = []

    for name, path in SOURCES:
        raw_bytes, provenance = acquire_source(
            name, path, input_files.get(name), source_urls.get(name), fetched_at)
        raws.append((name, raw_bytes))
        provenances.append(provenance)
        converted.append((name, convert(raw_bytes.decode("utf-8"))))

    manifest = build_manifest(converted, provenances, fetched_at)

    # Per-run unknown-option histogram (always printed to stderr for auditability).
    histogram = manifest.get("unknown_options", {})
    if histogram:
        print("Unknown/negated network options this run:", file=sys.stderr)
        for opt, n in sorted(histogram.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {opt}: {n}", file=sys.stderr)
    else:
        print("No unknown/negated network options this run.", file=sys.stderr)

    print_preprocessor_audit(manifest["preprocessor_audit"])

    if args.dry_run:
        print(json.dumps({
            "counts": manifest["counts"],
            "counts_by_source": manifest["counts_by_source"],
        }, indent=2))
        return 0

    write_outputs(raws, manifest, provenances, fetched_at)
    for name, raw_bytes in raws:
        print(f"Wrote {raw_path_for(name)} ({len(raw_bytes):,} bytes)")
    print(f"Wrote {MANIFEST_PATH}")
    print(f"Wrote {NOTICE_PATH}")
    print("Counts (merged):")
    for key, value in manifest["counts"].items():
        print(f"  {key}: {value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

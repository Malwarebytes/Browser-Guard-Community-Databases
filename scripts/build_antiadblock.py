#!/usr/bin/env python3
"""
Build Browser Guard's anti-adblock databases from AdGuard's filter lists.

Downloads, pinned to one upstream commit:
  BaseFilter/sections/antiadblock.txt   - every rule
  BaseFilter/sections/specific.txt      - only the sections in SPECIFIC_SECTIONS

and writes, into --out-dir, files the Browser Guard extension loads as they are:

  mbgc.mv3.antiadblock_1.json            Chromium MV3 static DNR ruleset (array of rules)
  mbgc.db.antiadblock.cosmetic.json      {specific_hide, extended_hide, exception_rules},
                                         host -> [selector]; merged into the easylist DB
  mbgc.db.antiadblock.heuristics.json    heuristics DB rules ({id, r, s, t, a}) for
                                         element removal (`:remove()`, `{ remove: true; }`)
  skipped.json                           every rule that was not converted, with the reason
  build.json                             provenance and counts
  antiadblock.txt, specific.txt          the upstream files, verbatim (GPL-3.0)
  NOTICE                                 licensing and provenance

Anything the extension cannot execute is skipped rather than approximated: scriptlets, inline
JS, HTML filtering, response rewriting, redirects, regex network patterns, generic cosmetic
rules, wildcard-TLD domains and CSS injections that do anything other than hide or remove.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path
from typing import Iterable, Iterator

UPSTREAM_REPO = "AdguardTeam/AdguardFilters"
UPSTREAM_LICENSE_URL = f"https://github.com/{UPSTREAM_REPO}/blob/master/LICENSE"
RAW_URL_TEMPLATE = f"https://raw.githubusercontent.com/{UPSTREAM_REPO}/{{ref}}/{{path}}"
COMMIT_API_URL = f"https://api.github.com/repos/{UPSTREAM_REPO}/commits/master"
USER_AGENT = "browserguard-community-databases"

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT_DIR = REPO_ROOT / "build" / "antiadblock"

DNR_FILE = "mbgc.mv3.antiadblock_1.json"
COSMETIC_FILE = "mbgc.db.antiadblock.cosmetic.json"
HEURISTICS_FILE = "mbgc.db.antiadblock.heuristics.json"
SCRIPTLETS_FILE = "mbgc.db.antiadblock.scriptlets.json"
SKIPPED_FILE = "skipped.json"
BUILD_FILE = "build.json"
NOTICE_FILE = "NOTICE"


@dataclasses.dataclass(frozen=True)
class Source:
    name: str
    path: str
    # None means the whole file; otherwise only lines between `! START: <name>` and
    # `! END: <name>` for each listed section.
    sections: tuple[str, ...] | None
    # Whether `#%#//scriptlet(...)` rules from this source are converted. Rolled out per source
    # so each list's scriptlets can be verified on their own before the next is turned on.
    scriptlets: bool


# specific.txt is a general site-specific ad list (~25k lines). Only its anti-adblock sections
# are taken: "Ad-Shield ad reinsertion" carries the html-load.com / Ad-Shield rules that
# watchuseek.com, archerytalk.com and worldjournal.com need, none of which are in antiadblock.txt.
SPECIFIC_SECTIONS = ("Ad-Shield ad reinsertion",)

SOURCES = (
    Source("antiadblock.txt", "BaseFilter/sections/antiadblock.txt", None, scriptlets=True),
    Source("specific.txt", "BaseFilter/sections/specific.txt", SPECIFIC_SECTIONS, scriptlets=True),
)

# Scriptlets the extension implements (guard-app/content-scripts/content-scriptlets). Anything
# else is skipped. trusted-* scriptlets are never supported: AdGuard only runs them from its own
# signed lists because they can inject arbitrary content.
SUPPORTED_SCRIPTLETS = frozenset({
    "abort-current-inline-script",
    "abort-on-property-read",
    "abort-on-property-write",
    "prevent-addEventListener",
    "prevent-fetch",
    "prevent-setInterval",
    "prevent-setTimeout",
    "prevent-xhr",
    "remove-attr",
    "remove-class",
    "remove-node-text",
    "set-constant",
    "set-cookie",
})

# Priorities are chosen against the extension's own (guard-app/app/scripts/mv3/dynamic-rule-utils.js):
#   static ads blocklist 90  <  anti-adblock block 100 / $important 105 / allow 110
#   < tracker whitelist 120 < risky TLDs 150 < per-site ads exclusion 210 < malware 211.
# So AdGuard exceptions (which un-block ad bait to get past detection) beat Browser Guard's ad
# rules, but never its tracker whitelist, user exclusions or malware blocking.
DNR_BLOCK_PRIORITY = 100
DNR_IMPORTANT_BLOCK_PRIORITY = 105
DNR_ALLOW_PRIORITY = 110

# Heuristic rule ids live in their own range so they never collide with mbgc.db.heuristics.json.
HEURISTIC_ID_BASE = 90_000_000

# `!#if` identifiers that are true for the Browser Guard Chromium MV3 build. Everything else
# (Safari, iOS, Firefox, desktop apps, uBlock) is false.
TRUE_CONDITIONS = frozenset({
    "adguard", "adguard_ext_chromium", "adguard_ext_chromium_mv3", "ext_chromium_mv3",
})

# `!+ PLATFORM(...)` / `!+ NOT_PLATFORM(...)` names that describe this build.
OUR_PLATFORMS = frozenset({"ext_chromium", "ext_chromium_mv3"})

DNR_RESOURCE_TYPES = {
    "script": "script",
    "image": "image",
    "stylesheet": "stylesheet",
    "css": "stylesheet",
    "object": "object",
    "xmlhttprequest": "xmlhttprequest",
    "xhr": "xmlhttprequest",
    "subdocument": "sub_frame",
    "frame": "sub_frame",
    "ping": "ping",
    "media": "media",
    "font": "font",
    "websocket": "websocket",
    "other": "other",
}

# Network options that need something DNR or the extension cannot do.
UNSUPPORTED_NETWORK_OPTIONS = frozenset({
    "redirect", "redirect-rule", "replace", "csp", "removeparam", "removeheader", "cookie",
    "header", "permissions", "referrerpolicy", "app", "network", "hls", "jsonprune",
    "urltransform", "empty", "mp4", "popup", "document", "doc", "generichide", "ghide",
    "elemhide", "ehide", "specifichide", "shide", "content", "jsinject", "urlblock",
    "genericblock", "extension", "stealth", "all", "inline-script", "inline-font",
    "webrtc", "xmlhttprequest-rule", "strict1p", "strict3p", "method", "path", "url",
})

# Any of these in a rule means its option list can contain regexes with `$` and `,`, which a
# plain split would mangle. They are all unsupported anyway, so reject before splitting.
EARLY_REJECT_OPTION = re.compile(
    r"[$,](redirect|redirect-rule|replace|csp|removeparam|removeheader|cookie|header|"
    r"permissions|urltransform|jsonprune|hls)(=|,|$)"
)

COSMETIC_SEPARATOR = re.compile(
    r"^(?P<domains>[^\s#$]*?)(?P<sep>#@\$\?#|#@\?#|#@\$#|#@%#|#@#|#\$\?#|#\?#|#\$#|#%#|##|\$@\$|\$\$)(?P<body>.+)$"
)

# AdGuard ExtCSS pseudo-classes rewritten to the spelling the extension's SelectorParser uses.
PSEUDO_ALIASES = (
    (":-abp-contains(", ":contains("),
    (":has-text(", ":contains("),
    (":-abp-has(", ":has("),
    (":if(", ":has("),
)
# Functional pseudo-classes every target browser's CSS engine evaluates natively.
NATIVE_PSEUDOS = frozenset({
    "not", "is", "where", "has", "nth-child", "nth-last-child", "nth-of-type",
    "nth-last-of-type", "lang", "dir",
})
# Functional pseudo-classes the extension's procedural tier (SelectorParser) evaluates.
PROCEDURAL_PSEUDOS = frozenset({"contains", "has", "not", "xpath"})
FUNCTIONAL_PSEUDO = re.compile(r":([a-zA-Z-]+)\(")

DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9-]{2,}$")
CSS_DISPLAY_NONE = re.compile(r"^display\s*:\s*none\s*(!\s*important)?\s*;?$", re.I)
CSS_REMOVE = re.compile(r"^remove\s*:\s*true\s*;?$", re.I)


# ---------------------------------------------------------------------------------------------
# Results
# ---------------------------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True)
class Origin:
    source: str
    line: int
    text: str


class Skip(Exception):
    """Raised by converters when a rule cannot be expressed; the message is the reason."""


@dataclasses.dataclass
class Outputs:
    dnr: list[dict] = dataclasses.field(default_factory=list)
    specific_hide: dict[str, set[str]] = dataclasses.field(default_factory=dict)
    extended_hide: dict[str, set[str]] = dataclasses.field(default_factory=dict)
    exception_rules: dict[str, set[str]] = dataclasses.field(default_factory=dict)
    heuristics: list[str] = dataclasses.field(default_factory=list)
    # (name, args) -> included hosts / excluded hosts
    scriptlets: dict[tuple[str, tuple[str, ...]], set[str]] = dataclasses.field(default_factory=dict)
    scriptlet_exclusions: dict[tuple[str, tuple[str, ...]], set[str]] = dataclasses.field(
        default_factory=dict
    )
    # Hosts where `#@%#//scriptlet()` disables every scriptlet.
    scriptlets_disabled: set[str] = dataclasses.field(default_factory=set)
    skipped: list[dict] = dataclasses.field(default_factory=list)
    out_of_scope: dict[str, int] = dataclasses.field(default_factory=dict)

    def skip(self, origin: Origin, reason: str) -> None:
        self.skipped.append(
            {"source": origin.source, "line": origin.line, "rule": origin.text, "reason": reason}
        )


# ---------------------------------------------------------------------------------------------
# Line selection and preprocessing
# ---------------------------------------------------------------------------------------------

def select_sections(text: str, sections: tuple[str, ...] | None) -> Iterator[tuple[int, str]]:
    """Yield (line number, line) for the requested `! START:`/`! END:` sections, or all lines."""
    lines = text.splitlines()
    if sections is None:
        yield from enumerate(lines, start=1)
        return

    found = set()
    active: str | None = None
    for number, line in enumerate(lines, start=1):
        stripped = line.strip()
        if active is None:
            for name in sections:
                if stripped == f"! START: {name}":
                    active = name
                    found.add(name)
            continue
        if stripped == f"! END: {active}":
            active = None
            continue
        yield number, line

    missing = set(sections) - found
    if missing:
        raise ValueError(f"select_sections: upstream sections not found: {sorted(missing)}")


def evaluate_condition(expression: str) -> bool:
    """Evaluate an `!#if` expression: identifiers, `!`, `&&`, `||`, parentheses."""
    tokens = re.findall(r"\|\||&&|!|\(|\)|[A-Za-z_][A-Za-z0-9_]*", expression)
    if "".join(tokens) != re.sub(r"\s+", "", expression):
        raise ValueError(f"evaluate_condition: unparseable expression {expression!r}")
    position = 0

    def peek() -> str | None:
        return tokens[position] if position < len(tokens) else None

    def take() -> str:
        nonlocal position
        position += 1
        return tokens[position - 1]

    def parse_or() -> bool:
        value = parse_and()
        while peek() == "||":
            take()
            value = parse_and() or value
        return value

    def parse_and() -> bool:
        value = parse_unary()
        while peek() == "&&":
            take()
            value = parse_unary() and value
        return value

    def parse_unary() -> bool:
        token = take() if peek() is not None else None
        if token == "!":
            return not parse_unary()
        if token == "(":
            value = parse_or()
            if take() != ")":
                raise ValueError(f"evaluate_condition: unbalanced parentheses in {expression!r}")
            return value
        if token is None or not re.match(r"[A-Za-z_]", token):
            raise ValueError(f"evaluate_condition: unexpected token {token!r} in {expression!r}")
        return token == "true" or token in TRUE_CONDITIONS

    result = parse_or()
    if peek() is not None:
        raise ValueError(f"evaluate_condition: trailing tokens in {expression!r}")
    return result


def hint_allows(hint: str) -> bool:
    """Apply one `!+` hint line. PLATFORM/NOT_PLATFORM restrict; other hints are ignored."""
    allowed = True
    for name, args in re.findall(r"(NOT_PLATFORM|PLATFORM)\(([^)]*)\)", hint):
        platforms = {p.strip() for p in args.split(",")}
        matches = bool(platforms & OUR_PLATFORMS)
        allowed = allowed and (not matches if name == "NOT_PLATFORM" else matches)
    return allowed


def active_rules(
    source: str, numbered_lines: Iterable[tuple[int, str]], outputs: Outputs
) -> Iterator[Origin]:
    """Yield the rules that apply to Chromium MV3, after `!#if` blocks and `!+` hints."""
    stack: list[bool] = []  # one entry per open !#if: is this branch active
    pending_hint: bool | None = None
    for number, raw in numbered_lines:
        line = raw.strip()
        if line.startswith("!#if"):
            stack.append(evaluate_condition(line[len("!#if"):]))
            continue
        if line.startswith("!#else"):
            if not stack:
                raise ValueError(f"active_rules: {source}:{number} !#else without !#if")
            stack[-1] = not stack[-1]
            continue
        if line.startswith("!#endif"):
            if not stack:
                raise ValueError(f"active_rules: {source}:{number} !#endif without !#if")
            stack.pop()
            continue
        if line.startswith("!+"):
            pending_hint = hint_allows(line[2:]) if pending_hint is None else (
                pending_hint and hint_allows(line[2:])
            )
            continue
        if not line or line.startswith("!") or (line.startswith("[") and line.endswith("]")):
            continue

        hint, pending_hint = pending_hint, None
        if not all(stack) or hint is False:
            outputs.out_of_scope[source] = outputs.out_of_scope.get(source, 0) + 1
            continue
        yield Origin(source, number, line)

    if stack:
        raise ValueError(f"active_rules: {source} ends with {len(stack)} unclosed !#if")


# ---------------------------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------------------------

def normalize_domain(domain: str) -> str:
    """Lowercase and punycode a hostname; raise Skip if it is not a concrete hostname."""
    domain = domain.strip().lower()
    if domain.endswith(".*") or "*" in domain:
        raise Skip("wildcard domain")
    if domain.startswith("/"):
        raise Skip("regex domain")
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError as error:
        raise Skip("invalid domain") from error
    if not DOMAIN_RE.match(domain):
        raise Skip("invalid domain")
    return domain


def split_domains(entries: Iterable[str]) -> tuple[list[str], list[str], int]:
    """Split `a.com|~b.com` style entries into (included, excluded, dropped wildcard count)."""
    included: list[str] = []
    excluded: list[str] = []
    dropped = 0
    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue
        negated = entry.startswith("~")
        try:
            domain = normalize_domain(entry[1:] if negated else entry)
        except Skip:
            if negated:
                # Dropping an exclusion would widen the rule, so the whole rule goes.
                raise Skip("wildcard or invalid excluded domain")
            dropped += 1
            continue
        target = excluded if negated else included
        if domain not in target:
            target.append(domain)
    return included, excluded, dropped


# ---------------------------------------------------------------------------------------------
# Network rules -> DNR
# ---------------------------------------------------------------------------------------------

def convert_network(rule: str) -> dict:
    """Convert one AdGuard network rule to a DNR rule (without id). Raise Skip if impossible."""
    is_allow = rule.startswith("@@")
    body = rule[2:] if is_allow else rule

    if EARLY_REJECT_OPTION.search(body):
        name = EARLY_REJECT_OPTION.search(body).group(1)
        raise Skip(f"unsupported option ${name}")

    pattern, options = body, ""
    if "$" in body:
        pattern, options = body.rsplit("$", 1)

    if pattern.startswith("/") and pattern.endswith("/") and len(pattern) > 1:
        raise Skip("regex pattern")

    condition: dict = {}
    priority = DNR_ALLOW_PRIORITY if is_allow else DNR_BLOCK_PRIORITY
    resource_types: list[str] = []
    excluded_resource_types: list[str] = []

    for option in filter(None, (o.strip() for o in options.split(","))):
        negated = option.startswith("~")
        name, _, value = option.lstrip("~").partition("=")
        name = name.lower()

        if name in DNR_RESOURCE_TYPES:
            target = excluded_resource_types if negated else resource_types
            if DNR_RESOURCE_TYPES[name] not in target:
                target.append(DNR_RESOURCE_TYPES[name])
        elif name in ("third-party", "3p"):
            condition["domainType"] = "firstParty" if negated else "thirdParty"
        elif name in ("first-party", "1p"):
            condition["domainType"] = "thirdParty" if negated else "firstParty"
        elif name == "domain" and not negated:
            included, excluded, dropped = split_domains(value.split("|"))
            if dropped and not included:
                raise Skip("only wildcard or invalid domains")
            if included:
                condition["initiatorDomains"] = included
            if excluded:
                condition["excludedInitiatorDomains"] = excluded
        elif name == "denyallow" and not negated:
            included, excluded, _ = split_domains(value.split("|"))
            if excluded or not included:
                raise Skip("invalid $denyallow")
            condition["excludedRequestDomains"] = included
        elif name == "to" and not negated:
            included, excluded, dropped = split_domains(value.split("|"))
            if dropped and not included:
                raise Skip("only wildcard or invalid domains")
            if included:
                condition["requestDomains"] = included
            if excluded:
                condition["excludedRequestDomains"] = (
                    condition.get("excludedRequestDomains", []) + excluded
                )
        elif name == "match-case" and not negated:
            condition["isUrlFilterCaseSensitive"] = True
        elif name == "important" and not negated:
            if not is_allow:
                priority = DNR_IMPORTANT_BLOCK_PRIORITY
        elif name in UNSUPPORTED_NETWORK_OPTIONS or name == "badfilter":
            raise Skip(f"unsupported option ${name}")
        else:
            raise Skip(f"unknown option ${name}")

    if resource_types:
        condition["resourceTypes"] = sorted(resource_types)
    if excluded_resource_types:
        condition["excludedResourceTypes"] = sorted(excluded_resource_types)

    url_filter = convert_url_filter(pattern)
    if url_filter:
        condition["urlFilter"] = url_filter
    elif not any(k in condition for k in ("initiatorDomains", "requestDomains")):
        raise Skip("pattern matches every request")

    return {
        "priority": priority,
        "action": {"type": "allow" if is_allow else "block"},
        "condition": condition,
    }


def convert_url_filter(pattern: str) -> str | None:
    """Return the DNR urlFilter for an AdGuard pattern, or None when it matches everything."""
    if pattern in ("", "*", "|", "||"):
        return None
    if not pattern.isascii():
        host_match = re.match(r"^(\|\|)?([^/^:*|]+)(.*)$", pattern)
        if not host_match:
            raise Skip("non-ASCII pattern")
        try:
            host = host_match.group(2).encode("idna").decode("ascii")
        except UnicodeError as error:
            raise Skip("non-ASCII pattern") from error
        pattern = (host_match.group(1) or "") + host + host_match.group(3)
        if not pattern.isascii():
            raise Skip("non-ASCII pattern")
    if pattern.startswith("||*"):
        pattern = pattern[2:]
    if "||" in pattern[2:] or re.search(r"\s", pattern):
        raise Skip("invalid pattern")
    return pattern


# ---------------------------------------------------------------------------------------------
# Cosmetic rules
# ---------------------------------------------------------------------------------------------

def normalize_selector(selector: str) -> str:
    selector = selector.strip()
    for alias, canonical in PSEUDO_ALIASES:
        selector = selector.replace(alias, canonical)
    return selector


def escape_contains_arguments(selector: str) -> str:
    """
    AdGuard's `:contains(text)` is a substring match; the extension's is a regex. Escape plain
    arguments so they keep substring semantics. `/regex/` arguments are left as they are.
    """
    out = []
    index = 0
    marker = ":contains("
    while True:
        start = selector.find(marker, index)
        if start == -1:
            out.append(selector[index:])
            return "".join(out)
        content_start = start + len(marker)
        end = matching_paren(selector, content_start)
        argument = selector[content_start:end]
        if not (argument.startswith("/") and argument.endswith("/") and len(argument) > 1):
            argument = re.sub(r"([\\.*+?^${}()|\[\]])", r"\\\1", argument)
        out.append(selector[index:content_start] + argument + ")")
        index = end + 1


def matching_paren(text: str, start: int) -> int:
    depth = 1
    index = start
    while index < len(text):
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    raise Skip("unbalanced parentheses")


def classify_selector(selector: str) -> str:
    """Return "plain" (CSS-native), "procedural" (extension's SelectorParser) or raise Skip."""
    if not selector or re.search(r"[{}\n\r]", selector):
        raise Skip("invalid selector")
    if selector[0] in ">+~":
        raise Skip("relative selector")
    if selector.count("[") != selector.count("]"):
        raise Skip("invalid selector")
    pseudos = {name.lower() for name in FUNCTIONAL_PSEUDO.findall(selector)}
    if pseudos <= NATIVE_PSEUDOS:
        return "plain"
    if pseudos <= PROCEDURAL_PSEUDOS:
        for inner_start in (m.end() for m in re.finditer(r":has\(", selector)):
            if selector[inner_start:].lstrip()[:1] in (">", "+", "~"):
                raise Skip("relative :has() in extended selector")
        return "procedural"
    unsupported = sorted(pseudos - NATIVE_PSEUDOS - PROCEDURAL_PSEUDOS)
    raise Skip(f"unsupported pseudo-class :{unsupported[0]}()")


def cosmetic_domains(domains: str) -> tuple[list[str], list[str]]:
    if not domains:
        raise Skip("generic cosmetic rule")
    included, excluded, dropped = split_domains(domains.split(","))
    if not included:
        raise Skip("only wildcard or invalid domains" if dropped else "generic cosmetic rule")
    return included, excluded


def heuristic_domain_pattern(included: list[str], excluded: list[str]) -> str:
    """
    Build the URL regex the heuristics engine matches against `location.href`.

    `[.]` rather than `\\.`: the engine collapses doubled backslashes, and a character class
    reads the same either way.
    """
    def alternation(domains: list[str]) -> str:
        return "|".join(d.replace(".", "[.]") for d in sorted(domains))

    host_suffix = r"([:/?]|$)"
    prefix = r"^https?://"
    exclusion = f"(?!([^/]+[.])?({alternation(excluded)}){host_suffix})" if excluded else ""
    return f"{prefix}{exclusion}([^/]+[.])?({alternation(included)}){host_suffix}"


def add_to(section: dict[str, set[str]], hosts: Iterable[str], selector: str) -> None:
    for host in hosts:
        section.setdefault(host, set()).add(selector)


def add_hide(outputs: Outputs, included: list[str], excluded: list[str], selector: str) -> None:
    selector = normalize_selector(selector)
    remove = re.fullmatch(r"(.+?):remove\(\)", selector)
    if remove:
        add_remove(outputs, included, excluded, remove.group(1))
        return
    kind = classify_selector(selector)
    if kind == "plain":
        add_to(outputs.specific_hide, included, selector)
    else:
        add_to(outputs.extended_hide, included, escape_contains_arguments(selector))
    # `a.com,~b.a.com##x`: hide on a.com, but not on b.a.com.
    add_to(outputs.exception_rules, excluded, selector)


def add_remove(outputs: Outputs, included: list[str], excluded: list[str], selector: str) -> None:
    selector = normalize_selector(selector)
    if classify_selector(selector) != "plain":
        raise Skip("extended selector in remove rule")
    if "#@#" in selector:
        raise Skip("invalid selector")
    outputs.heuristics.append(
        f"{heuristic_domain_pattern(included, excluded)}##{selector}:remove()"
    )


SCRIPTLET_ARGUMENT = re.compile(r"""\s*(?:'((?:[^'\\]|\\.)*)'|"((?:[^"\\]|\\.)*)")\s*(,|$)""", re.S)


def parse_scriptlet_call(body: str) -> tuple[str, tuple[str, ...]] | None:
    """
    Parse `//scriptlet('name', 'arg', ...)` into (name, args). `//scriptlet()` returns None,
    which as an exception means "every scriptlet". Raises Skip when the call is malformed.

    Inside a quoted argument the only escape is a backslash before the quote character. Every
    other backslash (regex escapes such as `\\.`) is kept as written, as AdGuard does.
    """
    match = re.fullmatch(r"//scriptlet\((.*)\)\s*", body, re.S)
    if not match:
        raise Skip("JavaScript injection")
    inner = match.group(1).strip()
    if not inner:
        return None

    values: list[str] = []
    position = 0
    while position < len(inner):
        argument = SCRIPTLET_ARGUMENT.match(inner, position)
        if not argument or argument.end() == position:
            raise Skip("invalid scriptlet arguments")
        single, double = argument.group(1), argument.group(2)
        quote, raw = ("'", single) if single is not None else ('"', double)
        values.append(raw.replace("\\" + quote, quote))
        position = argument.end()
        if argument.group(3) == "" and position < len(inner):
            raise Skip("invalid scriptlet arguments")

    name, *args = values
    # Trailing empty arguments are AdGuard's way of writing "default"; drop them so equal calls
    # compare equal.
    while args and args[-1] == "":
        args.pop()
    return name, tuple(args)


def convert_scriptlet(domains: str, body: str, is_exception: bool, outputs: Outputs) -> None:
    call = parse_scriptlet_call(body)
    if call is None:
        if not is_exception:
            raise Skip("invalid scriptlet arguments")
        included, _ = cosmetic_domains(domains)
        outputs.scriptlets_disabled.update(included)
        return
    name, _ = call
    if name.startswith("trusted-"):
        raise Skip("trusted scriptlet")
    if name not in SUPPORTED_SCRIPTLETS:
        raise Skip(f"unsupported scriptlet {name}")
    included, excluded = cosmetic_domains(domains)
    if is_exception:
        outputs.scriptlet_exclusions.setdefault(call, set()).update(included)
        return
    outputs.scriptlets.setdefault(call, set()).update(included)
    outputs.scriptlet_exclusions.setdefault(call, set()).update(excluded)


def convert_cosmetic(
    domains: str, separator: str, body: str, outputs: Outputs, scriptlets: bool
) -> None:
    if separator in ("#%#", "#@%#"):
        if not body.startswith("//scriptlet("):
            raise Skip("JavaScript injection")
        if not scriptlets:
            raise Skip("scriptlets not enabled for this source")
        convert_scriptlet(domains, body, separator == "#@%#", outputs)
        return
    if separator in ("$$", "$@$"):
        raise Skip("HTML filtering")
    if separator in ("#@$#", "#@$?#"):
        raise Skip("CSS injection exception")

    if separator in ("#@#", "#@?#"):
        included, _ = cosmetic_domains(domains)
        selector = normalize_selector(body)
        classify_selector(selector)
        add_to(outputs.exception_rules, included, selector)
        return

    if separator in ("#$#", "#$?#"):
        match = re.fullmatch(r"(.+?)\s*\{\s*(.*?)\s*\}", body.strip())
        if not match:
            raise Skip("invalid CSS injection")
        selector, declaration = match.group(1), match.group(2)
        included, excluded = cosmetic_domains(domains)
        if CSS_REMOVE.match(declaration):
            add_remove(outputs, included, excluded, selector)
        elif CSS_DISPLAY_NONE.match(declaration):
            add_hide(outputs, included, excluded, selector)
        else:
            raise Skip("CSS injection")
        return

    # ## and #?#
    if re.search(r":(style|matches-css|matches-css-before|matches-css-after)\(", body):
        raise Skip("CSS injection")
    included, excluded = cosmetic_domains(domains)
    add_hide(outputs, included, excluded, body)


# ---------------------------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------------------------

def badfilter_target(rule: str) -> str | None:
    """For `rule$opts,badfilter`, the rule text it disables (`rule$opts`); otherwise None."""
    if "$" not in rule:
        return None
    pattern, options = rule.rsplit("$", 1)
    names = options.split(",")
    if "badfilter" not in names:
        return None
    rest = [name for name in names if name != "badfilter"]
    return f"{pattern}${','.join(rest)}" if rest else pattern


def convert(texts: dict[str, str]) -> Outputs:
    """Convert upstream file contents (keyed by Source.name) into Outputs."""
    outputs = Outputs()
    network: list[tuple[Origin, dict]] = []
    badfilters: set[str] = set()

    for source in SOURCES:
        lines = select_sections(texts[source.name], source.sections)
        for origin in active_rules(source.name, lines, outputs):
            rule = origin.text
            try:
                if rule.startswith("[$"):
                    raise Skip("cosmetic rule modifiers")
                cosmetic = COSMETIC_SEPARATOR.match(rule)
                if cosmetic:
                    convert_cosmetic(
                        cosmetic["domains"], cosmetic["sep"], cosmetic["body"], outputs,
                        source.scriptlets,
                    )
                    continue
                disabled = badfilter_target(rule)
                if disabled is not None:
                    badfilters.add(disabled)
                    raise Skip("badfilter")
                network.append((origin, convert_network(rule)))
            except Skip as reason:
                outputs.skip(origin, str(reason))

    seen: set[str] = set()
    for origin, dnr in network:
        if origin.text in badfilters:
            outputs.skip(origin, "disabled by $badfilter")
            continue
        key = json.dumps(dnr, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        outputs.dnr.append({"id": len(outputs.dnr) + 1, **dnr})
    return outputs


def cosmetic_document(outputs: Outputs) -> dict:
    def sorted_section(section: dict[str, set[str]]) -> dict[str, list[str]]:
        return {host: sorted(section[host]) for host in sorted(section)}

    return {
        "specific_hide": sorted_section(outputs.specific_hide),
        "extended_hide": sorted_section(outputs.extended_hide),
        "exception_rules": sorted_section(outputs.exception_rules),
    }


def scriptlets_document(outputs: Outputs) -> dict:
    """
    Scriptlet calls plus host indexes into them, so a page looks up its own hostname ladder
    instead of scanning every rule:

      {"scriptlets": [{"name": ..., "args": [...]}],
       "hosts":    {host: [index, ...]},   # run these on host and its subdomains
       "excluded": {host: [index, ...]}}   # but not on this host or its subdomains

    A host in `#@%#//scriptlet()` is excluded from every scriptlet.
    """
    calls = sorted(outputs.scriptlets)
    hosts: dict[str, list[int]] = {}
    excluded: dict[str, list[int]] = {}
    for index, call in enumerate(calls):
        for host in outputs.scriptlets[call]:
            hosts.setdefault(host, []).append(index)
        for host in outputs.scriptlet_exclusions.get(call, set()) | outputs.scriptlets_disabled:
            excluded.setdefault(host, []).append(index)
    return {
        "scriptlets": [{"name": name, "args": list(args)} for name, args in calls],
        "hosts": {host: hosts[host] for host in sorted(hosts)},
        "excluded": {host: excluded[host] for host in sorted(excluded)},
    }


def heuristics_document(outputs: Outputs) -> list[dict]:
    rules = sorted(set(outputs.heuristics))
    return [
        {"id": HEURISTIC_ID_BASE + index, "r": rule, "s": False, "t": "adserver", "a": False}
        for index, rule in enumerate(rules)
    ]


def counts(outputs: Outputs) -> dict:
    by_reason: dict[str, int] = {}
    for entry in outputs.skipped:
        by_reason[entry["reason"]] = by_reason.get(entry["reason"], 0) + 1
    return {
        "dnr_block": sum(r["action"]["type"] == "block" for r in outputs.dnr),
        "dnr_allow": sum(r["action"]["type"] == "allow" for r in outputs.dnr),
        "specific_hide": sum(map(len, outputs.specific_hide.values())),
        "extended_hide": sum(map(len, outputs.extended_hide.values())),
        "exception_rules": sum(map(len, outputs.exception_rules.values())),
        "heuristics": len(set(outputs.heuristics)),
        "scriptlets": len(outputs.scriptlets),
        "skipped": len(outputs.skipped),
        "skipped_by_reason": dict(sorted(by_reason.items(), key=lambda kv: (-kv[1], kv[0]))),
        "out_of_scope_for_platform": dict(sorted(outputs.out_of_scope.items())),
    }


def download(url: str) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def resolve_upstream_commit() -> str:
    data = json.loads(download(COMMIT_API_URL))
    sha = data.get("sha")
    if not isinstance(sha, str) or not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError(f"resolve_upstream_commit: unexpected response from {COMMIT_API_URL}")
    return sha


def write_json(path: Path, data) -> None:
    # ASCII only: the extension reads bundled databases byte by byte (utils.binaryToString), with no
    # UTF-8 decoding, so non-ASCII selectors survive only as \uXXXX escapes.
    path.write_text(json.dumps(data, indent=1, ensure_ascii=True) + "\n", encoding="ascii")


def notice_text(commit: str, hashes: dict[str, str]) -> str:
    files = "\n".join(
        f"    {source.name}: {RAW_URL_TEMPLATE.format(ref=commit, path=source.path)}\n"
        f"        sha256 {hashes[source.name]}"
        for source in SOURCES
    )
    return (
        "antiadblock.txt and specific.txt in this release are unmodified copies of files from\n"
        f"{UPSTREAM_REPO} at commit {commit}:\n\n{files}\n\n"
        "They are distributed under the GNU General Public License v3.0:\n"
        f"    {UPSTREAM_LICENSE_URL}\n\n"
        f"{DNR_FILE}, {COSMETIC_FILE}, {HEURISTICS_FILE} and\n"
        f"{SCRIPTLETS_FILE} are derived from them by\n"
        "scripts/build_antiadblock.py in Malwarebytes/Browser-Guard-Community-Databases, and\n"
        "are likewise GPL-3.0.\n"
    )


def build(out_dir: Path, texts: dict[str, bytes], commit: str) -> dict:
    """Convert and write every artifact into out_dir. Returns the build summary."""
    decoded = {name: data.decode("utf-8") for name, data in texts.items()}
    outputs = convert(decoded)
    hashes = {name: hashlib.sha256(data).hexdigest() for name, data in texts.items()}

    out_dir.mkdir(parents=True, exist_ok=True)
    for name, data in texts.items():
        (out_dir / name).write_bytes(data)
    write_json(out_dir / DNR_FILE, outputs.dnr)
    write_json(out_dir / COSMETIC_FILE, cosmetic_document(outputs))
    write_json(out_dir / HEURISTICS_FILE, heuristics_document(outputs))
    write_json(out_dir / SCRIPTLETS_FILE, scriptlets_document(outputs))
    write_json(out_dir / SKIPPED_FILE, outputs.skipped)
    (out_dir / NOTICE_FILE).write_text(notice_text(commit, hashes), encoding="utf-8")

    summary = {
        "upstream_repo": UPSTREAM_REPO,
        "upstream_commit": commit,
        "sources": [
            {
                "name": source.name,
                "url": RAW_URL_TEMPLATE.format(ref=commit, path=source.path),
                "sections": list(source.sections) if source.sections else None,
                "sha256": hashes[source.name],
            }
            for source in SOURCES
        ],
        "built_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "counts": counts(outputs),
    }
    write_json(out_dir / BUILD_FILE, summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument(
        "--input-dir", type=Path,
        help="Read antiadblock.txt and specific.txt from here instead of downloading them.",
    )
    parser.add_argument("--commit", help="Upstream commit to fetch (default: master HEAD).")
    args = parser.parse_args(argv)

    if args.input_dir:
        commit = args.commit or "local"
        texts = {s.name: (args.input_dir / s.name).read_bytes() for s in SOURCES}
    else:
        commit = args.commit or resolve_upstream_commit()
        texts = {
            s.name: download(RAW_URL_TEMPLATE.format(ref=commit, path=s.path)) for s in SOURCES
        }

    summary = build(args.out_dir, texts, commit)
    print(json.dumps({"upstream_commit": commit, **summary["counts"]}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())

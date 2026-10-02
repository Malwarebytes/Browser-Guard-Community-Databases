"""
Pytest coverage for scripts/build_antiadblock.py, the multi-source filter builder.

The suite is organized into sections:

  * Fixture conversion   : the four real Fora rule forms (trimmed to three hosts) and the
                           merged output shape they produce.
  * Merge semantics      : contiguous ids, DNR/scriptlet/cosmetic dedupe, collisions, counts.
  * Fresh-gate isolation : per-source PreprocessorGate audit tables never leak.
  * Literal parser       : build_dnr_rule / parse_network_options edge cases.
  * Preprocessor audit   : nested / else / unknown-flag / hints / include / safari.
  * Provenance           : sources[] order, exact sha256, NOTICE paths/hashes, legacy block.
  * CLI                  : repeatable --input-file, byte-preserving raw writes, no download.
  * acquire_source       : commit resolution happens before the pinned download.
  * Single-source migration regression: the current converter run over the PRE-REFACTOR
    antiadblock.txt read from origin/main (local main fallback) via `git show`, with the
    intentional deltas documented inline. Skips once the base manifest carries sources[].

Fixtures (tests/fixtures/*.txt) are intentionally tiny. The migration regression reads its
baseline bytes from the base git ref, not the working tree, so a fresh daily build cannot move
the frozen numbers.
"""

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

# Import the module under test by path so the suite runs from anywhere.
REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import build_antiadblock as b  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
ANTIADBLOCK_FIXTURE = FIXTURES / "antiadblock.txt"
SPECIFIC_FIXTURE = FIXTURES / "specific.txt"


# ---------------------------------------------------------------------------
# Shared helpers / fixtures
# ---------------------------------------------------------------------------

def _sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def _stable_hash(obj) -> str:
    return _sha256_hex(json.dumps(obj, sort_keys=True))


@pytest.fixture(scope="module")
def fixture_bytes():
    return {
        "antiadblock": ANTIADBLOCK_FIXTURE.read_bytes(),
        "specific": SPECIFIC_FIXTURE.read_bytes(),
    }


@pytest.fixture(scope="module")
def converted(fixture_bytes):
    """Per-source convert() results in authoritative source order."""
    return [
        ("antiadblock", b.convert(fixture_bytes["antiadblock"].decode("utf-8"))),
        ("specific", b.convert(fixture_bytes["specific"].decode("utf-8"))),
    ]


@pytest.fixture(scope="module")
def merged(converted):
    return b.merge_sources(converted)


@pytest.fixture(scope="module")
def specific_result(converted):
    return dict(converted)["specific"]


# ---------------------------------------------------------------------------
# Fixture conversion: the four real Fora rule forms
# ---------------------------------------------------------------------------

def test_html_load_block_rule_shape(merged):
    """||html-load.com^$script,domain=... -> block, script-only, watchuseek initiator, specific."""
    html_load = [
        r for r in merged["network_rules_dnr"]
        if r["condition"]["urlFilter"] == "||html-load.com^"
    ]
    assert len(html_load) == 1
    rule = html_load[0]
    assert rule["action"] == {"type": "block"}
    assert rule["condition"]["resourceTypes"] == ["script"]
    # Initiators keep source order; watchuseek is the first-listed initiator.
    assert rule["condition"]["initiatorDomains"][0] == "watchuseek.com"
    assert set(rule["condition"]["initiatorDomains"]) == {
        "watchuseek.com", "edsupportforum.com", "toyotanation.com",
    }
    assert rule["source"] == "specific"
    assert rule["priority"] == 40  # plain block tier


def test_remove_node_text_scriptlet_fields_and_source(merged):
    """remove-node-text scriptlet keeps its name/args/domains and the specific source tag."""
    scriptlets = [s for s in merged["scriptlets"] if s["scriptlet"] == "remove-node-text"]
    assert len(scriptlets) == 1
    s = scriptlets[0]
    assert s["args"] == ["script", "html-load.com"]
    # Domain list preserved verbatim in source order (not sorted).
    assert s["domains"] == ["edsupportforum.com", "watchuseek.com", "toyotanation.com"]
    assert s["excludeDomains"] == []
    assert s["source"] == "specific"


def test_scriptlet_hostindex_positional_target(merged):
    """hostIndex points each scriptlet host at the scriptlet's positional index, not a copy."""
    scriptlets = merged["scriptlets"]
    idx = next(i for i, s in enumerate(scriptlets) if s["scriptlet"] == "remove-node-text")
    for host in ("edsupportforum.com", "watchuseek.com", "toyotanation.com"):
        assert idx in merged["hostIndex"][host]["scriptlets"]


def test_dollar_dollar_html_filter_skipped(merged):
    """$$script:contains(...) is recorded as an html-filter skip tagged specific."""
    dd = [
        s for s in merged["skipped"]
        if s["reason"] == "unsupported: $$ html-filter" and "script:contains" in s["rule"]
    ]
    assert len(dd) == 1
    assert dd[0]["source"] == "specific"


def test_firefox_replace_is_platform_gated(merged):
    """
    The empty-pattern $document,replace line lives inside !#if (adguard_ext_firefox).

    Chromium MV3 drops the whole block, so the line never reaches the $replace check: the
    skip reason is the platform gate, not '$replace'. The skip is tagged specific.
    """
    # The regex escapes the dot (error-report\.com), so match the hostname stem.
    gated = [
        s for s in merged["skipped"]
        if "error-report" in s["rule"]
    ]
    assert len(gated) == 1
    assert gated[0]["reason"] == "platform-gated (not chromium mv3)"
    assert gated[0]["source"] == "specific"


def test_firefox_if_expression_evaluates_false(specific_result):
    audit = specific_result["preprocessor_audit"]
    exprs = {e["expr"]: e for e in audit["if_expressions"]}
    assert "adguard_ext_firefox" in exprs
    assert exprs["adguard_ext_firefox"]["result"] is False
    assert exprs["adguard_ext_firefox"]["unknown_flags"] == []


# ---------------------------------------------------------------------------
# Merge semantics
# ---------------------------------------------------------------------------

def test_merged_dnr_ids_are_contiguous(merged):
    ids = [r["id"] for r in merged["network_rules_dnr"]]
    assert ids == list(range(1, len(ids) + 1))


def test_merged_literal_counts(merged):
    """Literal merged counts for the two-source fixture pair."""
    assert merged["counts"] == {
        "network": 2,
        "network_exception": 0,
        "cosmetic_hide": 1,
        "cosmetic_exception": 0,
        "cosmetic_extended": 0,
        "css_inject": 0,
        "scriptlet": 2,
        "skipped": 2,
    }


def test_counts_by_source_are_premerge_verbatim(merged):
    assert merged["counts_by_source"]["antiadblock"]["network"] == 1
    assert merged["counts_by_source"]["antiadblock"]["scriptlet"] == 1
    assert merged["counts_by_source"]["specific"]["network"] == 1
    assert merged["counts_by_source"]["specific"]["skipped"] == 2


def test_dnr_dedupe_keeps_first_source_and_max_important_priority():
    """
    Two sources emit the same ||x.com^ block condition; the second carries $important.

    The deduped rule keeps the first source's position/tag but is raised to the max
    (important) priority, so a later $important duplicate is not silently downgraded.
    """
    first = b.convert("||x.com^\n")              # plain block, priority 40
    second = b.convert("||x.com^$important\n")    # important block, priority 45
    merged = b.merge_sources([("antiadblock", first), ("specific", second)])

    blocks = [r for r in merged["network_rules_dnr"]
              if r["condition"]["urlFilter"] == "||x.com^"]
    assert len(blocks) == 1  # deduped
    assert blocks[0]["source"] == "antiadblock"  # first source wins the tag/position
    assert blocks[0]["priority"] == 45           # raised to the important maximum


def test_dnr_dedupe_does_not_downgrade_when_important_comes_first():
    """First source already important; a later plain duplicate must not lower the priority."""
    first = b.convert("||x.com^$important\n")
    second = b.convert("||x.com^\n")
    merged = b.merge_sources([("antiadblock", first), ("specific", second)])
    blocks = [r for r in merged["network_rules_dnr"]
              if r["condition"]["urlFilter"] == "||x.com^"]
    assert len(blocks) == 1
    assert blocks[0]["priority"] == 45
    assert blocks[0]["source"] == "antiadblock"


def test_scriptlet_dedupe_ignores_domain_ordering():
    """Same scriptlet with the same domain *set* in a different order dedupes to one entry."""
    first = b.convert("a.com,b.com#%#//scriptlet('noop')\n")
    second = b.convert("b.com,a.com#%#//scriptlet('noop')\n")
    merged = b.merge_sources([("antiadblock", first), ("specific", second)])
    noop = [s for s in merged["scriptlets"] if s["scriptlet"] == "noop"]
    assert len(noop) == 1
    assert noop[0]["source"] == "antiadblock"  # first source retained


def test_cosmetic_union_is_order_preserving_per_host():
    """Per host, selectors union in source order with no duplicate strings."""
    first = b.convert("shop.com##.a\nshop.com##.b\n")
    second = b.convert("shop.com##.b\nshop.com##.c\n")  # .b duplicate, .c new
    merged = b.merge_sources([("antiadblock", first), ("specific", second)])
    assert merged["cosmetic"]["hide"]["shop.com"] == [".a", ".b", ".c"]


def test_hide_and_exception_collision_both_retained():
    """A hide and a hide-exception for the same host+selector are both kept (different maps)."""
    conv = b.convert("site.com##.ad\nsite.com#@#.ad\n")
    merged = b.merge_sources([("specific", conv)])
    assert merged["cosmetic"]["hide"]["site.com"] == [".ad"]
    assert merged["cosmetic"]["exceptions"]["site.com"] == [".ad"]


def test_merged_cosmetic_counts_are_logical_not_per_host():
    """A single multi-host cosmetic line counts once in merged cosmetic_hide."""
    conv = b.convert("one.com,two.com,three.com##.promo\n")
    merged = b.merge_sources([("specific", conv)])
    assert merged["counts"]["cosmetic_hide"] == 1
    # ...but every host still appears in the emitted per-host map.
    assert set(merged["cosmetic"]["hide"]) == {"one.com", "two.com", "three.com"}


# ---------------------------------------------------------------------------
# Fresh-gate isolation
# ---------------------------------------------------------------------------

def test_fresh_gate_isolation_between_sources():
    """
    A source that leaves an !#if open must not gate the next source's rules. convert() uses a
    fresh PreprocessorGate per call, so the unclosed count is per-source and the second
    source still emits its rule.
    """
    leaky = b.convert("!#if (ext_chromium_mv3)\n||kept-a.com^\n")  # no !#endif
    clean = b.convert("||kept-b.com^\n")
    assert leaky["preprocessor_audit"]["unclosed_if"] == 1
    assert clean["preprocessor_audit"]["unclosed_if"] == 0

    merged = b.merge_sources([("antiadblock", leaky), ("specific", clean)])
    urls = {r["condition"]["urlFilter"] for r in merged["network_rules_dnr"]}
    assert "||kept-a.com^" in urls
    assert "||kept-b.com^" in urls
    # Per-source audit blocks are preserved independently.
    assert merged["preprocessor_audit"]["by_source"]["antiadblock"]["unclosed_if"] == 1
    assert merged["preprocessor_audit"]["by_source"]["specific"]["unclosed_if"] == 0


# ---------------------------------------------------------------------------
# Literal parser tests (build_dnr_rule / parse_network_options)
# ---------------------------------------------------------------------------

def test_important_option_raises_block_priority():
    rule, reason = b.build_dnr_rule(1, "||imp.com^$important", is_allow=False)
    assert reason is None
    assert rule["priority"] == 45
    assert rule["action"] == {"type": "block"}


def test_unknown_option_rejects_rule():
    rule, reason = b.build_dnr_rule(1, "||u.com^$totallybogus", is_allow=False)
    assert rule is None
    assert reason == "unsupported: unknown option(s) totallybogus"


def test_negated_resource_rejects_rule():
    rule, reason = b.build_dnr_rule(1, "||n.com^$~script", is_allow=False)
    assert rule is None
    assert reason == "unsupported: negated option(s) ~script"


def test_csp_option_uses_dedicated_skip_reason():
    rule, reason = b.build_dnr_rule(1, "@@||example.com^$csp", is_allow=True)
    assert rule is None
    assert reason == "unsupported: $csp"


def test_regex_pattern_with_hash_and_dollar_is_rejected_as_regex():
    """
    A /.../ regex literal may contain '##' and '$' internally. The pattern/options split must
    not treat the inner '$' as the options separator, and the whole thing is rejected as a
    regex network pattern (not expressible as a DNR urlFilter).
    """
    rule, reason = b.build_dnr_rule(1, r"/ad##banner\$x/", is_allow=False)
    assert rule is None
    assert reason == "unsupported: regex network pattern"


def test_empty_pattern_is_rejected():
    rule, reason = b.build_dnr_rule(1, "$script", is_allow=False)
    assert rule is None
    assert reason == "unsupported: empty network pattern"


def test_wildcard_tld_domain_option_is_kept():
    """domain=example.* is a valid initiator domain and must survive into the condition."""
    rule, reason = b.build_dnr_rule(1, "||w.com^$domain=example.*", is_allow=False)
    assert reason is None
    assert rule["condition"]["initiatorDomains"] == ["example.*"]


# ---------------------------------------------------------------------------
# Preprocessor audit assertions
# ---------------------------------------------------------------------------

def test_nested_if_blocks_gate_correctly():
    """
    Nested !#if: the inner block only keeps when both conditions hold. The outer-true /
    inner-false rule is dropped; the outer-true / inner-true rule is kept.
    """
    text = (
        "!#if (ext_chromium_mv3)\n"
        "||outer.com^\n"
        "!#if (adguard_ext_firefox)\n"
        "||inner-ff.com^\n"
        "!#endif\n"
        "||outer2.com^\n"
        "!#endif\n"
    )
    res = b.convert(text)
    urls = {r["condition"]["urlFilter"] for r in res["network_rules_dnr"]}
    assert "||outer.com^" in urls
    assert "||outer2.com^" in urls
    assert "||inner-ff.com^" not in urls
    assert res["preprocessor_audit"]["unclosed_if"] == 0


def test_else_flips_the_active_branch():
    """!#else inverts a false condition so the else-branch rule is kept."""
    text = (
        "!#if (adguard_ext_firefox)\n"
        "||ff-only.com^\n"
        "!#else\n"
        "||not-ff.com^\n"
        "!#endif\n"
    )
    res = b.convert(text)
    urls = {r["condition"]["urlFilter"] for r in res["network_rules_dnr"]}
    assert "||ff-only.com^" not in urls
    assert "||not-ff.com^" in urls


def test_unknown_flag_recorded_and_defaults_false():
    res = b.convert("!#if (made_up_platform)\n||x.com^\n!#endif\n")
    exprs = {e["expr"]: e for e in res["preprocessor_audit"]["if_expressions"]}
    assert exprs["made_up_platform"]["result"] is False
    assert exprs["made_up_platform"]["unknown_flags"] == ["made_up_platform"]


def test_leading_negation_of_false_flag_evaluates_true():
    res = b.convert("!#if (!ext_ublock)\n||chromium.com^\n!#endif\n")
    assert [r["condition"]["urlFilter"] for r in res["network_rules_dnr"]] == [
        "||chromium.com^"
    ]
    expr = res["preprocessor_audit"]["if_expressions"][0]
    assert expr == {"expr": "!ext_ublock", "result": True, "unknown_flags": []}


def test_informational_hint_does_not_gate_next_rule():
    """A !+ NOT_OPTIMIZED hint carries no PLATFORM clause; it must not gate the next rule."""
    res = b.convert("!+ NOT_OPTIMIZED\n||kept.com^\n")
    urls = {r["condition"]["urlFilter"] for r in res["network_rules_dnr"]}
    assert "||kept.com^" in urls
    hints = {h["hint"]: h for h in res["preprocessor_audit"]["plus_hints"]}
    assert hints["NOT_OPTIMIZED"]["informational"] is True
    assert hints["NOT_OPTIMIZED"]["result"] is None


def test_platform_hint_gates_only_the_next_rule():
    """!+ NOT_PLATFORM(ext_ff) keeps the next rule on Chromium; the rule after is unaffected."""
    res = b.convert("!+ NOT_PLATFORM(ext_ff)\n||gated.com^\n||after.com^\n")
    urls = {r["condition"]["urlFilter"] for r in res["network_rules_dnr"]}
    assert "||gated.com^" in urls
    assert "||after.com^" in urls
    hints = {h["hint"]: h for h in res["preprocessor_audit"]["plus_hints"]}
    assert hints["NOT_PLATFORM(ext_ff)"]["informational"] is False
    assert hints["NOT_PLATFORM(ext_ff)"]["result"] is True


def test_include_and_safari_affinity_are_ignored_and_recorded():
    text = (
        "!#include /foo/bar.txt\n"
        "!#safari_cb_affinity(general)\n"
        "||kept.com^\n"
    )
    res = b.convert(text)
    ignored = res["preprocessor_audit"]["ignored_directives"]
    assert any(d.startswith("!#include") for d in ignored)
    assert any(d.startswith("!#safari_cb_affinity") for d in ignored)
    urls = {r["condition"]["urlFilter"] for r in res["network_rules_dnr"]}
    assert "||kept.com^" in urls


def test_unmatched_endif_and_else_are_counted():
    res = b.convert("!#endif\n!#else\n")
    audit = res["preprocessor_audit"]
    assert audit["unmatched_endif"] == 1
    assert audit["unmatched_else"] == 1


# ---------------------------------------------------------------------------
# Provenance (fixture bytes)
# ---------------------------------------------------------------------------

def test_sources_are_ordered_and_carry_exact_sha256(fixture_bytes, converted):
    fetched = "2026-01-01T00:00:00Z"
    pa = b.Provenance.record(
        "antiadblock", "BaseFilter/sections/antiadblock.txt",
        fixture_bytes["antiadblock"], "http://local/aa", None, fetched)
    ps = b.Provenance.record(
        "specific", "BaseFilter/sections/specific.txt",
        fixture_bytes["specific"], "http://local/sp", None, fetched)

    manifest = b.build_manifest(converted, [pa, ps], fetched)

    # Ordered sources[] matches the authoritative source order.
    assert [s["name"] for s in manifest["sources"]] == ["antiadblock", "specific"]

    # Exact sha256 of the fixture bytes, per source.
    assert manifest["sources"][0]["upstream_sha256"] == _sha256_hex(fixture_bytes["antiadblock"])
    assert manifest["sources"][1]["upstream_sha256"] == _sha256_hex(fixture_bytes["specific"])

    # Legacy top-level provenance describes the antiadblock source only.
    assert manifest["source"] == "AdguardTeam/AdguardFilters/BaseFilter/sections/antiadblock.txt"
    assert manifest["upstream_sha256"] == _sha256_hex(fixture_bytes["antiadblock"])
    assert manifest["fetched_at"] == fetched


def test_notice_lists_each_source_path_and_hash(fixture_bytes):
    fetched = "2026-01-01T00:00:00Z"
    pa = b.Provenance.record(
        "antiadblock", "BaseFilter/sections/antiadblock.txt",
        fixture_bytes["antiadblock"], "http://local/aa", None, fetched)
    ps = b.Provenance.record(
        "specific", "BaseFilter/sections/specific.txt",
        fixture_bytes["specific"], "http://local/sp", None, fetched)

    notice = b.render_notice([pa, ps], fetched)

    assert "BaseFilter/sections/antiadblock.txt" in notice
    assert "BaseFilter/sections/specific.txt" in notice
    assert _sha256_hex(fixture_bytes["antiadblock"]) in notice
    assert _sha256_hex(fixture_bytes["specific"]) in notice
    # antiadblock block appears before the specific block (source order).
    assert notice.index("antiadblock.txt in this release") < \
        notice.index("specific.txt in this release")
    assert notice.rstrip().endswith("Do not edit by hand.")


# ---------------------------------------------------------------------------
# CLI: repeatable --input-file, byte-preserving writes, no download
# ---------------------------------------------------------------------------

def test_cli_writes_raw_bytes_verbatim_without_downloading(tmp_path, monkeypatch, fixture_bytes):
    """
    Running main() with a local --input-file override for every source must:
      * never call download() or resolve_upstream_commit(),
      * write each source's raw bytes verbatim (byte-for-byte),
      * write the manifest and NOTICE.
    """
    # Redirect every output path into tmp_path.
    out_dir = tmp_path / "antiadblock"
    monkeypatch.setattr(b, "OUTPUT_DIR", out_dir)
    monkeypatch.setattr(b, "MANIFEST_PATH", out_dir / "antiadblock.json")
    monkeypatch.setattr(b, "NOTICE_PATH", out_dir / "NOTICE")
    monkeypatch.setattr(b, "raw_path_for", lambda name: out_dir / f"{name}.txt")

    # Any network access is a test failure.
    def _boom(*args, **kwargs):  # pragma: no cover - must never run
        raise AssertionError("network access attempted during local --input-file build")

    monkeypatch.setattr(b, "download", _boom)
    monkeypatch.setattr(b, "resolve_upstream_commit", _boom)

    rc = b.main([
        f"--input-file=antiadblock={ANTIADBLOCK_FIXTURE}",
        f"--input-file=specific={SPECIFIC_FIXTURE}",
    ])
    assert rc == 0

    # Raw bytes written verbatim.
    assert (out_dir / "antiadblock.txt").read_bytes() == fixture_bytes["antiadblock"]
    assert (out_dir / "specific.txt").read_bytes() == fixture_bytes["specific"]

    # Manifest + NOTICE written and internally consistent.
    manifest = json.loads((out_dir / "antiadblock.json").read_text())
    assert [s["name"] for s in manifest["sources"]] == ["antiadblock", "specific"]
    assert manifest["sources"][0]["upstream_sha256"] == _sha256_hex(fixture_bytes["antiadblock"])
    notice = (out_dir / "NOTICE").read_text()
    assert _sha256_hex(fixture_bytes["specific"]) in notice


# ---------------------------------------------------------------------------
# acquire_source: commit resolution before pinned download
# ---------------------------------------------------------------------------

def test_acquire_source_resolves_commit_before_pinned_download(monkeypatch):
    """
    With no local override and no url override, acquire_source must resolve the path-specific
    upstream commit *first*, then download the sha-pinned raw URL. The recorded provenance
    pins that commit and the resolved url contains the sha.
    """
    calls = []

    def fake_resolve(path):
        calls.append(("resolve", path))
        return "deadbeefcafe"

    def fake_download(url):
        calls.append(("download", url))
        return b"raw-bytes"

    monkeypatch.setattr(b, "resolve_upstream_commit", fake_resolve)
    monkeypatch.setattr(b, "download", fake_download)

    path = "BaseFilter/sections/specific.txt"
    raw, prov = b.acquire_source("specific", path, None, None, "2026-01-01T00:00:00Z")

    # Resolution strictly precedes the download.
    assert [c[0] for c in calls] == ["resolve", "download"]
    assert calls[0] == ("resolve", path)
    # The downloaded URL is pinned to the resolved sha.
    assert "deadbeefcafe" in calls[1][1]
    assert path in calls[1][1]

    assert raw == b"raw-bytes"
    assert prov.upstream_commit == "deadbeefcafe"
    assert prov.upstream_sha256 == _sha256_hex(b"raw-bytes")


# ---------------------------------------------------------------------------
# Single-source migration regression against the pre-refactor artifact
# ---------------------------------------------------------------------------
#
# This freezes the migration from the single-source converter to the multi-source one. The
# baseline is the PRE-REFACTOR artifact as it exists on origin/main (local `main` is the
# fallback when the remote ref is not fetched): single-source, no sources[], no
# counts_by_source, no per-rule `source` tag, and no preprocessor_audit. Both the raw
# antiadblock.txt and the antiadblock.json manifest are read from that ref with `git show`,
# not from the working tree, because a real daily build regenerates the working-tree artifacts
# and would otherwise move these numbers out from under the test.
#
# Running the CURRENT converter over the origin/main raw antiadblock.txt (as a lone source)
# produces a different, known-good output. The deltas below are INTENTIONAL and are the point
# of the migration (pre -> cur):
#
#   network           344 -> 329   (-15)
#   network_exception 1245 -> 1080 (-165)
#   cosmetic_hide     610 -> 613   (+3)
#   cosmetic_exception 449 -> 450  (+1)
#   cosmetic_extended  11 -> 11    (0)
#   css_inject        457 -> 454   (-3)
#   scriptlet        1855 -> 1859  (+4)
#   skipped          2524 -> 2694  (+170)
#
# DNR list size: 1589 -> 1409.
#
# Two forces drive these deltas in opposite directions. Parser safety and dedupe REMOVE rules:
# stricter option parsing rejects unsupported/negated/regex/empty patterns into skipped, and
# exact (action, condition) DNR duplicates and identical logical scriptlets now collapse. At
# the same time, corrected leading-negation gating (e.g. `!#if (!ext_ublock)` evaluating true
# on Chromium) ADDS Chromium-applicable branches that the pre-refactor converter dropped. The
# net per-category sign depends on which force dominates that category.
#
# Once the migration lands on main, the base manifest itself carries sources[]. From that point
# the pre-refactor baseline no longer exists, so these migration-only assertions skip rather
# than fail every future PR forever.
#
# This test freezes the CURRENT normalized output (hashes + counts) so any future converter
# change that moves these numbers is caught and must be explained.

CUR_COUNTS = {
    "network": 329,
    "network_exception": 1080,
    "cosmetic_hide": 613,
    "cosmetic_exception": 450,
    "cosmetic_extended": 11,
    "css_inject": 454,
    "scriptlet": 1859,
    "skipped": 2694,
}
CUR_DNR_LEN = 1409
CUR_DNR_HASH = "99d07e1c81cc22090fe3bbc1057505308f4cd09c30b34a52ccb7cfd31ec214ee"
CUR_SCRIPTLET_LEN = 1859
CUR_SCRIPTLET_HASH = "07bb227556e75cb932604c852b7217b0ef2d31f6a84a620e5c204759f5a03629"
CUR_COSMETIC_HIDE_HASH = "a4a3002f227f80fa4323885af414be9635de917d44e4b8694f442f6967b38047"

# Pre-refactor artifact counts, asserted so the documented delta is not merely a comment.
PRE_REFACTOR_COUNTS = {
    "network": 344,
    "network_exception": 1245,
    "cosmetic_hide": 610,
    "cosmetic_exception": 449,
    "cosmetic_extended": 11,
    "css_inject": 457,
    "scriptlet": 1855,
    "skipped": 2524,
}
PRE_REFACTOR_DNR_LEN = 1589

# The pre-refactor baseline lives on origin/main; local main is the fallback when the remote
# tracking ref is not present (e.g. a shallow checkout without fetch-depth: 0).
_BASE_REFS = ("origin/main", "main")


def _git_show_bytes(ref: str, path: str) -> bytes:
    """Return `git show <ref>:<path>` bytes, or raise CalledProcessError. No shell."""
    return subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        cwd=str(REPO_ROOT),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout


def _base_blob(path: str):
    """
    Read `path` from the first available pre-refactor base ref.

    Returns (ref, bytes). Skips the whole migration-regression suite when neither
    origin/main nor main can be read.
    """
    last_err = None
    for ref in _BASE_REFS:
        try:
            return ref, _git_show_bytes(ref, path)
        except subprocess.CalledProcessError as exc:  # ref/path not available
            last_err = exc
    pytest.skip(
        "pre-refactor base ref unavailable (need origin/main or main with the "
        f"artifacts committed): {last_err}"
    )


@pytest.fixture(scope="module")
def base_manifest():
    """The pre-refactor manifest JSON read from the base ref (origin/main, then main)."""
    _ref, data = _base_blob("antiadblock/antiadblock.json")
    return json.loads(data.decode("utf-8"))


@pytest.fixture(scope="module")
def base_is_premigration(base_manifest):
    """
    True when the base manifest predates the multi-source migration.

    After the migration lands on main, the base manifest carries sources[]; the migration-only
    regression assertions then skip so post-migration PRs do not fail against a moved baseline.
    """
    return not base_manifest.get("sources")


@pytest.fixture(scope="module")
def normalized_single_source():
    """
    Current-converter output over the pre-refactor raw antiadblock.txt from the base ref.

    Returns (merged, dnr, scr). The raw bytes come from origin/main (local main fallback), not
    the working tree, so a fresh daily build cannot move these numbers.
    """
    _ref, raw_bytes = _base_blob("antiadblock/antiadblock.txt")
    raw = raw_bytes.decode("utf-8")
    merged = b.merge_sources([("antiadblock", b.convert(raw))])
    dnr = [
        {"priority": r["priority"], "action": r["action"], "condition": r["condition"]}
        for r in merged["network_rules_dnr"]
    ]
    scr = [{k: v for k, v in s.items() if k != "source"} for s in merged["scriptlets"]]
    return merged, dnr, scr


def test_single_source_regression_counts(base_is_premigration, normalized_single_source):
    if not base_is_premigration:
        pytest.skip("base manifest already has sources[]; migration regression retired")
    merged, _, _ = normalized_single_source
    assert merged["counts"] == CUR_COUNTS


def test_single_source_regression_normalized_hashes(base_is_premigration, normalized_single_source):
    if not base_is_premigration:
        pytest.skip("base manifest already has sources[]; migration regression retired")
    merged, dnr, scr = normalized_single_source
    assert len(dnr) == CUR_DNR_LEN
    assert _stable_hash(dnr) == CUR_DNR_HASH
    assert len(scr) == CUR_SCRIPTLET_LEN
    assert _stable_hash(scr) == CUR_SCRIPTLET_HASH
    assert _stable_hash(merged["cosmetic"]["hide"]) == CUR_COSMETIC_HIDE_HASH


def test_pre_refactor_artifact_counts_are_the_documented_baseline(
    base_is_premigration, base_manifest
):
    """Pin the pre-refactor artifact's own counts so the documented deltas stay verifiable."""
    if not base_is_premigration:
        pytest.skip("base manifest already has sources[]; migration regression retired")
    assert base_manifest["counts"] == PRE_REFACTOR_COUNTS
    assert len(base_manifest["network_rules_dnr"]) == PRE_REFACTOR_DNR_LEN
    # The pre-refactor artifact is single-source: no multi-source provenance machinery.
    assert base_manifest.get("sources", []) == []
    assert "counts_by_source" not in base_manifest


def test_regression_deltas_match_documentation():
    """The current-vs-pre deltas equal exactly what the module comment documents."""
    expected = {
        "network": -15,
        "network_exception": -165,
        "cosmetic_hide": +3,
        "cosmetic_exception": +1,
        "cosmetic_extended": 0,
        "css_inject": -3,
        "scriptlet": +4,
        "skipped": +170,
    }
    assert set(expected) == set(CUR_COUNTS) == set(PRE_REFACTOR_COUNTS)
    for key, delta in expected.items():
        assert CUR_COUNTS[key] - PRE_REFACTOR_COUNTS[key] == delta
    # DNR list size shrinks from the pre-refactor artifact to the current converter.
    assert (PRE_REFACTOR_DNR_LEN, CUR_DNR_LEN) == (1589, 1409)

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import build_antiadblock as bab  # noqa: E402

SPECIFIC_HEADER = "! START: Ad-Shield ad reinsertion\n"
SPECIFIC_FOOTER = "! END: Ad-Shield ad reinsertion\n"


def convert(antiadblock: str = "", specific: str = "") -> bab.Outputs:
    return bab.convert({
        "antiadblock.txt": antiadblock,
        "specific.txt": SPECIFIC_HEADER + specific + SPECIFIC_FOOTER,
    })


def only_dnr(rule: str) -> dict:
    outputs = convert(rule + "\n")
    assert outputs.skipped == []
    assert len(outputs.dnr) == 1
    return outputs.dnr[0]


def skip_reason(rule: str) -> str:
    outputs = convert(rule + "\n")
    assert outputs.dnr == [] and outputs.heuristics == []
    assert len(outputs.skipped) == 1
    return outputs.skipped[0]["reason"]


class TestNetworkRules:
    def test_block_rule_with_domains_and_type(self):
        assert only_dnr("||html-load.com^$script,domain=watchuseek.com|~forums.watchuseek.com") == {
            "id": 1,
            "priority": 100,
            "action": {"type": "block"},
            "condition": {
                "urlFilter": "||html-load.com^",
                "resourceTypes": ["script"],
                "initiatorDomains": ["watchuseek.com"],
                "excludedInitiatorDomains": ["forums.watchuseek.com"],
            },
        }

    def test_exception_becomes_allow_rule_above_browser_guard_ads(self):
        assert only_dnr("@@||example.com/ads.js$xhr,third-party,domain=site.com") == {
            "id": 1,
            "priority": 110,
            "action": {"type": "allow"},
            "condition": {
                "urlFilter": "||example.com/ads.js",
                "resourceTypes": ["xmlhttprequest"],
                "domainType": "thirdParty",
                "initiatorDomains": ["site.com"],
            },
        }

    @pytest.mark.parametrize("rule", [
        "@@||example.com/ads.js",
        "@@||cdn.example/fuckadblock.js$script",
        "@@/advertisement.js$~third-party",
        "@@||example.com/ads.js$domain=~site.com",
    ])
    def test_exceptions_without_domain_are_skipped(self, rule):
        assert skip_reason(rule) == "exception without $domain"

    def test_unscoped_block_rules_are_kept(self):
        assert only_dnr("||adblock-detector.example^$script")["action"] == {"type": "block"}

    def test_important_negated_types_match_case_denyallow(self):
        assert only_dnr("/adblock.$~image,~css,important,match-case,denyallow=a.com,domain=b.com") == {
            "id": 1,
            "priority": 105,
            "action": {"type": "block"},
            "condition": {
                "urlFilter": "/adblock.",
                "excludedResourceTypes": ["image", "stylesheet"],
                "isUrlFilterCaseSensitive": True,
                "excludedRequestDomains": ["a.com"],
                "initiatorDomains": ["b.com"],
            },
        }

    def test_wildcard_domains_are_dropped_but_concrete_ones_kept(self):
        rule = only_dnr("||ads.example^$domain=site.*|site.com")
        assert rule["condition"]["initiatorDomains"] == ["site.com"]

    def test_non_ascii_domain_is_punycoded(self):
        rule = only_dnr("||example.com/x.js$domain=bücher.de")
        assert rule["condition"]["initiatorDomains"] == ["xn--bcher-kva.de"]

    @pytest.mark.parametrize("rule, reason", [
        ("||example.com^$redirect=noopjs", "unsupported option $redirect"),
        ("||example.com^$domain=site.*", "only wildcard or invalid domains"),
        ("||example.com^$domain=a.com|~b.*", "wildcard or invalid excluded domain"),
        ("/ads\\d+\\.js/$script", "regex pattern"),
        ("$script,third-party", "pattern matches every request"),
        ("||example.com^$popup", "unsupported option $popup"),
        ("||example.com^$frobnicate", "unknown option $frobnicate"),
        ("@@||example.com^$generichide", "unsupported option $generichide"),
        ("||example.com^$replace=/a$b/c/", "unsupported option $replace"),
    ])
    def test_unsupported_rules_are_skipped_with_reason(self, rule, reason):
        assert skip_reason(rule) == reason

    def test_badfilter_disables_its_target(self):
        outputs = convert("||a.com^$script\n||a.com^$script,badfilter\n||b.com^\n")
        assert [r["condition"]["urlFilter"] for r in outputs.dnr] == ["||b.com^"]
        assert sorted(e["reason"] for e in outputs.skipped) == ["badfilter", "disabled by $badfilter"]

    def test_duplicates_collapse_and_ids_are_sequential(self):
        outputs = convert("||a.com^\n||a.com^\n||b.com^\n")
        assert [(r["id"], r["condition"]["urlFilter"]) for r in outputs.dnr] == [
            (1, "||a.com^"), (2, "||b.com^"),
        ]


class TestCosmeticRules:
    def test_plain_hide_and_exclusion(self):
        outputs = convert("a.com,~sub.a.com##.adblock-wall\n")
        assert bab.cosmetic_document(outputs) == {
            "specific_hide": {"a.com": [".adblock-wall"]},
            "extended_hide": {},
            "exception_rules": {"sub.a.com": [".adblock-wall"]},
        }

    def test_exception_rule(self):
        outputs = convert("a.com,b.com#@#.ad-banner\n")
        assert bab.cosmetic_document(outputs)["exception_rules"] == {
            "a.com": [".ad-banner"], "b.com": [".ad-banner"],
        }

    def test_extended_selectors_are_rewritten_and_escaped_for_the_procedural_tier(self):
        outputs = convert("a.com#?#div:has-text(Please disable (your) adblock.)\n"
                          "a.com##div:-abp-contains(/adblock/i)\n")
        assert bab.cosmetic_document(outputs)["extended_hide"] == {
            "a.com": [
                r"div:contains(/adblock/i)",
                r"div:contains(Please disable \(your\) adblock\.)",
            ],
        }

    def test_native_has_stays_in_the_stylesheet_tier(self):
        outputs = convert("a.com#?#.modal:has(> .adblock)\n")
        assert bab.cosmetic_document(outputs)["specific_hide"] == {"a.com": [".modal:has(> .adblock)"]}

    def test_css_injection_display_none_is_a_hide(self):
        outputs = convert("a.com#$#.overlay { display: none !important; }\n")
        assert bab.cosmetic_document(outputs)["specific_hide"] == {"a.com": [".overlay"]}

    def test_remove_rules_become_heuristics(self):
        outputs = convert("a.com,~x.a.com#$#.overlay { remove: true; }\nb.org##.wall:remove()\n")
        assert bab.heuristics_document(outputs) == [
            {
                "id": 90000000,
                "r": r"^https?://(?!([^/]+[.])?(x[.]a[.]com)([:/?]|$))([^/]+[.])?(a[.]com)([:/?]|$)##.overlay:remove()",
                "s": False, "t": "adserver", "a": False,
            },
            {
                "id": 90000001,
                "r": r"^https?://([^/]+[.])?(b[.]org)([:/?]|$)##.wall:remove()",
                "s": False, "t": "adserver", "a": False,
            },
        ]

    @pytest.mark.parametrize("rule, reason", [
        ("a.com#%#window.adblock = false;", "JavaScript injection"),
        ("a.com$$script:contains(html-load.com)", "HTML filtering"),
        ("a.com#$#body { overflow: auto !important; }", "CSS injection"),
        ("##.adblock-notice", "generic cosmetic rule"),
        ("~a.com##.adblock-notice", "generic cosmetic rule"),
        ("a.*##.adblock-notice", "only wildcard or invalid domains"),
        ("a.com##div:upward(2)", "unsupported pseudo-class :upward()"),
        ("a.com##div:style(display: none)", "CSS injection"),
        ("[$path=/x]a.com##.wall", "cosmetic rule modifiers"),
        ("a.com#@$#.x { color: red; }", "CSS injection exception"),
    ])
    def test_unsupported_rules_are_skipped_with_reason(self, rule, reason):
        assert skip_reason(rule) == reason


class TestScriptlets:
    def test_supported_scriptlets_are_indexed_by_host(self):
        outputs = convert(
            "a.com,b.com#%#//scriptlet('set-constant', 'adblock', 'false')\n"
            "c.com,~x.c.com#%#//scriptlet(\"prevent-xhr\", \"/pagead2\\.googlesyndication\\.com/\")\n"
            "d.com#%#//scriptlet('set-constant', 'adblock', 'false', '', '')\n"
        )
        assert bab.scriptlets_document(outputs) == {
            "scriptlets": [
                {"name": "prevent-xhr", "args": [r"/pagead2\.googlesyndication\.com/"]},
                {"name": "set-constant", "args": ["adblock", "false"]},
            ],
            "hosts": {"a.com": [1], "b.com": [1], "c.com": [0], "d.com": [1]},
            "excluded": {"x.c.com": [0]},
        }
        assert outputs.skipped == []

    def test_exceptions_exclude_hosts(self):
        outputs = convert(
            "a.com#%#//scriptlet('set-cookie', '__adblocker', 'false')\n"
            "sub.a.com#@%#//scriptlet('set-cookie', '__adblocker', 'false')\n"
            "a.com#%#//scriptlet('remove-attr', 'onerror', 'script[id]')\n"
            "other.a.com#@%#//scriptlet()\n"
        )
        assert bab.scriptlets_document(outputs) == {
            "scriptlets": [
                {"name": "remove-attr", "args": ["onerror", "script[id]"]},
                {"name": "set-cookie", "args": ["__adblocker", "false"]},
            ],
            "hosts": {"a.com": [0, 1]},
            "excluded": {"other.a.com": [0, 1], "sub.a.com": [1]},
        }

    def test_abort_on_stack_trace_is_converted(self):
        outputs = convert(
            "indiatimes.com#%#//scriptlet('abort-on-stack-trace', 'document.getElementById', 'onerror')\n"
        )
        assert bab.scriptlets_document(outputs) == {
            "scriptlets": [{"name": "abort-on-stack-trace", "args": ["document.getElementById", "onerror"]}],
            "hosts": {"indiatimes.com": [0]},
            "excluded": {},
        }

    def test_quote_escapes_are_unescaped_and_regex_escapes_kept(self):
        outputs = convert(r"a.com#%#//scriptlet('remove-node-text', '#text', 'it\'s /a\.b/')" + "\n")
        assert bab.scriptlets_document(outputs)["scriptlets"] == [
            {"name": "remove-node-text", "args": ["#text", r"it's /a\.b/"]},
        ]

    def test_specific_txt_scriptlets_are_converted(self):
        outputs = convert(specific="a.com#%#//scriptlet('remove-node-text', 'script', 'html-load.com')\n")
        assert outputs.scriptlets == {("remove-node-text", ("script", "html-load.com")): {"a.com"}}
        assert outputs.skipped == []

    @pytest.mark.parametrize("rule, reason", [
        ("a.com#%#//scriptlet('trusted-set-constant', 'a', '1')", "trusted scriptlet"),
        ("a.com#%#//scriptlet('json-prune', 'ads')", "unsupported scriptlet json-prune"),
        ("a.com#%#//scriptlet('set-constant' 'a')", "invalid scriptlet arguments"),
        ("#%#//scriptlet('set-constant', 'a', 'false')", "generic cosmetic rule"),
        ("a.com#%#window.x = 1;", "JavaScript injection"),
    ])
    def test_unsupported_scriptlets_are_skipped_with_reason(self, rule, reason):
        assert skip_reason(rule) == reason


class TestPreprocessor:
    def test_if_else_endif_and_nesting(self):
        outputs = convert(
            "!#if (adguard_ext_chromium_mv3 && !adguard_ext_safari)\n"
            "||kept-1.com^\n"
            "!#if adguard_app_ios\n"
            "||ios.com^\n"
            "!#else\n"
            "||kept-2.com^\n"
            "!#endif\n"
            "!#else\n"
            "||not-chromium.com^\n"
            "!#endif\n"
        )
        assert [r["condition"]["urlFilter"] for r in outputs.dnr] == ["||kept-1.com^", "||kept-2.com^"]
        assert outputs.out_of_scope == {"antiadblock.txt": 2}

    def test_platform_hints_apply_to_the_next_rule_only(self):
        outputs = convert(
            "!+ PLATFORM(ios, ext_safari)\n||safari.com^\n"
            "!+ NOT_PLATFORM(ext_chromium)\n||not-chrome.com^\n"
            "!+ NOT_OPTIMIZED PLATFORM(ext_chromium)\n||chrome.com^\n"
            "||plain.com^\n"
        )
        assert [r["condition"]["urlFilter"] for r in outputs.dnr] == ["||chrome.com^", "||plain.com^"]

    def test_unclosed_if_fails_the_build(self):
        with pytest.raises(ValueError, match="unclosed"):
            convert("!#if adguard\n||a.com^\n")


class TestSpecificSections:
    def test_only_listed_sections_of_specific_txt_are_used(self):
        outputs = bab.convert({
            "antiadblock.txt": "",
            "specific.txt": "||outside.com^\n" + SPECIFIC_HEADER + "||inside.com^\n"
                            + SPECIFIC_FOOTER + "||after.com^\n",
        })
        assert [r["condition"]["urlFilter"] for r in outputs.dnr] == ["||inside.com^"]

    def test_missing_section_fails_the_build(self):
        with pytest.raises(ValueError, match="Ad-Shield ad reinsertion"):
            bab.convert({"antiadblock.txt": "", "specific.txt": "||a.com^\n"})


FIXTURES = Path(__file__).parent / "fixtures"


class TestBuild:
    def test_writes_every_artifact_and_covers_the_target_sites(self, tmp_path):
        texts = {name: (FIXTURES / name).read_bytes() for name in ("antiadblock.txt", "specific.txt")}
        summary = bab.build(tmp_path, texts, "0" * 40)

        assert sorted(p.name for p in tmp_path.iterdir()) == sorted([
            "antiadblock.txt", "specific.txt", "NOTICE", "build.json", "skipped.json",
            "mbgc.mv3.antiadblock_1.json", "mbgc.db.antiadblock.cosmetic.json",
            "mbgc.db.antiadblock.heuristics.json", "mbgc.db.antiadblock.scriptlets.json",
        ])
        assert (tmp_path / "specific.txt").read_bytes() == texts["specific.txt"]

        dnr = json.loads((tmp_path / "mbgc.mv3.antiadblock_1.json").read_text())
        html_load = [r for r in dnr if r["condition"].get("urlFilter") == "||html-load.com^"]
        covered = {d for r in html_load for d in r["condition"]["initiatorDomains"]}
        assert {"watchuseek.com", "archerytalk.com", "worldjournal.com"} <= covered
        assert all(r["action"] == {"type": "block"} for r in html_load)
        assert all(r["condition"]["resourceTypes"] == ["script"] for r in html_load)

        assert summary["upstream_commit"] == "0" * 40
        assert summary["counts"]["dnr_block"] == sum(r["action"]["type"] == "block" for r in dnr)

    def test_database_files_are_ascii_so_the_extension_decodes_them_intact(self, tmp_path):
        texts = {"antiadblock.txt": "b\u00fccher.de##.\u0440\u0435\u043a\u043b\u0430\u043c\u0430\n".encode(),
                 "specific.txt": (SPECIFIC_HEADER + SPECIFIC_FOOTER).encode()}
        bab.build(tmp_path, texts, "c")
        raw = (tmp_path / "mbgc.db.antiadblock.cosmetic.json").read_bytes()
        assert raw.isascii()
        assert json.loads(raw)["specific_hide"] == {"xn--bcher-kva.de": [".\u0440\u0435\u043a\u043b\u0430\u043c\u0430"]}

    def test_output_is_deterministic(self, tmp_path):
        texts = {name: (FIXTURES / name).read_bytes() for name in ("antiadblock.txt", "specific.txt")}
        bab.build(tmp_path / "a", texts, "c")
        bab.build(tmp_path / "b", texts, "c")
        for name in ("mbgc.mv3.antiadblock_1.json", "mbgc.db.antiadblock.cosmetic.json",
                     "mbgc.db.antiadblock.heuristics.json", "mbgc.db.antiadblock.scriptlets.json",
                     "skipped.json", "NOTICE"):
            assert (tmp_path / "a" / name).read_bytes() == (tmp_path / "b" / name).read_bytes()

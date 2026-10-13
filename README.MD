# Malwarebytes Browser Guard Community Databases

Our version of popular open source databases.

## Store Listings

- [Chrome Web Store](https://chromewebstore.google.com/detail/malwarebytes-browser-guar/ihcjicgdanjaechkgeegckofjjedodee?hl=en)
- [Chrome Web Store (Beta)](https://chromewebstore.google.com/detail/malwarebytes-browser-guar/bdnmbmckbekibamnoenjkgmllboffdca?hl=en)
- [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/malwarebytes/)
- [Microsoft Edge Add-ons](https://microsoftedge.microsoft.com/addons/detail/malwarebytes-browser-guar/bojobppfploabceghnmlahpoonbcbacn)

## Databases

### Anti-adblock

Browser Guard's anti-adblock databases, built from two AdGuard filter lists in [AdguardTeam/AdguardFilters](https://github.com/AdguardTeam/AdguardFilters/tree/master/BaseFilter/sections):

- `antiadblock.txt`: every rule.
- `specific.txt`: only the sections listed in `SPECIFIC_SECTIONS` in `scripts/build_antiadblock.py`. The build fails if a listed section disappears upstream.

Both files are fetched at the same pinned upstream commit. `!#if` blocks and `!+ PLATFORM` hints are evaluated for Chromium MV3. The converter writes these files, which the extension loads without further processing:

| File | Contents |
| --- | --- |
| `mbgc.mv3.antiadblock_1.json` | Static DNR ruleset. Block rules have priority 100 (105 with `$important`). Allow rules have priority 110. |
| `mbgc.db.antiadblock.cosmetic.json` | `specific_hide`, `extended_hide` and `exception_rules` maps (host to selectors), merged into the easylist cosmetic database |
| `mbgc.db.antiadblock.heuristics.json` | Heuristic rules (`{id, r, s, t, a}`, ids from 90000000) for element removal |
| `mbgc.db.antiadblock.scriptlets.json` | Scriptlet calls (`scriptlets[]`) and host indexes into them (`hosts`, `excluded`). Only scriptlets in `SUPPORTED_SCRIPTLETS` are included, and only from sources with `scriptlets=True` |
| `skipped.json` | Every rule that was not converted, with the reason |
| `build.json` | Upstream commit, source hashes and counts |
| `antiadblock.txt`, `specific.txt`, `NOTICE` | Unmodified upstream files and their GPL-3.0 attribution |

The converter skips rules the extension cannot run and records each one in `skipped.json`. These include unsupported and `trusted-*` scriptlets, inline JS, `$$` HTML filtering, `$replace`, `$redirect`, regex network patterns, generic cosmetic rules, wildcard-TLD domains, and CSS injections that do anything other than hide or remove an element.

To build locally:

```sh
pip install -r requirements-dev.txt
python -m pytest -q
python scripts/build_antiadblock.py                 # writes build/antiadblock/
python scripts/build_antiadblock.py --input-dir DIR # use local antiadblock.txt/specific.txt
```

#### Releases

`.github/workflows/release-antiadblock.yml` runs daily at 06:00 UTC, on manual dispatch, and when the converter changes on `main`. It tests, builds and compares the database files against the latest release's `checksums.txt`. If any of them changed, it publishes a release tagged `antiadblock-YYYY.MM.DD-HHMM`. Nothing is committed to the repository.

When the repository is public, these URLs resolve to the newest release:

- https://github.com/Malwarebytes/Browser-Guard-Community-Databases/releases/latest/download/mbgc.mv3.antiadblock_1.json
- https://github.com/Malwarebytes/Browser-Guard-Community-Databases/releases/latest/download/mbgc.db.antiadblock.cosmetic.json
- https://github.com/Malwarebytes/Browser-Guard-Community-Databases/releases/latest/download/mbgc.db.antiadblock.heuristics.json
- https://github.com/Malwarebytes/Browser-Guard-Community-Databases/releases/latest/download/mbgc.db.antiadblock.scriptlets.json
- https://github.com/Malwarebytes/Browser-Guard-Community-Databases/releases/latest/download/checksums.txt

## Important Note

This repository is provided as-is and isn't bound to Malwarebytes' SLA.

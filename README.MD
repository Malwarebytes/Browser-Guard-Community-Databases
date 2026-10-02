# Malwarebytes Browser Guard Community Databases

Our version of popular open source databases.

## Store Listings

- [Chrome Web Store](https://chromewebstore.google.com/detail/malwarebytes-browser-guar/ihcjicgdanjaechkgeegckofjjedodee?hl=en)
- [Chrome Web Store (Beta)](https://chromewebstore.google.com/detail/malwarebytes-browser-guar/bdnmbmckbekibamnoenjkgmllboffdca?hl=en)
- [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/malwarebytes/)
- [Microsoft Edge Add-ons](https://microsoftedge.microsoft.com/addons/detail/malwarebytes-browser-guar/bojobppfploabceghnmlahpoonbcbacn)

## Databases

### `antiadblock/`

A daily rebuild of two AdGuard filter sections, [antiadblock.txt](https://github.com/AdguardTeam/AdguardFilters/blob/master/BaseFilter/sections/antiadblock.txt) and [specific.txt](https://github.com/AdguardTeam/AdguardFilters/blob/master/BaseFilter/sections/specific.txt), merged into a single JSON manifest that Browser Guard's extension build pipeline consumes.

- `antiadblock/antiadblock.txt` is the raw antiadblock upstream file, verbatim.
- `antiadblock/specific.txt` is the raw specific upstream file, verbatim.
- `antiadblock/antiadblock.json` is the manifest merged from both. It holds DNR rules, cosmetic selectors, CSS injections, and scriptlet directives, plus a `skipped[]` list of unsupported rules with reasons.
- `antiadblock/NOTICE` is the GPL-3.0 attribution for both verbatim upstream files, alongside the provenance of the build they came from.

#### Provenance and counts

The manifest's `sources[]` array is the authoritative, ordered provenance record: one entry per source, each with `name`, `source`, `source_url`, `upstream_sha256`, and `upstream_commit`. An `upstream_commit` is `null` when commit resolution was unavailable at build time, in which case the bytes came from `master` and that source's `source_url` is the unpinned URL.

The legacy top-level provenance fields (`source`, `source_url`, `upstream_sha256`, `upstream_commit`) describe the antiadblock source only and are retained for backward compatibility. For anything beyond antiadblock, read `sources[]`. The top-level `fetched_at` reflects the build run.

`counts_by_source` holds each source's own pre-merge conversion counters, keyed by source name; the top-level `counts` holds the merged totals. Because sources are converted independently and then merged, individual DNR rules, scriptlet directives, and `skipped[]` entries each carry a `source` tag naming the source they came from.

These manifest fields drive consumer collections: DNR rules become the extension's declarativeNetRequest rules, cosmetic selectors and CSS injections drive element hiding and styling, and scriptlet directives drive the injected scriptlets.

#### Build and publish

The `.github/workflows/update-antiadblock.yml` workflow rebuilds all four files daily (06:00 UTC) and on manual dispatch. It commits and publishes only when at least one verbatim upstream file (`antiadblock/*.txt`) actually changed, since the derived files carry a fresh `fetched_at` on every run. A converter change that alters `antiadblock.json` without an upstream change therefore needs its own commit; the workflow will not pick it up. Pull requests run the test suite instead of building. Regenerate locally with `python3 scripts/build_antiadblock.py`.

#### Downloads

Each upstream change publishes a dated release. These permalinks always resolve to the newest one:

- https://github.com/Malwarebytes/Browser-Guard-Community-Databases/releases/latest/download/antiadblock.json
- https://github.com/Malwarebytes/Browser-Guard-Community-Databases/releases/latest/download/antiadblock.txt
- https://github.com/Malwarebytes/Browser-Guard-Community-Databases/releases/latest/download/specific.txt

Both links need the repository to be public. It is internal today, so they will not resolve until that changes.

## Important Note

This repository is provided as-is and isn't bound to Malwarebytes' SLA.

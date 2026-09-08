# Malwarebytes Browser Guard Community Databases

Our version of popular open source databases.

## Store Listings

- [Chrome Web Store](https://chromewebstore.google.com/detail/malwarebytes-browser-guar/ihcjicgdanjaechkgeegckofjjedodee?hl=en)
- [Chrome Web Store (Beta)](https://chromewebstore.google.com/detail/malwarebytes-browser-guar/bdnmbmckbekibamnoenjkgmllboffdca?hl=en)
- [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/malwarebytes/)
- [Microsoft Edge Add-ons](https://microsoftedge.microsoft.com/addons/detail/malwarebytes-browser-guar/bojobppfploabceghnmlahpoonbcbacn)

## Databases

### `antiadblock/`

A daily rebuild of AdGuard's [antiadblock.txt](https://github.com/AdguardTeam/AdguardFilters/blob/master/BaseFilter/sections/antiadblock.txt) filter list, converted into a JSON manifest that Browser Guard's extension build pipeline consumes.

- `antiadblock/antiadblock.txt` is the raw upstream file, verbatim.
- `antiadblock/antiadblock.json` is the converted manifest. It holds DNR rules, cosmetic selectors, CSS injections, and scriptlet directives, plus a `skipped[]` list of unsupported rules with reasons.
- `antiadblock/NOTICE` is the GPL-3.0 attribution for the verbatim upstream file, alongside the provenance of the build it came from.

The manifest's `upstream_commit` field records the sha-pinned upstream commit the bytes were fetched at. It is `null` when commit resolution was unavailable at build time, in which case the bytes came from `master` and `source_url` is the unpinned URL.

The `.github/workflows/update-antiadblock.yml` workflow rebuilds all three files daily (06:00 UTC) and on manual dispatch. It commits and publishes only when the upstream `antiadblock.txt` actually changed, since the derived files carry a fresh `fetched_at` on every run. A converter change that alters `antiadblock.json` without an upstream change therefore needs its own commit; the workflow will not pick it up. Regenerate locally with `python3 scripts/build_antiadblock.py`.

#### Downloads

Each upstream change publishes a dated release. These permalinks always resolve to the newest one:

- https://github.com/Malwarebytes/Browser-Guard-Community-Databases/releases/latest/download/antiadblock.json
- https://github.com/Malwarebytes/Browser-Guard-Community-Databases/releases/latest/download/antiadblock.txt

Both links need the repository to be public. It is internal today, so they will not resolve until that changes.

## Important Note

This repository is provided as-is and isn't bound to Malwarebytes' SLA.

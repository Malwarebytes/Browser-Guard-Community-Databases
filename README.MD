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

- `antiadblock/antiadblock.txt` — the raw upstream file, verbatim.
- `antiadblock/antiadblock.mbgc.json` — the converted manifest: DNR rules, cosmetic selectors, CSS injections, and scriptlet directives, plus a `skipped[]` list of unsupported rules with reasons.

The `.github/workflows/update-antiadblock.yml` workflow rebuilds both files daily (06:00 UTC) and on manual dispatch. Regenerate locally with `python3 scripts/build_antiadblock.py`.

## Important Note

This repository is provided as-is and isn't bound to Malwarebytes' SLA.

# CLAUDE.md — frappe-drive (SWE-Pioneers fork)

Changes on top of upstream `frappe/drive` (main).

## Arabic i18n
- `drive/locale/ar.po` completed to **100% of app-owned strings** (Libyan-appropriate MSA), tagged
  `ai-translated; needs-native-review`. Built/filled via the parent repo's `scripts/i18n` pipeline
  (`generate-pot-file` sync for full doctype/field coverage). See the parent `SWE-Pioneers/frappe`
  `CLAUDE.md` for the pipeline + the runtime `.mo` compile mechanics.
- **RTL bootstrap added** (server-side, LMS pattern): the app's `www/*.py` `get_boot()`/context exposes `lang` + `text_direction` (via `frappe.utils.jinja_globals.is_rtl`); the SPA `index.html` `<html>` tag consumes them.

## Deploy
Built from `~/build/drive-custom` on the VPS (Containerfile repointed to this fork + per-app
`compile-po-to-mo`). Rebuild with `--no-cache`; see the parent `CLAUDE.md` for the `.mo` compile +
persist gotchas.

// Which files open in Collabora, and how the editor is launched.
//
// WOPI is NOT an <iframe src>. The host hands the editor a short-lived token, and the token must NOT
// travel in a URL — it would land in browser history, in any proxy log, and in the Referer header of
// every request the editor makes. The protocol therefore specifies a form POST: the editor URL is
// the action, `access_token` and `access_token_ttl` are form fields, and the target is the iframe.
//
// The editor is served same-origin (Traefik mounts Collabora at /browser, /cool and /hosting on this
// very host — see vps-infra collabora/), which is why the iframe is allowed at all: Traefik applies
// `frame-ancestors 'self'` globally on the websecure entrypoint.

// Collabora's own supported set, narrowed to what customers actually have. Anything not listed keeps
// the existing preview/download behaviour rather than opening an editor that would refuse the file.
export const OFFICE_MIME_TYPES = new Set([
  // Writer
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.oasis.opendocument.text",
  "application/rtf",
  // Calc
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "application/vnd.oasis.opendocument.spreadsheet",
  "text/csv",
  // Impress
  "application/vnd.ms-powerpoint",
  "application/vnd.openxmlformats-officedocument.presentationml.presentation",
  "application/vnd.oasis.opendocument.presentation",
])

export function isOfficeFile(entity) {
  if (!entity || entity.is_group || entity.is_link) return false
  return OFFICE_MIME_TYPES.has(entity.mime_type)
}

// Build the URL the form POSTs to. `editor_url` already ends with `?` (every urlsrc Collabora
// advertises does — the host is expected to append its own parameters), so WOPISrc is appended
// directly. The backend preserves that trailing separator deliberately; dropping it yields
// `cool.htmlWOPISrc=...`, which 404s.
export function buildEditorAction(cfg) {
  const sep = cfg.editor_url.endsWith("?") || cfg.editor_url.endsWith("&") ? "" : "?"
  return `${cfg.editor_url}${sep}WOPISrc=${encodeURIComponent(cfg.wopi_src)}`
}

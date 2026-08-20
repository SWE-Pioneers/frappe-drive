"""Frappe glue for the WOPI host. All the site-dependent parts live here.

`drive/api/wopi.py` holds the security core as pure functions so it can be unit-tested with plain
python (this fork has no test CI). THIS module is the half that needs a live site: the renderer, the
lock store, the secret, the entity lookups, the bytes. It imports the pure module; the pure module
must never import this one.

WHY A page_renderer AND NOT A WHITELISTED METHOD
------------------------------------------------
A WOPI client derives `<WOPISrc>/contents` from the file URL, so the routes must literally be
`/wopi/files/<id>` and `/wopi/files/<id>/contents`. That shape cannot be expressed as
`/api/method/<dotted.path>`. Frappe's supported mechanism for owning a URL space is the
`page_renderer` hook: `path_resolver` inserts our class BEFORE every built-in renderer, and
`frappe/app.py` routes GET, HEAD and POST through it, which is what makes the write path reachable.

THREE TRAPS, each verified against the running image rather than assumed:

1. **The caller is Guest.** Collabora talks to us server-to-server with no session cookie, so
   `frappe.session.user` is `Guest` for every WOPI request. Identity comes from the token and
   nowhere else. (Usefully, this also means Frappe's CSRF check returns early — a Guest session has
   no `csrf_token` — so POSTs are not rejected. That is why WOPI writes work at all here.)

2. **`serve.get_response` turns exceptions into HTML pages.** A raised `PermissionError` becomes a
   rendered "not permitted" page with an HTML body. A WOPI client needs a bare status code, so this
   renderer catches everything and returns a `Response` itself. It must never raise.

3. **Guest must not be allowed to widen access.** Every request re-checks the token's user against
   `get_user_access` on the CURRENT entity, so a share revoked mid-session takes effect on the next
   save rather than at token expiry.
"""

import json

import frappe
from werkzeug.wrappers import Response

from drive.api.permissions import get_user_access
from drive.api.wopi import (
    LOCK_TTL_SECONDS,
    WopiTokenError,
    check_file_info_payload,
    lock_decision,
    mint_token,
    parse_wopi_path,
    verify_token,
    wopi_action,
    wopi_put_is_safe,
)
from drive.utils.files import FileManager

# Collabora's own limit is 100 MiB by default; refusing early keeps a runaway body from being read
# into memory before we can reject it.
MAX_PUT_BYTES = 100 * 1024 * 1024


# --- secret ------------------------------------------------------------------------------------

def _secret() -> str:
    """Per-site HMAC key for WOPI tokens.

    Derived from Frappe's own site encryption key, which is generated on demand and always present.
    Deliberately NOT `Drive Disk Settings.jwt_key`: that field is declared as `Data` (not
    `Password`), is never auto-generated anywhere in this app, and is already used for a different
    token scheme. Reusing one secret across two token formats is how a token minted for one purpose
    becomes valid for the other.

    Domain-separated with a fixed label so the WOPI key can never equal the raw site key.
    """
    from frappe.utils.password import get_encryption_key

    return "wopi.v1:" + get_encryption_key()


# --- lock store --------------------------------------------------------------------------------
# Redis, not a DocType. A WOPI lock is ephemeral by definition — it expires after 30 minutes unless
# refreshed — and Redis gives that TTL for free, with no stale-lock reaper to write and no migration.
# frappe.cache() is shared by every worker, which is the property that actually matters here.
#
# A Redis flush drops all locks. That is acceptable and is why the lock is advisory: Collabora
# re-locks on its next operation. It is NOT a substitute for the atomic write in
# `FileManager.save_file_bytes` — the lock arbitrates writers, the atomic replace protects bytes.

def _lock_key(file_id: str) -> str:
    return f"drive|wopi|lock|{file_id}"


def _get_lock(file_id: str) -> str:
    # use_local_cache=False is load-bearing. frappe's cache wrapper memoises reads in a
    # PROCESS-LOCAL dict by default; a lock is cross-worker coordination, so it must be read from
    # Redis itself every time. A stale local copy is how two writers both believe they hold it.
    raw = frappe.cache().get_value(_lock_key(file_id), use_local_cache=False)
    if raw is None:
        return ""
    return raw.decode() if isinstance(raw, bytes) else str(raw)


def _apply_lock(file_id: str, decision: dict) -> None:
    action = decision.get("action")
    if action == "set":
        frappe.cache().set_value(_lock_key(file_id), decision["new_lock"], expires_in_sec=LOCK_TTL_SECONDS)
    elif action == "touch":
        # Re-set the SAME value purely to extend the TTL. Redis has no "expire only" through
        # frappe's cache wrapper, and a lock that silently stops being refreshed expires mid-edit.
        frappe.cache().set_value(_lock_key(file_id), decision["lock_header"], expires_in_sec=LOCK_TTL_SECONDS)
    elif action == "clear":
        frappe.cache().delete_value(_lock_key(file_id))


# --- helpers -----------------------------------------------------------------------------------

def _reply(status: int, body: bytes = b"", lock: str | None = None, mimetype="application/octet-stream"):
    r = Response(body, status=status, mimetype=mimetype)
    if lock is not None:
        # WOPI requires the current lock on EVERY conflict; omitting it leaves the client retrying
        # forever instead of recovering.
        r.headers["X-WOPI-Lock"] = lock
    return r


def _load_file(file_id: str):
    """The Drive File row, or None. Uses db.get_value so a Guest request is not filtered out by the
    permission query conditions — authorisation here is the token plus get_user_access, not the
    ambient session."""
    return frappe.db.get_value(
        "Drive File",
        {"name": file_id},
        ["name", "title", "team", "path", "mime_type", "file_size", "is_group", "is_link",
         "is_active", "owner", "modified"],
        as_dict=True,
    )


class WopiRenderer:
    """Owns /wopi/files/<id> and /wopi/files/<id>/contents."""

    def __init__(self, path=None, http_status_code=None):
        self.path = path or ""
        self.http_status_code = http_status_code
        self.parsed = None

    def can_render(self):
        # Read the ACTUAL request path, not the resolved endpoint: resolve_path may rewrite the
        # endpoint via route rules, and these URLs must match byte for byte.
        try:
            raw = frappe.local.request.path
        except Exception:
            raw = self.path
        self.parsed = parse_wopi_path(raw)
        return self.parsed is not None

    def render(self):
        # This method must NEVER raise: serve.get_response would turn the exception into an HTML
        # error page, and a WOPI client would read that as a corrupt document.
        try:
            return self._render()
        except Exception:
            frappe.log_error(title="WOPI request failed", message=frappe.get_traceback())
            return _reply(500)

    # -- internals

    def _render(self):
        file_id, is_contents = self.parsed
        req = frappe.local.request
        override = frappe.get_request_header("X-WOPI-Override")
        action = wopi_action(req.method, is_contents, override)

        if action == "method_not_allowed":
            return _reply(405)
        if action == "unsupported":
            return _reply(501)

        token = req.args.get("access_token") or ""
        try:
            claims = verify_token(token, file_id, _secret())
        except WopiTokenError:
            # 401 for every token failure, with no detail. Distinguishing expired from forged from
            # wrong-file turns the endpoint into an oracle.
            return _reply(401)

        drive_file = _load_file(file_id)
        if not drive_file or drive_file.is_group or drive_file.is_link or drive_file.is_active != 1:
            return _reply(404)

        # Re-check the live grant on every request, so revoking a share takes effect immediately
        # rather than when the token happens to expire.
        access = get_user_access(drive_file.name, claims["u"]) or {}
        if not access.get("read"):
            return _reply(404)  # not 403: existence itself is information

        if action == "check_file_info":
            return self._check_file_info(drive_file, claims, access)
        if action == "get_file":
            return self._get_file(drive_file)
        if action in ("lock", "unlock", "refresh_lock", "get_lock"):
            return self._lock_op(drive_file, action, claims, access)
        if action == "put_file":
            return self._put_file(drive_file, claims, access)
        return _reply(501)

    def _check_file_info(self, f, claims, access):
        _, expiry_ms = mint_token(f.name, claims["u"], _secret(), can_write=bool(claims.get("w")))
        user_name = frappe.db.get_value("User", claims["u"], "full_name") or claims["u"]
        body = check_file_info_payload(
            file_name=f.title,
            size=int(f.file_size or 0),
            owner_id=f.owner,
            user_name=user_name,
            # Version must change whenever the bytes change, or a client serves a stale cache.
            version=str(f.modified),
            access=access,
            can_write_token=bool(claims.get("w")),
            token_expiry_ms=expiry_ms,
        )
        return _reply(200, json.dumps(body).encode(), mimetype="application/json")

    def _get_file(self, f):
        buf = FileManager().get_file(f)
        data = buf.read()
        # Size in CheckFileInfo must equal what we actually return, or the client truncates. If the
        # stored row has drifted from the bytes on disk, the BYTES are the truth — correct the row.
        if int(f.file_size or 0) != len(data):
            frappe.db.set_value("Drive File", f.name, "file_size", len(data), update_modified=False)
            frappe.db.commit()
        return _reply(200, data)

    def _lock_op(self, f, action, claims, access):
        # Locking is a write-intent operation: a read-only session must not be able to hold a
        # document hostage. GET_LOCK is the exception — it only reports.
        if action != "get_lock" and not (access.get("write") and claims.get("w")):
            return _reply(404 if not access.get("read") else 409, lock=_get_lock(f.name))

        d = lock_decision(
            {"lock": "LOCK", "unlock": "UNLOCK", "refresh_lock": "REFRESH_LOCK", "get_lock": "GET_LOCK"}[action],
            _get_lock(f.name),
            frappe.get_request_header("X-WOPI-Lock"),
            old_lock=frappe.get_request_header("X-WOPI-OldLock"),
        )
        _apply_lock(f.name, d)
        return _reply(d["status"], lock=d["lock_header"])

    def _put_file(self, f, claims, access):
        if not (access.get("write") and claims.get("w")):
            return _reply(404 if not access.get("read") else 403)

        data = frappe.local.request.get_data(cache=False)
        if len(data) > MAX_PUT_BYTES:
            return _reply(413)

        current_size = int(f.file_size or 0)
        d = lock_decision("PUT", _get_lock(f.name), frappe.get_request_header("X-WOPI-Lock"),
                          file_size=current_size)
        if not d["write"]:
            return _reply(d["status"], lock=d["lock_header"])

        if not wopi_put_is_safe(len(data), current_size):
            # A zero-byte body against a document that has content. See wopi_put_is_safe: this is
            # what a crashed editor sends, and it is not worth the risk of being right.
            frappe.log_error(
                title="WOPI refused an emptying save",
                message=f"file={f.name} current_size={current_size} incoming=0",
            )
            return _reply(409, lock=d["lock_header"])

        written = FileManager().save_file_bytes(f, data)
        frappe.db.set_value("Drive File", f.name, "file_size", written, update_modified=True)
        frappe.db.commit()
        _apply_lock(f.name, d)

        r = _reply(200, lock=d["lock_header"])
        # Lets the client detect that the version it holds is no longer current.
        r.headers["X-WOPI-ItemVersion"] = str(frappe.db.get_value("Drive File", f.name, "modified"))
        return r


# --- editor entry point -------------------------------------------------------------------------

def _collabora_base() -> str:
    """Where the Collabora container lives. Overridable per site because the editor is reached by
    the BROWSER for the iframe but by the SERVER for discovery, and those are not always the same
    host."""
    return (frappe.conf.get("collabora_url") or "http://collabora:9980").rstrip("/")


def _discovery_urlsrc(extension: str) -> str | None:
    """The editor URL Collabora advertises for this file type.

    Read from `/hosting/discovery` rather than hardcoding `/browser/dist/cool.html`, because that
    path has changed between Collabora releases and a hardcoded one breaks silently on upgrade —
    the iframe just fails to load. Cached for an hour; discovery is a static document.
    """
    cache_key = "drive|wopi|discovery"
    cached = frappe.cache().get_value(cache_key)
    if cached:
        mapping = json.loads(cached if isinstance(cached, str) else cached.decode())
    else:
        import xml.etree.ElementTree as ET

        import requests

        xml = requests.get(f"{_collabora_base()}/hosting/discovery", timeout=10).text
        mapping = {}
        for app in ET.fromstring(xml).iter("app"):
            for action in app.iter("action"):
                ext = (action.get("ext") or "").lower()
                if ext and action.get("urlsrc"):
                    mapping.setdefault(ext, action.get("urlsrc"))
        frappe.cache().set_value(cache_key, json.dumps(mapping), expires_in_sec=3600)

    return mapping.get((extension or "").lower().lstrip("."))


@frappe.whitelist()
def get_editor_config(entity_name: str):
    """Everything the Drive frontend needs to open a document in Collabora.

    Called by the signed-in user, so this is the ONE place ambient session identity is the right
    source — the token is minted FOR that user and carries their write grant, which is what every
    later Guest-context WOPI request is then checked against.
    """
    access = get_user_access(entity_name) or {}
    if not access.get("read"):
        frappe.throw("You do not have permission to open this document", frappe.PermissionError)

    f = _load_file(entity_name)
    if not f or f.is_group or f.is_link or f.is_active != 1:
        frappe.throw("Not found", frappe.NotFound)

    extension = (f.title or "").rsplit(".", 1)[-1] if "." in (f.title or "") else ""
    urlsrc = _discovery_urlsrc(extension)
    if not urlsrc:
        frappe.throw(f"Collabora does not offer an editor for .{extension} files")

    can_write = bool(access.get("write"))
    token, expiry_ms = mint_token(f.name, frappe.session.user, _secret(), can_write=can_write)
    wopi_src = f"{frappe.utils.get_url()}/wopi/files/{f.name}"

    return {
        "editor_url": urlsrc,
        "wopi_src": wopi_src,
        "token": token,
        # Absolute epoch-ms, matching CheckFileInfo. The frontend uses it to refresh before expiry
        # rather than letting a session die mid-edit.
        "token_ttl": expiry_ms,
        "can_write": can_write,
        "title": f.title,
    }

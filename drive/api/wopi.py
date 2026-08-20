"""WOPI host for Frappe Drive — the protocol Collabora/LibreOffice Online speaks to a storage backend.

SCOPE: read AND write — `CheckFileInfo`, `GetFile`, `PutFile`, and the lock family
(`LOCK` / `UNLOCK` / `REFRESH_LOCK` / `GET_LOCK`). Collabora is the only WOPI client we serve, and
it is what merges the concurrent edits of several staff into one editing session; this host's job
is to hand the document out, arbitrate the lock, and take the saves back without losing bytes.

`PutFile` OVERWRITES, so it is the one operation here that can destroy a customer's work. Three
guards, and none of them is optional:
  * a save is refused unless the caller holds the lock (see `lock_decision`) — the whole point of
    the lock family is that an unlocked overwrite is someone else's document;
  * the write is ATOMIC (temp file + `os.replace`), so a save that dies half-way leaves the
    previous document intact rather than a truncated one;
  * a zero-byte body against a non-empty file is refused. That is what a crashed or disconnected
    editor sends, and it is indistinguishable at the protocol level from a deliberate "empty the
    document" — so it fails closed. `wopi_put_is_safe` is where that lives.

This module is still FRAPPE-FREE, on purpose. Everything security-critical is a PURE function of
its arguments — token minting and verification, the access mapping, the lock state machine, and the
overwrite guard. The fork has no unit-test infrastructure and no test CI, so anything that needs a
live site cannot be regression-tested at all; keeping this core importable without `frappe` is what
makes `drive/tests/test_wopi.py` runnable with plain python. The Frappe glue — the renderer, the
lock store, the secret, the entity lookups — lives in `drive/api/wopi_host.py`, which imports THIS
module and never the other way round.

Protocol notes worth keeping, each a documented trap:
  * `access_token_ttl` is an ABSOLUTE epoch-MILLISECONDS timestamp, not a duration. `0` means
    "unknown", which makes clients disable the session-refresh prompt — and then lose data when
    the token silently expires mid-edit. We always send a real value.
  * The token must be opaque and bound to (user, file). Collabora provides NO tenant isolation
    behind a single WOPI host: it is the client, and every request just carries the token we
    minted. One token not bound to a file is a cross-tenant document read.
  * `Size` must be the byte length of what `GetFile` will actually return, or clients truncate.
"""

import base64
import hashlib
import hmac
import json
import time

# --- token ------------------------------------------------------------------------------------
# A portal-minted, short-lived, opaque bearer. NEVER a raw storage key: the token travels through
# the browser to Collabora and back, so anything readable in it is effectively public.

TOKEN_VERSION = "v1"
DEFAULT_TTL_SECONDS = 10 * 60 * 60  # Collabora sessions are long; shorter TTLs mean mid-edit expiry


class WopiTokenError(Exception):
    """Raised for any token that is not valid, for any reason. Deliberately does NOT distinguish
    expired / tampered / wrong-file to the caller: a caller that branches on the reason tends to
    leak it to the client, which turns a token into an oracle."""


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _sign(payload: bytes, secret: str) -> str:
    return _b64e(hmac.new(secret.encode(), payload, hashlib.sha256).digest())


def mint_token(file_id: str, user: str, secret: str, ttl_seconds: int = DEFAULT_TTL_SECONDS,
               can_write: bool = False, now: float | None = None) -> tuple[str, int]:
    """Return (token, expiry_epoch_ms).

    The expiry is returned alongside because CheckFileInfo must report `access_token_ttl` as an
    absolute epoch-ms, and deriving it twice invites the two disagreeing.
    """
    if not file_id or not user:
        raise ValueError("file_id and user are both required to bind a token")
    now = time.time() if now is None else now
    exp = int(now) + int(ttl_seconds)
    claims = {"v": TOKEN_VERSION, "f": file_id, "u": user, "e": exp, "w": bool(can_write)}
    body = _b64e(json.dumps(claims, separators=(",", ":"), sort_keys=True).encode())
    return f"{body}.{_sign(body.encode(), secret)}", exp * 1000


def verify_token(token: str, file_id: str, secret: str, now: float | None = None) -> dict:
    """Return the claims, or raise WopiTokenError.

    Verifies the signature BEFORE parsing the payload, and checks that the token was minted for
    THIS file. A token valid for some other file must not open this one — that is the whole of
    tenant isolation here, since Collabora provides none.
    """
    now = time.time() if now is None else now
    try:
        body, sig = token.split(".", 1)
    except (ValueError, AttributeError):
        raise WopiTokenError("malformed token") from None
    # constant-time: a timing oracle on the signature is a forgery oracle
    if not hmac.compare_digest(sig, _sign(body.encode(), secret)):
        raise WopiTokenError("bad signature")
    try:
        claims = json.loads(_b64d(body))
    except Exception:
        raise WopiTokenError("unreadable payload") from None
    if claims.get("v") != TOKEN_VERSION:
        raise WopiTokenError("unknown token version")
    if claims.get("f") != file_id:
        raise WopiTokenError("token is not for this file")
    if not isinstance(claims.get("e"), int) or claims["e"] <= now:
        raise WopiTokenError("expired")
    if not claims.get("u"):
        raise WopiTokenError("token carries no user")
    return claims


# --- access mapping ---------------------------------------------------------------------------

def wopi_permissions(access: dict, can_write_token: bool = False) -> dict:
    """Map Drive's access dict onto the CheckFileInfo capability flags.

    FAILS CLOSED on every flag. An unknown or empty access dict yields a read-only, no-export
    session rather than an open one, because the failure modes are asymmetric: a wrongly
    read-only document is a support ticket, a wrongly writable one is data loss.

    `UserCanWrite` requires BOTH the stored permission and a token minted for writing. The token
    is what a browser actually presents, so a read-minted token must never become writable just
    because the underlying grant changed after minting.
    """
    access = access or {}
    write = bool(access.get("write")) and bool(can_write_token)
    return {
        "UserCanWrite": write,
        "UserCanNotWriteRelative": True,   # no "Save As" into Drive yet — PutRelativeFile is unimplemented
        "ReadOnly": not write,
        "UserCanRename": False,            # renaming is Drive's own surface, not the editor's
        # These three are advertised together and must stay together: a client told SupportsUpdate
        # without SupportsLocks will PutFile with no lock, which is precisely the unarbitrated
        # overwrite the lock family exists to prevent.
        "SupportsUpdate": True,
        "SupportsLocks": True,
        "SupportsGetLock": True,
        "SupportsRename": False,
        "HidePrintOption": not bool(access.get("read")),
        "HideExportOption": not bool(access.get("read")),
        "DisablePrint": not bool(access.get("read")),
        "DisableExport": not bool(access.get("read")),
    }


def check_file_info_payload(*, file_name: str, size: int, owner_id: str, user_name: str,
                            version: str, access: dict, can_write_token: bool,
                            token_expiry_ms: int, last_modified_iso: str | None = None) -> dict:
    """Build the CheckFileInfo body. Kept pure so its shape is testable without a site."""
    if size is None or size < 0:
        raise ValueError("Size must be the real byte length GetFile will return")
    body = {
        "BaseFileName": file_name,
        "Size": size,
        "OwnerId": owner_id,
        "UserId": owner_id if not user_name else user_name,
        "UserFriendlyName": user_name or "User",
        "Version": version,
        # absolute epoch-MILLISECONDS, not a duration, and never 0 — see the module docstring
        "access_token_ttl": int(token_expiry_ms),
        # Collabora-specific, harmless elsewhere: keeps the editor from offering features the host
        # cannot honour yet.
        "PostMessageOrigin": None,
    }
    if last_modified_iso:
        body["LastModifiedTime"] = last_modified_iso
    body.update(wopi_permissions(access, can_write_token))
    return {k: v for k, v in body.items() if v is not None}

# --- request routing (pure) -------------------------------------------------------------------
# WOPI clients derive `<WOPISrc>/contents` from the file URL, so the paths must literally be
# /wopi/files/<id> and /wopi/files/<id>/contents. That cannot be expressed as /api/method/<dotted>.
#
# Frappe's supported mechanism is the `page_renderer` hook: a class with can_render()/render() that
# path_resolver inserts BEFORE every built-in renderer, and whose build_response() returns arbitrary
# bytes with arbitrary headers (needed for X-WOPI-Lock). frappe/app.py routes GET, HEAD and POST
# through that same resolver, so the write path is reachable by the same route when it is built.
#
# Parsing and dispatch are kept pure so they are testable without a site.

WOPI_PREFIX = "wopi/files/"


def parse_wopi_path(path: str):
    """('<file_id>', is_contents) for a WOPI path, else None.

    `path` is Frappe's already-stripped route (no leading/trailing slash). Returns None for anything
    that is not ours, so can_render() cannot accidentally swallow another app's route.
    """
    if not path:
        return None
    path = path.strip("/")
    if not path.startswith(WOPI_PREFIX):
        return None
    rest = path[len(WOPI_PREFIX):]
    if not rest:
        return None
    if rest.endswith("/contents"):
        file_id = rest[: -len("/contents")]
        return (file_id, True) if file_id and "/" not in file_id else None
    return (rest, False) if "/" not in rest else None


# X-WOPI-Override values we implement, mapped to our internal action name.
_LOCK_OPS = {
    "LOCK": "lock",
    "UNLOCK": "unlock",
    "REFRESH_LOCK": "refresh_lock",
    "GET_LOCK": "get_lock",
}
# Recognised but deliberately NOT implemented. Named explicitly so they are refused as "we know
# this operation and decline it" rather than falling into the unknown-override bucket.
_DECLINED_OPS = {"PUT_RELATIVE", "RENAME_FILE", "DELETE"}


def wopi_action(method: str, is_contents: bool, override: str | None = None) -> str:
    """Map (method, path shape, X-WOPI-Override) to one of:
    check_file_info | get_file | put_file | lock | unlock | refresh_lock | get_lock |
    unsupported | method_not_allowed

    Deliberately explicit: an unrecognised override must NOT fall through to a write. WOPI sends
    several operations to the SAME URL and distinguishes them ONLY by this header, so a permissive
    default here would turn a typo'd or hostile header into an overwrite.
    """
    method = (method or "").upper()
    override = (override or "").upper().strip()
    if method in ("GET", "HEAD"):
        return "get_file" if is_contents else "check_file_info"
    if method == "POST":
        if is_contents:
            # PutFile is the only POST to /contents.
            return "put_file"
        if override in _LOCK_OPS:
            return _LOCK_OPS[override]
        if override in _DECLINED_OPS:
            return "unsupported"
        # An unknown override on the file URL is not a write. Refusing is the safe reading.
        return "unsupported"
    return "method_not_allowed"


# --- lock state machine (pure) -----------------------------------------------------------------
# WOPI locks are ADVISORY strings chosen by the client, not by us. The rules below are the ones
# Collabora actually relies on; getting a conflict response wrong is worse than not locking at all,
# because the client believes its lock is held and keeps editing against a document someone else
# now owns.
#
# On EVERY conflict the current lock must be echoed back in `X-WOPI-Lock`. A bare 409 makes the
# client retry forever instead of recovering, so `lock_header` is part of the decision, not an
# afterthought for the caller to remember.

LOCK_TTL_SECONDS = 30 * 60  # WOPI: a lock expires after 30 minutes unless refreshed


def lock_decision(op: str, current_lock: str | None, request_lock: str | None = None,
                  old_lock: str | None = None, file_size: int | None = None) -> dict:
    """Decide a lock-family (or PutFile) operation. PURE — no I/O, no clock, no frappe.

    Returns {"status", "action", "new_lock", "lock_header", "write"} where `action` is one of
    "set" (store new_lock with a fresh TTL) | "touch" (extend the existing TTL) | "clear" (delete)
    | "none", and `write` says whether the file bytes may be replaced.
    """
    op = (op or "").upper()
    cur = current_lock or ""
    req = request_lock or ""

    def out(status, action="none", new_lock=None, lock_header="", write=False):
        return {"status": status, "action": action, "new_lock": new_lock,
                "lock_header": lock_header, "write": write}

    if op == "GET_LOCK":
        # Always 200, even when unlocked — an empty X-WOPI-Lock IS the answer "not locked".
        return out(200, lock_header=cur)

    if op in ("LOCK", "UNLOCK", "REFRESH_LOCK") and not req:
        # A lock identifier is mandatory for these. Treating "" as a wildcard would let any client
        # steal or drop any lock.
        return out(400, lock_header=cur)

    if op == "LOCK":
        if old_lock is not None:
            # "Unlock and relock": valid ONLY if the caller correctly names the lock it is replacing.
            if cur and cur == old_lock:
                return out(200, action="set", new_lock=req, lock_header=req)
            return out(409, lock_header=cur)
        if not cur:
            return out(200, action="set", new_lock=req, lock_header=req)
        if cur == req:
            # Re-locking with the same id is a refresh, not a conflict.
            return out(200, action="touch", lock_header=req)
        return out(409, lock_header=cur)

    if op == "REFRESH_LOCK":
        if cur and cur == req:
            return out(200, action="touch", lock_header=req)
        return out(409, lock_header=cur)

    if op == "UNLOCK":
        if cur and cur == req:
            return out(200, action="clear", lock_header="")
        return out(409, lock_header=cur)

    if op == "PUT":
        if not cur:
            # An unlocked PutFile is legal in exactly one case: the initial save of a document that
            # is still empty. Anything else is an unarbitrated overwrite and must be refused.
            if file_size == 0:
                return out(200, write=True, lock_header="")
            return out(409, lock_header="")
        if cur == req:
            return out(200, action="touch", lock_header=req, write=True)
        return out(409, lock_header=cur)

    return out(501, lock_header=cur)


def rewrite_origin(urlsrc: str, public_base: str) -> str:
    """Repoint a discovery `urlsrc` at the origin a BROWSER can actually reach, keeping its path
    and query untouched.

    Collabora builds every `urlsrc` from the host it was asked on. Discovery is fetched
    server-to-server over the container network, so it advertises `http://collabora:9980/...` — a
    name that resolves only inside Docker. Handing that to an iframe produces a blank editor and
    nothing in the server log, because the failure happens in the browser.

    Path and query MUST survive: the query carries Collabora's own parameters (`WOPISrc` is
    appended to it later), and the path is the versioned `cool.html` location that moves between
    releases — which is why it is read from discovery instead of being hardcoded.
    """
    from urllib.parse import urlsplit, urlunsplit

    if not urlsrc:
        raise ValueError("urlsrc is required")
    if not public_base:
        raise ValueError("a public base URL is required — a container hostname is not reachable "
                         "from a browser")
    parts = urlsplit(urlsrc)
    pub = urlsplit(public_base.rstrip("/"))
    if not pub.scheme or not pub.netloc:
        raise ValueError(f"public base must be absolute, got {public_base!r}")
    return urlunsplit((pub.scheme, pub.netloc, parts.path, parts.query, parts.fragment))


def wopi_put_is_safe(new_size: int, current_size: int | None) -> bool:
    """False when a save would empty a document that currently has content.

    A crashed, killed or disconnected editor sends a zero-length body, and at the protocol level
    that is identical to a deliberate "make this document empty". The two are not equally costly:
    refusing a genuine emptying is a support ticket, accepting a spurious one destroys the file. So
    it fails closed. Deliberately allows 0 -> 0 (already empty, nothing to lose).
    """
    if new_size is None or new_size < 0:
        return False
    if new_size == 0 and (current_size or 0) > 0:
        return False
    return True

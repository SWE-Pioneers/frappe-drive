"""WOPI host for Frappe Drive — the protocol Collabora/LibreOffice Online speaks to a storage backend.

SCOPE, deliberately narrow (2026-08-20): this implements the READ path only —
`CheckFileInfo` and `GetFile`. That is enough for Collabora to render a document.
`PutFile` and the lock family are NOT implemented and return 501 rather than a stub, because
WOPI's `PutFile` OVERWRITES: a wrong lock implementation loses a customer's work with no error
and no version to recover from. That half needs Drive's versioning wired in first.

Everything security-critical here is a PURE function of its arguments — token minting and
verification, and the access-level mapping. The fork has no unit-test infrastructure and no test
CI, so anything that needs a live site cannot be regression-tested at all; keeping the security
core free of `frappe` is what makes `drive/tests/test_wopi.py` runnable with plain python.

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
        "SupportsUpdate": False,           # flipped on with PutFile; advertising it without it breaks saves
        "SupportsLocks": False,            # ditto — a client that believes we lock will not retry
        "SupportsGetLock": False,
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

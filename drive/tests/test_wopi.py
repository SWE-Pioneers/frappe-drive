"""Tests for the WOPI security core. Runs with plain `python drive/tests/test_wopi.py` — no site,
no bench, no database.

That is the point. This fork has no unit-test infrastructure and no test CI, so anything requiring
a live Frappe site cannot be regression-tested at all. Keeping token minting/verification and the
access mapping free of `frappe` is what makes them testable, and those are exactly the parts where
a mistake is a cross-tenant document read or silent data loss.

Every assertion below is a MUTATION the code must reject. A test that only checks the happy path
would pass against a `verify_token` that returns the claims unconditionally.
"""

import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
from drive.api.wopi import (  # noqa: E402
    WopiTokenError,
    check_file_info_payload,
    mint_token,
    verify_token,
    wopi_permissions,
)

SECRET = "test-secret-not-a-real-one"
OTHER_SECRET = "a-different-secret"
FILE = "abc123"
USER = "someone@example.com"


class TokenRoundTrip(unittest.TestCase):
    def test_a_freshly_minted_token_verifies(self):
        tok, exp_ms = mint_token(FILE, USER, SECRET)
        claims = verify_token(tok, FILE, SECRET)
        self.assertEqual(claims["u"], USER)
        self.assertEqual(claims["f"], FILE)
        self.assertGreater(exp_ms, int(time.time() * 1000))

    def test_expiry_is_epoch_MILLIseconds(self):
        # The classic WOPI trap: access_token_ttl is an absolute epoch-ms timestamp, not a
        # duration. Returning seconds here makes every session look decades expired; returning a
        # duration makes clients disable the refresh prompt and lose work mid-edit.
        _, exp_ms = mint_token(FILE, USER, SECRET, ttl_seconds=3600)
        self.assertAlmostEqual(exp_ms / 1000.0, time.time() + 3600, delta=5)
        self.assertGreater(exp_ms, 1_000_000_000_000)  # ms, not s


class TokenRejection(unittest.TestCase):
    """Each of these is a real attack or a real bug, not a formality."""

    def test_rejects_a_token_minted_for_another_file(self):
        # Cross-tenant document read. Collabora provides NO isolation behind one WOPI host, so
        # this binding is the only thing standing between two customers' documents.
        tok, _ = mint_token("file-A", USER, SECRET)
        with self.assertRaises(WopiTokenError):
            verify_token(tok, "file-B", SECRET)

    def test_rejects_a_tampered_payload(self):
        tok, _ = mint_token(FILE, USER, SECRET)
        body, sig = tok.split(".", 1)
        forged = body[:-2] + ("aa" if not body.endswith("aa") else "bb")
        with self.assertRaises(WopiTokenError):
            verify_token(f"{forged}.{sig}", FILE, SECRET)

    def test_rejects_a_token_signed_with_a_different_secret(self):
        tok, _ = mint_token(FILE, USER, OTHER_SECRET)
        with self.assertRaises(WopiTokenError):
            verify_token(tok, FILE, SECRET)

    def test_rejects_an_expired_token(self):
        tok, _ = mint_token(FILE, USER, SECRET, ttl_seconds=1, now=time.time() - 3600)
        with self.assertRaises(WopiTokenError):
            verify_token(tok, FILE, SECRET)

    def test_rejects_malformed_input(self):
        for bad in ["", "no-dot", "a.b.c.d", None, "....", "."]:
            with self.assertRaises(WopiTokenError):
                verify_token(bad, FILE, SECRET)

    def test_refuses_to_mint_an_unbound_token(self):
        # A token with no file or no user cannot be authorised against anything later.
        for f, u in [("", USER), (FILE, ""), (None, USER), (FILE, None)]:
            with self.assertRaises(ValueError):
                mint_token(f, u, SECRET)


class AccessMapping(unittest.TestCase):
    def test_write_requires_BOTH_the_grant_and_a_write_token(self):
        # Asymmetric failure: a wrongly read-only doc is a support ticket, a wrongly writable one
        # is data loss. So both must agree.
        self.assertTrue(wopi_permissions({"write": True, "read": True}, True)["UserCanWrite"])
        self.assertFalse(wopi_permissions({"write": True, "read": True}, False)["UserCanWrite"])
        self.assertFalse(wopi_permissions({"write": False, "read": True}, True)["UserCanWrite"])

    def test_fails_closed_on_empty_or_unknown_access(self):
        for access in [{}, None, {"nonsense": True}]:
            p = wopi_permissions(access, True)
            self.assertFalse(p["UserCanWrite"], f"{access!r} must not grant write")
            self.assertTrue(p["ReadOnly"], f"{access!r} must be read-only")

    def test_does_not_advertise_capabilities_it_lacks(self):
        # Advertising SupportsUpdate/SupportsLocks without implementing PutFile makes a client
        # believe a save succeeded, or that a lock is held. Both lose work silently.
        p = wopi_permissions({"read": True, "write": True}, True)
        for flag in ("SupportsUpdate", "SupportsLocks", "SupportsGetLock", "SupportsRename"):
            self.assertFalse(p[flag], f"{flag} must stay off until it is implemented")


class CheckFileInfoBody(unittest.TestCase):
    def _payload(self, **over):
        args = dict(file_name="Report.docx", size=1234, owner_id="owner@x.io",
                    user_name="Reader", version="7", access={"read": True},
                    can_write_token=False, token_expiry_ms=int(time.time() * 1000) + 60000)
        args.update(over)
        return check_file_info_payload(**args)

    def test_required_fields_present(self):
        b = self._payload()
        for k in ("BaseFileName", "Size", "OwnerId", "Version", "access_token_ttl"):
            self.assertIn(k, b)

    def test_rejects_a_missing_or_negative_size(self):
        # Clients truncate the download to Size. A wrong Size corrupts the document silently.
        for bad in (None, -1):
            with self.assertRaises(ValueError):
                self._payload(size=bad)

    def test_read_only_access_never_yields_a_writable_session(self):
        self.assertFalse(self._payload(access={"read": True}, can_write_token=True)["UserCanWrite"])

    def test_ttl_is_never_zero(self):
        # 0 means "unknown" to a WOPI client, which then disables the session-refresh prompt.
        self.assertNotEqual(self._payload()["access_token_ttl"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)

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
    lock_decision,
    mint_token,
    parse_wopi_path,
    rewrite_origin,
    verify_token,
    wopi_action,
    wopi_permissions,
    wopi_put_is_safe,
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

    def test_advertises_exactly_the_capabilities_it_has(self):
        # Advertising a capability we lack makes a client believe a save succeeded or a lock is
        # held; NOT advertising one we have makes Collabora open the document read-only. Both are
        # wrong, so this pins the set in both directions.
        p = wopi_permissions({"read": True, "write": True}, True)
        for flag in ("SupportsUpdate", "SupportsLocks", "SupportsGetLock"):
            self.assertTrue(p[flag], f"{flag} is implemented and must be advertised")
        for flag in ("SupportsRename", "UserCanRename"):
            self.assertFalse(p[flag], f"{flag} is not implemented and must stay off")
        # PutRelativeFile ("Save As" into Drive) is still unimplemented, so the editor must be told
        # not to offer it.
        self.assertTrue(p["UserCanNotWriteRelative"])

    def test_update_and_locks_are_advertised_together(self):
        # SupportsUpdate without SupportsLocks tells a client to PutFile without ever taking a
        # lock, which is exactly the unarbitrated overwrite the lock family exists to prevent.
        p = wopi_permissions({"read": True, "write": True}, True)
        self.assertEqual(p["SupportsUpdate"], p["SupportsLocks"])


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


class PathParsing(unittest.TestCase):
    def test_parses_both_wopi_shapes(self):
        self.assertEqual(parse_wopi_path("wopi/files/ABC"), ("ABC", False))
        self.assertEqual(parse_wopi_path("wopi/files/ABC/contents"), ("ABC", True))
        self.assertEqual(parse_wopi_path("/wopi/files/ABC/contents/"), ("ABC", True))

    def test_ignores_paths_that_are_not_ours(self):
        # can_render() runs BEFORE every built-in renderer, so a greedy match here would swallow
        # another app's route and 404 it.
        for p in ["", None, "drive/x", "wopi", "wopi/files/", "wopi/files", "api/method/x",
                  "wopi/files/a/b", "wopi/files/a/b/contents"]:
            self.assertIsNone(parse_wopi_path(p), f"{p!r} must not be claimed")


class ActionDispatch(unittest.TestCase):
    def test_read_operations(self):
        self.assertEqual(wopi_action("GET", False), "check_file_info")
        self.assertEqual(wopi_action("GET", True), "get_file")
        self.assertEqual(wopi_action("HEAD", False), "check_file_info")

    def test_post_to_contents_is_putfile(self):
        self.assertEqual(wopi_action("POST", True), "put_file")

    def test_lock_overrides_dispatch_to_their_own_operation(self):
        for ov, expected in [("LOCK", "lock"), ("UNLOCK", "unlock"),
                             ("REFRESH_LOCK", "refresh_lock"), ("GET_LOCK", "get_lock"),
                             ("lock", "lock")]:  # case-insensitive per spec
            self.assertEqual(wopi_action("POST", False, ov), expected, f"override={ov!r}")

    def test_an_unknown_override_is_never_treated_as_a_write(self):
        # WOPI sends several operations to the SAME url, distinguished only by X-WOPI-Override.
        # Falling through to a write on an unrecognised value would overwrite a document.
        for ov in ["SOMETHING_NEW", "", None, "put", "PUT", "PUT_RELATIVE", "RENAME_FILE", "DELETE"]:
            self.assertEqual(wopi_action("POST", False, ov), "unsupported", f"override={ov!r}")

    def test_no_override_ever_yields_put_file_on_the_file_url(self):
        # PutFile lives at /contents ONLY. If any override on the bare file URL could return
        # "put_file", a client that mis-sent a header would overwrite the document.
        for ov in ["LOCK", "UNLOCK", "GET_LOCK", "PUT", "PUT_RELATIVE", "", None, "anything"]:
            self.assertNotEqual(wopi_action("POST", False, ov), "put_file", f"override={ov!r}")

    def test_other_methods_are_refused(self):
        for m in ["PUT", "DELETE", "PATCH", "OPTIONS", "", None]:
            self.assertEqual(wopi_action(m, False), "method_not_allowed")


class DiscoveryOriginRewrite(unittest.TestCase):
    """Collabora builds urlsrc from the host it was ASKED on. Discovery is fetched over the
    container network, so the reply advertises a hostname only Docker can resolve — handing that
    to an iframe is a blank editor with nothing in the server log."""

    SRC = "http://collabora:9980/browser/abc123/cool.html?"

    def test_replaces_the_unreachable_container_origin(self):
        out = rewrite_origin(self.SRC, "https://office.swe.com.ly")
        self.assertTrue(out.startswith("https://office.swe.com.ly/"), out)
        self.assertNotIn("collabora:9980", out)

    def test_keeps_the_versioned_path_and_query(self):
        # The path is the release-specific cool.html location — the whole reason discovery is read
        # instead of hardcoded. Losing the query would drop Collabora's own parameters.
        out = rewrite_origin("http://collabora:9980/browser/abc123/cool.html?lang=ar&foo=1",
                             "https://office.swe.com.ly")
        self.assertIn("/browser/abc123/cool.html", out)
        self.assertIn("lang=ar", out)
        self.assertIn("foo=1", out)

    def test_preserves_the_trailing_question_mark(self):
        # Every one of the 276 urlsrc values Collabora advertises ends with `cool.html?`. The
        # caller appends `WOPISrc=...` straight onto it, so dropping the separator yields
        # `cool.htmlWOPISrc=...`, which 404s. urlunsplit drops an empty query — that is exactly the
        # bug this pins, and it was found on the live box, not in review.
        out = rewrite_origin(self.SRC, "https://office.swe.com.ly")
        self.assertTrue(out.endswith("cool.html?"), out)
        self.assertIn("WOPISrc=abc", out + "WOPISrc=abc")

    def test_preserves_everything_after_the_origin_byte_for_byte(self):
        src = "http://collabora:9980/browser/h/cool.html?lang=ar&x=1#frag"
        out = rewrite_origin(src, "https://d.example.com")
        self.assertEqual(out, "https://d.example.com/browser/h/cool.html?lang=ar&x=1#frag")

    def test_refuses_a_relative_urlsrc(self):
        with self.assertRaises(ValueError):
            rewrite_origin("/browser/h/cool.html?", "https://d.example.com")

    def test_tolerates_a_trailing_slash_on_the_public_base(self):
        self.assertEqual(rewrite_origin(self.SRC, "https://office.swe.com.ly/"),
                         rewrite_origin(self.SRC, "https://office.swe.com.ly"))

    def test_refuses_a_missing_or_relative_public_base(self):
        # Failing loudly beats a silently unreachable iframe.
        for bad in ["", None, "office.swe.com.ly", "/office"]:
            with self.assertRaises(ValueError, msg=f"{bad!r} must be refused"):
                rewrite_origin(self.SRC, bad)

    def test_refuses_an_empty_urlsrc(self):
        with self.assertRaises(ValueError):
            rewrite_origin("", "https://office.swe.com.ly")


class LockStateMachine(unittest.TestCase):
    """The rules Collabora actually relies on. Every conflict must echo the CURRENT lock back —
    a bare 409 makes the client retry forever instead of recovering."""

    def test_taking_a_lock_on_an_unlocked_file(self):
        d = lock_decision("LOCK", None, "LCK1")
        self.assertEqual(d["status"], 200)
        self.assertEqual(d["action"], "set")
        self.assertEqual(d["new_lock"], "LCK1")

    def test_relocking_with_the_same_id_is_a_refresh_not_a_conflict(self):
        # Collabora re-sends LOCK periodically. Answering 409 here would make it abandon the
        # session it legitimately owns.
        d = lock_decision("LOCK", "LCK1", "LCK1")
        self.assertEqual(d["status"], 200)
        self.assertEqual(d["action"], "touch")

    def test_a_conflicting_lock_is_refused_AND_echoes_the_current_holder(self):
        d = lock_decision("LOCK", "HELD_BY_OTHER", "MINE")
        self.assertEqual(d["status"], 409)
        self.assertEqual(d["lock_header"], "HELD_BY_OTHER",
                         "a 409 without X-WOPI-Lock leaves the client unable to recover")
        self.assertEqual(d["action"], "none")
        self.assertFalse(d["write"])

    def test_unlock_requires_the_matching_id(self):
        self.assertEqual(lock_decision("UNLOCK", "LCK1", "LCK1")["action"], "clear")
        stolen = lock_decision("UNLOCK", "LCK1", "NOT_MINE")
        self.assertEqual(stolen["status"], 409)
        self.assertEqual(stolen["action"], "none", "one client must not drop another's lock")
        self.assertEqual(stolen["lock_header"], "LCK1")

    def test_unlocking_an_unlocked_file_is_a_conflict_not_a_success(self):
        d = lock_decision("UNLOCK", None, "LCK1")
        self.assertEqual(d["status"], 409)

    def test_refresh_only_extends_a_lock_you_hold(self):
        self.assertEqual(lock_decision("REFRESH_LOCK", "LCK1", "LCK1")["action"], "touch")
        for cur in (None, "SOMEONE_ELSE"):
            self.assertEqual(lock_decision("REFRESH_LOCK", cur, "LCK1")["status"], 409)

    def test_get_lock_always_answers_200(self):
        # An empty X-WOPI-Lock IS the answer "not locked" — 404/409 here confuses clients.
        self.assertEqual(lock_decision("GET_LOCK", None)["status"], 200)
        self.assertEqual(lock_decision("GET_LOCK", None)["lock_header"], "")
        self.assertEqual(lock_decision("GET_LOCK", "LCK1")["lock_header"], "LCK1")

    def test_an_empty_lock_id_is_rejected_not_treated_as_a_wildcard(self):
        # If "" matched anything, any client could steal or drop any lock.
        for op in ("LOCK", "UNLOCK", "REFRESH_LOCK"):
            for req in ("", None):
                d = lock_decision(op, "LCK1", req)
                self.assertEqual(d["status"], 400, f"{op} with {req!r}")
                self.assertEqual(d["action"], "none")

    def test_unlock_and_relock_requires_naming_the_old_lock(self):
        ok = lock_decision("LOCK", "OLD", "NEW", old_lock="OLD")
        self.assertEqual(ok["status"], 200)
        self.assertEqual(ok["new_lock"], "NEW")
        wrong = lock_decision("LOCK", "OLD", "NEW", old_lock="GUESS")
        self.assertEqual(wrong["status"], 409)
        self.assertEqual(wrong["lock_header"], "OLD")

    def test_an_unknown_operation_never_writes(self):
        d = lock_decision("EXPLODE", "LCK1", "LCK1")
        self.assertEqual(d["status"], 501)
        self.assertFalse(d["write"])


class PutFileArbitration(unittest.TestCase):
    def test_a_save_needs_the_lock(self):
        self.assertTrue(lock_decision("PUT", "LCK1", "LCK1")["write"])

    def test_a_save_with_the_wrong_lock_is_refused(self):
        d = lock_decision("PUT", "HELD", "MINE")
        self.assertEqual(d["status"], 409)
        self.assertFalse(d["write"], "this is the unarbitrated overwrite the lock exists to stop")
        self.assertEqual(d["lock_header"], "HELD")

    def test_an_unlocked_save_is_refused_unless_the_file_is_empty(self):
        # WOPI allows an unlocked PutFile only for the first save of a still-empty document.
        self.assertTrue(lock_decision("PUT", None, "", file_size=0)["write"])
        for size in (1, 1024, None):
            d = lock_decision("PUT", None, "", file_size=size)
            self.assertEqual(d["status"], 409, f"size={size}")
            self.assertFalse(d["write"], f"size={size} must not be overwritten without a lock")

    def test_a_lockless_client_cannot_write_by_omitting_the_header(self):
        # The dangerous shape: file IS locked, client sends no X-WOPI-Lock at all.
        d = lock_decision("PUT", "HELD", None)
        self.assertEqual(d["status"], 409)
        self.assertFalse(d["write"])


class OverwriteGuard(unittest.TestCase):
    def test_refuses_to_empty_a_document_that_has_content(self):
        # A crashed or disconnected editor sends zero bytes, and that is indistinguishable from a
        # deliberate emptying. Refusing costs a support ticket; accepting destroys the file.
        self.assertFalse(wopi_put_is_safe(0, 5000))

    def test_allows_a_normal_save(self):
        self.assertTrue(wopi_put_is_safe(5100, 5000))
        self.assertTrue(wopi_put_is_safe(10, 5000), "documents legitimately shrink")

    def test_allows_zero_onto_an_already_empty_file(self):
        for cur in (0, None):
            self.assertTrue(wopi_put_is_safe(0, cur))

    def test_rejects_a_nonsense_size(self):
        self.assertFalse(wopi_put_is_safe(-1, 10))
        self.assertFalse(wopi_put_is_safe(None, 10))


if __name__ == "__main__":
    unittest.main(verbosity=2)

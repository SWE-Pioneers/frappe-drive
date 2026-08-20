"""Mutation probe for the WOPI security core. Run: `python drive/tests/mutation_probe.py`

WHY THIS FILE EXISTS
--------------------
`test_wopi.py` passing proves nothing on its own. A test that cannot fail is not a test, and this
estate has shipped several that could not: a gate whose regex held a literal BACKSPACE byte, another
reporting "ok 0 items" after the list it parsed was refactored away, and two assertions that "passed"
only because a crashed mock also exits non-zero.

So each entry below BREAKS one real invariant in `drive/api/wopi.py` and requires the suite to fail
**with the specific test that guards it**. A mutation that merely produces some failure is not
accepted — the named test must be the one that fires, otherwise the suite is failing for an
unrelated reason and the guard is still unproven.

Every mutation here is a plausible mistake, not a strawman: dropping the lock check on save,
treating an empty lock id as a wildcard, forgetting to echo the current lock on a 409. Each one, if
shipped, silently destroys or leaks a customer's document.

Restores the file in a `finally` and verifies the restore by hash before exiting.
"""

import hashlib
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
TARGET = HERE.parent / "api" / "wopi.py"
SUITE = HERE / "test_wopi.py"

# (label, find, replace, test that MUST fail)
MUTATIONS = [
    (
        "PutFile ignores a conflicting lock and overwrites anyway",
        '        if cur == req:\n            return out(200, action="touch", lock_header=req, write=True)\n        return out(409, lock_header=cur)',
        '        return out(200, action="touch", lock_header=req, write=True)',
        "test_a_save_with_the_wrong_lock_is_refused",
    ),
    (
        "an empty lock id is treated as a wildcard that matches any lock",
        '    if op in ("LOCK", "UNLOCK", "REFRESH_LOCK") and not req:\n        # A lock identifier is mandatory for these. Treating "" as a wildcard would let any client\n        # steal or drop any lock.\n        return out(400, lock_header=cur)',
        '    if False:\n        return out(400, lock_header=cur)',
        "test_an_empty_lock_id_is_rejected_not_treated_as_a_wildcard",
    ),
    (
        "a lock conflict returns 409 but forgets to echo the current holder",
        '        if cur == req:\n            # Re-locking with the same id is a refresh, not a conflict.\n            return out(200, action="touch", lock_header=req)\n        return out(409, lock_header=cur)',
        '        if cur == req:\n            return out(200, action="touch", lock_header=req)\n        return out(409, lock_header="")',
        "test_a_conflicting_lock_is_refused_AND_echoes_the_current_holder",
    ),
    (
        "an unlocked save is allowed to overwrite a file that has content",
        "            if file_size == 0:\n                return out(200, write=True, lock_header=\"\")\n            return out(409, lock_header=\"\")",
        '            return out(200, write=True, lock_header="")',
        "test_an_unlocked_save_is_refused_unless_the_file_is_empty",
    ),
    (
        "the zero-byte guard accepts a save that empties a document",
        "    if new_size == 0 and (current_size or 0) > 0:\n        return False",
        "    if False:\n        return False",
        "test_refuses_to_empty_a_document_that_has_content",
    ),
    (
        "UNLOCK drops whatever lock is held regardless of who owns it",
        '        if cur and cur == req:\n            return out(200, action="clear", lock_header="")\n        return out(409, lock_header=cur)',
        '        return out(200, action="clear", lock_header="")',
        "test_unlock_requires_the_matching_id",
    ),
    (
        "an unknown X-WOPI-Override falls through to a write",
        '        # An unknown override on the file URL is not a write. Refusing is the safe reading.\n        return "unsupported"',
        '        return "put_file"',
        "test_an_unknown_override_is_never_treated_as_a_write",
    ),
    (
        "a read-minted token still yields a writable session",
        "    write = bool(access.get(\"write\")) and bool(can_write_token)",
        '    write = bool(access.get("write"))',
        "test_write_requires_BOTH_the_grant_and_a_write_token",
    ),
    (
        "verify_token stops checking which file the token was minted for",
        '    if claims.get("f") != file_id:\n        raise WopiTokenError("token is not for this file")',
        "    if False:\n        raise WopiTokenError(\"x\")",
        "test_rejects_a_token_minted_for_another_file",
    ),
]


def run_suite():
    p = subprocess.run([sys.executable, str(SUITE)], capture_output=True, text=True, cwd=str(HERE.parent.parent))
    return p.returncode, p.stdout + p.stderr


def main():
    original = TARGET.read_bytes()
    original_sha = hashlib.sha256(original).hexdigest()
    # Normalise to LF for matching. A Windows checkout (core.autocrlf=true) stores this file CRLF,
    # so every multi-line anchor below would silently miss and the probe would report "anchor not
    # found" for all of them — a probe that tests nothing, which is the very thing it guards against.
    text = original.decode("utf-8").replace("\r\n", "\n")
    failures = []

    try:
        rc, out = run_suite()
        if rc != 0:
            print("BASELINE IS ALREADY RED — fix that before probing\n" + out[-2000:])
            return 1
        print(f"baseline: green ({len(MUTATIONS)} mutations to apply)\n")

        for label, find, replace, must_fail in MUTATIONS:
            if find not in text:
                # The code moved and this probe silently stopped testing anything. That is the exact
                # failure mode this file exists to prevent, so it is an ERROR, never a skip.
                print(f"  BROKEN PROBE - anchor not found: {label}")
                failures.append(label)
                continue
            TARGET.write_text(text.replace(find, replace, 1), encoding="utf-8")
            rc, out = run_suite()
            TARGET.write_bytes(original)

            if rc == 0:
                print(f"  NOT CAUGHT      {label}")
                failures.append(label)
            elif must_fail not in out:
                # Failing for the wrong reason is not proof. Name what actually broke.
                print(f"  WRONG FAILURE   {label}\n                  expected {must_fail} to fail")
                failures.append(label)
            else:
                print(f"  caught          {label}")
    finally:
        TARGET.write_bytes(original)
        restored = hashlib.sha256(TARGET.read_bytes()).hexdigest()
        assert restored == original_sha, "FAILED TO RESTORE wopi.py — check `git diff` before committing"

    print()
    if failures:
        print(f"{len(failures)} mutation(s) NOT caught — those invariants are unguarded")
        return 1
    print(f"all {len(MUTATIONS)} mutations caught by the named test")
    return 0


if __name__ == "__main__":
    sys.exit(main())

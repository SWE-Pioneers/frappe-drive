#!/bin/bash
# Ensure `pnpm` actually resolves to pnpm 10 before the frontend install runs.
#
# This script used to check whether pnpm EXISTS. That check can never fail, and so the
# `pnpm@latest-10` pin below has never once taken effect:
#
#   1. Node ships COREPACK, which installs a shim at <node>/bin/pnpm -> corepack/dist/pnpm.js.
#      `command -v pnpm` is satisfied by that shim on a machine with no pnpm installed at all,
#      so the install was always skipped — and corepack then downloads whatever version is
#      CURRENT (11.x today), not the version this project pins.
#   2. Even when the install did run, `npm install -g pnpm@...` aborts with EEXIST rather than
#      overwrite that same corepack shim.
#
# pnpm 11 is not simply "newer" here, it breaks this project in two concrete ways:
#   - blocked dependency build scripts become a FATAL ERR_PNPM_IGNORED_BUILDS instead of a
#     warning, and esbuild, vue-demi, @swc/core, canvas and core-js are all blocked. The
#     frontend install exits 1, which fails `bench get-app drive` outright.
#   - it no longer reads the "pnpm" field in package.json, silently discarding our own
#     overrides.yjs pin.
#
# So: compare the MAJOR VERSION rather than test for existence, and clear corepack's shim
# before installing so npm has somewhere to write.
set -uo pipefail

REQUIRED_MAJOR=10

current="$(pnpm --version 2>/dev/null || true)"

if [ "${current%%.*}" = "$REQUIRED_MAJOR" ]; then
    echo "pnpm $current is already installed."
    echo "pnpm version: $current"
    exit 0
fi

echo "pnpm ${current:-not found} is not v${REQUIRED_MAJOR} — installing pnpm@latest-${REQUIRED_MAJOR}..."

# npm refuses to clobber corepack's shim (EEXIST), so remove it first — but ONLY if that is
# what we actually have. A real pnpm installed elsewhere is left alone for npm to upgrade.
shim="$(command -v pnpm 2>/dev/null || true)"
if [ -n "$shim" ] && readlink -f "$shim" 2>/dev/null | grep -q corepack; then
    if ! rm -f "$shim" "$(dirname "$shim")/pnpx" 2>/dev/null; then
        echo "error: cannot remove corepack's pnpm shim at $shim (not writable by $(id -un))." >&2
        echo "       Remove it as root, or pre-install pnpm ${REQUIRED_MAJOR} in the image:" >&2
        echo "         rm -f '$shim' '$(dirname "$shim")/pnpx' && npm install -g pnpm@latest-${REQUIRED_MAJOR}" >&2
        exit 1
    fi
fi

if ! npm install -g "pnpm@latest-${REQUIRED_MAJOR}"; then
    echo "error: failed to install pnpm@latest-${REQUIRED_MAJOR}" >&2
    exit 1
fi

installed="$(pnpm --version 2>/dev/null || true)"
if [ "${installed%%.*}" != "$REQUIRED_MAJOR" ]; then
    echo "error: pnpm still reports '${installed:-nothing}' after install; expected v${REQUIRED_MAJOR}." >&2
    exit 1
fi

echo "pnpm version: $installed"

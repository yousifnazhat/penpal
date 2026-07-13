#!/usr/bin/env bash
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
ROOT_DIR="$(dirname -- "$SCRIPT_DIR")"
PI_VERSION="$(tr -d '[:space:]' < "$ROOT_DIR/.pi-version")"
PI_PACKAGE="${PI_PACKAGE:-@earendil-works/pi-coding-agent@${PI_VERSION}}"
ALLOW_VERSION_MISMATCH=0

python_is_supported() {
  "$1" -c 'import sys; raise SystemExit(0 if (3, 11) <= sys.version_info[:2] < (3, 14) else 1)' >/dev/null 2>&1
}

if [ -n "${PENPAL_PYTHON:-}" ]; then
  if ! command -v "$PENPAL_PYTHON" >/dev/null 2>&1 || ! python_is_supported "$PENPAL_PYTHON"; then
    echo "error: PENPAL_PYTHON must name Python 3.11, 3.12, or 3.13" >&2
    exit 1
  fi
else
  for candidate in python3.13 python3.12 python3.11 python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && python_is_supported "$candidate"; then
      PENPAL_PYTHON="$candidate"
      break
    fi
  done
  if [ -z "${PENPAL_PYTHON:-}" ]; then
    echo "error: Python 3.11, 3.12, or 3.13 is required" >&2
    exit 1
  fi
fi
export PENPAL_PYTHON
echo "PenPal Python: $PENPAL_PYTHON ($("$PENPAL_PYTHON" --version 2>&1))"

if ! command -v node >/dev/null 2>&1; then
  echo "error: Node.js is required for PI. Install Node.js, then rerun ./scripts/setup-pi.sh" >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "error: npm is required for PI. Install npm, then rerun ./scripts/setup-pi.sh" >&2
  exit 1
fi

if ! node -e 'const [major, minor] = process.versions.node.split(".").map(Number); process.exit(major > 22 || (major === 22 && minor >= 19) ? 0 : 1)'; then
  echo "error: PI ${PI_VERSION} requires Node.js 22.19.0 or newer; found $(node --version)" >&2
  exit 1
fi

install_pi() {
  echo "Installing tested PI: ${PI_PACKAGE}"
  npm install -g --ignore-scripts "${PI_PACKAGE}"
}

if command -v pi >/dev/null 2>&1; then
  INSTALLED_VERSION="$(pi --version)"
  if [ "$INSTALLED_VERSION" = "$PI_VERSION" ]; then
    echo "PI already installed at tested version: ${INSTALLED_VERSION}"
  elif [ "${PI_FORCE_INSTALL:-0}" = "1" ]; then
    echo "Replacing PI ${INSTALLED_VERSION} with tested version ${PI_VERSION}."
    install_pi
  else
    echo "PI ${INSTALLED_VERSION} is installed; PenPal is pinned and tested with ${PI_VERSION}."
    echo "Keeping the installed version and running the compatibility smoke. Set PI_FORCE_INSTALL=1 to replace it."
    ALLOW_VERSION_MISMATCH=1
  fi
else
  install_pi
fi

if [ "$ALLOW_VERSION_MISMATCH" = "1" ]; then
  PI_ALLOW_VERSION_MISMATCH=1 node "$ROOT_DIR/scripts/check-pi.mjs"
else
  node "$ROOT_DIR/scripts/check-pi.mjs"
fi

cat <<'EOF'

Next:
  pi
  /login
  /penpal-status

Then tell PI to create an authorized target and paste enumeration output into the conversation.
EOF

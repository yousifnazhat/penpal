#!/usr/bin/env bash
set -eu

PI_PACKAGE="${PI_PACKAGE:-@earendil-works/pi-coding-agent}"

if ! command -v node >/dev/null 2>&1; then
  echo "error: Node.js is required for PI. Install Node.js, then rerun ./scripts/setup-pi.sh" >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "error: npm is required for PI. Install npm, then rerun ./scripts/setup-pi.sh" >&2
  exit 1
fi

if command -v pi >/dev/null 2>&1; then
  echo "PI already installed: $(pi --version)"
else
  echo "Installing PI: ${PI_PACKAGE}"
  npm install -g --ignore-scripts "${PI_PACKAGE}"
  echo "PI installed: $(pi --version)"
fi

cat <<'EOF'

Next:
  pi
  /login

Then from this repository:
  export PENPAL_CWD="$PWD"
  export PENPAL_WORKSPACE=penpal-workspace
  pi -e ./examples/pi/penpal-extension.example.ts
EOF

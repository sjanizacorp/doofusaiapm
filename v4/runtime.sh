#!/bin/sh
# Select a compatible Python before loading the compiled lifecycle module.
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
runner="$here/lifecycle.py"
if [ ! -f "$runner" ]; then
    runner="$here/lifecycle.pyc"
fi
if [ ! -f "$runner" ]; then
    echo "DoofusAI SPM: lifecycle runtime is missing. Extract the complete package again." >&2
    exit 1
fi

compatible() {
    command -v "$1" >/dev/null 2>&1 || return 1
    "$1" -c '
import importlib.util
from pathlib import Path
import sys
runtime = Path(sys.argv[1])
if sys.implementation.name != "cpython" or sys.version_info[:2] != (3, 13):
    raise SystemExit(1)
if runtime.suffix == ".pyc":
    with runtime.open("rb") as file:
        if file.read(4) != importlib.util.MAGIC_NUMBER:
            raise SystemExit(1)
' "$runner" >/dev/null 2>&1
}

# Installed controls use their own environment first.
if [ -f "$here/../.doofusai-spm-installation" ] && compatible "$here/../venv/bin/python"; then
    exec "$here/../venv/bin/python" -B "$runner" "$@"
fi

if [ -n "${DOOFUS_PYTHON:-}" ]; then
    if compatible "$DOOFUS_PYTHON"; then
        exec "$DOOFUS_PYTHON" -B "$runner" "$@"
    fi
    echo "DoofusAI SPM: DOOFUS_PYTHON must point to a compatible CPython 3.13 executable." >&2
    echo "Example: DOOFUS_PYTHON=/path/to/python3.13 ./install.sh" >&2
    exit 1
fi

for candidate in python3.13 python3 \
    /Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13 \
    /opt/homebrew/bin/python3.13 /usr/local/bin/python3.13 /usr/bin/python3.13
do
    if compatible "$candidate"; then
        exec "$candidate" -B "$runner" "$@"
    fi
done

echo "DoofusAI SPM: a compatible CPython 3.13 installation was not found." >&2
echo "Install CPython 3.13, then run this command again." >&2
echo "If it is already installed, set DOOFUS_PYTHON to its full executable path." >&2
echo "If CPython 3.13 is present but rejected, extract a fresh copy of the client ZIP." >&2
exit 1

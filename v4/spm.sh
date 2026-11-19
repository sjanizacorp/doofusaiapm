#!/bin/sh
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
runner="$here/lifecycle.py"
[ -f "$runner" ] || runner="$here/lifecycle.pyc"
exec "${DOOFUS_PYTHON:-python3}" -B "$runner" "spm" "$@"

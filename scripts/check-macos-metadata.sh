#!/bin/sh

set -eu

if [ "$#" -gt 1 ]; then
    echo "usage: $0 [repository-root]" >&2
    exit 2
fi

if [ "$#" -eq 1 ]; then
    scan_root=$1
else
    script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    scan_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
fi

if [ ! -d "$scan_root" ]; then
    echo "repository root does not exist: $scan_root" >&2
    exit 2
fi

pollution_file=$(mktemp "${TMPDIR:-/tmp}/xminds-macos-metadata.XXXXXX")
trap 'rm -f "$pollution_file"' EXIT HUP INT TERM

find "$scan_root" \
    -path "$scan_root/.git" -prune -o \
    \( \
        -name '.DS_Store' -o \
        -name '._*' -o \
        -name '__MACOSX' -o \
        -name '.AppleDouble' -o \
        -name 'AppleDouble' -o \
        -name 'FinderInfo' -o \
        -name 'ResourceFork' \
    \) -print >"$pollution_file"

if [ -s "$pollution_file" ]; then
    echo "macOS metadata pollution detected:" >&2
    sed 's/^/  - /' "$pollution_file" >&2
    exit 1
fi

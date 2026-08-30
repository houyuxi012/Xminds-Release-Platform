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

cd "$scan_root"

find . \
    -type d \( \
        -name '.git' -o \
        -name 'node_modules' -o \
        -name 'dist' -o \
        -name '.cache' -o \
        -name 'coverage' \
    \) -prune -o \
    -type f \( -name '*.go' -o -name '*.ts' -o -name '*.tsx' \) \
    -exec awk '
        function check_import_line(line) {
            remaining = line
            while (match(remaining, /["\047](\.\.\/)+/)) {
                parent_count = (RLENGTH - 1) / 3
                source_path = FILENAME
                sub(/^\.\//, "", source_path)

                if (source_path !~ /\//) {
                    directory_depth = 0
                } else {
                    sub(/\/[^\/]+$/, "", source_path)
                    directory_depth = split(source_path, segments, "/")
                }

                if (parent_count > directory_depth) {
                    printf "boundary violation: %s:%d imports outside repository\n", FILENAME, FNR > "/dev/stderr"
                    invalid = 1
                }

                remaining = substr(remaining, RSTART + RLENGTH)
            }
        }
        FNR == 1 {
            in_go_import_block = 0
        }
        FILENAME ~ /\.go$/ {
            if ($0 ~ /^[[:space:]]*import[[:space:]]*\(/) {
                in_go_import_block = 1
                next
            }
            if (in_go_import_block && $0 ~ /^[[:space:]]*\)/) {
                in_go_import_block = 0
                next
            }
            if ($0 ~ /^[[:space:]]*import[[:space:]]*["\047](\.\.\/)+/ ||
                (in_go_import_block && $0 ~ /^[[:space:]]*["\047](\.\.\/)+/)) {
                check_import_line($0)
            }
            next
        }
        {
            if ($0 ~ /^[[:space:]]*(import|export)[[:space:]]/ ||
                $0 ~ /(require|import)[[:space:]]*\(/) {
                check_import_line($0)
            }
        }
        END { exit invalid }
    ' {} +

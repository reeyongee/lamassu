#!/bin/sh
# run.sh <events.jsonl> <spans.jsonl> [--match=..] [--secs=..]
#
# Builds the replay driver (core + tree + replay, libc only, C11, -Werror) and
# runs it. stdout is the CONTRACTS.md §9 stream; stderr is diagnostics plus the
# count table. Exit status is replay's: 0 on a clean run, non-zero on a
# malformed fixture (never a crash).
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/.." && pwd)

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <events.jsonl> <spans.jsonl> [core flags...]" >&2
    exit 2
fi

bin="${TMPDIR:-/tmp}/lamassu_replay.$$"
cc -std=c11 -Wall -Wextra -Werror -D_GNU_SOURCE -I "$root/core" \
   -o "$bin" \
   $(ls "$root"/core/*.c | grep -v selftest.c) \
   "$root/replay/replay.c"

set +e
"$bin" "$@"
rc=$?
set -e
rm -f "$bin"
exit $rc

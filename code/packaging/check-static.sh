#!/bin/sh
# Fail unless every BINARY is a statically linked ELF executable: `file`
# says so, there is no program interpreter and no DT_NEEDED entry. With
# --ldd (native architecture only) the dynamic loader must agree too:
# "not a dynamic executable" (static) or "statically linked" (static-pie).
set -eu

use_ldd=0
if [ "${1:-}" = "--ldd" ]; then
    use_ldd=1
    shift
fi
if [ "$#" -eq 0 ]; then
    echo "usage: $0 [--ldd] BINARY..." >&2
    exit 2
fi

for b in "$@"; do
    info=$(file -b "$b")
    echo "$b: $info"
    case "$info" in
        ELF*"statically linked"* | ELF*"static-pie linked"*) ;;
        *)
            echo "::error::$b is not a statically linked ELF executable" >&2
            exit 1
            ;;
    esac
    if readelf -lW "$b" | grep -q 'Requesting program interpreter'; then
        echo "::error::$b requests a program interpreter" >&2
        exit 1
    fi
    if readelf -dW "$b" | grep -q '(NEEDED)'; then
        echo "::error::$b needs shared libraries" >&2
        exit 1
    fi
    if [ "$use_ldd" = 1 ]; then
        out=$(ldd "$b" 2>&1 || true)
        echo "  ldd: $out"
        case "$out" in
            *"not a dynamic executable"* | *"statically linked"*) ;;
            *)
                echo "::error::ldd lists dynamic dependencies for $b" >&2
                exit 1
                ;;
        esac
    fi
done

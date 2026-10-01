#!/bin/sh
# Write CycloneDX SBOMs (JSON, spec 1.5, every dependency) of the three
# shipped programs as built for TARGET into OUTDIR as
# <program>.<TARGET>.cdx.json. Run from code/ with cargo-cyclonedx on PATH.
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 TARGET OUTDIR" >&2
    exit 2
fi
target=$1
out=$2
mkdir -p "$out"

# cargo-cyclonedx writes one file per binary next to each crate's manifest.
cargo cyclonedx --format json --spec-version 1.5 --all --describe binaries \
    --target "$target" --target-in-filename

for bin in broker brokerd broker-sandbox-shim; do
    found=$(find crates -name "${bin}_bin_${target}.cdx.json")
    if [ -z "$found" ] || [ "$(printf '%s\n' "$found" | wc -l)" -ne 1 ]; then
        echo "::error::expected one SBOM for $bin ($target), found: ${found:-none}" >&2
        exit 1
    fi
    dst="$out/$bin.$target.cdx.json"
    mv "$found" "$dst"
    # Fail closed on an empty or malformed SBOM.
    jq -e '.bomFormat == "CycloneDX" and (.components | length) > 0' "$dst" >/dev/null || {
        echo "::error::$dst is not a CycloneDX SBOM with components" >&2
        exit 1
    }
    echo "$dst: $(jq '.components | length' "$dst") components"
done

# Drop the SBOMs of crates that are not shipped (libraries, test binaries).
find crates tests -name '*.cdx.json' -exec rm -f {} +

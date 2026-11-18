#!/usr/bin/env bash
# Time each upstream SURI stage and compare generated assembly on a C fixture.
set -euo pipefail
if [[ $# != 3 ]]; then
    echo "Usage: $0 SURI_CHECKOUT CC1 NEW_RESULTS_DIR" >&2
    exit 2
fi
suri=$(realpath "$1")
input=$(realpath "$2")
[[ -x "$input" ]]
results=$(realpath -m "$3")
if [[ "$results" == *[!a-zA-Z0-9_./-]* ]]; then
    echo "Results path must contain only letters, digits, _, ., /, and -" >&2
    exit 2
fi
mkdir -- "$results"
cd -- "$results"
export LC_ALL=C
export PYTHONPATH="$suri${PYTHONPATH:+:$PYTHONPATH}"
dotnet_bin=${DOTNET:-dotnet}
python_bin=${PYTHON:-python3}
builder="$suri/superCFGBuilder/superCFGBuilder/bin/Release/net9.0/superCFGBuilder.dll"
[[ -f "$builder" ]]
{
    git -C "$suri" rev-parse HEAD
    git -C "$suri" submodule status
    git -C "$suri" diff --stat
    lscpu || nproc
    "$dotnet_bin" --version
    uname -a
    sha256sum "$input"
    readelf -dW "$input"
    stat -c '%s bytes' "$input"
    readelf -hW -SW -nW "$input"
} > environment.txt
run_stage() {
    local name=$1
    shift
    echo "Running $name" >&2
    "${GNU_TIME:-/usr/bin/time}" -o "$name.time" -f 'wall_seconds=%e\nuser_seconds=%U\nsystem_seconds=%S\nmax_rss_kib=%M\nexit_status=%x' \
        timeout --kill-after=30s "${STAGE_TIMEOUT:-2h}" "$@" >"$name.log" 2>&1
}
run_stage recovery "$dotnet_bin" "$builder" "$input" recovered.json
test -s recovered.json
run_stage symbolization "$python_bin" "$suri/superSymbolizer/SuperSymbolizer.py" \
    "$input" recovered.json recovered.s --optimization 3
test -s recovered.s
run_stage reassembly "$python_bin" "$suri/superSymbolizer/CustomCompiler.py" \
    "$input" recovered.s cc1 --verbose
test -x my_cc1
readelf -hW my_cc1 > output-elf.txt
cat > fixture.i <<'C'
int sum(const int *p, int n) {
    int result = 0;
    for (int i = 0; i < n; ++i) result += p[i];
    return result;
}
C
run_stage original-smoke "$input" -quiet -O2 fixture.i -o original.s
run_stage rewritten-smoke ./my_cc1 -quiet -O2 fixture.i -o rewritten.s
test -s original.s
cmp original.s rewritten.s
echo 'PASS: original and rewritten cc1 emitted identical assembly'

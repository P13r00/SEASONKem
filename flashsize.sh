#!/usr/bin/env bash
#
# flash_bss_sweep.sh
#
# Measures per-algorithm (and per-combination) Flash and static BSS by
# building isolated binaries and diffing against a "__RUNTIME__" baseline
# (harness + shared malloc/RNG runtime, zero crypto algorithms) so shared
# fixed cost doesn't get double-attributed to every algorithm that uses it.
#
# EDIT THE THREE SECTIONS MARKED "EDIT ME" BELOW, then run:
#   bash flash_bss_sweep.sh
#
set -e

# ---------------------------------------------------------------------------
# EDIT ME (1): single algorithms to measure individually.
# Must match COMPILE_<NAME> entries in benchmark_config.h / ALGO_LIST in
# CMakeLists.txt exactly.
# ---------------------------------------------------------------------------
ALGOS=(
    CHACHA20_POLY1305
    LWC_SPARKLE_AEAD256
    LWC_SPARKLE_AEAD192
    LWC_ASCON80PQ_AEAD
    LWC_XOODYAK_AEAD
    LWC_SPARKLE_HASHXOF
    LWC_SPARKLE_HASH256
    LWC_XOODYAK_HASH
    LWC_ASCON_HASHXOF
)

# ---------------------------------------------------------------------------
# EDIT ME (2): named combinations. Give each a short label (used as the map
# key — bash 4+ required for associative arrays) and list the algorithm
# names joined with '+' (not ';' or ',' — '+' passes through the cmake -D
# command line as a single shell argument without escaping headaches).
#
# Every name referenced here must already exist as a COMPILE_<NAME> macro
# and an ALGO_LIST entry in CMakeLists.txt / benchmark_config.h, or the
# build will fail loudly (on purpose) with "not a recognized algorithm".
# ---------------------------------------------------------------------------
declare -A COMBOS
COMBOS["xoodyak_suite"]="LWC_XOODYAK_HASH+LWC_XOODYAK_AEAD"
COMBOS["sparkle_suite"]="LWC_SPARKLE_HASHXOF+LWC_SPARKLE_AEAD256"
COMBOS["ascon_suite"]="LWC_ASCON_HASHXOF+LWC_ASCON80PQ_AEAD"
COMBOS["flexwing0"]="FLEXWING0+PQM4_KYBER512+WOLF_X25519+PQM4_SHA3_256+CHACHA20_POLY1305"
COMBOS["flexwing1"]="FLEXWING1+PQM4_KYBER512+WOLF_X25519+LWC_XOODYAK_HASH+LWC_XOODYAK_AEAD"
COMBOS["flexwing2"]="FLEXWING2+PQM4_KYBER512+WOLF_X25519+LWC_ASCON_HASHXOF+LWC_ASCON80PQ_AEAD"
COMBOS["flexwing3"]="FLEXWING3+PQM4_KYBER512+WOLF_X25519+LWC_SPARKLE_HASHXOF+LWC_SPARKLE_AEAD256"

# ---------------------------------------------------------------------------
# EDIT ME (3): build directory / tool names, if your setup differs.
# ---------------------------------------------------------------------------
BUILD_DIR="build_iso"
CMAKE_BIN="cmake"
SIZE_BIN="arm-none-eabi-size"
TARGET_PLATFORM="STM32"
ELF_NAME="stm32_benchmark.elf"

# ===========================================================================
# Implementation below — shouldn't need to edit past this line.
# ===========================================================================

build_and_measure() {
    local iso="$1"
    rm -rf "$BUILD_DIR"
    mkdir "$BUILD_DIR"
    (
        cd "$BUILD_DIR"
        "$CMAKE_BIN" -DTARGET_PLATFORM="$TARGET_PLATFORM" -DISOLATE_ALGO="$iso" .. > /dev/null
        "$CMAKE_BIN" --build . > /dev/null
    )
    # SysV size format, row 2 is: text data bss dec hex filename
    read -r flash bss < <("$SIZE_BIN" "$BUILD_DIR/$ELF_NAME" | awk 'NR==2{print $1, $3}')
    echo "$flash $bss"
}

echo "=== Baseline & shared runtime ==="
read -r BASE_F BASE_B < <(build_and_measure "__NONE__")
echo "Baseline (harness only):        flash=$BASE_F  bss=$BASE_B"

read -r RT_F RT_B < <(build_and_measure "__RUNTIME__")
RT_DF=$((RT_F - BASE_F))
RT_DB=$((RT_B - BASE_B))
echo "Shared crypto runtime overhead:  flash=$RT_DF  bss=$RT_DB"
echo

echo "=== Single algorithms (net of shared runtime) ==="
for a in "${ALGOS[@]}"; do
    read -r F B < <(build_and_measure "$a")
    df=$((F - RT_F))
    db=$((B - RT_B))
    if [ "$db" -lt 0 ]; then
        # This algorithm never linked in malloc/RNG (e.g. pure hash/XOF) —
        # subtracting the runtime baseline overshoots. Report against true
        # zero baseline instead, with no shared-overhead attribution.
        df=$((F - BASE_F))
        db=$((B - BASE_B))
        echo "$a: flash=$df  bss=$db  (no shared runtime)"
    else
        echo "$a: flash=$df  bss=$db  (uses shared runtime)"
    fi
done
echo

if [ "${#COMBOS[@]}" -gt 0 ]; then
    echo "=== Named combinations (net of shared runtime) ==="
    for name in "${!COMBOS[@]}"; do
        combo="${COMBOS[$name]}"
        read -r F B < <(build_and_measure "$combo")
        df=$((F - RT_F))
        db=$((B - RT_B))
        if [ "$db" -lt 0 ]; then
            df=$((F - BASE_F))
            db=$((B - BASE_B))
            echo "$name ($combo): flash=$df  bss=$db  (no shared runtime)"
        else
            echo "$name ($combo): flash=$df  bss=$db  (uses shared runtime)"
        fi
    done
fi
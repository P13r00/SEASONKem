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
    CHACHA20_POLY1305 PQM4_DILITHIUM2 PQM4_FALCON512 PQM4_KYBER512 PQM4_KYBER768
    X25519 PQM4_SHA3_256 PQM4_SHAKE256 LWC_SPARKLE_AEAD256 LWC_SPARKLE_AEAD128
    LWC_SPARKLE_AEAD192 LWC_SPARKLE_HASHXOF256 LWC_SPARKLE_HASHXOF384 LWC_XOODYAK_HASH
    LWC_ASCON80PQ_AEAD LWC_ASCON128_AEAD LWC_ASCON_HASHXOF
    LWC_ASCON_HASH256 
    LWC_SPARKLE_HASH256
    LWC_SPARKLE_HASH384
    LWC_XOODYAK_AEAD LWC_SPARKLE_HASH384 AES_GCM192 AES_GCM256
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
#COMBOS["trad_suite"]="PQM4_SHA3_256+CHACHA20_POLY1305"
#COMBOS["xoodyak_suite"]="LWC_XOODYAK_HASH+LWC_XOODYAK_AEAD"
#COMBOS["sparkle_suite"]="LWC_SPARKLE_HASH256+LWC_SPARKLE_AEAD256"
#COMBOS["ascon_suite"]="LWC_ASCON_HASHXOF+LWC_ASCON80PQ_AEAD"

# XWing Combinations
COMBOS["xwing+chacha"]="XWING+PQM4_KYBER768+X25519+PQM4_SHA3_256+CHACHA20_POLY1305"
COMBOS["xwing+sparkle256"]="XWING+PQM4_KYBER768+X25519+PQM4_SHA3_256+LWC_SPARKLE_AEAD256"
COMBOS["xwing+sparkle128"]="XWING+PQM4_KYBER768+X25519+PQM4_SHA3_256+LWC_SPARKLE_AEAD128"
COMBOS["xwing+sparkle192"]="XWING+PQM4_KYBER768+X25519+PQM4_SHA3_256+LWC_SPARKLE_AEAD192"
COMBOS["xwing+ascon80pq"]="XWING+PQM4_KYBER768+X25519+PQM4_SHA3_256+LWC_ASCON80PQ_AEAD"
COMBOS["xwing+ascon"]="XWING+PQM4_KYBER768+X25519+PQM4_SHA3_256+LWC_ASCON128_AEAD"
COMBOS["xwing+xoodyak"]="XWING+PQM4_KYBER768+X25519+PQM4_SHA3_256+LWC_XOODYAK_AEAD"
COMBOS["xwing+aes192"]="XWING+PQM4_KYBER768+X25519+PQM4_SHA3_256+AES_GCM192"
COMBOS["xwing+aes256"]="XWING+PQM4_KYBER768+X25519+PQM4_SHA3_256+AES_GCM256"

# Season0 Combinations
COMBOS["season0+chacha"]="SEASON0+PQM4_KYBER512+X25519+PQM4_SHA3_256+CHACHA20_POLY1305"
COMBOS["season0+sparkle256"]="SEASON0+PQM4_KYBER512+X25519+PQM4_SHA3_256+LWC_SPARKLE_AEAD256"
COMBOS["season0+sparkle128"]="SEASON0+PQM4_KYBER512+X25519+PQM4_SHA3_256+LWC_SPARKLE_AEAD128"
COMBOS["season0+sparkle192"]="SEASON0+PQM4_KYBER512+X25519+PQM4_SHA3_256+LWC_SPARKLE_AEAD192"
COMBOS["season0+ascon80pq"]="SEASON0+PQM4_KYBER512+X25519+PQM4_SHA3_256+LWC_ASCON80PQ_AEAD"
COMBOS["season0+ascon"]="SEASON0+PQM4_KYBER512+X25519+PQM4_SHA3_256+LWC_ASCON128_AEAD"
COMBOS["season0+xoodyak"]="SEASON0+PQM4_KYBER512+X25519+PQM4_SHA3_256+LWC_XOODYAK_AEAD"
COMBOS["season0+aes192"]="SEASON0+PQM4_KYBER512+X25519+PQM4_SHA3_256+AES_GCM192"
COMBOS["season0+aes256"]="SEASON0+PQM4_KYBER512+X25519+PQM4_SHA3_256+AES_GCM256"

# Spring Combinations
COMBOS["spring+chacha"]="SPRING+PQM4_KYBER512+X25519+LWC_XOODYAK_HASH+CHACHA20_POLY1305"
COMBOS["spring+sparkle256"]="SPRING+PQM4_KYBER512+X25519+LWC_XOODYAK_HASH+LWC_SPARKLE_AEAD256"
COMBOS["spring+sparkle128"]="SPRING+PQM4_KYBER512+X25519+LWC_XOODYAK_HASH+LWC_SPARKLE_AEAD128"
COMBOS["spring+sparkle192"]="SPRING+PQM4_KYBER512+X25519+LWC_XOODYAK_HASH+LWC_SPARKLE_AEAD192"
COMBOS["spring+ascon80pq"]="SPRING+PQM4_KYBER512+X25519+LWC_XOODYAK_HASH+LWC_ASCON80PQ_AEAD"
COMBOS["spring+ascon"]="SPRING+PQM4_KYBER512+X25519+LWC_XOODYAK_HASH+LWC_ASCON128_AEAD"
COMBOS["spring+xoodyak"]="SPRING+PQM4_KYBER512+X25519+LWC_XOODYAK_HASH+LWC_XOODYAK_AEAD"
COMBOS["spring+aes192"]="SPRING+PQM4_KYBER512+X25519+LWC_XOODYAK_HASH+AES_GCM192"
COMBOS["spring+aes256"]="SPRING+PQM4_KYBER512+X25519+LWC_XOODYAK_HASH+AES_GCM256"

# Summer Combinations
COMBOS["summer+chacha"]="SUMMER+PQM4_KYBER512+X25519+LWC_ASCON_HASH256+CHACHA20_POLY1305"
COMBOS["summer+sparkle256"]="SUMMER+PQM4_KYBER512+X25519+LWC_ASCON_HASH256+LWC_SPARKLE_AEAD256"
COMBOS["summer+sparkle128"]="SUMMER+PQM4_KYBER512+X25519+LWC_ASCON_HASH256+LWC_SPARKLE_AEAD128"
COMBOS["summer+sparkle192"]="SUMMER+PQM4_KYBER512+X25519+LWC_ASCON_HASH256+LWC_SPARKLE_AEAD192"
COMBOS["summer+ascon80pq"]="SUMMER+PQM4_KYBER512+X25519+LWC_ASCON_HASH256+LWC_ASCON80PQ_AEAD"
COMBOS["summer+ascon"]="SUMMER+PQM4_KYBER512+X25519+LWC_ASCON_HASH256+LWC_ASCON128_AEAD"
COMBOS["summer+xoodyak"]="SUMMER+PQM4_KYBER512+X25519+LWC_ASCON_HASH256+LWC_XOODYAK_AEAD"
COMBOS["summer+aes192"]="SUMMER+PQM4_KYBER512+X25519+LWC_ASCON_HASH256+AES_GCM192"
COMBOS["summer+aes256"]="SUMMER+PQM4_KYBER512+X25519+LWC_ASCON_HASH256+AES_GCM256"

# Autumn Combinations
COMBOS["autumn+chacha"]="AUTUMN+PQM4_KYBER512+X25519+LWC_SPARKLE_HASH256+CHACHA20_POLY1305"
COMBOS["autumn+sparkle256"]="AUTUMN+PQM4_KYBER512+X25519+LWC_SPARKLE_HASH256+LWC_SPARKLE_AEAD256"
COMBOS["autumn+sparkle128"]="AUTUMN+PQM4_KYBER512+X25519+LWC_SPARKLE_HASH256+LWC_SPARKLE_AEAD128"
COMBOS["autumn+sparkle192"]="AUTUMN+PQM4_KYBER512+X25519+LWC_SPARKLE_HASH256+LWC_SPARKLE_AEAD192"
COMBOS["autumn+ascon80pq"]="AUTUMN+PQM4_KYBER512+X25519+LWC_SPARKLE_HASH256+LWC_ASCON80PQ_AEAD"
COMBOS["autumn+ascon"]="AUTUMN+PQM4_KYBER512+X25519+LWC_SPARKLE_HASH256+LWC_ASCON128_AEAD"
COMBOS["autumn+xoodyak"]="AUTUMN+PQM4_KYBER512+X25519+LWC_SPARKLE_HASH256+LWC_XOODYAK_AEAD"
COMBOS["autumn+aes192"]="AUTUMN+PQM4_KYBER512+X25519+LWC_SPARKLE_HASH256+AES_GCM192"
COMBOS["autumn+aes256"]="AUTUMN+PQM4_KYBER512+X25519+LWC_SPARKLE_HASH256+AES_GCM256"

# Winter Combinations
COMBOS["winter+chacha"]="WINTER+PQM4_KYBER768+X25519+LWC_SPARKLE_HASH384+CHACHA20_POLY1305"
COMBOS["winter+sparkle256"]="WINTER+PQM4_KYBER768+X25519+LWC_SPARKLE_HASH384+LWC_SPARKLE_AEAD256"
COMBOS["winter+sparkle128"]="WINTER+PQM4_KYBER768+X25519+LWC_SPARKLE_HASH384+LWC_SPARKLE_AEAD128"
COMBOS["winter+sparkle192"]="WINTER+PQM4_KYBER768+X25519+LWC_SPARKLE_HASH384+LWC_SPARKLE_AEAD192"
COMBOS["winter+ascon80pq"]="WINTER+PQM4_KYBER768+X25519+LWC_SPARKLE_HASH384+LWC_ASCON80PQ_AEAD"
COMBOS["winter+ascon"]="WINTER+PQM4_KYBER768+X25519+LWC_SPARKLE_HASH384+LWC_ASCON128_AEAD"
COMBOS["winter+xoodyak"]="WINTER+PQM4_KYBER768+X25519+LWC_SPARKLE_HASH384+LWC_XOODYAK_AEAD"
COMBOS["winter+aes192"]="WINTER+PQM4_KYBER768+X25519+LWC_SPARKLE_HASH384+AES_GCM192"
COMBOS["winter+aes256"]="WINTER+PQM4_KYBER768+X25519+LWC_SPARKLE_HASH384+AES_GCM256"

#COMBOS["xwingRAW"]="XWING+PQM4_KYBER768+X25519+PQM4_SHA3_256"
#COMBOS["season0RAW"]="SEASON0+PQM4_KYBER512+X25519+PQM4_SHA3_256"
#COMBOS["springRAW"]="SPRING+PQM4_KYBER512+X25519+LWC_XOODYAK_HASH"
#COMBOS["summerRAW"]="SUMMER+PQM4_KYBER512+X25519+LWC_ASCON_HASH256"
#COMBOS["autumnRAW"]="AUTUMN+PQM4_KYBER512+X25519+LWC_SPARKLE_HASH256"
#COMBOS["winterRAW"]="WINTER+PQM4_KYBER768+X25519+LWC_SPARKLE_HASH384"


# ---------------------------------------------------------------------------
# EDIT ME (3): build directory / tool names, if your setup differs.
# ---------------------------------------------------------------------------
BUILD_DIR="build_iso"
CMAKE_BIN="cmake"
SIZE_BIN="arm-none-eabi-size"
TARGET_PLATFORM="STM32F411_NUCLEO"
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
cmake_minimum_required(VERSION 3.15)

if(TARGET_PLATFORM STREQUAL "STM32")
    set(CMAKE_SYSTEM_NAME Generic)
    set(CMAKE_SYSTEM_PROCESSOR arm)

    set(CMAKE_C_COMPILER   arm-none-eabi-gcc)
    set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
    set(CMAKE_OBJCOPY      arm-none-eabi-objcopy)
    set(CMAKE_SIZE         arm-none-eabi-size)

    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
endif()

project(crypto_heterogeneous_benchmark C ASM)

set(CMAKE_C_STANDARD 99)

# ---------------------------------------------------------------------------
# Master algorithm list — single source of truth, used both for parsing
# benchmark_config.h defaults and for ISOLATE_ALGO override below.
# ---------------------------------------------------------------------------
set(ALGO_LIST
    ASCON80 ASCON_AEAD128 ASCON_HASH256 ASCON_XOF
    PQM4_KYBER512 PQM4_KYBER768 PQM4_DILITHIUM2 PQM4_FALCON512
    X25519 PQM4_SHA3_256 PQM4_SHAKE256 CHACHA20_POLY1305
    LWC_SPARKLE_AEAD256 LWC_SPARKLE_AEAD192 LWC_SPARKLE_HASHXOF
    LWC_SPARKLE_HASH256 LWC_XOODYAK_HASH LWC_ASCON80PQ_AEAD
    LWC_ASCON_HASHXOF LWC_XOODYAK_AEAD 
    XWING FLEXWING0 FLEXWING1 FLEXWING2 FLEXWING3
)
# NOTE: WOLF_X25519 keeps its historical name for the ALGO_LIST slot / ops
# struct symbol, but no longer means "wolfCrypt" -- wolfCrypt has been fully
# removed (see below). X25519 is now provided by
# adapters/x25519/crypto_x25519.c, backed by the Emill X25519-Cortex-M4
# assembly library, vendored as a submodule at third_party/X25519-Cortex-M4.
# XWING and FLEXWING0-3 all depend on this X25519 KEX ops struct for their
# combiner. See docs/x25519-adapter-handover.md.

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/core/src/benchmark_config.h" RUNNER_CONTENT)

foreach(ALG ${ALGO_LIST})
    if(RUNNER_CONTENT MATCHES "#define[ \t]+COMPILE_${ALG}[ \t]+1")
        set(COMPILE_${ALG} 1)
    else()
        set(COMPILE_${ALG} 0)
    endif()
endforeach()

if(DEFINED ISOLATE_ALGO AND NOT ISOLATE_ALGO STREQUAL "")
    if(ISOLATE_ALGO STREQUAL "__NONE__" OR ISOLATE_ALGO STREQUAL "__RUNTIME__")
        foreach(ALG ${ALGO_LIST})
            set(COMPILE_${ALG} 0)
        endforeach()
    else()
        # Accept a '+'-separated combination, e.g.
        # -DISOLATE_ALGO="LWC_XOODYAK_AEAD+LWC_XOODYAK_HASH"
        string(REPLACE "+" ";" _isolate_requested "${ISOLATE_ALGO}")

        # Validate every requested name up front so a typo fails loudly
        # instead of silently compiling zero algorithms.
        foreach(REQ ${_isolate_requested})
            list(FIND ALGO_LIST "${REQ}" _valid_idx)
            if(_valid_idx EQUAL -1)
                message(FATAL_ERROR "ISOLATE_ALGO entry '${REQ}' is not a recognized "
                                     "algorithm. Valid names: ${ALGO_LIST}")
            endif()
        endforeach()

        foreach(ALG ${ALGO_LIST})
            list(FIND _isolate_requested "${ALG}" _idx)
            if(_idx EQUAL -1)
                set(COMPILE_${ALG} 0)
            else()
                set(COMPILE_${ALG} 1)
            endif()
        endforeach()
    endif()

    message(STATUS "ISOLATE_ALGO active: ${ISOLATE_ALGO}")
endif()

set(CORE_SOURCES
    core/src/benchmark_runner.c
    core/src/benchmark_metrics.c
    core/src/benchmarks/bm_aead.c
    core/src/benchmarks/bm_hash.c
    core/src/benchmarks/bm_kdf.c
    core/src/benchmarks/bm_kem.c
    core/src/benchmarks/bm_kex.c
    core/src/benchmarks/bm_signature.c
)

if (COMPILE_XWING)
    list(APPEND CORE_SOURCES "adapters/xwing.c")
endif()
if (COMPILE_FLEXWING0)
    list(APPEND CORE_SOURCES "adapters/flexwing0.c")
endif()
if (COMPILE_FLEXWING1)
    list(APPEND CORE_SOURCES "adapters/flexwing1.c")
endif()
if (COMPILE_FLEXWING2)
    list(APPEND CORE_SOURCES "adapters/flexwing2.c")
endif()
if (COMPILE_FLEXWING3)
    list(APPEND CORE_SOURCES "adapters/flexwing3.c")
endif()

# --- RNG architecture ---------------------------------------------------
# wolfCrypt has been fully removed from the project, RNG included. There is
# no third_party/wolfssl dependency, no WC_RNG type, and no
# CUSTOM_RAND_GENERATE_BLOCK hook left anywhere.
#
# The single hardware-facing RNG source is
# platforms/stm32_renode/adapter_rng_seed.c (int randombytes(uint8_t*,
# size_t), polled directly off the STM32F4 RNG peripheral registers).
# adapters/adapter_rng.c is portable, backend-agnostic middleware over that
# one function -- PQM4 (via PQCLEAN_randombytes), ASCON, and lwc-finalists
# all draw from it. It is compiled unconditionally: every backend needs
# randomness, so this isn't gated behind any COMPILE_* flag.
# -------------------------------------------------------------------------
set(RNG_SOURCES
    adapters/adapter_rng.c
)

set(WOLFCRYPT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl)
set(WOLFCRYPT_SOURCES "")
list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/wc_port.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/memory.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/misc.c
)
set(WOLFCRYPT_INCLUDES
    ${WOLFCRYPT_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/adapters/wolf   # location of user_settings.h -- adjust if it lives elsewhere
)

if(COMPILE_CHACHA20_POLY1305)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/chacha.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/poly1305.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/chacha20_poly1305.c
    )
    list(APPEND CORE_SOURCES "adapters/wolf/crypto_chacha20_poly1305.c")
endif()

# --- X25519 -----------------------------------------------------------
# The previous X25519 KEX adapter (adapters/wolf/crypto_wolf_x25519.c) was
# wolfCrypt-based and has been removed along with wolfCrypt itself. It is
# replaced by adapters/x25519/crypto_x25519.c, backed by Emil Lenngren's
# X25519-Cortex-M4 assembly library, vendored as a git submodule:
# https://github.com/Emill/X25519-Cortex-M4
#
# Added via:
#   git submodule add https://github.com/Emill/X25519-Cortex-M4 third_party/X25519-Cortex-M4
# and checked out with the rest of the submodules via
#   git submodule update --init --recursive
#
# The adapter still exports its ops struct as `wolf_x25519_ops`, so XWING
# and FLEXWING0-3 (adapters/xwing.c, adapters/flexwing0.c-flexwing3.c) did
# not need to change.
set(X25519_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/X25519-Cortex-M4)
set(X25519_SOURCES "")
set(X25519_INCLUDES
    ${X25519_DIR}
)

if(COMPILE_X25519)
    if(NOT EXISTS ${X25519_DIR}/x25519-cortex-m4-gcc.s)
        message(FATAL_ERROR "third_party/X25519-Cortex-M4 submodule is missing or "
                             "not checked out. Run: git submodule update --init "
                             "--recursive")
    endif()
    list(APPEND X25519_SOURCES ${X25519_DIR}/x25519-cortex-m4-gcc.s)
    list(APPEND CORE_SOURCES "adapters/crypto_x25519.c")
endif()

set(ASCON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ascon)
set(ASCON_SOURCES "")
set(ASCON_INCLUDES
    ${ASCON_DIR}
    ${ASCON_DIR}/tests
)

if(COMPILE_ASCON80)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_aead/ascon80pqv12/armv7m/aead.c
        ${ASCON_DIR}/crypto_aead/ascon80pqv12/armv7m/permutations.c
    )
    list(APPEND CORE_SOURCES "adapters/ascon/crypto_ascon80pq.c")
endif()

if(COMPILE_ASCON_AEAD128)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_aead/ascon128abi32v12/bi32_armv7m/aead.c
        ${ASCON_DIR}/crypto_aead/ascon128abi32v12/bi32_armv7m/permutations.c
    )
    list(APPEND CORE_SOURCES "adapters/ascon/crypto_asconaead128.c")
endif()

if(COMPILE_ASCON_HASH256)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_hash/asconhashav12/bi32_armv7m_small/hash.c
        ${ASCON_DIR}/crypto_hash/asconhashav12/bi32_armv7m_small/permutations.c
        ${ASCON_DIR}/crypto_hash/asconhashav12/bi32_armv7m_small/interleave.c
        ${ASCON_DIR}/crypto_hash/asconhashav12/bi32_armv7m_small/constants.c
    )
    list(APPEND CORE_SOURCES "adapters/ascon/crypto_asconhash256.c")
endif()

if(COMPILE_ASCON_XOF)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_hash/asconxofav12/bi32_armv7m_small/hash.c
        ${ASCON_DIR}/crypto_hash/asconxofav12/bi32_armv7m_small/permutations.c
        ${ASCON_DIR}/crypto_hash/asconxofav12/bi32_armv7m_small/interleave.c
        ${ASCON_DIR}/crypto_hash/asconxofav12/bi32_armv7m_small/constants.c
    )
    list(APPEND CORE_SOURCES "adapters/ascon/crypto_asconxof.c")
endif()

set(PQM4_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/pqm4)
set(PQM4_SOURCES "")
set(PQM4_INCLUDES
    ${PQM4_DIR}/mupq/common
    ${PQM4_DIR}/crypto_sign/ml-dsa-44/m4f
    ${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f
    ${PQM4_DIR}
)

if(COMPILE_PQM4_KYBER512)
    file(GLOB PQM4_KEM_SOURCES
        "${PQM4_DIR}/crypto_kem/ml-kem-512/m4fspeed/*.c"
        "${PQM4_DIR}/crypto_kem/ml-kem-512/m4fspeed/*.S"
        "${PQM4_DIR}/crypto_kem/ml-kem-512/m4fspeed/*.s"
    )
    list(APPEND PQM4_SOURCES
        ${PQM4_KEM_SOURCES}
        ${PQM4_DIR}/mupq/common/fips202.c
        ${PQM4_DIR}/common/keccakf1600.S
    )
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_kyber512.c")
endif()

if(COMPILE_PQM4_KYBER768)
    file(GLOB PQM4_KEM_SOURCES
        "${PQM4_DIR}/crypto_kem/ml-kem-768/m4fspeed/*.c"
        "${PQM4_DIR}/crypto_kem/ml-kem-768/m4fspeed/*.S"
        "${PQM4_DIR}/crypto_kem/ml-kem-768/m4fspeed/*.s"
    )
    list(APPEND PQM4_SOURCES
        ${PQM4_KEM_SOURCES}
        ${PQM4_DIR}/mupq/common/fips202.c
        ${PQM4_DIR}/common/keccakf1600.S
    )
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_kyber768.c")
endif()

if(COMPILE_PQM4_DILITHIUM2)
    file(GLOB PQM4_SIGN_M4F_SOURCES
        "${PQM4_DIR}/crypto_sign/ml-dsa-44/m4f/*.c"
        "${PQM4_DIR}/crypto_sign/ml-dsa-44/m4f/*.S"
        "${PQM4_DIR}/crypto_sign/ml-dsa-44/m4f/*.s"
    )
    list(APPEND PQM4_SOURCES
        ${PQM4_SIGN_M4F_SOURCES}
        ${PQM4_DIR}/mupq/common/fips202.c
        ${PQM4_DIR}/common/keccakf1600.S
    )
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_dilithium2.c")
endif()

if(COMPILE_PQM4_FALCON512)
    file(GLOB PQM4_FALCON_SOURCES
        "${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f/*.c"
        "${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f/*.s"
        "${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f/*.S"
    )
    list(APPEND PQM4_SOURCES ${PQM4_FALCON_SOURCES})
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_falcon512.c")
endif()

if(COMPILE_PQM4_SHA3_256)
    list(APPEND PQM4_SOURCES
        ${PQM4_DIR}/mupq/common/fips202.c
        ${PQM4_DIR}/common/keccakf1600.S
    )
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_sha3_256.c")
endif()

if(COMPILE_PQM4_SHAKE256)
    list(APPEND PQM4_SOURCES
        ${PQM4_DIR}/mupq/common/fips202.c
        ${PQM4_DIR}/common/keccakf1600.S
    )
    list(APPEND CORE_SOURCES "adapters/pqm4/crypto_pqm4_shake256.c")
endif()

if(PQM4_SOURCES)
    list(REMOVE_DUPLICATES PQM4_SOURCES)
endif()


set(LWC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lwc-finalists)
set(LWC_SOURCES "")
set(LWC_INCLUDES
)

if(COMPILE_LWC_SPARKLE_AEAD256)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-aead.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
        ${LWC_DIR}/src/combined/internal-util.c
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_aead256.c")
endif()

if(COMPILE_LWC_SPARKLE_AEAD192)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-aead.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
        ${LWC_DIR}/src/combined/internal-util.c
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_aead192.c")
endif()

if(COMPILE_LWC_ASCON80PQ_AEAD)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/ascon-aead.c
        ${LWC_DIR}/src/combined/internal-ascon-armv7m.S
        ${LWC_DIR}/src/combined/internal-util.c
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_ascon80pq_aead.c")
endif()

if(COMPILE_LWC_SPARKLE_HASHXOF)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-hash.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_hashxof.c")
endif()

if(COMPILE_LWC_SPARKLE_HASH256)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-hash.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_hash256.c")
endif()

if(COMPILE_LWC_XOODYAK_HASH)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/xoodyak-hash.c
        ${LWC_DIR}/src/combined/internal-xoodoo-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_xoodyak.c")
endif()

if(COMPILE_LWC_ASCON_HASHXOF)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/ascon-xof.c
        ${LWC_DIR}/src/combined/internal-ascon-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_ascon_hashxof.c")
endif()

if(COMPILE_LWC_XOODYAK_AEAD)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/xoodyak-aead.c
        ${LWC_DIR}/src/combined/internal-xoodoo-armv7m.S
        ${LWC_DIR}/src/combined/internal-util.c
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_xoodyak_aead.c")
endif()

if(LWC_SOURCES)
    list(REMOVE_DUPLICATES LWC_SOURCES)
endif()

if(TARGET_PLATFORM STREQUAL "STM32")

    set(ARM_MCU_FLAGS
        -mcpu=cortex-m4
        -mthumb
        -mfloat-abi=hard
        -mfpu=fpv4-sp-d16
    )

    set(PLATFORM_SOURCES
        platforms/stm32_renode/main.c
        platforms/stm32_renode/libc_stub.c
        platforms/stm32_renode/adapter_rng_seed.c
        platforms/stm32_renode/runtime_overhead_probe.c
        ${REGISTERED_ADAPTER_SOURCES}
        ${RNG_SOURCES}
        ${ASCON_SOURCES}
        ${PQM4_SOURCES}
        ${LWC_SOURCES}
        ${X25519_SOURCES}
        ${WOLFCRYPT_SOURCES}
    )

    set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32_renode/linker.ld")

    add_executable(stm32_benchmark.elf ${CORE_SOURCES} ${PLATFORM_SOURCES})

    target_compile_definitions(stm32_benchmark.elf PRIVATE
        RENODE_SIMULATION
        WOLFSSL_USER_SETTINGS
    )

    # Force the compiled-in COMPILE_<ALG> values (whether they came from
    # benchmark_config.h defaults or from an ISOLATE_ALGO override) to match
    # exactly what CMake decided above. Without this, the #if COMPILE_X guards
    # inside bm_*.c / adapter headers would still see benchmark_config.h's
    # original values via #include, which defeats ISOLATE_ALGO entirely.
    # This requires each COMPILE_* macro in benchmark_config.h to be wrapped
    # in #ifndef / #endif so a command-line -D definition can override it:
    #
    #   #ifndef COMPILE_WOLF_X25519
    #   #define COMPILE_WOLF_X25519 1
    #   #endif
    #
    foreach(ALG ${ALGO_LIST})
        target_compile_definitions(stm32_benchmark.elf PRIVATE COMPILE_${ALG}=${COMPILE_${ALG}})
    endforeach()

    if(ISOLATE_ALGO STREQUAL "__RUNTIME__")
        target_compile_definitions(stm32_benchmark.elf PRIVATE FORCE_RUNTIME_OVERHEAD=1)
    endif()

    target_compile_options(stm32_benchmark.elf PRIVATE
        ${ARM_MCU_FLAGS}
        -ffreestanding
        -O3
        -ffunction-sections
        -fdata-sections
    )

    target_include_directories(stm32_benchmark.elf PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/core/src/benchmarks
        ${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32_renode
        ${PQM4_INCLUDES}
        ${ASCON_INCLUDES}
        ${X25519_INCLUDES}
        ${WOLFCRYPT_INCLUDES}
    )

    target_link_options(stm32_benchmark.elf PRIVATE
        ${ARM_MCU_FLAGS}
        -T ${LINKER_SCRIPT}
        -nodefaultlibs
        -nostartfiles
        -Wl,--gc-sections
    )
    target_link_libraries(stm32_benchmark.elf PRIVATE gcc)

    add_custom_command(TARGET stm32_benchmark.elf POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:stm32_benchmark.elf> ${CMAKE_PROJECT_NAME}.bin
        COMMAND ${CMAKE_OBJCOPY} -O ihex   $<TARGET_FILE:stm32_benchmark.elf> ${CMAKE_PROJECT_NAME}.hex
        COMMAND ${CMAKE_SIZE} $<TARGET_FILE:stm32_benchmark.elf>
    )

elseif(TARGET_PLATFORM STREQUAL "RP2040")
    # Placeholder
endif()
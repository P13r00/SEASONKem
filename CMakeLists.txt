cmake_minimum_required(VERSION 3.15)

if(TARGET_PLATFORM STREQUAL "STM32" OR TARGET_PLATFORM STREQUAL "STM32F411_NUCLEO")
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

set(ALGO_LIST
    PQM4_KYBER512 PQM4_KYBER768 PQM4_DILITHIUM2 PQM4_FALCON512
    X25519 PQM4_SHA3_256 PQM4_SHAKE256 CHACHA20_POLY1305 AES_GCM192 AES_GCM256
    LWC_SPARKLE_AEAD256 LWC_SPARKLE_AEAD192 LWC_SPARKLE_AEAD128 
    LWC_SPARKLE_HASHXOF256 LWC_SPARKLE_HASHXOF384 LWC_SPARKLE_HASH256 LWC_SPARKLE_HASH384
    LWC_XOODYAK_HASH LWC_ASCON80PQ_AEAD LWC_ASCON128_AEAD
    LWC_ASCON_HASHXOF LWC_ASCON_HASH256 LWC_XOODYAK_AEAD 
    XWING SEASON0 SPRING SUMMER AUTUMN WINTER
)

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
    core/src/benchmarks/bm_kem.c
    core/src/benchmarks/bm_kex.c
    core/src/benchmarks/bm_signature.c
)

if (COMPILE_XWING)
    list(APPEND CORE_SOURCES "adapters/xwing.c")
endif()
if (COMPILE_SEASON0)
    list(APPEND CORE_SOURCES "adapters/season0.c")
endif()
if (COMPILE_SPRING)
    list(APPEND CORE_SOURCES "adapters/spring.c")
endif()
if (COMPILE_SUMMER)
    list(APPEND CORE_SOURCES "adapters/summer.c")
endif()
if (COMPILE_AUTUMN)
    list(APPEND CORE_SOURCES "adapters/autumn.c")
endif()
if (COMPILE_WINTER)
    list(APPEND CORE_SOURCES "adapters/winter.c")
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

if(COMPILE_AES_GCM192)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/aes.c
    )
    list(APPEND CORE_SOURCES "adapters/wolf/crypto_aes_gcm192.c")
endif()

if(COMPILE_AES_GCM256)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/aes.c
    )
    list(APPEND CORE_SOURCES "adapters/wolf/crypto_aes_gcm256.c")
endif()

if(WOLFCRYPT_SOURCES)
    list(REMOVE_DUPLICATES WOLFCRYPT_SOURCES)
endif()

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

if(COMPILE_LWC_SPARKLE_AEAD128)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-aead.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
        ${LWC_DIR}/src/combined/internal-util.c
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_aead128.c")
endif()

if(COMPILE_LWC_ASCON80PQ_AEAD)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/ascon-aead.c
        ${LWC_DIR}/src/combined/internal-ascon-armv7m.S
        ${LWC_DIR}/src/combined/internal-util.c
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_ascon80pq_aead.c")
endif()

if(COMPILE_LWC_ASCON128_AEAD)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/ascon-aead.c
        ${LWC_DIR}/src/combined/internal-ascon-armv7m.S
        ${LWC_DIR}/src/combined/internal-util.c
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_ascon128_aead.c")
endif()

if(COMPILE_LWC_SPARKLE_HASHXOF256)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-hash.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_hashxof256.c")
endif()

if(COMPILE_LWC_SPARKLE_HASHXOF384)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-hash.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_hashxof384.c")
endif()

if(COMPILE_LWC_SPARKLE_HASH256)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-hash.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_hash256.c")
endif()

if(COMPILE_LWC_SPARKLE_HASH384)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/sparkle-hash.c
        ${LWC_DIR}/src/combined/internal-sparkle-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_sparkle_hash384.c")
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

if(COMPILE_LWC_ASCON_HASH256)
    list(APPEND LWC_SOURCES
        ${LWC_DIR}/src/combined/ascon-hash.c
        ${LWC_DIR}/src/combined/ascon-xof.c
        ${LWC_DIR}/src/combined/internal-ascon-armv7m.S
    )
    list(APPEND CORE_SOURCES "adapters/lwc/crypto_lwc_ascon_hash256.c")
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

elseif(TARGET_PLATFORM STREQUAL "STM32F411_NUCLEO")
    set(ARM_MCU_FLAGS
        -mcpu=cortex-m4
        -mthumb
        -mfloat-abi=hard
        -mfpu=fpv4-sp-d16
    )

    set(PLATFORM_SOURCES
        platforms/stm32f411_nucleo/main.c
        platforms/stm32f411_nucleo/libc_stub.c
        platforms/stm32f411_nucleo/adapter_rng_seed.c
        platforms/stm32f411_nucleo/runtime_overhead_probe.c
        ${REGISTERED_ADAPTER_SOURCES}
        ${RNG_SOURCES}
        ${PQM4_SOURCES}
        ${LWC_SOURCES}
        ${X25519_SOURCES}
        ${WOLFCRYPT_SOURCES}
    )

    set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32f411_nucleo/linker_f411.ld")

    add_executable(stm32_benchmark.elf ${CORE_SOURCES} ${PLATFORM_SOURCES})

    target_compile_definitions(stm32_benchmark.elf PRIVATE
        STM32F411_NUCLEO
        REAL_HARDWARE
        WOLFSSL_USER_SETTINGS
    )

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
        ${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32f411_nucleo
        ${PQM4_INCLUDES}
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
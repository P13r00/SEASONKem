cmake_minimum_required(VERSION 3.15)

# ==============================================================================
# CROSS-COMPILATION SETUP (MUST BE BEFORE project())
# ==============================================================================
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

# ==============================================================================
# AUTOMATIC PROFILE CONFIGURATION EXTRACTION
# Reads the macro toggles directly from benchmark_runner.c
# ==============================================================================
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/core/src/benchmark_runner.c" RUNNER_CONTENT)

foreach(ALG ED25519 AES_GCM CHACHA20_POLY1305 HKDF_SHA256 ASCON80 ASCON_HASH ECDSAP256 KYBER512 KYBER768 DILITHIUM2 FALCON512)
    if(RUNNER_CONTENT MATCHES "#define[ \t]+COMPILE_${ALG}[ \t]+1")
        set(COMPILE_${ALG} 1)
    else()
        set(COMPILE_${ALG} 0)
    endif()
endforeach()

# ==============================================================================
# Core / Platform-Agnostic Setup
# ==============================================================================
set(CORE_SOURCES
    core/src/benchmark_runner.c
)

# --- wolfcrypt Setup ---
set(WOLFCRYPT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl)
set(WOLFCRYPT_SOURCES "")

# wolfcrypt base is needed by all wolfcrypt algorithms and by the inline
# WC_RNG used in the pqm4 adapters (Kyber, Dilithium, Falcon).
if(COMPILE_ED25519 OR COMPILE_AES_GCM OR COMPILE_CHACHA20_POLY1305 OR COMPILE_HKDF_SHA256 OR
   COMPILE_ECDSAP256 OR COMPILE_KYBER512 OR COMPILE_KYBER768 OR COMPILE_DILITHIUM2 OR COMPILE_FALCON512 OR COMPILE_ASCON80 OR COMPILE_ASCON_HASH)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/wc_port.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/memory.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/wolfmath.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/misc.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/asn.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/random.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/hash.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/sha256.c
    )
endif()

if(COMPILE_HKDF_SHA256)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/hmac.c
    )
    list(APPEND CORE_SOURCES "adapters/crypto_hkdfsha256.c")
endif()

if(COMPILE_ED25519)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/sha512.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/ed25519.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/ge_operations.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/fe_operations.c
    )
    list(APPEND CORE_SOURCES "adapters/crypto_ed25519.c")
endif()

if(COMPILE_ECDSAP256)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/ecc.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/sp_int.c
    )
    list(APPEND CORE_SOURCES "adapters/crypto_ecdsap256.c")
endif()

if(COMPILE_AES_GCM)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/aes.c
    )
    list(APPEND CORE_SOURCES "adapters/crypto_aes_gcm.c")
endif()

if(COMPILE_CHACHA20_POLY1305)
    list(APPEND WOLFCRYPT_SOURCES
        ${WOLFCRYPT_DIR}/wolfcrypt/src/chacha.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/poly1305.c
        ${WOLFCRYPT_DIR}/wolfcrypt/src/chacha20_poly1305.c
    )
    list(APPEND CORE_SOURCES "adapters/crypto_chacha20_poly1305.c")
endif()

# --- Ascon Setup ---
set(ASCON_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ascon)
set(ASCON_SOURCES "")

if(COMPILE_ASCON80)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_aead/ascon80pqv12/armv7m/aead.c
        ${ASCON_DIR}/crypto_aead/ascon80pqv12/armv7m/permutations.c
    )
    list(APPEND CORE_SOURCES "adapters/crypto_ascon80pq.c")
endif()

if(COMPILE_ASCON_HASH)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_hash/asconhashabi32v12/bi32_armv7m/hash.c
        ${ASCON_DIR}/crypto_hash/asconhashabi32v12/bi32_armv7m/permutations.c
    )
    list(APPEND CORE_SOURCES "adapters/crypto_asconhash256.c")
endif()

# --- PQM4 Setup ---
set(PQM4_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/pqm4)
set(PQM4_SOURCES "")

if(COMPILE_KYBER512)
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
    list(APPEND CORE_SOURCES "adapters/crypto_kyber512.c")
endif()

if(COMPILE_KYBER768)
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
    list(APPEND CORE_SOURCES "adapters/crypto_kyber768.c")
endif()

if(COMPILE_DILITHIUM2)
    # ml-dsa-44/m4f is self-contained: sign.c implements all _ctx entry points;
    # crypto_sign / crypto_sign_open etc. are macros in api.h → _ctx variants.
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
    list(APPEND CORE_SOURCES "adapters/crypto_dilithium2.c")
endif()

if(COMPILE_FALCON512)
    file(GLOB PQM4_FALCON_SOURCES
        "${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f/*.c"
        "${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f/*.s"
        "${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f/*.S"
    )
    # Exclude the bundled sysrng.c — crypto_falcon512.c provides sysrng().
    #list(FILTER PQM4_FALCON_SOURCES EXCLUDE REGEX "sysrng\\.c$")
    list(APPEND PQM4_SOURCES ${PQM4_FALCON_SOURCES})
    list(APPEND CORE_SOURCES "adapters/crypto_falcon512.c")
endif()

# Deduplicate shared files (fips202 / keccakf1600) if multiple algorithms are active.
if(PQM4_SOURCES)
    list(REMOVE_DUPLICATES PQM4_SOURCES)
endif()

# ==============================================================================
# STM32 Target Binaries Setup
# ==============================================================================
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
        ${REGISTERED_ADAPTER_SOURCES}
        ${WOLFCRYPT_SOURCES}
        ${ASCON_SOURCES}
        ${PQM4_SOURCES}
    )

    set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32_renode/linker.ld")

    add_executable(stm32_benchmark.elf ${CORE_SOURCES} ${PLATFORM_SOURCES})

    target_compile_definitions(stm32_benchmark.elf PRIVATE
        WOLFSSL_USER_SETTINGS
        RENODE_SIMULATION
    )

    target_compile_options(stm32_benchmark.elf PRIVATE
        ${ARM_MCU_FLAGS}
        -ffreestanding
        -O3
        -ffunction-sections
        -fdata-sections
    )

    # Include order: pqm4 paths first so their randombytes.h wins over any
    # stray header with the same name.  ascon/tests is excluded — its
    # randombytes.h pulls in forceinline.h which does not exist here.
    # ml-dsa-44/m4f must be present so crypto_dilithium2.c can find api.h.
    target_include_directories(stm32_benchmark.elf PRIVATE
        ${PQM4_DIR}/mupq/common
        ${PQM4_DIR}/crypto_sign/ml-dsa-44/m4f
        ${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f
        ${PQM4_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32_renode
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ascon
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/ascon/tests
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
        COMMENT "Generating binaries and printing execution size logs..."
    )

elseif(TARGET_PLATFORM STREQUAL "RP2040")
    # Placeholder
endif()
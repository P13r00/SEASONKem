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


file(READ "${CMAKE_CURRENT_SOURCE_DIR}/core/src/benchmark_runner.c" RUNNER_CONTENT)

foreach(ALG ED25519 AES_GCM CHACHA20_POLY1305 HKDF_SHA256 ASCON80 ASCON_AEAD128 ASCON_HASH256 ASCON_XOF ECDSAP256 KYBER512 KYBER768 DILITHIUM2 FALCON512)
    if(RUNNER_CONTENT MATCHES "#define[ \t]+COMPILE_${ALG}[ \t]+1")
        set(COMPILE_${ALG} 1)
    else()
        set(COMPILE_${ALG} 0)
    endif()
endforeach()


set(CORE_SOURCES
    core/src/benchmark_runner.c
)

# --- wolfcrypt Setup ---
set(WOLFCRYPT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl)
set(WOLFCRYPT_SOURCES "")
set(WOLFCRYPT_INCLUDES 
    ${WOLFCRYPT_DIR}
)


if(COMPILE_ED25519 OR COMPILE_AES_GCM OR COMPILE_CHACHA20_POLY1305 OR COMPILE_HKDF_SHA256 OR
COMPILE_ECDSAP256 OR COMPILE_KYBER512 OR COMPILE_KYBER768 OR COMPILE_DILITHIUM2 OR COMPILE_FALCON512 OR COMPILE_ASCON80 OR COMPILE_ASCON_AEAD128 OR COMPILE_ASCON_HASH256 OR COMPILE_ASCON_XOF)
set(WOLFCRYPT_RNG 1)
endif()

if(WOLFCRYPT_RNG) # section will be changed as base wolfcrypt combination, when rng is changed
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
    list(APPEND CORE_SOURCES "adapters/crypto_ascon80pq.c")
endif()

if(COMPILE_ASCON_AEAD128)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_aead/ascon128bi32v12/bi32_armv7m/aead.c
        ${ASCON_DIR}/crypto_aead/ascon128bi32v12/bi32_armv7m/permutations.c
    )
    list(APPEND CORE_SOURCES "adapters/crypto_asconaead128.c")
endif()

if(COMPILE_ASCON_HASH256)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_hash/asconhashv12/bi32_armv7m_small/hash.c
        ${ASCON_DIR}/crypto_hash/asconhashv12/bi32_armv7m_small/permutations.c
        ${ASCON_DIR}/crypto_hash/asconhashv12/bi32_armv7m_small/interleave.c
        ${ASCON_DIR}/crypto_hash/asconhashv12/bi32_armv7m_small/constants.c
    )
    list(APPEND CORE_SOURCES "adapters/crypto_asconhash256.c")
endif()

if(COMPILE_ASCON_XOF)
    list(APPEND ASCON_SOURCES
        ${ASCON_DIR}/crypto_hash/asconxofv12/bi32_armv7m_small/hash.c
        ${ASCON_DIR}/crypto_hash/asconxofv12/bi32_armv7m_small/permutations.c
        ${ASCON_DIR}/crypto_hash/asconxofv12/bi32_armv7m_small/interleave.c
        ${ASCON_DIR}/crypto_hash/asconxofv12/bi32_armv7m_small/constants.c
    )
    list(APPEND CORE_SOURCES "adapters/crypto_asconxof.c")
endif()

set(PQM4_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/pqm4)
set(PQM4_SOURCES "")
set(PQM4_INCLUDES
    ${PQM4_DIR}/mupq/common
    ${PQM4_DIR}/crypto_sign/ml-dsa-44/m4f
    ${PQM4_DIR}/crypto_sign/fndsa_provisional-512/m4f
    ${PQM4_DIR}
)

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
    list(APPEND PQM4_SOURCES ${PQM4_FALCON_SOURCES})
    list(APPEND CORE_SOURCES "adapters/crypto_falcon512.c")
endif()

if(PQM4_SOURCES)
    list(REMOVE_DUPLICATES PQM4_SOURCES)
endif()

if(TARGET_PLATFORM STREQUAL "STM32")

    set(ARM_MCU_FLAGS
        -mcpu=cortex-m4
        -mthumb
        -mfloat-abi=hard
        -mfpu=fpv4-sp-d16
    )

    set(PLATFORM_SOURCES
        adapters/adapter_rng.c
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

    # Include order: PQM4 paths are placed first so their randombytes.h wins 
    # over any stray header with the same name.
    target_include_directories(stm32_benchmark.elf PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32_renode
        ${PQM4_INCLUDES}
        ${WOLFCRYPT_INCLUDES}
        ${ASCON_INCLUDES}
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
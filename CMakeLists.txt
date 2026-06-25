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

foreach(ALG ED25519 AES_GCM CHACHA20_POLY1305 HKDF_SHA256 ASCON80 ASCON_HASH ECDSAP256)
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

set(WOLFCRYPT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl)
set(WOLFCRYPT_SOURCES "")

if(COMPILE_ED25519 OR COMPILE_AES_GCM OR COMPILE_CHACHA20_POLY1305 OR COMPILE_HKDF_SHA256 OR COMPILE_ECDSAP256)
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

    target_include_directories(stm32_benchmark.elf PRIVATE
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
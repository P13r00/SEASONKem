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

    # Prevent CMake from trying to link a test executable during configuration
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
endif()

project(crypto_heterogeneous_benchmark C ASM)

set(CMAKE_C_STANDARD 99)

# ==============================================================================
# Platform-agnostic core
# ==============================================================================
set(CORE_SOURCES
    core/src/benchmark_runner.c     # includes watermark utils + all benchmark runners
)

set(WOLFCRYPT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/wolfssl)

set(WOLFCRYPT_SOURCES
    # Core / porting
    ${WOLFCRYPT_DIR}/wolfcrypt/src/wc_port.c
    ${WOLFCRYPT_DIR}/wolfcrypt/src/memory.c
    ${WOLFCRYPT_DIR}/wolfcrypt/src/wolfmath.c
    ${WOLFCRYPT_DIR}/wolfcrypt/src/misc.c
    ${WOLFCRYPT_DIR}/wolfcrypt/src/random.c

    # Hash primitives
    ${WOLFCRYPT_DIR}/wolfcrypt/src/hash.c
    ${WOLFCRYPT_DIR}/wolfcrypt/src/sha256.c   # for HMAC-SHA256 (HKDF)
    ${WOLFCRYPT_DIR}/wolfcrypt/src/sha512.c   # for Ed25519

    # Ed25519 — group / field arithmetic lives in ge_/fe_ files
    ${WOLFCRYPT_DIR}/wolfcrypt/src/ed25519.c
    ${WOLFCRYPT_DIR}/wolfcrypt/src/ge_operations.c
    ${WOLFCRYPT_DIR}/wolfcrypt/src/fe_operations.c

    # AES-GCM
    ${WOLFCRYPT_DIR}/wolfcrypt/src/aes.c

    # ChaCha20-Poly1305
    ${WOLFCRYPT_DIR}/wolfcrypt/src/chacha.c
    ${WOLFCRYPT_DIR}/wolfcrypt/src/poly1305.c
    ${WOLFCRYPT_DIR}/wolfcrypt/src/chacha20_poly1305.c

    # HKDF_SHA256
    ${WOLFCRYPT_DIR}/wolfcrypt/src/hmac.c
)
# ==============================================================================
# STM32 / Renode target
# ==============================================================================
if(TARGET_PLATFORM STREQUAL "STM32")

    set(ARM_MCU_FLAGS
        -mcpu=cortex-m4
        -mthumb
        -mfloat-abi=hard
        -mfpu=fpv4-sp-d16
    )

    # Gather adapter sources from the benchmark registry in benchmark_runner.c
    # so the build only compiles the algorithms that are actually benchmarked.
    file(READ "${CMAKE_CURRENT_SOURCE_DIR}/core/src/benchmark_runner.c" BENCHMARK_RUNNER_SRC)
    string(REGEX MATCHALL "&([A-Za-z0-9_]+)_ops" BENCHMARK_REGISTRY_SYMBOLS "${BENCHMARK_RUNNER_SRC}")

    set(REGISTERED_ADAPTER_SOURCES "")
    foreach(registry_symbol IN LISTS BENCHMARK_REGISTRY_SYMBOLS)
        string(REGEX REPLACE "^&" "" registry_symbol "${registry_symbol}")
        string(REGEX REPLACE "_ops$" "" op_name "${registry_symbol}")

        string(TOLOWER "${op_name}" op_name_lower)
        if(op_name_lower STREQUAL "hkdf_sha256")
            set(op_name_lower "hkdfsha256")
        endif()

        if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/adapters/crypto_${op_name_lower}.c")
            list(APPEND REGISTERED_ADAPTER_SOURCES "adapters/crypto_${op_name_lower}.c")
        endif()
    endforeach()
    list(REMOVE_DUPLICATES REGISTERED_ADAPTER_SOURCES)

    set(PLATFORM_SOURCES
        platforms/stm32_renode/main.c
        platforms/stm32_renode/libc_stub.c
        ${REGISTERED_ADAPTER_SOURCES}
        ${WOLFCRYPT_SOURCES}
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
    )

    # STRICT LINK PROPERTIES: freestanding bare-metal, no runtime, no stdlib.
    # -nostdlib already implies -nodefaultlibs.  Do NOT add -nolibc or
    # -nodefaultlibs redundantly — extra flags cause ld to misbehave when the
    # linker script names archives it can no longer find in the search path.
    target_link_options(stm32_benchmark.elf PRIVATE
        ${ARM_MCU_FLAGS}
        -T ${LINKER_SCRIPT}
        -nostartfiles
        -nostdlib
        -Wl,--gc-sections
    )

    add_custom_command(TARGET stm32_benchmark.elf POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary
                $<TARGET_FILE:stm32_benchmark.elf>
                ${CMAKE_PROJECT_NAME}.bin
        COMMAND ${CMAKE_OBJCOPY} -O ihex
                $<TARGET_FILE:stm32_benchmark.elf>
                ${CMAKE_PROJECT_NAME}.hex
        COMMAND ${CMAKE_SIZE} $<TARGET_FILE:stm32_benchmark.elf>
        COMMENT "Generating .bin, .hex and printing size..."
    )

elseif(TARGET_PLATFORM STREQUAL "RP2040")
    # Placeholder
endif()

cmake_minimum_required(VERSION 3.15)

# ==============================================================================
# CROSS-COMPILATION SETUP (MUST BE BEFORE project())
# ==============================================================================
if(TARGET_PLATFORM STREQUAL "STM32")
    set(CMAKE_SYSTEM_NAME Generic)
    set(CMAKE_SYSTEM_PROCESSOR arm)
    
    # Force the ARM cross-compiler and tools
    set(CMAKE_C_COMPILER arm-none-eabi-gcc)
    set(CMAKE_ASM_COMPILER arm-none-eabi-gcc)
    set(CMAKE_OBJCOPY arm-none-eabi-objcopy)
    set(CMAKE_SIZE arm-none-eabi-size)
    
    # Prevent CMake from trying to link a test executable during configuration
    set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
endif()

# Enable ASM language for the startup file
project(crypto_heterogeneous_benchmark C ASM)

set(CMAKE_C_STANDARD 99)

# 1. Platform-agnostic Core Logic
set(CORE_SOURCES
    core/src/benchmark_runner.c
)

# 2. Conditionally build based on target platform
if(TARGET_PLATFORM STREQUAL "STM32")
    # ARM Architecture Flags (Adjust -mcpu/-mfpu for your specific STM32 variant)
    # Example below is for Cortex-M4F (e.g., STM32F4, STM32G4). 
    # Use -mcpu=cortex-m3 for F1/F2, or -mcpu=cortex-m7 for F7/H7.
    set(ARM_MCU_FLAGS -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16)

    set(PLATFORM_SOURCES 
        platforms/stm32_renode/main.c
        adapters/crypto_ecc_classical.c
        adapters/crypto_ascon.c
    )
    
    set(LINKER_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32_renode/linker.ld")
    
    add_executable(stm32_benchmark.elf ${CORE_SOURCES} ${PLATFORM_SOURCES})
    
    # FORCE FREESTANDING COMPILATION & ARCHITECTURE FLAGS
    target_compile_options(stm32_benchmark.elf PRIVATE 
        ${ARM_MCU_FLAGS}
        "-ffreestanding"
        "-O2"
        "-ffunction-sections"
        "-fdata-sections"
    )
    
    target_include_directories(stm32_benchmark.elf PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/platforms/stm32_renode
    )
    
    # STRICT LINK PROPERTIES: freestanding bare-metal, no runtime, no standard libs.
    # -nostdlib already implies -nodefaultlibs. Do NOT add -nolibc or -nodefaultlibs
    # redundantly — extra flags cause ld to misbehave when the linker script names
    # archives it can no longer find in the search path.
    target_link_options(stm32_benchmark.elf PRIVATE
        ${ARM_MCU_FLAGS}
        "-T" "${LINKER_SCRIPT}"
        "-nostartfiles"
        "-nostdlib"
        "-Wl,--gc-sections"
    )

    # Generate .bin and .hex files (Required for Renode / Flashing)
    add_custom_command(TARGET stm32_benchmark.elf POST_BUILD
        COMMAND ${CMAKE_OBJCOPY} -O binary $<TARGET_FILE:stm32_benchmark.elf> ${CMAKE_PROJECT_NAME}.bin
        COMMAND ${CMAKE_OBJCOPY} -O ihex $<TARGET_FILE:stm32_benchmark.elf> ${CMAKE_PROJECT_NAME}.hex
        COMMAND ${CMAKE_SIZE} $<TARGET_FILE:stm32_benchmark.elf>
        COMMENT "Generating .bin, .hex, and printing size..."
    )

elseif(TARGET_PLATFORM STREQUAL "RP2040")
    # Placeholder
endif()
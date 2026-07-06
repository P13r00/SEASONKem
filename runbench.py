import os
import shutil
import subprocess
import sys


def run_command(cmd, cwd=None):
    """Runs a shell command and exits immediately if it fails (mimicking set -e)."""
    try:
        subprocess.run(cmd, shell=True, check=True, cwd=cwd)
    except subprocess.CalledProcessError as e:
        print(f"\n[ERROR] Command failed with exit code {e.returncode}: {cmd}")
        sys.exit(e.returncode)


def execute_build_cycle(root_dir, alg=None):
    """Executes the clean, config, make, and emulate cycle for a given configuration."""
    build_dir = os.path.join(root_dir, "build")

    # === Cleaning old build files ===
    print("\n=== Cleaning old build files ===")
    if os.path.exists(build_dir):
        shutil.rmtree(build_dir)

    # === Configuring build with CMake ===
    print("=== Configuring build with CMake ===")
    os.makedirs(build_dir)
    
    # Adapt the command based on whether an algorithm was specified
    if alg:
        cmake_cmd = f"cmake .. -DTARGET_PLATFORM=STM32 -DISOLATE_ALGO={alg}"
    else:
        cmake_cmd = "cmake .. -DTARGET_PLATFORM=STM32"
        
    run_command(cmake_cmd, cwd=build_dir)

    # === Compiling binaries ===
    print("=== Compiling binaries ===")
    run_command("make", cwd=build_dir)

    # === Launching Renode Emulator ===
    print("=== Launching Renode Emulator ===")
    renode_cmd = "renode platforms/stm32_renode/stm32f4.resc"
    run_command(renode_cmd, cwd=root_dir)


def main():
    print("Enter the algorithms to test (separated by spaces or commas).")
    raw_input = input("Or press [ENTER] to run a single standard build: ")
    
    # Parse input into a list if it exists
    algs = [alg.strip() for alg in raw_input.replace(",", " ").split() if alg.strip()]
    root_dir = os.getcwd()

    if not algs:
        # Standard Single-Build Mode
        print("\n" + "="*50)
        print("Running standard single build (No specific algorithm)")
        print("="*50)
        execute_build_cycle(root_dir, alg=None)
        print("\nStandard build and emulation completed successfully!")
    else:
        # Loop Mode
        for idx, alg in enumerate(algs, 1):
            print("\n" + "="*50)
            print(f"Processing Algorithm [{idx}/{len(algs)}]: {alg}")
            print("="*50)

            execute_build_cycle(root_dir, alg=alg)

            # Wait for button press to continue to the next loop iteration
            if idx < len(algs):
                input(f"\n[Finished {alg}] Press Enter to continue to the next algorithm...")
            else:
                print(f"\n[Finished {alg}] All algorithms processed successfully!")


if __name__ == "__main__":
    main()
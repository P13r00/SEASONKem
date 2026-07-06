set -e

echo "=== Cleaning old build files ==="
rm -rf build/

echo "=== Configuring build with CMake ==="
mkdir build 
cd build
cmake .. -DTARGET_PLATFORM=STM32

echo "=== Compiling binaries ==="
make

echo "=== Returning to root directory ==="
cd ..

echo "=== Launching Renode Emulatorr ==="
renode platforms/stm32_renode/stm32f4.resc
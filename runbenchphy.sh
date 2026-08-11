set -e

echo "=== Cleaning old build files ==="
rm -rf build/

echo "=== Configuring build with CMake ==="
mkdir build
cd build
cmake .. -DTARGET_PLATFORM=STM32F411_NUCLEO

echo "=== Compiling binaries ==="
make

echo "=== Returning to root directory ==="
cd ..

echo "=== Locating ST-Link VCP serial port ==="
# The VCP shows up as soon as the board is plugged in, independent of
# whatever firmware is currently programmed onto it -- so we can find
# it and open a monitor on it *before* flashing.
SERIAL_PORT=$(ls /dev/ttyACM* 2>/dev/null | head -n1)

if [ -z "$SERIAL_PORT" ]; then
    echo "!! No /dev/ttyACM* device found. Is the board plugged in?"
    echo "     ls /dev/ttyACM* /dev/ttyUSB* 2>/dev/null"
    exit 1
fi
echo "Using $SERIAL_PORT"

echo "=== Opening serial monitor in a new terminal window (before flashing) ==="
# Opening the monitor first means it's already listening when the reset
# happens during flashing, so it catches the boot banner and everything
# else from byte one -- rather than missing the first few seconds while
# the monitor is still starting up. SWD (programming) and the VCP
# (serial) are independent USB interfaces on the ST-Link, so having both
# open at once is fine.
#
# Using stty + cat instead of picocom/minicom/screen: no alternate-screen
# buffer (so your terminal's normal mouse-wheel/Shift-PageUp scrollback
# just works), no app-specific banners or exit-key gymnastics -- just the
# raw stream. stty configures the port's line settings explicitly first
# (115200 8N1, raw mode, no local echo) so it doesn't depend on whatever
# state a previous tool left the port in.
MONITOR_CMD="stty -F $SERIAL_PORT 115200 cs8 -cstopb -parenb raw -echo && cat $SERIAL_PORT"

opened=0
for term in gnome-terminal konsole xfce4-terminal terminator alacritty kitty xterm; do
    if command -v "$term" >/dev/null 2>&1; then
        case "$term" in
            gnome-terminal) gnome-terminal -- bash -c "$MONITOR_CMD; exec bash" & ;;
            konsole)        konsole -e bash -c "$MONITOR_CMD; exec bash" & ;;
            xfce4-terminal) xfce4-terminal -e "bash -c '$MONITOR_CMD; exec bash'" & ;;
            terminator)     terminator -e "bash -c '$MONITOR_CMD; exec bash'" & ;;
            alacritty)      alacritty -e bash -c "$MONITOR_CMD; exec bash" & ;;
            kitty)          kitty bash -c "$MONITOR_CMD; exec bash" & ;;
            xterm)          xterm -hold -e bash -c "$MONITOR_CMD" & ;;
        esac
        disown
        opened=1
        break
    fi
done

if [ "$opened" -eq 0 ]; then
    echo "!! No supported terminal emulator found to spawn a new window."
    echo "   Run this manually in another terminal before continuing:"
    echo "     stty -F $SERIAL_PORT 115200 cs8 -cstopb -parenb raw -echo && cat $SERIAL_PORT"
    read -p "Press Enter once the monitor is open and ready..." _
fi

# Give the monitor a moment to actually finish opening the port before
# we reset the target into it.
sleep 1

echo "=== Flashing to STM32F411 Nucleo via onboard ST-Link ==="
openocd -f platforms/stm32f411_nucleo/openocd_f411.cfg \
        -c "init" \
        -c "reset halt" \
        -c "stm32f4x mass_erase 0" \
        -c "program build/stm32_benchmark.elf verify" \
        -c "reset run" \
        -c "shutdown"
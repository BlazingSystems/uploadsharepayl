# ESP32 optimization audit

Audit date: 2026-10-03

Pinned upstream firmware: `7wp81x/NRSuite-firmware` at `0566adf0eaa1ed133c97c308c1ae17409cd0d59c`.

This directory deliberately keeps the ESP32 project anchored to the canonical upstream implementation instead of maintaining a silently diverging copy. The current upstream build is already configured for size and dead-code elimination and has board-specific feature selection.

## Existing upstream optimizations

The audited `platformio.ini` already applies:

- `-Os`
- `-ffunction-sections`
- `-fdata-sections`
- `-Wl,--gc-sections`
- `CORE_DEBUG_LEVEL=0`
- board-specific BLE/USB feature flags
- single-application 4 MB partition layouts instead of redundant OTA slots
- omission of BLE dependencies on ESP32-S2
- board-specific native USB / TinyUSB settings

The upstream configuration also documents why `BOARD_HAS_PSRAM=0` must not be defined on non-PSRAM boards and leaves LTO disabled by default because it can make failures harder to diagnose.

## Reconciliation result

No speculative compiler flag was added to the ESP32 build. Enabling LTO or changing Wi-Fi/USB linker behavior without a hardware regression pass could produce a smaller binary while breaking timing-sensitive serial, Wi-Fi monitor, USB CDC/HID/MSC, or BLE behavior.

For a future measured optimization pass, compare each supported board before/after using:

1. firmware binary size and linker map,
2. static RAM and boot-time free heap,
3. free heap while each supported module is active,
4. protocol throughput and oversized/resync counters,
5. detector event drop counts,
6. USB CDC/HID/MSC reconnect behavior,
7. Wi-Fi scan/monitor stability,
8. BLE scan/profile/HID coexistence.

Only keep an optimization when behavior remains equivalent on real hardware. This preserves the user's requirement that optimization not turn into a reduced-function rewrite.

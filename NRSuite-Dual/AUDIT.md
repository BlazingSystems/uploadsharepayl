# NRSuite Dual Port — Audit & Reconciliation

## Upstream reviewed

- `7wp81x/NRSuite-Android` — Android companion application.
- `7wp81x/NRSuite-firmware` — ESP32 PlatformIO firmware.
- `7wp81x/NRSuite-Protocol` — wire protocol v1.0.

Upstream revisions reviewed on 2026-10-03:

- Android tree: `aa25ea1e304138b25012965732a45b8e9b246611`
- ESP32 firmware tree: `0566adf0eaa1ed133c97c308c1ae17409cd0d59c`

## What was preserved

The ESP8266 port preserves the NRSuite v1 serial frame envelope:

`AD DE | type | id | uint32_le payload_length | payload`

The Android app establishes a session by sending `PING`, then `STATUS`. It does not hard-code an ESP32-only chip allow-list in the session layer, so an ESP8266 can participate when connected through a USB-UART bridge such as CH340/CP2102.

Implemented compatible commands:

- `PING`
- `STATUS`
- `HEAP`
- `STOP_ALL`
- `SET_CHANNEL`
- `SCAN_WIFI`
- `DEAUTH_DETECT_START`
- `DEAUTH_DETECT_STOP`
- `DEAUTH_DETECT_STATUS`
- `START_HIDDEN_AP`
- `STOP_HIDDEN_AP`

Implemented compatible events:

- `heartbeat`
- `scan_ap`
- `deauth_detected`
- `deauth_detector_hop`
- `hidden_ap`
- `hidden_ap_hop`

## ESP8266 hardware reconciliation

ESP8266 has one 2.4 GHz radio, no BLE radio, no native USB device controller, and much less RAM than the ESP32 family. Therefore:

- BLE scanner/GATT/HID cannot be ported to ESP8266 hardware.
- Native USB MSC / BadUSB cannot be ported to ESP8266 hardware.
- Android app control uses the board's USB-UART bridge rather than native USB CDC.
- Promiscuous channel hopping cannot coexist with a stable AP/STA/repeater connection because the radio has one channel at a time. Fixed-channel passive monitoring keeps the web UI reachable. Hopping mode is available through serial control and temporarily suspends networking.

## Repeater reconciliation

Current ESP8266 Arduino Core 3.x contains lwIP NAPT support and an official `RangeExtender-NAPT` example. The port uses that native NAPT path when `IP_NAPT` is enabled at compile time. It does not pretend AP+STA alone is a repeater.

The NAPT table is deliberately smaller than the upstream core defaults (`128` NAT entries / `8` port mappings) to protect heap on common ESP8266 modules.

## Optimization choices

- Single `.ino` for Arduino IDE portability.
- Web page stored in PROGMEM.
- No ArduinoJson dependency on ESP8266: a narrow parser handles the simple NRSuite command envelope, reducing flash/RAM pressure.
- Promiscuous callback performs no `String`, heap allocation, web handling, or serial writes; it only copies compact events into a fixed ring buffer.
- Binary serial output is kept clean (`Serial.setDebugOutput(false)`).
- Scan result count is capped to avoid large dynamic JSON strings on crowded channels.
- Persistent configuration uses a compact EEPROM struct with magic/version migration guard.
- STA-only mode falls back to a protected management AP if upstream association fails.
- Web endpoints use HTTP Basic authentication and the default credentials are documented so they can be changed immediately.

## Upstream ESP32 audit findings

The upstream firmware is well-separated into radio modules and a bridge protocol, but the following are useful optimization targets for constrained builds:

1. `BridgeProtocol::_dispatch()` creates `JsonDocument` with `new` for every command/ACK. Reusing a bounded document or stack/static document can reduce heap fragmentation during long sessions.
2. `sendResp()` / `sendEvent()` serialize through temporary `String` objects. Preallocated buffers or direct stream serialization reduce transient allocations.
3. The bridge RX buffer is `PROTO_MAX_CHUNK + header + 64`; on smaller targets, keeping upload/PCAP paths compile-time gated avoids paying the full buffer cost when unsupported.
4. Board feature flags should drive both compile-time modules and `STATUS.features`; this port does that so the Android UI does not expose unsupported modules.
5. Radio modes should be centralized. Several ESP32 modules independently toggle promiscuous mode/channel/AP state; a small radio-state arbiter would make web+app dual control safer and prevent mode collisions.
6. A web control surface should call the same command handlers as serial rather than duplicate radio logic. That is the architecture used by the ESP8266 port.

## Deliberately excluded functionality

This fork does not reproduce active disruption, credential theft, or HID-injection features from the upstream offensive toolchain. Commands for those operations return a clear disabled response. The port focuses on device management, scanning, and passive defensive detection.

## Validation status

The sketch was statically reconciled against the current ESP8266 Arduino APIs for:

- `wifi_set_promiscuous_rx_cb` / `wifi_promiscuous_enable`
- `wifi_set_channel`
- lwIP `ip_napt_init` / `ip_napt_enable_no`
- ESP8266WebServer / DNSServer / EEPROM

A local compile could not be run in the ChatGPT execution container because external package download/DNS is disabled there. A GitHub Actions Arduino compile workflow is included in the repository so the checked-in sketch can be compiled on the repository side.

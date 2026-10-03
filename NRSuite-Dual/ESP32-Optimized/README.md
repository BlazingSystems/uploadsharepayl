# NRSuite ESP32 Optimized Reconciliation

This directory is an optimization overlay for the upstream \`7wp81x/NRSuite-firmware\` project, reconciled against the Android app and protocol at the source revisions recorded in \`../UPSTREAM.md\`.

It intentionally does not vendor or extend the upstream active credential-capture, deauthentication-injection, WPA cracking, beacon-spam, or BadUSB payload modules. The goal here is to make the maintainable/safe portions dual-control and more resource-efficient.

## Included code

- `BridgeProtocolOptimized.h/.cpp` — protocol-v1-compatible bridge refactor that reuses the receive JSON document and streams JSON directly to the serial transport after `measureJson()`, removing the upstream per-frame `new/delete` and temporary JSON `String`.
- The ESP8266 single-file implementation remains the reference for the dual app+web command surface and constrained-memory queueing.

## Recommended architecture

1. Keep the v1 framed serial protocol as the compatibility layer for the Android app.
2. Add one \`CommandRouter\` used by both serial and HTTP handlers. The web server should call the same command functions as the app transport instead of reimplementing module logic.
3. Add a \`RadioArbiter\` that owns Wi-Fi/BLE state transitions. A module must acquire the radio role before changing promiscuous mode, channel, STA/AP state, or BLE scanning.
4. Use compile-time feature flags to build the \`STATUS.features\` array. Do not advertise modules that are unavailable on a board.
5. Replace per-command heap allocation in \`BridgeProtocol::_dispatch\` with bounded/reusable JSON documents and avoid transient \`String\` objects for hot-path events where practical.
6. Put the web page and static strings in flash/PROGMEM; expose compact JSON APIs for status, scan results, passive detector events, and network configuration.
7. On current Arduino-ESP32 3.x, AP+STA NAT can use the core's NAPT support. Keep repeater/NAT setup isolated from monitor-mode modules because one radio cannot simultaneously hop channels and maintain a stable upstream/downstream link.

## Dual-control safe module set

- \`PING\`, \`STATUS\`, \`HEAP\`, \`STOP_ALL\`, \`SET_CHANNEL\`
- Wi-Fi AP scanning and \`scan_ap\` events
- Passive deauthentication/disassociation detection
- Passive hidden-AP observation
- Web UI + API
- AP, STA, AP+STA, and AP+STA NAT/repeater networking
- Heartbeat/status telemetry

The ESP8266 implementation in \`../ESP8266/NRSuite_ESP8266_Dual.ino\` is the concrete reference for the command-router/web-control behavior and low-allocation detector queues. Port the same separation of concerns into the ESP32 firmware rather than copying ESP8266-specific SDK calls.

## Audit notes from upstream ESP32 firmware

- \`BridgeProtocol::_dispatch()\` allocates a \`JsonDocument\` using \`new\` for each command and ACK. A fixed/reused document avoids fragmentation and allocator overhead.
- \`sendResp()\` / \`sendEvent()\` serialize through temporary \`String\` buffers. A bounded character buffer or direct stream serialization is cheaper for frequent events.
- The full bridge RX buffer is always present. It should be feature/target sized where smaller boards do not need 1 KiB uploads.
- Radio-changing modules independently toggle promiscuous mode/channel/AP state. Central arbitration reduces cross-module state leakage.
- The firmware and Android app already negotiate capabilities via \`STATUS.features\`; this should remain the source of truth for board-specific UI availability.
- Web control should be transport-only: serial and HTTP requests should converge on the same validated command implementation.

## Build/reconciliation target

Preserve NRSuite protocol major \`1\` so the current Android app can still establish \`PING\` -> \`STATUS\` sessions. Web control is additive, not a replacement transport.

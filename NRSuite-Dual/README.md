# NRSuite Dual ESP8266 mirror

This directory mirrors the CI-verified ESP8266 dual-control sketch from:

`NRSuite/ESP8266/NRSuite_ESP8266/NRSuite_ESP8266.ino`

Both files are intentionally kept byte-for-byte identical. The canonical build path is the one under `NRSuite/ESP8266/`; this mirror exists so the dual Android + web-controller variant is easy to find.

## Control paths

- Android NRSuite app over the upstream v1 serial framing at 115200 baud.
- Standalone authenticated web UI.
- AP-only, STA-only, AP+STA, and AP+STA NAPT repeater modes.
- Shared runtime state between serial/app and web controls.

## Verified build

GitHub Actions compiled the canonical sketch successfully on 2026-10-03 using ESP8266 Arduino Core 3.1.2 and ArduinoJson 7.4.3 for NodeMCU 1.0 / ESP-12E.

Measured build footprint from that run:

- Data RAM: 34,952 / 80,192 bytes (43%)
- IRAM + cache reservation: 59,983 / 65,536 bytes (91% reported by the toolchain)
- Flash code: 316,040 / 1,048,576 bytes (30%)

See `NRSuite/docs/RECONCILIATION.md` for the capability matrix and upstream revisions.

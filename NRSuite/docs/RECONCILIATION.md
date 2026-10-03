# NRSuite ESP8266 reconciliation audit

Audit date: 2026-10-03

## Sources pinned

| Component | Repository | Audited revision |
|---|---|---|
| Android app | `7wp81x/NRSuite-Android` | `aa25ea1e304138b25012965732a45b8e9b246611` |
| ESP32 firmware | `7wp81x/NRSuite-firmware` | `0566adf0eaa1ed133c97c308c1ae17409cd0d59c` |
| Protocol | `7wp81x/NRSuite-Protocol` | v1.0 documents on 2026-10-03 |
| ESP8266 Arduino core | `esp8266/Arduino` | 3.1.2 API baseline |

## Protocol compatibility

The port keeps the upstream 8-byte wire header, magic bytes `0xAD 0xDE`, frame types, 1024-byte maximum JSON payload, response frame-ID correlation, event `type` field, and 115200 8N1 serial transport. The parser scans forward to the next magic pair after malformed or oversized data so ESP8266 boot noise/partial UART reads do not permanently desynchronize the Android session.

## Command matrix

| Upstream command group | ESP8266 result | Notes |
|---|---|---|
| `PING`, `STATUS`, `HEAP`, `STOP_ALL`, `SET_CHANNEL` | Implemented | v1-compatible responses; additive ESP8266 web/repeater status |
| `SCAN_WIFI` | Implemented | Emits `scan_ap`; WPS is false because the Arduino scan API does not expose the upstream WPS flag |
| `START/STOP_CLIENT_DETECT` | Implemented | Passive management-frame observation |
| `DEAUTH_DETECT_START/STOP/STATUS` | Implemented | Passive detection, RSSI threshold, BSSID/client filters, fixed/hop channels |
| `START/STOP_HIDDEN_AP` | Implemented | Hidden beacon/probe detection, candidate and association-resolution events |
| BLE scan/profile/HID | Hardware unavailable | ESP8266 has no Bluetooth radio |
| Native USB MSC / BadUSB | Hardware unavailable | ESP8266 has no native USB device controller |
| Raw PCAP sniffer | Not advertised | Not included in this compatibility build |
| Active deauth/reconnect/beacon injection | Not advertised | Not included in this compatibility build |
| Credential collection / Evil Twin portal | Not advertised | Not included in this compatibility build |

Unsupported known commands return a structured `{ok:false,msg:...}` response instead of hanging the Android client.

## Network-mode reconciliation

The original NRSuite transport is app/USB-centric. This port adds web control without creating a second device state machine: serial commands and browser controls act on the same runtime monitor/network state.

Modes are AP-only, STA-only, AP+STA, and AP+STA Repeater with lwIP2 NAPT when compiled. ESP8266 has one Wi-Fi radio, so passive promiscuous monitoring and normal AP/STA service are serialized. Starting a detector suspends AP/STA/NAPT; `STOP_*`, `STOP_ALL`, or the browser capture timeout restores the saved profile.

## Memory / stability choices

- Fixed-size serial receive buffer with the v1 1024-byte protocol cap.
- Fixed monitor-event queue; the Wi-Fi callback does not build JSON or allocate `String`.
- Fixed hidden-BSSID cache.
- Event serialization in the normal loop, outside the Wi-Fi callback.
- EEPROM config with version, magic, and FNV-1a checksum.
- No human-readable debug output on the binary NRSuite serial transport.
- Web monitor start is deferred until after HTTP acknowledgement.

## ESP32 optimization review

The pinned ESP32 firmware already uses `-Os`, function/data sections, linker garbage collection, board-specific feature flags, and a single-app 4 MB partition strategy. No unbenchmarked rewrite is claimed as an optimization. A future ESP32 optimization pass should measure flash, static RAM, free heap under each module, detector event loss, and USB framing throughput before and after each change.

# NRSuite ESP8266 Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build an ESP8266 NRSuite v1 compatibility firmware with Android serial control plus AP/STA/AP+STA/NAPT web management.

**Architecture:** Keep one internal runtime state shared by the NRSuite binary serial dispatcher and the web UI. Use a fixed-buffer protocol parser and passive promiscuous-mode event queue; suspend normal networking during monitor mode and restore the persistent network profile afterwards.

**Tech Stack:** Arduino C++17, ESP8266 Arduino Core 3.1.2, ArduinoJson 7.4.3, ESP8266WebServer, DNSServer, EEPROM, lwIP2 NAPT.

**Spec:** `NRSuite/docs/RECONCILIATION.md`

## Global Constraints

- Preserve NRSuite protocol v1 framing and 115200 serial transport.
- Target NodeMCU 1.0 / ESP-12E with 4 MB flash.
- Do not claim BLE/native USB capabilities on ESP8266.
- Do not emit debug text onto the binary NRSuite serial transport.
- One Wi-Fi radio means monitor and AP/STA/repeater modes must be serialized.

## Review Focus

- UART boot garbage/partial frames must resynchronize at the next `AD DE` magic pair.
- Promiscuous callback must avoid heap-heavy JSON/String work.
- Web-started monitor must return HTTP acknowledgement before AP shutdown.
- Repeater must only report active after STA connectivity and successful NAPT enable.
- Unsupported app commands must fail explicitly rather than time out.

### Task 1: Protocol bridge
- [x] Define v1 constants and fixed receive buffer.
- [x] Implement resynchronization, payload limit, command dispatch, response/event encoding.
- [x] Verify no `Serial.print*` debug calls share the transport.

### Task 2: Passive ESP8266 monitor engine
- [x] Define documented 12-byte `RxControl` with size assertion.
- [x] Queue minimal packet metadata inside the promiscuous callback.
- [x] Serialize events in `loop()` and implement fixed/hopping channels plus filters/counters.

### Task 3: Dual app/web network control
- [x] Implement AP, STA, AP+STA, and NAPT repeater modes.
- [x] Add authenticated responsive web UI.
- [x] Suspend networking during passive monitor mode and restore it afterwards.
- [x] Delay web monitor start until after HTTP acknowledgement.

### Task 4: Capability negotiation and reconciliation
- [x] Advertise only capabilities the ESP8266 build implements.
- [x] Return explicit errors for known unsupported command names.
- [x] Document hardware-impossible BLE/native-USB parity and radio scheduling constraint.

### Task 5: Compile CI and final audit
- [x] Compile against ESP8266 core 3.1.2 and ArduinoJson 7.4.3.
- [x] Fix all compile failures without weakening protocol behavior.
- [x] Inspect final diff before merge.

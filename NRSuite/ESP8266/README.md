# NRSuite ESP8266 Compatibility Port

This directory contains an ESP8266 port of the NRSuite v1 device protocol plus a standalone web controller. It targets NodeMCU/ESP-12E-class boards with the normal USB-UART bridge.

## What this preserves

- NRSuite v1 serial framing: `AD DE`, frame type, frame ID, little-endian payload length, JSON payloads, 115200 baud.
- Android compatibility for `PING`, `STATUS`/`HEAP`, `STOP_ALL`, `SET_CHANNEL`, `SCAN_WIFI`, Client Detector, Deauth Detector, and Hidden AP Revealer.
- The same event names expected by the Android app for supported passive Wi-Fi modules.
- Persistent device/network settings.

## Added web mode

The sketch has its own authenticated web UI with AP-only, STA-only, AP+STA, and AP+STA NAPT repeater modes, Wi-Fi scan, timed passive monitoring, runtime status, and recent event history.

Default first boot:

- SSID: `NRSuite-8266`
- Wi-Fi password: `nrsuite8266`
- Web user: `admin`
- Web password: `nrsuite8266`
- AP address: `192.168.50.1`

Change the defaults after first boot.

## ESP8266 hardware boundary

ESP8266 has no Bluetooth radio and no native USB device controller, so BLE HID/scanning/GATT, native USB HID/BadUSB, and USB MSC cannot be reproduced on this chip. Those feature flags are not advertised to the Android app.

ESP8266 also has one 2.4 GHz Wi-Fi radio. Promiscuous monitoring disrupts normal AP/STA traffic, so this port suspends the management/repeater network while a passive monitor is active and restores the saved configuration when monitoring stops. Browser-started captures are timed so the web network returns automatically.

The port does not advertise active Wi-Fi frame-injection, credential-collection portal, or raw-PCAP modules. Unsupported known commands receive an explicit response instead of silently timing out.

## Build

Recommended baseline:

- ESP8266 Arduino Core `3.1.2`
- ArduinoJson `7.4.3`
- Board: `NodeMCU 1.0 (ESP-12E Module)` / `nodemcuv2`
- Flash: 4 MB
- Serial: 115200

Open `NRSuite_ESP8266/NRSuite_ESP8266.ino` in Arduino IDE, install ArduinoJson, select NodeMCU 1.0, then Verify/Upload.

See `../docs/RECONCILIATION.md` for the audited command matrix and pinned upstream versions.

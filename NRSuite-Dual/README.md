# NRSuite Dual-Control Reconciliation

A resource-conscious reconciliation of the NRSuite Android / ESP32 ecosystem with an ESP8266 defensive port and a web-control architecture for both MCU families.

## Contents

- \`ESP8266/NRSuite_ESP8266_Dual.ino\` — single-file ESP8266 firmware with Android-compatible framed serial control plus built-in web control.
- \`ESP32-Optimized/README.md\` — audited optimization/refactor overlay for the upstream ESP32 firmware.
- \`AUDIT.md\` — compatibility, hardware, resource, and safety reconciliation notes.
- \`UPSTREAM.md\` — exact upstream projects/revisions used for this reconciliation.

## ESP8266 quick start

Recommended: ESP8266 Arduino Core 3.x, NodeMCU 1.0 / ESP-12E or Wemos D1 mini, preferably 4 MB flash.

Default setup AP: \`NRSuite-xxxxxx\`

Default setup password: \`nrsuite8266\`

Default web credentials: \`admin\` / \`nrsuite8266\`

Open \`http://192.168.4.1/\` while connected to the setup AP.

The network page supports AP, STA with fallback AP, AP+STA, and AP+STA Internet Repeater (NAPT). Because ESP8266 has one 2.4 GHz radio, channel-hopping passive monitoring temporarily conflicts with a stable STA/repeater link; the firmware handles that as an explicit radio mode instead of pretending both can run independently.

## Android app compatibility

The ESP8266 firmware preserves NRSuite protocol v1 framing and the \`PING\` / \`STATUS\` handshake. A board with a CH340/CP2102 USB-UART interface can therefore be controlled through the existing Android serial session for supported commands. Unsupported active/offensive feature flags are not advertised.

## Scope

This fork focuses on device management, scanning, passive detection, telemetry, web control, and network/repeater operation. Active deauthentication injection, credential-capture portals, WPA cracking, beacon spam, and BadUSB payload execution are intentionally not reproduced in this port.

# Android upstream reference

- Repository: `7wp81x/NRSuite-Android`
- Audited commit: `aa25ea1e304138b25012965732a45b8e9b246611`
- App release compatibility documented upstream: `v1.0.0-beta.2`
- Protocol: NRSuite v1.0

The ESP8266 port keeps the original USB-UART serial framing so the existing Android transport can identify and control the capabilities the ESP8266 firmware advertises through `STATUS.features`.

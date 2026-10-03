/*
 * NRSuite ESP8266 Compatibility Port
 * ----------------------------------
 * Upstream Android app: https://github.com/7wp81x/NRSuite-Android
 * Upstream ESP32 firmware: https://github.com/7wp81x/NRSuite-firmware
 * Wire protocol: https://github.com/7wp81x/NRSuite-Protocol (v1.0)
 *
 * Goals:
 *  - Keep the NRSuite v1 USB-serial frame protocol so the Android app can
 *    connect through the ESP8266 board's normal USB-UART bridge.
 *  - Add a standalone responsive web UI so the device does not require the app.
 *  - Support AP, STA, AP+STA, and AP+STA NAPT range-extender modes.
 *  - Port the ESP8266-capable passive Wi-Fi research/detection modules.
 *  - Report unsupported ESP32-only capabilities honestly through STATUS.features.
 *
 * Required:
 *  - ESP8266 Arduino Core 3.1.2 or later
 *  - ArduinoJson 7.4.x
 *
 * Tested/targeted board profile:
 *  - NodeMCU 1.0 (ESP-12E), 4 MB flash, 80/160 MHz
 *
 * IMPORTANT RADIO LIMIT:
 * ESP8266 has one 2.4 GHz radio. Promiscuous monitor mode and normal AP/STA
 * networking are mutually disruptive. When a passive detector is started,
 * this firmware suspends normal Wi-Fi networking; stopping it restores the
 * saved AP/STA/repeater configuration. Browser-started monitors therefore use
 * a timed capture window and restore the web network automatically.
 */

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <EEPROM.h>
#include <ArduinoJson.h>
#include <stddef.h>

extern "C" {
  #include "user_interface.h"
}

// ESP8266 NONOS promiscuous callbacks prepend this 12-byte metadata block.
// The SDK exposes the callback API but not this historical layout in
// user_interface.h, so define the documented receive-control structure here.
struct RxControl {
  signed rssi:8;
  unsigned rate:4;
  unsigned is_group:1;
  unsigned:1;
  unsigned sig_mode:2;
  unsigned legacy_length:12;
  unsigned damatch0:1;
  unsigned damatch1:1;
  unsigned bssidmatch0:1;
  unsigned bssidmatch1:1;
  unsigned MCS:7;
  unsigned CWB:1;
  unsigned HT_length:16;
  unsigned Smoothing:1;
  unsigned Not_Sounding:1;
  unsigned:1;
  unsigned Aggregation:1;
  unsigned STBC:2;
  unsigned FEC_CODING:1;
  unsigned SGI:1;
  unsigned rxend_state:8;
  unsigned ampdu_cnt:8;
  unsigned channel:4;
  unsigned:12;
} __attribute__((packed));
static_assert(sizeof(RxControl) == 12, "ESP8266 RxControl layout must be 12 bytes");

#if LWIP_FEATURES && !LWIP_IPV6
  #include <lwip/napt.h>
  #include <lwip/dns.h>
  #define NR_HAS_NAPT 1
#else
  #define NR_HAS_NAPT 0
#endif

// -----------------------------------------------------------------------------
// Build identity / protocol constants
// -----------------------------------------------------------------------------
#define NR_FW_VERSION       "1.0.0-esp8266.1"
#define NR_PROTO_VERSION    1
#define NR_PROTO_MAGIC_0    0xAD
#define NR_PROTO_MAGIC_1    0xDE
#define NR_PROTO_HEADER_SZ  8
#define NR_PROTO_MAX_CHUNK  1024
#define NR_RX_BUF_SIZE      (NR_PROTO_MAX_CHUNK + NR_PROTO_HEADER_SZ + 64)

#define NR_TYPE_CMD   0x01
#define NR_TYPE_RESP  0x02
#define NR_TYPE_EVENT 0x03
#define NR_TYPE_PCAP  0x04
#define NR_TYPE_ACK   0x05
#define NR_TYPE_HTML  0x06

#define NR_EEPROM_SIZE 1024
#define NR_CONFIG_MAGIC 0x4E523836UL  // "NR86"
#define NR_CONFIG_VERSION 2

#define NR_MAX_PENDING_EVENTS 20
#define NR_MAX_WEB_EVENTS 24
#define NR_HIDDEN_CACHE 16

#if NR_HAS_NAPT
  #define NR_NAPT_ENTRIES 256
  #define NR_NAPT_PORTMAP 8
#endif

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------
enum NetworkMode : uint8_t {
  NET_AP_ONLY = 0,
  NET_STA_ONLY = 1,
  NET_AP_STA = 2,
  NET_REPEATER = 3
};

struct DeviceConfig {
  uint32_t magic;
  uint16_t version;
  uint8_t networkMode;
  uint8_t reserved;
  char apSsid[33];
  char apPass[65];
  char staSsid[33];
  char staPass[65];
  char webUser[33];
  char webPass[65];
  uint32_t crc;
};

DeviceConfig cfg;

static uint32_t fnv1a(const uint8_t* data, size_t len) {
  uint32_t h = 2166136261UL;
  for (size_t i = 0; i < len; ++i) {
    h ^= data[i];
    h *= 16777619UL;
  }
  return h;
}

static void setDefaults() {
  memset(&cfg, 0, sizeof(cfg));
  cfg.magic = NR_CONFIG_MAGIC;
  cfg.version = NR_CONFIG_VERSION;
  cfg.networkMode = NET_AP_ONLY;
  strlcpy(cfg.apSsid, "NRSuite-8266", sizeof(cfg.apSsid));
  strlcpy(cfg.apPass, "nrsuite8266", sizeof(cfg.apPass));
  strlcpy(cfg.webUser, "admin", sizeof(cfg.webUser));
  strlcpy(cfg.webPass, "nrsuite8266", sizeof(cfg.webPass));
  cfg.crc = fnv1a(reinterpret_cast<const uint8_t*>(&cfg), offsetof(DeviceConfig, crc));
}

static void saveConfig() {
  cfg.magic = NR_CONFIG_MAGIC;
  cfg.version = NR_CONFIG_VERSION;
  cfg.crc = fnv1a(reinterpret_cast<const uint8_t*>(&cfg), offsetof(DeviceConfig, crc));
  EEPROM.put(0, cfg);
  EEPROM.commit();
}

static void loadConfig() {
  EEPROM.begin(NR_EEPROM_SIZE);
  EEPROM.get(0, cfg);
  uint32_t expected = fnv1a(reinterpret_cast<const uint8_t*>(&cfg), offsetof(DeviceConfig, crc));
  if (cfg.magic != NR_CONFIG_MAGIC || cfg.version != NR_CONFIG_VERSION || cfg.crc != expected) {
    setDefaults();
    saveConfig();
  }
  if (cfg.networkMode > NET_REPEATER) cfg.networkMode = NET_AP_ONLY;
}

// -----------------------------------------------------------------------------
// NRSuite serial bridge
// -----------------------------------------------------------------------------
class NrBridge {
public:
  typedef void (*CommandHandler)(uint8_t id, JsonDocument& doc);

  void begin(Stream& stream, CommandHandler handler) {
    _stream = &stream;
    _handler = handler;
    _rxLen = 0;
    _oversized = 0;
  }

  uint32_t oversizedFrames() const { return _oversized; }

  void update() {
    if (!_stream) return;
    while (_stream->available()) {
      int c = _stream->read();
      if (c < 0) break;
      if (_rxLen < sizeof(_rx)) {
        _rx[_rxLen++] = static_cast<uint8_t>(c);
      } else {
        resync();
        if (_rxLen >= sizeof(_rx)) {
          memmove(_rx, _rx + 1, --_rxLen);
        }
      }
      while (tryParse()) yield();
    }
  }

  void sendResp(uint8_t id, bool ok, const char* msg = nullptr) {
    JsonDocument doc;
    doc["ok"] = ok;
    if (msg && *msg) doc["msg"] = msg;
    sendJson(NR_TYPE_RESP, id, doc);
  }

  void sendEvent(const char* type, JsonDocument& doc) {
    doc["type"] = type;
    sendJson(NR_TYPE_EVENT, 0, doc);
  }

  void sendJson(uint8_t type, uint8_t id, JsonDocument& doc) {
    String out;
    out.reserve(384);
    serializeJson(doc, out);
    sendRaw(type, id, reinterpret_cast<const uint8_t*>(out.c_str()), out.length());
  }

  void sendRaw(uint8_t type, uint8_t id, const uint8_t* payload, uint32_t len) {
    if (!_stream || len > NR_PROTO_MAX_CHUNK) return;
    uint8_t h[NR_PROTO_HEADER_SZ];
    h[0] = NR_PROTO_MAGIC_0;
    h[1] = NR_PROTO_MAGIC_1;
    h[2] = type;
    h[3] = id;
    h[4] = len & 0xFF;
    h[5]
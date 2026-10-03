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
    h[5] = (len >> 8) & 0xFF;
    h[6] = (len >> 16) & 0xFF;
    h[7] = (len >> 24) & 0xFF;
    _stream->write(h, sizeof(h));
    if (len && payload) _stream->write(payload, len);
  }

private:
  Stream* _stream = nullptr;
  CommandHandler _handler = nullptr;
  uint8_t _rx[NR_RX_BUF_SIZE];
  size_t _rxLen = 0;
  uint32_t _oversized = 0;

  bool tryParse() {
    if (_rxLen < NR_PROTO_HEADER_SZ) return false;
    if (_rx[0] != NR_PROTO_MAGIC_0 || _rx[1] != NR_PROTO_MAGIC_1) {
      resync();
      return _rxLen >= NR_PROTO_HEADER_SZ;
    }

    uint8_t type = _rx[2];
    uint8_t id = _rx[3];
    uint32_t len = static_cast<uint32_t>(_rx[4])
                 | (static_cast<uint32_t>(_rx[5]) << 8)
                 | (static_cast<uint32_t>(_rx[6]) << 16)
                 | (static_cast<uint32_t>(_rx[7]) << 24);

    if (len > NR_PROTO_MAX_CHUNK) {
      ++_oversized;
      resync();
      return true;
    }

    size_t total = NR_PROTO_HEADER_SZ + len;
    if (_rxLen < total) return false;

    if (type == NR_TYPE_CMD && _handler) {
      JsonDocument doc;
      DeserializationError err = deserializeJson(doc, _rx + NR_PROTO_HEADER_SZ, len);
      if (!err) {
        _handler(id, doc);
      } else {
        sendResp(id, false, "parse error");
      }
    }

    memmove(_rx, _rx + total, _rxLen - total);
    _rxLen -= total;
    return true;
  }

  void resync() {
    if (_rxLen == 0) return;
    for (size_t i = 1; i + 1 < _rxLen; ++i) {
      if (_rx[i] == NR_PROTO_MAGIC_0 && _rx[i + 1] == NR_PROTO_MAGIC_1) {
        memmove(_rx, _rx + i, _rxLen - i);
        _rxLen -= i;
        return;
      }
    }
    if (_rx[_rxLen - 1] == NR_PROTO_MAGIC_0) {
      _rx[0] = NR_PROTO_MAGIC_0;
      _rxLen = 1;
    } else {
      _rxLen = 0;
    }
  }
};

NrBridge bridge;

// -----------------------------------------------------------------------------
// Passive Wi-Fi monitor engine
// -----------------------------------------------------------------------------
enum MonitorMode : uint8_t {
  MON_NONE = 0,
  MON_CLIENT = 1,
  MON_DEAUTH = 2,
  MON_HIDDEN = 3
};

enum MonitorEventType : uint8_t {
  EV_NONE = 0,
  EV_CLIENT = 1,
  EV_DEAUTH = 2,
  EV_HIDDEN_AP = 3,
  EV_HIDDEN_CANDIDATE = 4,
  EV_HIDDEN_RESOLVED = 5,
  EV_HOP = 6
};

struct MonitorEvent {
  uint8_t type;
  uint8_t subtype;
  uint8_t channel;
  int8_t rssi;
  uint16_t reason;
  uint32_t uptimeMs;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t bssid[6];
  char ssid[33];
};

struct HiddenCacheEntry {
  bool used;
  uint8_t bssid[6];
  uint32_t lastSeen;
};

volatile uint8_t pendingHead = 0;
volatile uint8_t pendingTail = 0;
MonitorEvent pendingEvents[NR_MAX_PENDING_EVENTS];
HiddenCacheEntry hiddenCache[NR_HIDDEN_CACHE];

MonitorMode monitorMode = MON_NONE;
bool monitorHop = false;
uint8_t monitorChannel = 1;
uint16_t monitorHopIntervalMs = 300;
int8_t monitorRssiMin = -100;
uint32_t monitorLastHop = 0;
uint32_t monitorAutoStopAt = 0;
uint32_t monitorDetected = 0;
uint32_t monitorSent = 0;
uint32_t monitorDropped = 0;
uint32_t hiddenSeen = 0;
uint32_t hiddenCandidates = 0;
uint32_t hiddenResolved = 0;
bool deauthFilterHasBssid = false;
bool deauthFilterHasClient = false;
uint8_t deauthFilterBssid[6] = {0};
uint8_t deauthFilterClient[6] = {0};

// Browser requests must be acknowledged before radio-monitor mode tears down
// the AP/STA interface that carried the HTTP request.
bool pendingWebMonitorStart = false;
MonitorMode pendingWebMonitorMode = MON_NONE;
uint8_t pendingWebMonitorChannel = 1;
bool pendingWebMonitorHop = false;
uint32_t pendingWebMonitorDurationMs = 0;
uint32_t pendingWebMonitorStartAt = 0;

static bool parseMacText(const char* text, uint8_t out[6]) {
  if (!text || !*text || !out) return false;
  unsigned int b[6];
  if (sscanf(text, "%x:%x:%x:%x:%x:%x",
             &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) return false;
  for (uint8_t i = 0; i < 6; ++i) {
    if (b[i] > 0xFF) return false;
    out[i] = static_cast<uint8_t>(b[i]);
  }
  return true;
}

static void macToString(const uint8_t* mac, char* out) {
  snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static bool parseSsidIe(const uint8_t* frame, size_t frameLen, size_t offset,
                        char* out, size_t outSize, bool* present) {
  if (present) *present = false;
  if (!frame || !out || outSize < 2) return false;
  out[0] = '\0';
  while (offset + 2 <= frameLen) {
    uint8_t id = frame[offset];
    uint8_t ieLen = frame[offset + 1];
    if (offset + 2 + ieLen > frameLen) break;
    if (id == 0) {
      if (present) *present = true;
      size_t n = min(static_cast<size_t>(ieLen), outSize - 1);
      if (n) memcpy(out, frame + offset + 2, n);
      out[n] = '\0';
      return n > 0;
    }
    offset += 2 + ieLen;
  }
  return false;
}

static bool queueMonitorEvent(const MonitorEvent& ev) {
  uint8_t next = (pendingHead + 1) % NR_MAX_PENDING_EVENTS;
  if (next == pendingTail) {
    ++monitorDropped;
    return false;
  }
  pendingEvents[pendingHead] = ev;
  pendingHead = next;
  return true;
}

static void promiscuousCb(uint8_t* buf, uint16_t len) {
  if (monitorMode == MON_NONE || !buf || len <= sizeof(RxControl)) return;

  RxControl* rx = reinterpret_cast<RxControl*>(buf);
  const uint8_t* frame = buf + sizeof(RxControl);
  size_t frameLen = len - sizeof(RxControl);
  if (frameLen < 24) return;

  uint8_t fc0 = frame[0];
  uint8_t type = (fc0 >> 2) & 0x03;
  if (type != 0) return; // management frames only for reliability on ESP8266

  uint8_t subtype = (fc0 >> 4) & 0x0F;
  int8_t rssi = rx->rssi;
  if (rssi < monitorRssiMin) return;

  MonitorEvent ev{};
  ev.subtype = subtype;
  ev.channel = wifi_get_channel();
  ev.rssi = rssi;
  ev.uptimeMs = millis();
  memcpy(ev.addr1, frame + 4, 6);
  memcpy(ev.addr2, frame + 10, 6);
  memcpy(ev.bssid, frame + 16, 6);

  if (monitorMode == MON_DEAUTH) {
    if (subtype != 0x0C && subtype != 0x0A) return;
    ev.type = EV_DEAUTH;
    if (frameLen >= 26) ev.reason = frame[24] | (static_cast<uint16_t>(frame[25]) << 8);
    queueMonitorEvent(ev);
    return;
  }

  if (monitorMode == MON_CLIENT) {
    if (subtype != 0x04 && subtype != 0x00 && subtype != 0x02 && subtype != 0x0B) return;
    ev.type = EV_CLIENT;
    bool present = false;
    if (subtype == 0x04) parseSsidIe(frame, frameLen, 24, ev.ssid, sizeof(ev.ssid), &present);
    else if (subtype == 0x00) parseSsidIe(frame, frameLen, 28, ev.ssid, sizeof(ev.ssid), &present);
    else if (subtype == 0x02) parseSsidIe(frame, frameLen, 34, ev.ssid, sizeof(ev.ssid), &present);
    queueMonitorEvent(ev);
    return;
  }

  if (monitorMode == MON_HIDDEN) {
    if (subtype == 0x08 || subtype == 0x05) {
      if (frameLen < 36) return;
      bool present = false;
      bool hasSsid = parseSsidIe(frame, frameLen, 36, ev.ssid, sizeof(ev.ssid), &present);
      if (hasSsid) return;
      ev.type = EV_HIDDEN_AP;
      queueMonitorEvent(ev);
      return;
    }
    if (subtype == 0x04) {
      bool present = false;
      bool hasSsid = parseSsidIe(frame, frameLen, 24, ev.ssid, sizeof(ev.ssid), &present);
      if (!hasSsid || !present) return;
      ev.type = EV_HIDDEN_CANDIDATE;
      queueMonitorEvent(ev);
      return;
    }
    if (subtype == 0x00 || subtype == 0x02) {
      size_t off = subtype == 0x00 ? 28 : 34;
      bool present = false;
      bool hasSsid = parseSsidIe(frame, frameLen, off, ev.ssid, sizeof(ev.ssid), &present);
      if (!hasSsid || !present) return;
      ev.type = EV_HIDDEN_RESOLVED;
      queueMonitorEvent(ev);
      return;
    }
  }
}

static void rememberHidden(const uint8_t* bssid) {
  uint32_t now = millis();
  int empty = -1;
  int oldest = 0;
  uint32_t oldestMs = 0xFFFFFFFFUL;
  for (int i = 0; i < NR_HIDDEN_CACHE; ++i) {
    if (hiddenCache[i].used && memcmp(hiddenCache[i].bssid, bssid, 6) == 0) {
      hiddenCache[i].lastSeen = now;
      return;
    }
    if (!hiddenCache[i].used && empty < 0) empty = i;
    if (hiddenCache[i].used && hiddenCache[i].lastSeen < oldestMs) {
      oldestMs = hiddenCache[i].lastSeen;
      oldest = i;
    }
  }
  int slot = empty >= 0 ? empty : oldest;
  hiddenCache[slot].used = true;
  memcpy(hiddenCache[slot].bssid, bssid, 6);
  hiddenCache[slot].lastSeen = now;
}

static bool isKnownHidden(const uint8_t* bssid) {
  for (int i = 0; i < NR_HIDDEN_CACHE; ++i) {
    if (hiddenCache[i].used && memcmp(hiddenCache[i].bssid, bssid, 6) == 0) return true;
  }
  return false;
}

// -----------------------------------------------------------------------------
// Web event ring
// -----------------------------------------------------------------------------
String webEvents[NR_MAX_WEB_EVENTS];
uint8_t webEventHead = 0;
uint8_t webEventCount = 0;

static void logWebEvent(const String& json) {
  webEvents[webEventHead] = json;
  webEventHead = (webEventHead + 1) % NR_MAX_WEB_EVENTS;
  if (webEventCount < NR_MAX_WEB_EVENTS) ++webEventCount;
}

// -----------------------------------------------------------------------------
// Network / web server
// -----------------------------------------------------------------------------
ESP8266WebServer web(80);
DNSServer dns;
bool webStarted = false;
bool dnsStarted = false;
bool naptEnabled = false;
uint32_t lastNetworkService = 0;

static const IPAddress AP_IP(192, 168, 50, 1);
static const IPAddress AP_GW(192, 168, 50, 1);
static const IPAddress AP_MASK(255, 255, 255, 0);

static bool hasApMode() {
  return cfg.networkMode == NET_AP_ONLY || cfg.networkMode == NET_AP_STA || cfg.networkMode == NET_REPEATER;
}

static bool hasStaMode() {
  return cfg.networkMode == NET_STA_ONLY || cfg.networkMode == NET_AP_STA || cfg.networkMode == NET_REPEATER;
}

static String networkModeName() {
  switch (cfg.networkMode) {
    case NET_AP_ONLY: return F("AP");
    case NET_STA_ONLY: return F("STA");
    case NET_AP_STA: return F("AP+STA");
    case NET_REPEATER: return F("AP+STA Repeater");
    default: return F("Unknown");
  }
}

static void stopDns() {
  if (dnsStarted) {
    dns.stop();
    dnsStarted = false;
  }
}

static void stopNapt() {
#if NR_HAS_NAPT
  if (naptEnabled) {
    ip_napt_enable_no(SOFTAP_IF, 0);
    naptEnabled = false;
  }
#else
  naptEnabled = false;
#endif
}

static void startWebIfNeeded();

static void applyNetworkConfig() {
  stopDns();
  stopNapt();
  wifi_promiscuous_enable(0);
  delay(1);
  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);

  if (cfg.networkMode == NET_AP_ONLY) WiFi.mode(WIFI_AP);
  else if (cfg.networkMode == NET_STA_ONLY) WiFi.mode(WIFI_STA);
  else WiFi.mode(WIFI_AP_STA);

  if (hasStaMode() && cfg.staSsid[0]) {
    WiFi.begin(cfg.staSsid, cfg.staPass);
  } else if (hasStaMode()) {
    WiFi.disconnect();
  }

  if (hasApMode()) {
    WiFi.softAPConfig(AP_IP, AP_GW, AP_MASK);
    size_t passLen = strlen(cfg.apPass);
    if (passLen >= 8) WiFi.softAP(cfg.apSsid, cfg.apPass);
    else WiFi.softAP(cfg.apSsid);
    dns.setErrorReplyCode(DNSReplyCode::NoError);
    dns.start(53, "*", AP_IP);
    dnsStarted = true;
  }

  startWebIfNeeded();
}

static void serviceNapt() {
  if (cfg.networkMode != NET_REPEATER || monitorMode != MON_NONE) {
    stopNapt();
    return;
  }
#if NR_HAS_NAPT
  if (WiFi.status() == WL_CONNECTED && !naptEnabled) {
    auto& dhcp = WiFi.softAPDhcpServer();
    IPAddress upstreamDns = WiFi.dnsIP(0);
    if (upstreamDns != IPAddress(0, 0, 0, 0)) dhcp.setDns(upstreamDns);
    err_t ret = ip_napt_init(NR_NAPT_ENTRIES, NR_NAPT_PORTMAP);
    if (ret == ERR_OK) {
      ret = ip_napt_enable_no(SOFTAP_IF, 1);
      naptEnabled = (ret == ERR_OK);
    }
  }
#else
  naptEnabled = false;
#endif
}

// -----------------------------------------------------------------------------
// Monitor lifecycle - suspends web/AP/STA because ESP8266 promiscuous mode is
// not a reliable concurrent range-extender transport.
// -----------------------------------------------------------------------------
static bool startMonitor(MonitorMode mode, uint8_t channel, bool hop,
                         uint16_t hopInterval, int8_t rssiMin,
                         uint32_t autoDurationMs = 0) {
  if (mode == MON_NONE) return false;
  if (channel < 1 || channel > 13) channel = 1;
  if (hopInterval < 50) hopInterval = 50;
  if (hopInterval > 5000) hopInterval = 5000;
  if (rssiMin < -100) rssiMin = -100;
  if (rssiMin > -10) rssiMin = -10;

  if (monitorMode != MON_NONE) {
    wifi_promiscuous_enable(0);
    monitorMode = MON_NONE;
  }

  stopDns();
  stopNapt();
  WiFi.disconnect(true);
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
  delay(20);

  wifi_set_opmode(STATION_MODE);
  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(promiscuousCb);
  monitorMode = mode;
  monitorHop = hop;
  monitorChannel = hop ? 1 : channel;
  monitorHopIntervalMs = hopInterval;
  monitorRssiMin = rssiMin;
  monitorLastHop = millis();
  monitorAutoStopAt = autoDurationMs ? millis() + autoDurationMs : 0;
  monitorDetected = monitorSent = monitorDropped = 0;
  hiddenSeen = hiddenCandidates = hiddenResolved = 0;
  pendingHead = pendingTail = 0;
  memset(hiddenCache, 0, sizeof(hiddenCache));
  wifi_set_channel(monitorChannel);
  wifi_promiscuous_enable(1);
  return true;
}

static void stopMonitor(bool restoreNetwork = true) {
  if (monitorMode != MON_NONE) {
    wifi_promiscuous_enable(0);
    wifi_set_promiscuous_rx_cb(nullptr);
    monitorMode = MON_NONE;
    monitorAutoStopAt = 0;
    deauthFilterHasBssid = false;
    deauthFilterHasClient = false;
    delay(10);
  }
  if (restoreNetwork) applyNetworkConfig();
}

static const char* subtypeName(uint8_t subtype) {
  switch (subtype) {
    case 0x00: return "assoc";
    case 0x02: return "reassoc";
    case 0x04: return "probe";
    case 0x0A: return "disassoc";
    case 0x0B: return "auth";
    case 0x0C: return "deauth";
    default: return "mgmt";
  }
}

static void emitMonitorEvent(MonitorEvent& ev) {
  char a1[18], a2[18], bssid[18];
  macToString(ev.addr1, a1);
  macToString(ev.addr2, a2);
  macToString(ev.bssid, bssid);

  JsonDocument doc;
  const char* eventName = "debug";

  if (ev.type == EV_DEAUTH) {
    if (deauthFilterHasBssid &&
        memcmp(ev.addr2, deauthFilterBssid, 6) != 0 &&
        memcmp(ev.bssid, deauthFilterBssid, 6) != 0) return;
    if (deauthFilterHasClient && memcmp(ev.addr1, deauthFilterClient, 6) != 0) return;
    ++monitorDetected;
    eventName = "deauth_detected";
    doc["subtype"] = ev.subtype == 0x0C ? "deauth" : "disassoc";
    doc["subtype_code"] = ev.subtype;
    doc["bssid"] = bssid;
    doc["source"] = a2;
    doc["client"] = a1;
    doc["destination"] = a1;
    doc["channel"] = ev.channel;
    doc["rssi"] = ev.rssi;
    doc["reason"] = ev.reason;
    doc["uptime_ms"] = ev.uptimeMs;
  } else if (ev.type == EV_CLIENT) {
    ++monitorDetected;
    eventName = "client_detected";
    doc["client"] = a2;
    doc["bssid"] = bssid;
    if (ev.ssid[0]) doc["ssid"] = ev.ssid;
    doc["subtype"] = subtypeName(ev.subtype);
    doc["rssi"] = ev.rssi;
    doc["channel"] = ev.channel;
  } else if (ev.type == EV_HIDDEN_AP) {
    ++monitorDetected;
    rememberHidden(ev.bssid);
    ++hiddenSeen;
    eventName = "hidden_ap";
    doc["bssid"] = bssid;
    doc["channel"] = ev.channel;
    doc["rssi"] = ev.rssi;
    doc["uptime_ms"] = ev.uptimeMs;
    doc["subtype"] = subtypeName(ev.subtype);
  } else if (ev.type == EV_HIDDEN_CANDIDATE) {
    ++monitorDetected;
    ++hiddenCandidates;
    eventName = "hidden_ssid_candidate";
    doc["client"] = a2;
    doc["ssid"] = ev.ssid;
    doc["channel"] = ev.channel;
    doc["rssi"] = ev.rssi;
    doc["uptime_ms"] = ev.uptimeMs;
    doc["subtype"] = subtypeName(ev.subtype);
  } else if (ev.type == EV_HIDDEN_RESOLVED) {
    if (!isKnownHidden(ev.bssid)) return;
    ++monitorDetected;
    ++hiddenResolved;
    eventName = "hidden_ssid_resolved";
    doc["bssid"] = bssid;
    doc["client"] = a2;
    doc["ssid"] = ev.ssid;
    doc["channel"] = ev.channel;
    doc["rssi"] = ev.rssi;
    doc["uptime_ms"] = ev.uptimeMs;
    doc["subtype"] = subtypeName(ev.subtype);
  } else {
    return;
  }

  bridge.sendEvent(eventName, doc);
  ++monitorSent;
  String json;
  doc["type"] = eventName;
  serializeJson(doc, json);
  logWebEvent(json);
}

static void serviceMonitor() {
  if (monitorMode == MON_NONE) return;

  if (monitorHop && millis() - monitorLastHop >= monitorHopIntervalMs) {
    monitorLastHop = millis();
    monitorChannel = (monitorChannel % 13) + 1;
    wifi_set_channel(monitorChannel);
    JsonDocument ev;
    ev["channel"] = monitorChannel;
    if (monitorMode == MON_DEAUTH) bridge.sendEvent("deauth_detector_hop", ev);
    else if (monitorMode == MON_HIDDEN) bridge.sendEvent("hidden_ap_hop", ev);
  }

  while (pendingTail != pendingHead) {
    MonitorEvent ev = pendingEvents[pendingTail];
    pendingTail = (pendingTail + 1) % NR_MAX_PENDING_EVENTS;
    emitMonitorEvent(ev);
    yield();
  }

  if (monitorAutoStopAt && static_cast<int32_t>(millis() - monitorAutoStopAt) >= 0) {
    stopMonitor(true);
  }
}

// -----------------------------------------------------------------------------
// Wi-Fi scan helpers
// -----------------------------------------------------------------------------
static const char* encName(uint8_t enc) {
  switch (enc) {
#ifdef ENC_TYPE_NONE
    case ENC_TYPE_NONE: return "OPEN";
#endif
#ifdef ENC_TYPE_WEP
    case ENC_TYPE_WEP: return "WEP";
#endif
#ifdef ENC_TYPE_TKIP
    case ENC_TYPE_TKIP: return "WPA/TKIP";
#endif
#ifdef ENC_TYPE_CCMP
    case ENC_TYPE_CCMP: return "WPA2/CCMP";
#endif
#ifdef ENC_TYPE_AUTO
    case ENC_TYPE_AUTO: return "WPA/WPA2";
#endif
    default: return "UNKNOWN";
  }
}

static int scanWifiAndEmit() {
  int n = WiFi.scanNetworks(false, true);
  if (n < 0) return n;
  for (int i = 0; i < n; ++i) {
    JsonDocument ev;
    ev["ssid"] = WiFi.SSID(i);
    ev["bssid"] = WiFi.BSSIDstr(i);
    ev["channel"] = WiFi.channel(i);
    ev["rssi"] = WiFi.RSSI(i);
    ev["security"] = encName(WiFi.encryptionType(i));
    ev["wps"] = false; // ESP8266 Arduino scan API does not expose a WPS flag.
    bridge.sendEvent("scan_ap", ev);
    yield();
  }
  WiFi.scanDelete();
  return n;
}

// -----------------------------------------------------------------------------
// STATUS document / feature negotiation
// -----------------------------------------------------------------------------
static void fillStatus(JsonDocument& doc) {
  doc["ok"] = true;
  doc["uptime"] = millis();
  doc["heap"] = ESP.getFreeHeap();
  doc["chip"] = "ESP8266";
  doc["proto"] = NR_PROTO_VERSION;
  doc["fw"] = NR_FW_VERSION;
  char dev[16];
  snprintf(dev, sizeof(dev), "NR%08X", ESP.getChipId());
  doc["device_id"] = dev;

  JsonArray features = doc["features"].to<JsonArray>();
  features.add("wifi");
  features.add("client_detect");
  features.add("deauth_detect");
  features.add("hidden_ap");
  features.add("stop_all");
  // Custom additive flags; old Android clients safely ignore unknown flags.
  features.add("web_admin");
#if NR_HAS_NAPT
  features.add("repeater");
#endif

  doc["sniffing"] = false;
  doc["client_detecting"] = (monitorMode == MON_CLIENT);
  doc["portal"] = false;
  doc["beacon"] = false;
  doc["deauth_detector"] = (monitorMode == MON_DEAUTH);
  doc["hidden_ap"] = (monitorMode == MON_HIDDEN);
  doc["ble_scanning"] = false;
  doc["ble_profiling"] = false;
  doc["oversized_frames"] = bridge.oversizedFrames();
  doc["channel"] = monitorMode != MON_NONE ? monitorChannel : WiFi.channel();
  doc["deauth_detector_channel"] = monitorChannel;
  doc["deauth_detector_hopping"] = monitorMode == MON_DEAUTH && monitorHop;
  doc["deauth_detected"] = monitorMode == MON_DEAUTH ? monitorDetected : 0;
  doc["deauth_detector_sent"] = monitorMode == MON_DEAUTH ? monitorSent : 0;
  doc["deauth_detector_dropped"] = monitorMode == MON_DEAUTH ? monitorDropped : 0;
  doc["hidden_ap_channel"] = monitorChannel;
  doc["hidden_ap_hopping"] = monitorMode == MON_HIDDEN && monitorHop;
  doc["hidden_ap_seen"] = monitorMode == MON_HIDDEN ? hiddenSeen : 0;
  doc["hidden_ap_candidates"] = monitorMode == MON_HIDDEN ? hiddenCandidates : 0;
  doc["hidden_ap_resolved"] = monitorMode == MON_HIDDEN ? hiddenResolved : 0;
  doc["hidden_ap_sent"] = monitorMode == MON_HIDDEN ? monitorSent : 0;
  doc["hidden_ap_dropped"] = monitorMode == MON_HIDDEN ? monitorDropped : 0;

  // ESP8266 extension fields for the web UI.
  doc["network_mode"] = networkModeName();
  doc["sta_connected"] = WiFi.status() == WL_CONNECTED;
  doc["sta_ip"] = WiFi.localIP().toString();
  doc["ap_ip"] = hasApMode() ? WiFi.softAPIP().toString() : String("");
  doc["ap_clients"] = hasApMode() ? WiFi.softAPgetStationNum() : 0;
  doc["napt"] = naptEnabled;
  doc["napt_compiled"] = static_cast<bool>(NR_HAS_NAPT);
}

// -----------------------------------------------------------------------------
// Command dispatcher
// -----------------------------------------------------------------------------
static bool isAnyOf(const char* cmd, const char* const* list, size_t n) {
  for (size_t i = 0; i < n; ++i) if (strcmp(cmd, list[i]) == 0) return true;
  return false;
}

static void handleCommand(uint8_t id, JsonDocument& doc) {
  const char* cmd = doc["cmd"] | "";
  if (!*cmd) {
    bridge.sendResp(id, false, "missing cmd");
    return;
  }

  if (strcmp(cmd, "PING") == 0) {
    bridge.sendResp(id, true, "pong");
    return;
  }

  if (strcmp(cmd, "STATUS") == 0 || strcmp(cmd, "HEAP") == 0) {
    JsonDocument out;
    fillStatus(out);
    bridge.sendJson(NR_TYPE_RESP, id, out);
    return;
  }

  if (strcmp(cmd, "STOP_ALL") == 0) {
    stopMonitor(true);
    bridge.sendResp(id, true, "all ESP8266 modules stopped");
    return;
  }

  if (strcmp(cmd, "SET_CHANNEL") == 0) {
    uint8_t ch = doc["args"]["channel"] | 1;
    if (ch < 1 || ch > 13) {
      bridge.sendResp(id, false, "invalid channel (must be 1-13)");
      return;
    }
    monitorChannel = ch;
    if (monitorMode != MON_NONE) wifi_set_channel(ch);
    bridge.sendResp(id, true, "channel set");
    return;
  }

  if (strcmp(cmd, "SCAN_WIFI") == 0) {
    MonitorMode savedMode = monitorMode;
    bool savedHop = monitorHop;
    uint8_t savedChannel = monitorChannel;
    uint16_t savedInterval = monitorHopIntervalMs;
    int8_t savedRssi = monitorRssiMin;
    if (monitorMode != MON_NONE) stopMonitor(true);
    int n = scanWifiAndEmit();
    if (savedMode != MON_NONE) startMonitor(savedMode, savedChannel, savedHop, savedInterval, savedRssi, 0);
    if (n < 0) bridge.sendResp(id, false, "scan failed");
    else {
      JsonDocument out;
      out["ok"] = true;
      out["count"] = n;
      bridge.sendJson(NR_TYPE_RESP, id, out);
    }
    return;
  }

  if (strcmp(cmd, "START_CLIENT_DETECT") == 0) {
    const char* mode = doc["args"]["mode"] | "fixed";
    bool hop = strcmp(mode, "hop") == 0;
    uint8_t ch = doc["args"]["channel"] | 1;
    uint16_t interval = doc["args"]["interval_ms"] | 300;
    bool ok = startMonitor(MON_CLIENT, ch, hop, interval, -100, 0);
    bridge.sendResp(id, ok, ok ? "client detection started" : "start failed");
    return;
  }

  if (strcmp(cmd, "STOP_CLIENT_DETECT") == 0) {
    uint32_t captured = monitorDetected, sent = monitorSent, dropped = monitorDropped;
    stopMonitor(true);
    JsonDocument out;
    out["ok"] = true;
    out["captured"] = captured;
    out["sent"] = sent;
    out["dropped"] = dropped;
    bridge.sendJson(NR_TYPE_RESP, id, out);
    return;
  }

  if (strcmp(cmd, "DEAUTH_DETECT_START") == 0) {
    const char* mode = doc["args"]["mode"] | "fixed";
    bool hop = strcmp(mode, "hop") == 0 || static_cast<bool>(doc["args"]["hop"] | false);
    uint8_t ch = doc["args"]["channel"] | 1;
    uint16_t interval = doc["args"]["interval_ms"] | 300;
    int8_t rssi = doc["args"]["rssi_min"] | -100;
    deauthFilterHasBssid = parseMacText(doc["args"]["bssid"] | "", deauthFilterBssid);
    deauthFilterHasClient = parseMacText(doc["args"]["client"] | "", deauthFilterClient);
    bool ok = startMonitor(MON_DEAUTH, ch, hop, interval, rssi, 0);
    if (!ok) {
      bridge.sendResp(id, false, "start failed");
    } else {
      JsonDocument out;
      out["ok"] = true;
      out["channel"] = monitorChannel;
      out["hopping"] = monitorHop;
      bridge.sendJson(NR_TYPE_RESP, id, out);
    }
    return;
  }

  if (strcmp(cmd, "DEAUTH_DETECT_STOP") == 0) {
    uint32_t detected = monitorDetected, sent = monitorSent, dropped = monitorDropped;
    stopMonitor(true);
    JsonDocument out;
    out["ok"] = true;
    out["detected"] = detected;
    out["sent"] = sent;
    out["dropped"] = dropped;
    bridge.sendJson(NR_TYPE_RESP, id, out);
    return;
  }

  if (strcmp(cmd, "DEAUTH_DETECT_STATUS") == 0) {
    JsonDocument out;
    out["ok"] = true;
    out["active"] = monitorMode == MON_DEAUTH;
    out["hopping"] = monitorMode == MON_DEAUTH && monitorHop;
    out["channel"] = monitorChannel;
    out["detected"] = monitorDetected;
    out["sent"] = monitorSent;
    out["dropped"] = monitorDropped;
    bridge.sendJson(NR_TYPE_RESP, id, out);
    return;
  }

  if (strcmp(cmd, "START_HIDDEN_AP") == 0) {
    const char* mode = doc["args"]["mode"] | "fixed";
    bool hop = strcmp(mode, "hop") == 0;
    uint8_t ch = doc["args"]["channel"] | 1;
    uint16_t interval = doc["args"]["interval_ms"] | 300;
    bool ok = startMonitor(MON_HIDDEN, ch, hop, interval, -100, 0);
    bridge.sendResp(id, ok, ok ? "hidden AP detection started" : "start failed");
    return;
  }

  if (strcmp(cmd, "STOP_HIDDEN_AP") == 0) {
    uint32_t seen = hiddenSeen, candidates = hiddenCandidates, resolved = hiddenResolved;
    uint32_t sent = monitorSent, dropped = monitorDropped;
    stopMonitor(true);
    JsonDocument out;
    out["ok"] = true;
    out["hidden"] = seen;
    out["candidates"] = candidates;
    out["resolved"] = resolved;
    out["sent"] = sent;
    out["dropped"] = dropped;
    bridge.sendJson(NR_TYPE_RESP, id, out);
    return;
  }

  // ESP32-only hardware modules. Keep the command names recognizable so the
  // app gets a clean response instead of timing out on accidental invocation.
  static const char* const chipOnly[] = {
    "BLE_SCAN_START", "BLE_SCAN_STOP", "BLE_PROFILE_START", "BLE_PROFILE_STOP",
    "BLE_START", "BLE_STATUS", "BLE_STOP", "BLE_RUN_SCRIPT", "BLE_STOP_SCRIPT",
    "BLE_KEY_DOWN", "BLE_KEY_UP", "BLE_KEY_TAP", "BLE_TYPE_TEXT", "BLE_MOUSE_MOVE",
    "BLE_MOUSE_SCROLL", "BLE_MOUSE_BUTTON", "BLE_MOUSE_RELEASE", "BLE_RELEASE_ALL",
    "START_MSC", "MSC_SETUP", "START_BADUSB"
  };
  if (isAnyOf(cmd, chipOnly, sizeof(chipOnly) / sizeof(chipOnly[0]))) {
    bridge.sendResp(id, false, "unsupported on ESP8266 hardware");
    return;
  }

  // The ESP8266 port intentionally does not advertise active frame-injection,
  // credential-collection portal, or raw-PCAP capture features. The Android app
  // will therefore gate those modules from STATUS.features instead of exposing
  // a control that cannot be safely/reliably matched on this target.
  static const char* const notInBuild[] = {
    "START_SNIFF", "STOP_SNIFF", "DEAUTH", "DEAUTH_CAPTURE",
    "HIDDEN_AP_FORCE_RECONNECT", "START_BEACON", "STOP_BEACON", "BEACON_STATUS",
    "START_PORTAL", "STOP_PORTAL", "RESET_HTML", "SET_HTML_CHUNK", "PORTAL_STATUS",
    "MSC_LIST", "MSC_READ", "MSC_WRITE", "MSC_DELETE", "MSC_SPACE", "SET_FILE_CHUNK"
  };
  if (isAnyOf(cmd, notInBuild, sizeof(notInBuild) / sizeof(notInBuild[0]))) {
    bridge.sendResp(id, false, "not available in ESP8266 compatibility build");
    return;
  }

  bridge.sendResp(id, false, "unknown command");
}

// -----------------------------------------------------------------------------
// Web UI
// -----------------------------------------------------------------------------
static bool webAuth() {
  if (!cfg.webUser[0] && !cfg.webPass[0]) return true;
  if (web.authenticate(cfg.webUser, cfg.webPass)) return true;
  web.requestAuthentication(BASIC_AUTH, "NRSuite ESP8266");
  return false;
}

static const char INDEX_HTML[] PROGMEM = R"NRHTML(
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NRSuite ESP8266</title><style>
:root{color-scheme:dark;--bg:#0b1016;--card:#121a23;--line:#263342;--text:#e7edf3;--muted:#93a4b5;--accent:#55c2ff;--good:#72db9a;--warn:#ffcf66;--bad:#ff7676}
*{box-sizing:border-box}body{margin:0;font:14px system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text)}
main{max-width:1100px;margin:auto;padding:18px}.top{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}.brand h1{font-size:22px;margin:0}.brand p{color:var(--muted);margin:4px 0 0}.pill{border:1px solid var(--line);padding:7px 10px;border-radius:999px;color:var(--muted)}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:12px;margin-top:14px}.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:14px}.card h2{font-size:15px;margin:0 0 10px}.kv{display:grid;grid-template-columns:1fr auto;gap:7px}.kv span:nth-child(odd){color:var(--muted)}
button,input,select{font:inherit;border-radius:9px;border:1px solid var(--line);background:#0d151e;color:var(--text);padding:9px 10px}button{cursor:pointer}button.primary{background:#16334a;border-color:#2a6287}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.row>*{flex:1;min-width:100px}.tiny{font-size:12px;color:var(--muted)}
pre{white-space:pre-wrap;word-break:break-word;background:#080d12;border:1px solid var(--line);border-radius:10px;padding:10px;max-height:280px;overflow:auto}.status-good{color:var(--good)}.status-warn{color:var(--warn)}.status-bad{color:var(--bad)}
label{display:block;color:var(--muted);font-size:12px;margin:8px 0 4px}.wide{width:100%}.danger{border-color:#6a3030}.footer{color:var(--muted);font-size:12px;margin:18px 2px}
</style></head><body><main>
<div class="top"><div class="brand"><h1>NRSuite ESP8266</h1><p>Protocol-compatible controller + standalone web management</p></div><div id="chip" class="pill">Loading…</div></div>
<div class="grid">
<section class="card"><h2>Device</h2><div id="device" class="kv"></div></section>
<section class="card"><h2>Network</h2><div id="network" class="kv"></div></section>
<section class="card"><h2>Wi-Fi scan</h2><p class="tiny">Scans visible 2.4 GHz APs. The access point may pause briefly.</p><button class="primary" onclick="scan()">Scan now</button><pre id="scan">No scan yet.</pre></section>
<section class="card"><h2>Passive monitor</h2><p class="tiny">ESP8266 monitor mode suspends AP/STA traffic. Browser-started capture automatically stops and restores networking.</p>
<div class="row"><select id="mon"><option value="deauth">Deauth detector</option><option value="client">Client detector</option><option value="hidden">Hidden AP revealer</option></select><select id="hop"><option value="1">Hop channels</option><option value="0">Fixed channel</option></select><input id="ch" type="number" min="1" max="13" value="1"></div>
<div class="row" style="margin-top:8px"><input id="dur" type="number" min="5" max="120" value="15" title="Seconds"><button class="primary" onclick="startMon()">Start timed capture</button><button onclick="stopMon()">Stop</button></div>
<pre id="events">No captured events yet.</pre></section>
<section class="card"><h2>Network settings</h2><form method="post" action="/api/settings">
<label>Mode</label><select name="mode" class="wide"><option value="0">AP only</option><option value="1">STA only</option><option value="2">AP + STA</option><option value="3">AP + STA internet repeater (NAPT)</option></select>
<label>AP SSID</label><input class="wide" name="ap_ssid" placeholder="NRSuite-8266"><label>AP password</label><input class="wide" name="ap_pass" type="password" placeholder="Leave blank to keep current">
<label>Upstream STA SSID</label><input class="wide" name="sta_ssid"><label>Upstream STA password</label><input class="wide" name="sta_pass" type="password" placeholder="Leave blank to keep current">
<label>Web user</label><input class="wide" name="web_user"><label>Web password</label><input class="wide" name="web_pass" type="password" placeholder="Leave blank to keep current"><button class="primary" style="margin-top:10px" type="submit">Save & reboot</button></form></section>
<section class="card"><h2>Maintenance</h2><p class="tiny">Serial app transport stays at 115200 baud. Browser and Android app use the same runtime state.</p><button class="danger" onclick="reboot()">Reboot device</button></section>
</div><div class="footer">NRSuite ESP8266 compatibility port. Use passive radio analysis only on networks/devices you own or are authorized to test.</div>
<script>
const esc=s=>String(s??'').replace(/[&<>]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;'}[m]));
async function status(){try{let r=await fetch('/api/status');let j=await r.json();chip.textContent=j.chip+' · '+j.fw;device.innerHTML=`<span>Device ID</span><b>${esc(j.device_id)}</b><span>Free heap</span><b>${j.heap}</b><span>Monitor</span><b>${j.monitor||'idle'}</b><span>Channel</span><b>${j.channel||'-'}</b>`;network.innerHTML=`<span>Mode</span><b>${esc(j.network_mode)}</b><span>STA</span><b class="${j.sta_connected?'status-good':'status-warn'}">${j.sta_connected?'connected':'offline'}</b><span>STA IP</span><b>${esc(j.sta_ip)}</b><span>AP IP</span><b>${esc(j.ap_ip)}</b><span>AP clients</span><b>${j.ap_clients}</b><span>NAPT</span><b>${j.napt?'on':(j.napt_compiled?'off':'not compiled')}</b>`;}catch(e){chip.textContent='Disconnected / monitor active';}}
async function scan(){document.getElementById('scan').textContent='Scanning…';try{let r=await fetch('/api/scan',{method:'POST'}),j=await r.json();document.getElementById('scan').textContent=(j.networks||[]).map(x=>`${x.rssi} dBm  ch${x.channel}  ${x.bssid}  ${x.security}  ${x.ssid||'<hidden>'}`).join('\n')||'No networks found.';}catch(e){document.getElementById('scan').textContent='Scan connection interrupted.'}}
async function startMon(){let q=new URLSearchParams({mode:mon.value,hop:hop.value,channel:ch.value,duration:dur.value});try{await fetch('/api/monitor/start?'+q,{method:'POST'});events.textContent='Capture running. Wi-Fi management network is temporarily suspended; reconnect after the selected duration.';}catch(e){events.textContent='Capture started; connection dropped as expected. Reconnect after the timer expires.'}}
async function stopMon(){try{await fetch('/api/monitor/stop',{method:'POST'});}catch(e){}setTimeout(()=>location.reload(),1500)}
async function loadEvents(){try{let r=await fetch('/api/events'),j=await r.json();events.textContent=(j.events||[]).join('\n')||'No captured events yet.';}catch(e){}}
async function reboot(){if(confirm('Reboot NRSuite ESP8266?')){try{await fetch('/api/reboot',{method:'POST'})}catch(e){} }}
status();loadEvents();setInterval(status,3000);setInterval(loadEvents,5000);
</script></main></body></html>
)NRHTML";

static void redirectRoot() {
  web.sendHeader("Location", String("http://") + (hasApMode() ? WiFi.softAPIP().toString() : WiFi.localIP().toString()), true);
  web.send(302, "text/plain", "");
}

static void handleStatusApi() {
  if (!webAuth()) return;
  JsonDocument doc;
  fillStatus(doc);
  if (monitorMode == MON_CLIENT) doc["monitor"] = "client";
  else if (monitorMode == MON_DEAUTH) doc["monitor"] = "deauth";
  else if (monitorMode == MON_HIDDEN) doc["monitor"] = "hidden";
  else doc["monitor"] = "idle";
  String out;
  serializeJson(doc, out);
  web.send(200, "application/json", out);
}

static void handleScanApi() {
  if (!webAuth()) return;
  if (monitorMode != MON_NONE) {
    web.send(409, "application/json", "{\"ok\":false,\"msg\":\"stop monitor first\"}");
    return;
  }
  int n = WiFi.scanNetworks(false, true);
  JsonDocument doc;
  doc["ok"] = n >= 0;
  JsonArray arr = doc["networks"].to<JsonArray>();
  if (n > 0) {
    for (int i = 0; i < n; ++i) {
      JsonObject o = arr.add<JsonObject>();
      o["ssid"] = WiFi.SSID(i);
      o["bssid"] = WiFi.BSSIDstr(i);
      o["channel"] = WiFi.channel(i);
      o["rssi"] = WiFi.RSSI(i);
      o["security"] = encName(WiFi.encryptionType(i));
    }
  }
  WiFi.scanDelete();
  String out;
  serializeJson(doc, out);
  web.send(n >= 0 ? 200 : 500, "application/json", out);
}

static void handleMonitorStartApi() {
  if (!webAuth()) return;
  String mode = web.arg("mode");
  bool hop = web.arg("hop") != "0";
  int channel = web.arg("channel").toInt();
  int duration = web.arg("duration").toInt();
  duration = constrain(duration, 5, 120);
  MonitorMode mm = MON_DEAUTH;
  if (mode == "client") mm = MON_CLIENT;
  else if (mode == "hidden") mm = MON_HIDDEN;

  pendingWebMonitorMode = mm;
  pendingWebMonitorChannel = constrain(channel, 1, 13);
  pendingWebMonitorHop = hop;
  pendingWebMonitorDurationMs = static_cast<uint32_t>(duration) * 1000UL;
  pendingWebMonitorStartAt = millis() + 250;
  pendingWebMonitorStart = true;
  web.send(202, "application/json", "{\"ok\":true,\"state\":\"starting\"}");
}

static void servicePendingWebMonitorStart() {
  if (!pendingWebMonitorStart) return;
  if (static_cast<int32_t>(millis() - pendingWebMonitorStartAt) < 0) return;
  pendingWebMonitorStart = false;
  deauthFilterHasBssid = false;
  deauthFilterHasClient = false;
  startMonitor(pendingWebMonitorMode, pendingWebMonitorChannel, pendingWebMonitorHop,
               300, -100, pendingWebMonitorDurationMs);
}

static void handleMonitorStopApi() {
  if (!webAuth()) return;
  stopMonitor(true);
  web.send(200, "application/json", "{\"ok\":true}");
}

static void handleEventsApi() {
  if (!webAuth()) return;
  JsonDocument doc;
  doc["ok"] = true;
  JsonArray arr = doc["events"].to<JsonArray>();
  uint8_t start = (webEventHead + NR_MAX_WEB_EVENTS - webEventCount) % NR_MAX_WEB_EVENTS;
  for (uint8_t i = 0; i < webEventCount; ++i) {
    arr.add(webEvents[(start + i) % NR_MAX_WEB_EVENTS]);
  }
  String out;
  serializeJson(doc, out);
  web.send(200, "application/json", out);
}

static void handleSettingsApi() {
  if (!webAuth()) return;
  int mode = web.arg("mode").toInt();
  if (mode < NET_AP_ONLY || mode > NET_REPEATER) mode = NET_AP_ONLY;
  cfg.networkMode = mode;

  String s;
  s = web.arg("ap_ssid"); if (s.length()) strlcpy(cfg.apSsid, s.c_str(), sizeof(cfg.apSsid));
  s = web.arg("ap_pass"); if (s.length()) strlcpy(cfg.apPass, s.c_str(), sizeof(cfg.apPass));
  s = web.arg("sta_ssid"); strlcpy(cfg.staSsid, s.c_str(), sizeof(cfg.staSsid));
  s = web.arg("sta_pass"); if (s.length()) strlcpy(cfg.staPass, s.c_str(), sizeof(cfg.staPass));
  s = web.arg("web_user"); if (s.length()) strlcpy(cfg.webUser, s.c_str(), sizeof(cfg.webUser));
  s = web.arg("web_pass"); if (s.length()) strlcpy(cfg.webPass, s.c_str(), sizeof(cfg.webPass));

  if (strlen(cfg.apPass) > 0 && strlen(cfg.apPass) < 8) {
    web.send(400, "text/plain", "AP password must be empty/open or at least 8 characters.");
    return;
  }
  saveConfig();
  web.send(200, "text/html", "<meta name=viewport content='width=device-width'><body style='font-family:system-ui;background:#0b1016;color:#e7edf3;padding:24px'><h2>Saved</h2><p>Rebooting with the new network configuration…</p></body>");
  delay(250);
  ESP.restart();
}

static void startWebIfNeeded() {
  if (webStarted) return;
  web.on("/", HTTP_GET, []() {
    if (!webAuth()) return;
    web.send_P(200, "text/html", INDEX_HTML);
  });
  web.on("/api/status", HTTP_GET, handleStatusApi);
  web.on("/api/scan", HTTP_POST, handleScanApi);
  web.on("/api/monitor/start", HTTP_POST, handleMonitorStartApi);
  web.on("/api/monitor/stop", HTTP_POST, handleMonitorStopApi);
  web.on("/api/events", HTTP_GET, handleEventsApi);
  web.on("/api/settings", HTTP_POST, handleSettingsApi);
  web.on("/api/reboot", HTTP_POST, []() {
    if (!webAuth()) return;
    web.send(200, "application/json", "{\"ok\":true}");
    delay(150);
    ESP.restart();
  });

  // Common captive-network probes route to the local controller.
  web.on("/generate_204", HTTP_ANY, redirectRoot);
  web.on("/gen_204", HTTP_ANY, redirectRoot);
  web.on("/hotspot-detect.html", HTTP_ANY, redirectRoot);
  web.on("/ncsi.txt", HTTP_ANY, redirectRoot);
  web.onNotFound(redirectRoot);
  web.begin();
  webStarted = true;
}

// -----------------------------------------------------------------------------
// Arduino entry points
// -----------------------------------------------------------------------------
void setup() {
  // Never print human-readable debug output to Serial: this port intentionally
  // keeps the byte stream clean for the NRSuite binary protocol.
  Serial.begin(115200);
  Serial.setDebugOutput(false);
  delay(20);

  loadConfig();
  bridge.begin(Serial, handleCommand);
  applyNetworkConfig();
}

void loop() {
  bridge.update();
  servicePendingWebMonitorStart();
  serviceMonitor();

  if (monitorMode == MON_NONE) {
    if (dnsStarted) dns.processNextRequest();
    if (webStarted) web.handleClient();
    if (millis() - lastNetworkService >= 1000) {
      lastNetworkService = millis();
      serviceNapt();
    }
  }

  yield();
}

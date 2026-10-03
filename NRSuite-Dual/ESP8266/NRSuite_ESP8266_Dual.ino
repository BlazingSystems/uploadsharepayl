/*
  NRSuite ESP8266 Dual-Control (defensive/safe port)
  --------------------------------------------------
  Target: ESP8266 Arduino Core 3.x (NodeMCU / Wemos D1 mini / ESP-12E/F)

  Control surfaces:
    1) NRSuite Android-compatible framed serial protocol @ 115200 baud
    2) Built-in authenticated web UI over AP / STA / AP+STA / NAPT repeater

  Included modules:
    - PING / STATUS / HEAP / STOP_ALL / SET_CHANNEL
    - Wi-Fi AP scan (SCAN_WIFI + scan_ap events)
    - Passive deauthentication/disassociation detector
    - Passive hidden-AP observation
    - Persistent Wi-Fi/web configuration
    - AP fallback when STA association fails
    - ESP8266 lwIP NAPT repeater when compiled with IP_NAPT support

  Intentionally NOT implemented:
    - deauthentication injection
    - beacon spam
    - credential-harvesting captive portal / evil twin
    - WPA handshake capture/cracking
    - BadUSB / HID injection
    - BLE (ESP8266 has no BLE radio)

  Upstream protocol framing:
    magic: AD DE | type | id | uint32 little-endian length | payload

  License: MIT-compatible derivative. See repository README/UPSTREAM.md.
*/

#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <DNSServer.h>
#include <EEPROM.h>
#include <ESP8266HTTPUpdateServer.h>

extern "C" {
#include <user_interface.h>
}

#include <lwip/opt.h>
#if IP_NAPT
#include <lwip/napt.h>
#endif

// -----------------------------------------------------------------------------
// Build identity / limits
// -----------------------------------------------------------------------------
#define NR_FW_VERSION        "1.0.0-esp8266-dual.1"
#define NR_PROTO_MAJOR       1
#define NR_PROTO_MAGIC0      0xAD
#define NR_PROTO_MAGIC1      0xDE
#define NR_PROTO_HEADER      8
#define NR_PROTO_MAX         1024
#define NR_RX_CAP            (NR_PROTO_HEADER + NR_PROTO_MAX + 16)
#define NR_EVENT_LOG_SIZE    20
#define NR_MON_QUEUE_SIZE    16
#define NR_MAX_SCAN_RESULTS  28
#define NR_EEPROM_SIZE       512
#define NR_CFG_MAGIC         0x4E523836UL  // "NR86"
#define NR_CFG_VERSION       2
#define NR_DNS_PORT          53
#define NR_HEARTBEAT_MS      5000UL
#define NR_STA_TIMEOUT_MS    12000UL
#define NR_MON_DEFAULT_MS    500U
#define NR_WEB_MON_TIMEOUT   120000UL
#define NR_NAPT_ENTRIES      128
#define NR_NAPT_PORTMAP      8

// Protocol frame types (NRSuite v1)
enum : uint8_t {
  TYPE_CMD   = 0x01,
  TYPE_RESP  = 0x02,
  TYPE_EVENT = 0x03,
  TYPE_PCAP  = 0x04,
  TYPE_ACK   = 0x05,
  TYPE_HTML  = 0x06
};

enum NetMode : uint8_t {
  NET_AP = 0,
  NET_STA = 1,
  NET_APSTA = 2,
  NET_REPEATER = 3
};

enum MonitorMode : uint8_t {
  MON_NONE = 0,
  MON_DEAUTH = 1,
  MON_HIDDEN = 2,
  MON_CLIENT = 3
};

struct Config {
  uint32_t magic;
  uint8_t version;
  uint8_t netMode;
  uint8_t apChannel;
  uint8_t reserved;
  char staSsid[33];
  char staPass[65];
  char apSsid[33];
  char apPass[65];
  char adminUser[17];
  char adminPass[33];
};

struct MonitorEvent {
  uint8_t kind;       // 1 deauth, 2 disassoc, 3 hidden AP
  int8_t rssi;
  uint8_t channel;
  uint16_t reason;
  uint32_t uptime;
  uint8_t dst[6];
  uint8_t src[6];
  uint8_t bssid[6];
};

struct EventLine {
  uint32_t ms;
  String text;
};

Config cfg;
ESP8266WebServer server(80);
DNSServer dnsServer;
ESP8266HTTPUpdateServer httpUpdater(false);

static uint8_t protoRx[NR_RX_CAP];
static uint16_t protoRxLen = 0;
static uint32_t protoOversized = 0;
static uint32_t lastHeartbeat = 0;
static uint32_t lastStaRetry = 0;
static bool dnsRunning = false;
static bool webStarted = false;
static bool naptEnabled = false;
static bool fallbackAp = false;

static volatile MonitorMode monitorMode = MON_NONE;
static volatile bool monitorActive = false;
static volatile uint8_t monitorChannel = 1;
static volatile bool monitorHop = false;
static volatile uint16_t monitorHopMs = NR_MON_DEFAULT_MS;
static uint32_t monitorLastHop = 0;
static uint32_t monitorStarted = 0;
static bool monitorStartedFromWeb = false;
static bool monitorNetworkSuspended = false;
static NetMode monitorSavedMode = NET_AP;

static volatile MonitorEvent monQueue[NR_MON_QUEUE_SIZE];
static volatile uint8_t monHead = 0;
static volatile uint8_t monTail = 0;
static uint32_t deauthDetected = 0;
static volatile uint32_t deauthDropped = 0;
static uint32_t hiddenSeen = 0;
static volatile uint32_t hiddenDropped = 0;
static uint32_t clientSeen = 0;
static volatile uint32_t clientDropped = 0;

static EventLine eventLog[NR_EVENT_LOG_SIZE];
static uint8_t eventLogHead = 0;

// Forward declarations
void applyNetworkConfig(bool fromMonitorRestore = false);
void stopMonitor(bool restoreNetwork = true);
String statusJson();
void sendEvent(const char* type, const String& fields = "");

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------
String chipIdString() {
  char id[12];
  snprintf(id, sizeof(id), "NR%08X", ESP.getChipId());
  return String(id);
}

String htmlEscape(const String& in) {
  String out;
  out.reserve(in.length() + 8);
  for (size_t i = 0; i < in.length(); ++i) {
    char c = in[i];
    if (c == '&') out += F("&amp;");
    else if (c == '<') out += F("&lt;");
    else if (c == '>') out += F("&gt;");
    else if (c == '"') out += F("&quot;");
    else out += c;
  }
  return out;
}

String jsonEscape(const String& in) {
  String out;
  out.reserve(in.length() + 8);
  for (size_t i = 0; i < in.length(); ++i) {
    char c = in[i];
    switch (c) {
      case '\\': out += F("\\\\"); break;
      case '"': out += F("\\\""); break;
      case '\n': out += F("\\n"); break;
      case '\r': out += F("\\r"); break;
      case '\t': out += F("\\t"); break;
      default:
        if ((uint8_t)c >= 0x20) out += c;
        break;
    }
  }
  return out;
}

String macString(const uint8_t* m) {
  char b[18];
  snprintf(b, sizeof(b), "%02X:%02X:%02X:%02X:%02X:%02X",
           m[0], m[1], m[2], m[3], m[4], m[5]);
  return String(b);
}

const char* netModeName(uint8_t m) {
  switch (m) {
    case NET_AP: return "AP";
    case NET_STA: return "STA";
    case NET_APSTA: return "AP+STA";
    case NET_REPEATER: return "REPEATER";
    default: return "AP";
  }
}

String encName(uint8_t enc) {
  switch (enc) {
    case ENC_TYPE_NONE: return F("OPEN");
    case ENC_TYPE_WEP: return F("WEP");
    case ENC_TYPE_TKIP: return F("WPA/TKIP");
    case ENC_TYPE_CCMP: return F("WPA2/CCMP");
#ifdef ENC_TYPE_AUTO
    case ENC_TYPE_AUTO: return F("WPA/WPA2");
#endif
    default: return F("UNKNOWN");
  }
}

void addEventLog(const String& line) {
  eventLog[eventLogHead].ms = millis();
  eventLog[eventLogHead].text = line;
  eventLogHead = (eventLogHead + 1) % NR_EVENT_LOG_SIZE;
}

void setDefaultConfig() {
  memset(&cfg, 0, sizeof(cfg));
  cfg.magic = NR_CFG_MAGIC;
  cfg.version = NR_CFG_VERSION;
  cfg.netMode = NET_AP;
  cfg.apChannel = 1;
  snprintf(cfg.apSsid, sizeof(cfg.apSsid), "NRSuite-%06X", ESP.getChipId() & 0xFFFFFF);
  strlcpy(cfg.apPass, "nrsuite8266", sizeof(cfg.apPass));
  strlcpy(cfg.adminUser, "admin", sizeof(cfg.adminUser));
  strlcpy(cfg.adminPass, "nrsuite8266", sizeof(cfg.adminPass));
}

void saveConfig() {
  cfg.magic = NR_CFG_MAGIC;
  cfg.version = NR_CFG_VERSION;
  EEPROM.put(0, cfg);
  EEPROM.commit();
}

void loadConfig() {
  EEPROM.begin(NR_EEPROM_SIZE);
  EEPROM.get(0, cfg);
  if (cfg.magic != NR_CFG_MAGIC || cfg.version != NR_CFG_VERSION || cfg.netMode > NET_REPEATER) {
    setDefaultConfig();
    saveConfig();
  }
  cfg.staSsid[32] = 0;
  cfg.staPass[64] = 0;
  cfg.apSsid[32] = 0;
  cfg.apPass[64] = 0;
  cfg.adminUser[16] = 0;
  cfg.adminPass[32] = 0;
  if (strlen(cfg.apSsid) == 0) snprintf(cfg.apSsid, sizeof(cfg.apSsid), "NRSuite-%06X", ESP.getChipId() & 0xFFFFFF);
  if (strlen(cfg.apPass) < 8) strlcpy(cfg.apPass, "nrsuite8266", sizeof(cfg.apPass));
  if (strlen(cfg.adminUser) == 0) strlcpy(cfg.adminUser, "admin", sizeof(cfg.adminUser));
  if (strlen(cfg.adminPass) < 8) strlcpy(cfg.adminPass, "nrsuite8266", sizeof(cfg.adminPass));
}

bool authOk() {
  if (server.authenticate(cfg.adminUser, cfg.adminPass)) return true;
  server.requestAuthentication(BASIC_AUTH, "NRSuite ESP8266");
  return false;
}

// -----------------------------------------------------------------------------
// Tiny JSON readers for protocol commands (avoids ArduinoJson RAM/flash cost)
// Handles the simple command payloads emitted by the Android app.
// -----------------------------------------------------------------------------
int jsonFindKey(const String& s, const char* key) {
  String pattern = String('"') + key + F("\"");
  return s.indexOf(pattern);
}

String jsonStringValue(const String& s, const char* key, const String& def = "") {
  int p = jsonFindKey(s, key);
  if (p < 0) return def;
  p = s.indexOf(':', p);
  if (p < 0) return def;
  p++;
  while (p < (int)s.length() && isspace((unsigned char)s[p])) p++;
  if (p >= (int)s.length() || s[p] != '"') return def;
  p++;
  String out;
  while (p < (int)s.length()) {
    char c = s[p++];
    if (c == '"') break;
    if (c == '\\' && p < (int)s.length()) {
      char e = s[p++];
      if (e == 'n') out += '\n';
      else if (e == 'r') out += '\r';
      else if (e == 't') out += '\t';
      else out += e;
    } else out += c;
  }
  return out;
}

long jsonIntValue(const String& s, const char* key, long def) {
  int p = jsonFindKey(s, key);
  if (p < 0) return def;
  p = s.indexOf(':', p);
  if (p < 0) return def;
  p++;
  while (p < (int)s.length() && isspace((unsigned char)s[p])) p++;
  bool neg = false;
  if (p < (int)s.length() && s[p] == '-') { neg = true; p++; }
  long v = 0;
  bool any = false;
  while (p < (int)s.length() && isdigit((unsigned char)s[p])) {
    any = true;
    v = v * 10 + (s[p++] - '0');
  }
  return any ? (neg ? -v : v) : def;
}

bool jsonBoolValue(const String& s, const char* key, bool def) {
  int p = jsonFindKey(s, key);
  if (p < 0) return def;
  p = s.indexOf(':', p);
  if (p < 0) return def;
  p++;
  while (p < (int)s.length() && isspace((unsigned char)s[p])) p++;
  if (s.substring(p, p + 4) == "true") return true;
  if (s.substring(p, p + 5) == "false") return false;
  return def;
}

// -----------------------------------------------------------------------------
// NRSuite serial framing
// -----------------------------------------------------------------------------
void sendRawFrame(uint8_t type, uint8_t id, const uint8_t* payload, uint32_t len) {
  if (len > NR_PROTO_MAX) return;
  uint8_t h[NR_PROTO_HEADER];
  h[0] = NR_PROTO_MAGIC0;
  h[1] = NR_PROTO_MAGIC1;
  h[2] = type;
  h[3] = id;
  h[4] = (uint8_t)(len & 0xFF);
  h[5] = (uint8_t)((len >> 8) & 0xFF);
  h[6] = (uint8_t)((len >> 16) & 0xFF);
  h[7] = (uint8_t)((len >> 24) & 0xFF);
  Serial.write(h, sizeof(h));
  if (len && payload) Serial.write(payload, len);
}

void sendJsonFrame(uint8_t type, uint8_t id, const String& json) {
  sendRawFrame(type, id, (const uint8_t*)json.c_str(), json.length());
}

void sendResponse(uint8_t id, bool ok, const String& extra = "", const String& msg = "") {
  String j = String(F("{\"ok\":")) + (ok ? F("true") : F("false"));
  if (msg.length()) j += String(F(",\"msg\":\"")) + jsonEscape(msg) + '"';
  if (extra.length()) {
    if (extra[0] != ',') j += ',';
    j += extra;
  }
  j += '}';
  sendJsonFrame(TYPE_RESP, id, j);
}

void sendEvent(const char* type, const String& fields) {
  String j = String(F("{\"type\":\"")) + type + '"';
  if (fields.length()) {
    if (fields[0] != ',') j += ',';
    j += fields;
  }
  j += '}';
  sendJsonFrame(TYPE_EVENT, 0, j);
}

void protoResync() {
  if (protoRxLen < 2) { protoRxLen = 0; return; }
  for (uint16_t i = 1; i + 1 < protoRxLen; ++i) {
    if (protoRx[i] == NR_PROTO_MAGIC0 && protoRx[i + 1] == NR_PROTO_MAGIC1) {
      memmove(protoRx, protoRx + i, protoRxLen - i);
      protoRxLen -= i;
      return;
    }
  }
  protoRxLen = 0;
}

void handleProtocolCommand(uint8_t id, const String& payload);

bool protoTryParse() {
  if (protoRxLen < NR_PROTO_HEADER) return false;
  if (protoRx[0] != NR_PROTO_MAGIC0 || protoRx[1] != NR_PROTO_MAGIC1) {
    protoResync();
    return protoRxLen >= NR_PROTO_HEADER;
  }
  uint8_t type = protoRx[2];
  uint8_t id = protoRx[3];
  uint32_t len = (uint32_t)protoRx[4] |
                 ((uint32_t)protoRx[5] << 8) |
                 ((uint32_t)protoRx[6] << 16) |
                 ((uint32_t)protoRx[7] << 24);
  if (len > NR_PROTO_MAX) {
    protoOversized++;
    protoResync();
    return protoRxLen >= NR_PROTO_HEADER;
  }
  uint32_t total = NR_PROTO_HEADER + len;
  if (protoRxLen < total) return false;

  if (type == TYPE_CMD) {
    String payload;
    payload.reserve(len + 1);
    for (uint32_t i = 0; i < len; ++i) payload += (char)protoRx[NR_PROTO_HEADER + i];
    handleProtocolCommand(id, payload);
  }
  // ACK/PCAP/HTML are intentionally ignored in this ESP8266-safe subset.

  memmove(protoRx, protoRx + total, protoRxLen - total);
  protoRxLen -= total;
  return protoRxLen >= NR_PROTO_HEADER;
}

void protoUpdate() {
  while (Serial.available()) {
    int c = Serial.read();
    if (c < 0) break;
    if (protoRxLen < sizeof(protoRx)) protoRx[protoRxLen++] = (uint8_t)c;
    else {
      protoOversized++;
      protoResync();
    }
    while (protoTryParse()) yield();
  }
}

// -----------------------------------------------------------------------------
// Wi-Fi network mode / NAPT
// -----------------------------------------------------------------------------
void stopDns() {
  if (dnsRunning) {
    dnsServer.stop();
    dnsRunning = false;
  }
}

void startDnsIfAp() {
  stopDns();
  WiFiMode_t m = WiFi.getMode();
  if (m == WIFI_AP || m == WIFI_AP_STA) {
    dnsServer.start(NR_DNS_PORT, "*", WiFi.softAPIP());
    dnsRunning = true;
  }
}

void disableNapt() {
#if IP_NAPT
  if (naptEnabled) {
    ip_napt_enable_no(SOFTAP_IF, 0);
    naptEnabled = false;
  }
#else
  naptEnabled = false;
#endif
}

bool enableNapt() {
#if IP_NAPT
  disableNapt();
  err_t e = ip_napt_init(NR_NAPT_ENTRIES, NR_NAPT_PORTMAP);
  if (e != ERR_OK) return false;
  e = ip_napt_enable_no(SOFTAP_IF, 1);
  naptEnabled = (e == ERR_OK);
#if defined(ARDUINO_ESP8266_MAJOR) && ARDUINO_ESP8266_MAJOR >= 3
  if (naptEnabled && WiFi.dnsIP(0) != IPAddress((uint32_t)0)) {
    WiFi.softAPDhcpServer().setDns(WiFi.dnsIP(0));
  }
#endif
  return naptEnabled;
#else
  naptEnabled = false;
  return false;
#endif
}

void startAp(bool fallback = false) {
  IPAddress ip(192, 168, 4, 1), mask(255, 255, 255, 0);
  WiFi.softAPConfig(ip, ip, mask);
  const char* ssid = cfg.apSsid;
  const char* pass = cfg.apPass;
  if (fallback) {
    static char fssid[33];
    snprintf(fssid, sizeof(fssid), "NRSuite-Fallback-%06X", ESP.getChipId() & 0xFFFFFF);
    ssid = fssid;
  }
  WiFi.softAP(ssid, pass, cfg.apChannel >= 1 && cfg.apChannel <= 13 ? cfg.apChannel : 1, false, 8);
}

bool connectSta(uint32_t timeoutMs) {
  if (strlen(cfg.staSsid) == 0) return false;
  WiFi.persistent(false);
  WiFi.setAutoReconnect(true);
  WiFi.begin(cfg.staSsid, cfg.staPass);
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    delay(25);
    yield();
    protoUpdate();
  }
  return WiFi.status() == WL_CONNECTED;
}

void applyNetworkConfig(bool fromMonitorRestore) {
  (void)fromMonitorRestore;
  stopDns();
  disableNapt();
  fallbackAp = false;
  WiFi.disconnect(true);
  WiFi.softAPdisconnect(true);
  delay(50);

  NetMode mode = (NetMode)cfg.netMode;
  if (mode == NET_AP) {
    WiFi.mode(WIFI_AP);
    startAp(false);
  } else if (mode == NET_STA) {
    WiFi.mode(WIFI_STA);
    if (!connectSta(NR_STA_TIMEOUT_MS)) {
      WiFi.mode(WIFI_AP_STA);
      startAp(true);
      fallbackAp = true;
    }
  } else {
    WiFi.mode(WIFI_AP_STA);
    startAp(false);
    bool ok = connectSta(NR_STA_TIMEOUT_MS);
    if (!ok) {
      fallbackAp = true;
      // Keep the management AP up even without upstream.
    } else if (mode == NET_REPEATER) {
      enableNapt();
    }
  }
  startDnsIfAp();
  addEventLog(String(F("Network mode: ")) + netModeName(cfg.netMode));
}

void maintainNetwork() {
  if (monitorNetworkSuspended) return;
  if (cfg.netMode == NET_STA || cfg.netMode == NET_APSTA || cfg.netMode == NET_REPEATER) {
    if (strlen(cfg.staSsid) && WiFi.status() != WL_CONNECTED && millis() - lastStaRetry > 15000UL) {
      lastStaRetry = millis();
      WiFi.begin(cfg.staSsid, cfg.staPass);
    }
    if (cfg.netMode == NET_REPEATER && WiFi.status() == WL_CONNECTED && !naptEnabled) {
      enableNapt();
    }
  }
}

// -----------------------------------------------------------------------------
// Promiscuous monitor (passive only)
// ESP8266 callback prepends a 12-byte RxControl block to management payloads.
// Keep callback tiny: no String, no heap allocation, no Serial.
// -----------------------------------------------------------------------------
void ICACHE_RAM_ATTR queueMonitorEvent(const MonitorEvent& e) {
  uint8_t next = (uint8_t)((monHead + 1) % NR_MON_QUEUE_SIZE);
  if (next == monTail) {
    if (e.kind <= 2) deauthDropped++;
    else if (e.kind == 3) hiddenDropped++;
    else clientDropped++;
    return;
  }
  memcpy((void*)&monQueue[monHead], &e, sizeof(e));
  monHead = next;
}

void ICACHE_RAM_ATTR promiscCb(uint8_t* buff, uint16_t len) {
  if (!monitorActive || !buff || len < 12 + 24) return;
  const uint8_t* p = buff + 12;
  uint16_t plen = len - 12;
  uint8_t fc0 = p[0];
  uint8_t type = (fc0 >> 2) & 0x3;
  if (type != 0) return; // management frames only
  uint8_t subtype = (fc0 >> 4) & 0x0F;

  if (monitorMode == MON_DEAUTH) {
    if (subtype != 0x0C && subtype != 0x0A) return;
    MonitorEvent e{};
    e.kind = (subtype == 0x0C) ? 1 : 2;
    e.rssi = (int8_t)buff[0];
    e.channel = monitorChannel;
    e.uptime = millis();
    memcpy(e.dst, p + 4, 6);
    memcpy(e.src, p + 10, 6);
    memcpy(e.bssid, p + 16, 6);
    if (plen >= 26) e.reason = (uint16_t)p[24] | ((uint16_t)p[25] << 8);
    queueMonitorEvent(e);
    return;
  }

  if (monitorMode == MON_CLIENT) {
    if (subtype != 0x04 && subtype != 0x00 && subtype != 0x02 && subtype != 0x0B) return;
    MonitorEvent e{};
    e.kind = 4;
    e.rssi = (int8_t)buff[0];
    e.channel = monitorChannel;
    e.uptime = millis();
    e.reason = subtype; // reuse field for management subtype
    memcpy(e.dst, p + 4, 6);
    memcpy(e.src, p + 10, 6);
    memcpy(e.bssid, p + 16, 6);
    queueMonitorEvent(e);
    return;
  }

  if (monitorMode == MON_HIDDEN) {
    if (subtype != 0x08 && subtype != 0x05) return; // beacon / probe response
    if (plen < 38) return;
    size_t off = 36; // 24-byte mgmt header + 12-byte beacon/probe fixed body
    bool ssidSeen = false;
    uint8_t ssidLen = 0;
    while (off + 2 <= plen) {
      uint8_t id = p[off];
      uint8_t ilen = p[off + 1];
      if (off + 2 + ilen > plen) break;
      if (id == 0) {
        ssidSeen = true;
        ssidLen = ilen;
        break;
      }
      off += 2 + ilen;
    }
    if (ssidSeen && ssidLen > 0) return;
    MonitorEvent e{};
    e.kind = 3;
    e.rssi = (int8_t)buff[0];
    e.channel = monitorChannel;
    e.uptime = millis();
    memcpy(e.bssid, p + 16, 6);
    queueMonitorEvent(e);
  }
}

bool suspendNetworkForHopping() {
  if (monitorNetworkSuspended) return true;
  monitorSavedMode = (NetMode)cfg.netMode;
  stopDns();
  disableNapt();
  WiFi.softAPdisconnect(true);
  WiFi.disconnect(true);
  WiFi.mode(WIFI_STA);
  delay(30);
  monitorNetworkSuspended = true;
  return true;
}

bool startMonitor(MonitorMode mode, uint8_t channel, bool hop, uint16_t hopMs, bool fromWeb) {
  stopMonitor(true);
  if (channel < 1 || channel > 13) channel = 1;
  hopMs = constrain(hopMs, (uint16_t)100, (uint16_t)5000);

  if (hop) {
    // Channel hopping and live AP/STA cannot coexist on ESP8266's single radio.
    // Preserve Android serial control while temporarily suspending web networking.
    suspendNetworkForHopping();
    channel = 1;
  } else {
    // If connected, fixed monitoring must stay on the radio's current channel.
    uint8_t current = wifi_get_channel();
    if (current >= 1 && current <= 13) channel = current;
  }

  wifi_promiscuous_enable(0);
  wifi_set_promiscuous_rx_cb(promiscCb);
  wifi_set_channel(channel);
  monitorMode = mode;
  monitorChannel = channel;
  monitorHop = hop;
  monitorHopMs = hopMs;
  monHead = monTail = 0;
  monitorLastHop = millis();
  monitorStarted = millis();
  monitorStartedFromWeb = fromWeb;
  monitorActive = true;
  wifi_promiscuous_enable(1);
  const __FlashStringHelper* modeName = mode == MON_DEAUTH ? F("deauth") : (mode == MON_HIDDEN ? F("hidden AP") : F("client presence"));
  addEventLog(String(F("Passive monitor started: ")) + modeName);
  return true;
}

void stopMonitor(bool restoreNetwork) {
  if (monitorActive) wifi_promiscuous_enable(0);
  monitorActive = false;
  monitorMode = MON_NONE;
  monitorHop = false;
  monHead = monTail = 0;
  bool suspended = monitorNetworkSuspended;
  monitorNetworkSuspended = false;
  if (restoreNetwork && suspended) applyNetworkConfig(true);
}

void processMonitorEvents() {
  if (monitorActive && monitorHop && millis() - monitorLastHop >= monitorHopMs) {
    monitorLastHop = millis();
    uint8_t c = monitorChannel + 1;
    if (c > 13) c = 1;
    wifi_promiscuous_enable(0);
    wifi_set_channel(c);
    monitorChannel = c;
    wifi_promiscuous_enable(1);
    if (monitorMode == MON_DEAUTH) sendEvent("deauth_detector_hop", String(F("\"channel\":")) + c);
    else if (monitorMode == MON_HIDDEN) sendEvent("hidden_ap_hop", String(F("\"channel\":")) + c);
    else sendEvent("client_detector_hop", String(F("\"channel\":")) + c);
  }

  // Web-triggered hopping auto-stops so the browser cannot strand the user indefinitely.
  if (monitorActive && monitorHop && monitorStartedFromWeb && millis() - monitorStarted > NR_WEB_MON_TIMEOUT) {
    stopMonitor(true);
    addEventLog(F("Web monitor timeout; network restored"));
  }

  while (monTail != monHead) {
    noInterrupts();
    MonitorEvent e{};
    memcpy(&e, (const void*)&monQueue[monTail], sizeof(e));
    monTail = (uint8_t)((monTail + 1) % NR_MON_QUEUE_SIZE);
    interrupts();

    if (e.kind == 1 || e.kind == 2) {
      deauthDetected++;
      String subtype = (e.kind == 1) ? F("deauth") : F("disassoc");
      String fields = String(F("\"subtype\":\"")) + subtype +
        F("\",\"subtype_code\":") + String(e.kind == 1 ? 12 : 10) +
        F(",\"bssid\":\"") + macString(e.bssid) +
        F("\",\"source\":\"") + macString(e.src) +
        F("\",\"client\":\"") + macString(e.dst) +
        F("\",\"destination\":\"") + macString(e.dst) +
        F("\",\"channel\":") + String(e.channel) +
        F(",\"rssi\":") + String(e.rssi) +
        F(",\"reason\":") + String(e.reason) +
        F(",\"uptime_ms\":") + String(e.uptime);
      sendEvent("deauth_detected", fields);
      addEventLog(String(F("Deauth alert ch")) + e.channel + F(" ") + macString(e.bssid));
    } else if (e.kind == 3) {
      hiddenSeen++;
      String fields = String(F("\"bssid\":\"")) + macString(e.bssid) +
        F("\",\"channel\":") + String(e.channel) +
        F(",\"rssi\":") + String(e.rssi) +
        F(",\"uptime_ms\":") + String(e.uptime);
      sendEvent("hidden_ap", fields);
      addEventLog(String(F("Hidden AP ch")) + e.channel + F(" ") + macString(e.bssid));
    } else if (e.kind == 4) {
      clientSeen++;
      const char* st = e.reason == 0x04 ? "probe" : (e.reason == 0x00 ? "assoc" : (e.reason == 0x02 ? "reassoc" : "auth"));
      String fields = String(F("\"client\":\"")) + macString(e.src) +
        F("\",\"bssid\":\"") + macString(e.bssid) +
        F("\",\"subtype\":\"") + st +
        F("\",\"rssi\":") + String(e.rssi) +
        F(",\"channel\":") + String(e.channel) +
        F(",\"uptime_ms\":") + String(e.uptime);
      sendEvent("client_detected", fields);
      addEventLog(String(F("Client ")) + st + F(" ch") + e.channel + F(" ") + macString(e.src));
    }
    yield();
  }
}

// -----------------------------------------------------------------------------
// Wi-Fi scan
// -----------------------------------------------------------------------------
String scanJson(bool emitProtocolEvents, int* outCount = nullptr) {
  if (monitorActive) {
    if (outCount) *outCount = -1;
    return F("{\"ok\":false,\"msg\":\"stop passive monitor before scanning\"}");
  }

  WiFiMode_t before = WiFi.getMode();
  if (before == WIFI_AP) WiFi.mode(WIFI_AP_STA);
  int n = WiFi.scanNetworks(false, true);
  if (n < 0) n = 0;
  int limit = min(n, NR_MAX_SCAN_RESULTS);
  if (outCount) *outCount = limit;

  String j = F("{\"ok\":true,\"networks\":[");
  for (int i = 0; i < limit; ++i) {
    if (i) j += ',';
    String ssid = WiFi.SSID(i);
    String bssid = WiFi.BSSIDstr(i);
    String sec = encName(WiFi.encryptionType(i));
    int ch = WiFi.channel(i);
    int rssi = WiFi.RSSI(i);
    j += String(F("{\"ssid\":\"")) + jsonEscape(ssid) +
         F("\",\"bssid\":\"") + bssid +
         F("\",\"channel\":") + ch +
         F(",\"rssi\":") + rssi +
         F(",\"security\":\"") + sec + F("\",\"wps\":false}");

    if (emitProtocolEvents) {
      String fields = String(F("\"ssid\":\"")) + jsonEscape(ssid) +
        F("\",\"bssid\":\"") + bssid +
        F("\",\"channel\":") + ch +
        F(",\"rssi\":") + rssi +
        F(",\"security\":\"") + sec + F("\",\"wps\":false");
      sendEvent("scan_ap", fields);
      yield();
    }
  }
  j += F("]}");
  WiFi.scanDelete();
  if (before == WIFI_AP && cfg.netMode == NET_AP) WiFi.mode(WIFI_AP);
  return j;
}

// -----------------------------------------------------------------------------
// Status / command bridge
// -----------------------------------------------------------------------------
String statusJson() {
  String features = F("[\"wifi\",\"client_detect\",\"deauth_detect\",\"hidden_ap\",\"stop_all\",\"webui\",\"repeater\",\"web_ota\"]");
  String j = F("{\"ok\":true");
  j += F(",\"uptime\":") + String(millis());
  j += F(",\"heap\":") + String(ESP.getFreeHeap());
  j += F(",\"chip\":\"ESP8266\"");
  j += F(",\"proto\":") + String(NR_PROTO_MAJOR);
  j += F(",\"fw\":\"") + String(NR_FW_VERSION) + '"';
  j += F(",\"device_id\":\"") + chipIdString() + '"';
  j += F(",\"features\":") + features;
  j += F(",\"sniffing\":false,\"client_detecting\":") + String((monitorActive && monitorMode == MON_CLIENT) ? F("true") : F("false")) + F(",\"portal\":false,\"beacon\":false");
  j += F(",\"deauth_detector\":") + String((monitorActive && monitorMode == MON_DEAUTH) ? F("true") : F("false"));
  j += F(",\"hidden_ap\":") + String((monitorActive && monitorMode == MON_HIDDEN) ? F("true") : F("false"));
  j += F(",\"ble_scanning\":false,\"ble_profiling\":false");
  j += F(",\"oversized_frames\":") + String(protoOversized);
  j += F(",\"deauth_detector_channel\":") + String(monitorChannel);
  j += F(",\"deauth_detector_hopping\":") + String(monitorHop ? F("true") : F("false"));
  j += F(",\"deauth_detected\":") + String(deauthDetected);
  j += F(",\"deauth_detector_dropped\":") + String(deauthDropped);
  j += F(",\"hidden_ap_channel\":") + String(monitorChannel);
  j += F(",\"hidden_ap_hopping\":") + String(monitorHop ? F("true") : F("false"));
  j += F(",\"hidden_ap_seen\":") + String(hiddenSeen);
  j += F(",\"hidden_ap_dropped\":") + String(hiddenDropped);
  j += F(",\"client_detected\":") + String(clientSeen);
  j += F(",\"client_detector_dropped\":") + String(clientDropped);
  j += F(",\"network_mode\":\"") + String(netModeName(cfg.netMode)) + '"';
  j += F(",\"sta_connected\":") + String(WiFi.status() == WL_CONNECTED ? F("true") : F("false"));
  j += F(",\"sta_ip\":\"") + WiFi.localIP().toString() + '"';
  j += F(",\"ap_ip\":\"") + WiFi.softAPIP().toString() + '"';
  j += F(",\"napt\":") + String(naptEnabled ? F("true") : F("false"));
  j += F(",\"fallback_ap\":") + String(fallbackAp ? F("true") : F("false"));
#if IP_NAPT
  j += F(",\"napt_compiled\":true");
#else
  j += F(",\"napt_compiled\":false");
#endif
  j += '}';
  return j;
}

void handleProtocolCommand(uint8_t id, const String& payload) {
  String cmd = jsonStringValue(payload, "cmd", "");
  if (!cmd.length()) { sendResponse(id, false, "", F("missing cmd")); return; }

  if (cmd == "PING") {
    sendResponse(id, true, "", F("pong"));
    return;
  }
  if (cmd == "STATUS" || cmd == "HEAP") {
    sendJsonFrame(TYPE_RESP, id, statusJson());
    return;
  }
  if (cmd == "STOP_ALL") {
    stopMonitor(true);
    sendResponse(id, true);
    return;
  }
  if (cmd == "SET_CHANNEL") {
    int ch = (int)jsonIntValue(payload, "channel", 1);
    if (ch < 1 || ch > 13) { sendResponse(id, false, "", F("channel must be 1..13")); return; }
    if (monitorActive) {
      wifi_promiscuous_enable(0);
      wifi_set_channel(ch);
      monitorChannel = ch;
      wifi_promiscuous_enable(1);
    }
    cfg.apChannel = ch;
    sendResponse(id, true, String(F("\"channel\":")) + ch);
    return;
  }
  if (cmd == "SCAN_WIFI") {
    int count = 0;
    String result = scanJson(true, &count);
    if (count < 0) sendResponse(id, false, "", F("stop passive monitor before scanning"));
    else sendResponse(id, true, String(F("\"count\":")) + count);
    return;
  }
  if (cmd == "DEAUTH_DETECT_START") {
    String mode = jsonStringValue(payload, "mode", "fixed");
    bool hop = jsonBoolValue(payload, "hop", mode == "hop");
    int ch = (int)jsonIntValue(payload, "channel", wifi_get_channel());
    int interval = (int)jsonIntValue(payload, "interval_ms", NR_MON_DEFAULT_MS);
    bool ok = startMonitor(MON_DEAUTH, ch, hop, interval, false);
    sendResponse(id, ok, String(F("\"channel\":")) + monitorChannel + F(",\"hopping\":") + (monitorHop ? F("true") : F("false")));
    return;
  }
  if (cmd == "DEAUTH_DETECT_STOP") {
    stopMonitor(true);
    sendResponse(id, true, String(F("\"detected\":")) + deauthDetected + F(",\"sent\":") + deauthDetected + F(",\"dropped\":") + deauthDropped);
    return;
  }
  if (cmd == "DEAUTH_DETECT_STATUS") {
    sendResponse(id, true,
      String(F("\"active\":")) + ((monitorActive && monitorMode == MON_DEAUTH) ? F("true") : F("false")) +
      F(",\"hopping\":") + (monitorHop ? F("true") : F("false")) +
      F(",\"channel\":") + String((int)monitorChannel) +
      F(",\"detected\":") + deauthDetected +
      F(",\"sent\":") + deauthDetected +
      F(",\"dropped\":") + deauthDropped);
    return;
  }
  if (cmd == "START_HIDDEN_AP") {
    String mode = jsonStringValue(payload, "mode", "fixed");
    bool hop = jsonBoolValue(payload, "hop", mode == "hop");
    int ch = (int)jsonIntValue(payload, "channel", wifi_get_channel());
    int interval = (int)jsonIntValue(payload, "interval_ms", NR_MON_DEFAULT_MS);
    bool ok = startMonitor(MON_HIDDEN, ch, hop, interval, false);
    sendResponse(id, ok, String(F("\"channel\":")) + monitorChannel + F(",\"hopping\":") + (monitorHop ? F("true") : F("false")));
    return;
  }
  if (cmd == "STOP_HIDDEN_AP") {
    stopMonitor(true);
    sendResponse(id, true,
      String(F("\"hidden\":")) + hiddenSeen +
      F(",\"candidates\":0,\"resolved\":0,\"sent\":") + hiddenSeen +
      F(",\"dropped\":") + hiddenDropped);
    return;
  }

  // Explicitly reject active/disruptive upstream commands.
  if (cmd == "DEAUTH" || cmd == "DEAUTH_CAPTURE" || cmd == "START_BEACON" ||
      cmd == "START_PORTAL" || cmd == "RESET_HTML" || cmd == "SET_HTML_CHUNK") {
    sendResponse(id, false, "", F("disabled in ESP8266 defensive port"));
    return;
  }

  sendResponse(id, false, "", F("unknown command"));
}

// -----------------------------------------------------------------------------
// Web UI
// -----------------------------------------------------------------------------
const char INDEX_HTML[] PROGMEM = R"HTML(
<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NRSuite ESP8266</title><style>
:root{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color-scheme:dark;background:#0e1116;color:#e8edf3}*{box-sizing:border-box}
body{margin:0;max-width:980px;padding:18px;margin:auto}.top{display:flex;gap:12px;align-items:center;justify-content:space-between;flex-wrap:wrap}
h1{font-size:1.35rem;margin:0}.tag{font-size:.8rem;padding:5px 9px;border:1px solid #334155;border-radius:999px;color:#b8c4d6}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:12px;margin-top:14px}.card{background:#151a22;border:1px solid #29303d;border-radius:14px;padding:14px}
h2{font-size:1rem;margin:0 0 10px}label{display:block;font-size:.8rem;color:#aab5c4;margin:8px 0 4px}input,select,button{width:100%;padding:10px;border-radius:9px;border:1px solid #364152;background:#0f141b;color:#eef2f7}
button{cursor:pointer;background:#263244;font-weight:650;margin-top:8px}button:hover{background:#324157}.row{display:grid;grid-template-columns:1fr 1fr;gap:8px}.muted{color:#9aa6b5;font-size:.82rem}.ok{color:#87d37c}.warn{color:#f6c177}pre{white-space:pre-wrap;word-break:break-word;background:#0b0f14;padding:10px;border-radius:9px;max-height:330px;overflow:auto;font-size:.78rem}
table{width:100%;border-collapse:collapse;font-size:.76rem}th,td{text-align:left;border-bottom:1px solid #29303d;padding:6px}.wide{grid-column:1/-1}
</style></head><body>
<div class="top"><h1>NRSuite ESP8266 Dual</h1><span class="tag">App serial + Web UI</span></div>
<p class="muted">Defensive port: Wi-Fi scan, passive deauth detection, hidden-AP observation, and AP/STA/NAPT management. Active attack modules are disabled.</p>
<div class="grid">
<section class="card"><h2>Status</h2><pre id="status">Loading…</pre><button onclick="loadStatus()">Refresh</button></section>
<section class="card"><h2>Network mode</h2><form id="wifi" onsubmit="saveWifi(event)"><label>Mode</label><select name="mode"><option value="0">AP only</option><option value="1">STA only (+fallback AP)</option><option value="2">AP + STA</option><option value="3">AP + STA Internet Repeater (NAPT)</option></select><label>Upstream SSID</label><input name="sta_ssid" maxlength="32"><label>Upstream password</label><input name="sta_pass" type="password" maxlength="64"><label>Management AP SSID</label><input name="ap_ssid" maxlength="32"><label>Management AP password (8+)</label><input name="ap_pass" type="password" maxlength="64"><div class="row"><div><label>AP channel</label><input name="channel" type="number" min="1" max="13"></div><div><label>Admin user</label><input name="admin_user" maxlength="16"></div></div><label>Admin password (8+)</label><input name="admin_pass" type="password" maxlength="32"><button>Save & apply</button></form><p class="muted">Changing credentials can disconnect this browser.</p></section>
<section class="card wide"><h2>Wi-Fi scan</h2><button onclick="scanWifi()">Scan nearby APs</button><div id="scan" class="muted">No scan yet.</div></section>
<section class="card"><h2>Passive defense</h2><div class="row"><button onclick="monitor('deauth')">Deauth detector</button><button onclick="monitor('hidden')">Hidden AP</button></div><button onclick="monitor('stop')">Stop monitor</button><p class="muted">Fixed-channel monitoring stays compatible with the web link. Channel hopping is available through the Android serial protocol because ESP8266 has one 2.4 GHz radio.</p></section>
<section class="card"><h2>Recent alerts</h2><pre id="events">Loading…</pre><button onclick="loadEvents()">Refresh</button></section>
</div>
<script>
async function j(u,o){let r=await fetch(u,o);let t=await r.text();try{return JSON.parse(t)}catch(e){return {ok:false,msg:t}}}
function esc(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function loadStatus(){let x=await j('/api/status');document.querySelector('#status').textContent=JSON.stringify(x,null,2);let f=document.querySelector('#wifi');if(x.config){f.mode.value=x.config.mode;f.sta_ssid.value=x.config.sta_ssid;f.ap_ssid.value=x.config.ap_ssid;f.channel.value=x.config.channel;f.admin_user.value=x.config.admin_user}}
async function saveWifi(e){e.preventDefault();let b=new URLSearchParams(new FormData(e.target));let x=await j('/api/wifi',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b});alert(x.msg||JSON.stringify(x));setTimeout(()=>location.reload(),1800)}
async function scanWifi(){let d=document.querySelector('#scan');d.textContent='Scanning…';let x=await j('/api/scan');if(!x.ok){d.textContent=x.msg||'Scan failed';return}let h='<table><tr><th>SSID</th><th>RSSI</th><th>Ch</th><th>Security</th><th>BSSID</th></tr>';for(let n of x.networks)h+='<tr><td>'+esc(n.ssid||'(hidden)')+'</td><td>'+n.rssi+'</td><td>'+n.channel+'</td><td>'+esc(n.security)+'</td><td>'+esc(n.bssid)+'</td></tr>';d.innerHTML=h+'</table>'}
async function monitor(k){let b=new URLSearchParams({kind:k});let x=await j('/api/monitor',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:b});alert(x.msg||JSON.stringify(x));loadStatus();loadEvents()}
async function loadEvents(){let x=await j('/api/events');document.querySelector('#events').textContent=(x.events||[]).map(e=>'['+(e.ms/1000).toFixed(1)+'s] '+e.text).join('\n')||'No alerts.'}
loadStatus();loadEvents();setInterval(()=>{loadStatus();loadEvents()},5000)
</script></body></html>
)HTML";

String configJson() {
  String j = F("{\"mode\":");
  j += String(cfg.netMode);
  j += F(",\"sta_ssid\":\"") + jsonEscape(cfg.staSsid) + '"';
  j += F(",\"ap_ssid\":\"") + jsonEscape(cfg.apSsid) + '"';
  j += F(",\"channel\":") + String(cfg.apChannel);
  j += F(",\"admin_user\":\"") + jsonEscape(cfg.adminUser) + F("\"}");
  return j;
}

void setupWeb() {
  if (webStarted) return;
  webStarted = true;

  server.on("/", HTTP_GET, []() {
    if (!authOk()) return;
    server.send_P(200, PSTR("text/html; charset=utf-8"), INDEX_HTML);
  });

  server.on("/api/status", HTTP_GET, []() {
    if (!authOk()) return;
    String j = statusJson();
    j.remove(j.length() - 1);
    j += F(",\"config\":") + configJson() + '}';
    server.send(200, "application/json", j);
  });

  server.on("/api/events", HTTP_GET, []() {
    if (!authOk()) return;
    String j = F("{\"ok\":true,\"events\":[");
    bool first = true;
    for (uint8_t i = 0; i < NR_EVENT_LOG_SIZE; ++i) {
      uint8_t idx = (eventLogHead + i) % NR_EVENT_LOG_SIZE;
      if (!eventLog[idx].text.length()) continue;
      if (!first) j += ',';
      first = false;
      j += String(F("{\"ms\":")) + eventLog[idx].ms + F(",\"text\":\"") + jsonEscape(eventLog[idx].text) + F("\"}");
    }
    j += F("]}");
    server.send(200, "application/json", j);
  });

  server.on("/api/scan", HTTP_GET, []() {
    if (!authOk()) return;
    int count = 0;
    String j = scanJson(false, &count);
    server.send(count < 0 ? 409 : 200, "application/json", j);
  });

  server.on("/api/monitor", HTTP_POST, []() {
    if (!authOk()) return;
    String kind = server.arg("kind");
    if (kind == "stop") {
      stopMonitor(true);
      server.send(200, "application/json", F("{\"ok\":true,\"msg\":\"monitor stopped\"}"));
      return;
    }
    uint8_t ch = wifi_get_channel();
    if (ch < 1 || ch > 13) ch = cfg.apChannel;
    if (kind == "deauth") {
      startMonitor(MON_DEAUTH, ch, false, NR_MON_DEFAULT_MS, true);
      server.send(200, "application/json", F("{\"ok\":true,\"msg\":\"passive deauth detector started\"}"));
    } else if (kind == "hidden") {
      startMonitor(MON_HIDDEN, ch, false, NR_MON_DEFAULT_MS, true);
      server.send(200, "application/json", F("{\"ok\":true,\"msg\":\"passive hidden-AP observer started\"}"));
    } else {
      server.send(400, "application/json", F("{\"ok\":false,\"msg\":\"unknown monitor kind\"}"));
    }
  });

  server.on("/api/wifi", HTTP_POST, []() {
    if (!authOk()) return;
    int mode = server.arg("mode").toInt();
    if (mode < 0 || mode > 3) mode = NET_AP;
    String staSsid = server.arg("sta_ssid");
    String staPass = server.arg("sta_pass");
    String apSsid = server.arg("ap_ssid");
    String apPass = server.arg("ap_pass");
    String adminUser = server.arg("admin_user");
    String adminPass = server.arg("admin_pass");
    int ch = server.arg("channel").toInt();
    if (apSsid.length() == 0 || apSsid.length() > 32 || apPass.length() < 8 || adminUser.length() == 0 || adminPass.length() < 8 || ch < 1 || ch > 13) {
      server.send(400, "application/json", F("{\"ok\":false,\"msg\":\"invalid AP/admin fields or channel\"}"));
      return;
    }
    cfg.netMode = mode;
    cfg.apChannel = ch;
    strlcpy(cfg.staSsid, staSsid.c_str(), sizeof(cfg.staSsid));
    if (staPass.length()) strlcpy(cfg.staPass, staPass.c_str(), sizeof(cfg.staPass));
    strlcpy(cfg.apSsid, apSsid.c_str(), sizeof(cfg.apSsid));
    if (apPass.length()) strlcpy(cfg.apPass, apPass.c_str(), sizeof(cfg.apPass));
    strlcpy(cfg.adminUser, adminUser.c_str(), sizeof(cfg.adminUser));
    if (adminPass.length()) strlcpy(cfg.adminPass, adminPass.c_str(), sizeof(cfg.adminPass));
    saveConfig();
    server.send(200, "application/json", F("{\"ok\":true,\"msg\":\"saved; applying network settings\"}"));
    delay(100);
    stopMonitor(false);
    applyNetworkConfig();
  });

  server.onNotFound([]() {
    if (!authOk()) return;
    server.sendHeader("Location", "/", true);
    server.send(302, "text/plain", "");
  });

  server.begin();
}

// -----------------------------------------------------------------------------
// Arduino setup / loop
// -----------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  Serial.setDebugOutput(false); // keep serial channel clean for binary protocol
  loadConfig();
  applyNetworkConfig();
  setupWeb();
  addEventLog(String(F("Boot ")) + NR_FW_VERSION + F(" / ") + chipIdString());
  lastHeartbeat = millis();
}

void loop() {
  protoUpdate();
  processMonitorEvents();

  if (!monitorNetworkSuspended) {
    if (dnsRunning) dnsServer.processNextRequest();
    server.handleClient();
    maintainNetwork();
  }

  if (millis() - lastHeartbeat >= NR_HEARTBEAT_MS) {
    lastHeartbeat = millis();
    sendEvent("heartbeat", String(F("\"uptime\":")) + millis() + F(",\"heap\":") + ESP.getFreeHeap());
  }
  yield();
}

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
  MON_HIDDEN = 2
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
    else hiddenDropped++;
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
  addEventLog(String(F("Passive monitor started: ")) + (mode == MON_DEAUTH ? F("deauth") : F("hidden AP")));
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
    else sendEvent("hidden_ap_hop", String(F("\"channel\":")) + c);
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
    }
    yield();
  }
}

// -----------------------------------------------------------------------------
// Wi-Fi scan
// -----------------------------------------------------------------------------

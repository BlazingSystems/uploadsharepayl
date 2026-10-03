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

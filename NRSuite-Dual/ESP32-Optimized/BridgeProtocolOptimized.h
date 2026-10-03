#pragma once
#include <Arduino.h>
#include <ArduinoJson.h>
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>

// Drop-in-oriented optimized bridge for the pinned NRSuite ESP32 firmware.
// Protocol constants remain NRSuite v1 compatible.
#define PROTO_MAGIC_0   0xAD
#define PROTO_MAGIC_1   0xDE
#define PROTO_HEADER_SZ 8
#define PROTO_MAX_CHUNK 1024
#define PROTO_RX_BUF_SIZE (PROTO_MAX_CHUNK + PROTO_HEADER_SZ + 64)

#define TYPE_CMD   0x01
#define TYPE_RESP  0x02
#define TYPE_EVENT 0x03
#define TYPE_PCAP  0x04
#define TYPE_ACK   0x05
#define TYPE_HTML  0x06

struct ProtoFrame {
    uint8_t type;
    uint8_t id;
    uint32_t length;
    uint8_t* payload;
    bool valid;
};

using CmdCallback = void (*)(uint8_t id, JsonDocument& doc);
using AckCallback = void (*)(uint32_t chunk_index);
using HtmlCallback = void (*)(const uint8_t* data, size_t len);

class BridgeProtocolOptimized {
public:
    explicit BridgeProtocolOptimized(Stream& stream) : _stream(stream) {}

    void begin();
    void update();

    void onCmd(CmdCallback cb) { _onCmd = cb; }
    void onAck(AckCallback cb) { _onAck = cb; }
    void onHtml(HtmlCallback cb) { _onHtml = cb; }

    void sendResp(uint8_t id, bool ok, const char* msg = nullptr);
    void sendEvent(const char* type, JsonDocument& doc);
    void sendPcapChunk(uint8_t chunkIdx, const uint8_t* data, uint32_t len);
    void sendRaw(uint8_t type, uint8_t id, const uint8_t* payload, uint32_t len);

    uint32_t oversizedFrameCount() const { return _oversizedFrames; }

private:
    Stream& _stream;
    CmdCallback _onCmd = nullptr;
    AckCallback _onAck = nullptr;
    HtmlCallback _onHtml = nullptr;
    SemaphoreHandle_t _txMutex = nullptr;

    uint8_t _buf[PROTO_RX_BUF_SIZE]{};
    uint32_t _bufLen = 0;
    uint32_t _oversizedFrames = 0;

    // Reused between received JSON frames. This removes the upstream
    // per-command new/delete churn while keeping ArduinoJson v7 compatibility.
    JsonDocument _rxDoc;

    bool tryParse();
    void dispatch(ProtoFrame& frame);
    void resync();
    bool sendJson(uint8_t type, uint8_t id, JsonDocument& doc);
    void writeHeader(uint8_t type, uint8_t id, uint32_t len);
};

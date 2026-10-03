#include "BridgeProtocolOptimized.h"
#include <cstring>

static inline bool decodeHeader(const uint8_t* buf, size_t len,
                                uint8_t& type, uint8_t& id, uint32_t& payloadLen) {
    if (!buf || len < PROTO_HEADER_SZ) return false;
    if (buf[0] != PROTO_MAGIC_0 || buf[1] != PROTO_MAGIC_1) return false;
    type = buf[2];
    id = buf[3];
    payloadLen = (uint32_t)buf[4]
               | ((uint32_t)buf[5] << 8)
               | ((uint32_t)buf[6] << 16)
               | ((uint32_t)buf[7] << 24);
    return true;
}

void BridgeProtocolOptimized::begin() {
    if (!_txMutex) _txMutex = xSemaphoreCreateMutex();
}

void BridgeProtocolOptimized::update() {
    while (_stream.available()) {
        if (_bufLen < sizeof(_buf)) {
            _buf[_bufLen++] = (uint8_t)_stream.read();
        } else {
            ++_oversizedFrames;
            resync();
        }
        while (tryParse()) {
            taskYIELD();
        }
    }
}

bool BridgeProtocolOptimized::tryParse() {
    if (_bufLen < PROTO_HEADER_SZ) return false;

    uint8_t type = 0;
    uint8_t id = 0;
    uint32_t len = 0;
    if (!decodeHeader(_buf, _bufLen, type, id, len)) {
        resync();
        return _bufLen >= PROTO_HEADER_SZ;
    }

    if (len > PROTO_MAX_CHUNK || PROTO_HEADER_SZ + len > sizeof(_buf)) {
        ++_oversizedFrames;
        resync();
        return _bufLen >= PROTO_HEADER_SZ;
    }

    const uint32_t total = PROTO_HEADER_SZ + len;
    if (_bufLen < total) return false;

    ProtoFrame frame{type, id, len, _buf + PROTO_HEADER_SZ, true};
    dispatch(frame);

    const uint32_t remain = _bufLen - total;
    if (remain) memmove(_buf, _buf + total, remain);
    _bufLen = remain;
    return _bufLen >= PROTO_HEADER_SZ;
}

void BridgeProtocolOptimized::resync() {
    if (_bufLen < 2) {
        _bufLen = 0;
        return;
    }
    for (uint32_t i = 1; i + 1 < _bufLen; ++i) {
        if (_buf[i] == PROTO_MAGIC_0 && _buf[i + 1] == PROTO_MAGIC_1) {
            memmove(_buf, _buf + i, _bufLen - i);
            _bufLen -= i;
            return;
        }
    }
    _bufLen = 0;
}

void BridgeProtocolOptimized::dispatch(ProtoFrame& frame) {
    if (frame.type == TYPE_CMD && _onCmd) {
        _rxDoc.clear();
        if (!deserializeJson(_rxDoc, frame.payload, frame.length)) {
            _onCmd(frame.id, _rxDoc);
        }
        return;
    }

    if (frame.type == TYPE_ACK && _onAck) {
        _rxDoc.clear();
        if (!deserializeJson(_rxDoc, frame.payload, frame.length) &&
            _rxDoc["chunk"].is<uint32_t>()) {
            _onAck(_rxDoc["chunk"].as<uint32_t>());
        }
        return;
    }

    if (frame.type == TYPE_HTML && _onHtml) {
        _onHtml(frame.payload, frame.length);
    }
}

void BridgeProtocolOptimized::writeHeader(uint8_t type, uint8_t id, uint32_t len) {
    uint8_t header[PROTO_HEADER_SZ] = {
        PROTO_MAGIC_0, PROTO_MAGIC_1, type, id,
        (uint8_t)(len & 0xFF),
        (uint8_t)((len >> 8) & 0xFF),
        (uint8_t)((len >> 16) & 0xFF),
        (uint8_t)((len >> 24) & 0xFF)
    };
    _stream.write(header, sizeof(header));
}

bool BridgeProtocolOptimized::sendJson(uint8_t type, uint8_t id, JsonDocument& doc) {
    const size_t len = measureJson(doc);
    if (len > PROTO_MAX_CHUNK) {
        ++_oversizedFrames;
        return false;
    }

    if (_txMutex) xSemaphoreTake(_txMutex, portMAX_DELAY);
    writeHeader(type, id, (uint32_t)len);
    serializeJson(doc, _stream); // no intermediate String allocation
    if (_txMutex) xSemaphoreGive(_txMutex);
    return true;
}

void BridgeProtocolOptimized::sendResp(uint8_t id, bool ok, const char* msg) {
    JsonDocument doc;
    doc["ok"] = ok;
    if (msg) doc["msg"] = msg;
    sendJson(TYPE_RESP, id, doc);
}

void BridgeProtocolOptimized::sendEvent(const char* type, JsonDocument& doc) {
    doc["type"] = type;
    sendJson(TYPE_EVENT, 0, doc);
}

void BridgeProtocolOptimized::sendPcapChunk(uint8_t chunkIdx, const uint8_t* data, uint32_t len) {
    sendRaw(TYPE_PCAP, chunkIdx, data, len);
}

void BridgeProtocolOptimized::sendRaw(uint8_t type, uint8_t id, const uint8_t* payload, uint32_t len) {
    if (len > PROTO_MAX_CHUNK) {
        ++_oversizedFrames;
        return;
    }
    if (_txMutex) xSemaphoreTake(_txMutex, portMAX_DELAY);
    writeHeader(type, id, len);
    if (len && payload) _stream.write(payload, len);
    if (_txMutex) xSemaphoreGive(_txMutex);
}

#pragma once
#include <cstdint>

#define PACKET_MAGIC 0xAABBCCDD
#define PROTOCOL_VERSION 1

enum MessageType : uint16_t {
    MSG_HELLO = 1,
    MSG_WELCOME = 2,
    MSG_SCAN_REQ = 3,
    MSG_SCAN_RESP = 4,
    MSG_QUERY_JOB = 5,
    MSG_JOB_STATUS = 6,
    MSG_CANCEL_JOB = 7
};

#pragma pack(push, 1)

struct PacketHeader {
    uint32_t magic;
    uint16_t version;
    uint16_t type;
    uint32_t payloadSize;
    uint32_t sequenceId;
    uint32_t sessionId;
    uint32_t checksum;
};

struct PayloadHello {
    uint32_t processId;
    uint32_t clientVersion;
    char     username[32];
};

struct PayloadWelcome {
    uint32_t sessionId;
    uint32_t serverVersion;
    char     status[64];
};

struct PayloadScanReq {
    wchar_t  filePath[260];
    int32_t  priority;
    uint32_t timeoutMs;
};

struct PayloadScanResp {
    uint32_t jobId;
    bool     accepted;
};

struct PayloadQueryJob {
    uint32_t jobId;
};

struct PayloadCancelJob {
    uint32_t jobId;
};

struct PayloadJobStatus {
    uint32_t jobId;
    int32_t  status;      // 0: Pending, 1: Running, 2: Completed, 3: Cancelled
    int32_t  progress;    // 0 - 100
    int32_t  result;      // 0: Clean, 1: Suspicious, 2: Virus
    wchar_t  message[256];
    wchar_t  threatList[1024]; // Danh sách file nhiễm
};

#pragma pack(pop)

inline uint32_t CalculateChecksum(const void* data, size_t size) {
    const uint8_t* p = (const uint8_t*)data;
    uint32_t sum = 0;
    for (size_t i = 0; i < size; ++i) sum += p[i];
    return sum;
}
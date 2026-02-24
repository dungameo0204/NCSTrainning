#pragma once
#include <cstdint>

#define PACKET_MAGIC 0xAABBCCDD
#define PROTOCOL_VERSION 1

enum MessageType : uint16_t {
    MSG_HELLO = 1,
    MSG_WELCOME = 2,
    MSG_SCAN_REQ = 3,
    MSG_SCAN_RESP = 4,
    MSG_JOB_STATUS = 6,
    MSG_FLOW_CONTROL = 8,
    MSG_RESUME = 9, // [MỚI]
    MSG_ERROR = 99
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

struct PayloadHello { uint32_t processId; uint32_t clientVersion; char username[32]; };
struct PayloadWelcome { uint32_t sessionId; uint32_t serverVersion; char status[64]; };
struct PayloadScanReq { wchar_t filePath[260]; int32_t priority; uint32_t timeoutMs; };
struct PayloadScanResp { uint32_t jobId; bool accepted; };

struct PayloadJobStatus {
    uint32_t jobId;
    int32_t  status;      // 0:Pending, 1:Running, 2:Completed
    int32_t  progress;
    int32_t  result;      // 0:Clean, 1:Suspicious, 2:Virus
    wchar_t  message[256];
    wchar_t  threatList[1024];
};

struct PayloadFlowControl { uint32_t droppedCount; };

// [MỚI] Cấu trúc gói tin Resume
struct PayloadResume {
    uint32_t sessionId;      // Phiên làm việc cũ
    uint32_t lastEventSeq;   // Gói tin cuối cùng client nhận được
};

// [MỚI] Gói tin trả về khi gói bị hỏng
struct PayloadError {
    uint32_t errorCode; // 1: Lỗi Checksum, 2: Lỗi Version
    char message[64];
};
#pragma pack(pop)

// [MỚI] Hàm tính Checksum cực nhanh (Dùng chung 2 bên)
inline uint32_t CalculateChecksum(const void* data, size_t size) {
    if (!data || size == 0) return 0;
    const uint8_t* bytes = static_cast<const uint8_t*>(data);
    uint32_t sum = 0;
    for (size_t i = 0; i < size; ++i) {
        sum = (sum << 1) | (sum >> 31); // Xoay trái 1 bit (Rotate Left)
        sum ^= bytes[i];                // XOR với từng byte
    }
    return sum;
}
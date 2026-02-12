#pragma once
#include <windows.h>
#include <stdint.h> 

// --- 1. MESSAGE TYPES ---
#define MSG_HELLO       1001
#define MSG_WELCOME     1002
#define MSG_SCAN_REQ    2001
#define MSG_SCAN_RESP   2002
#define MSG_ERROR       500
#define MSG_QUERY_JOB   3001
#define MSG_JOB_STATUS  3002
#define MSG_CANCEL_JOB  4001

// --- 2. HEADER ---
#pragma pack(push, 1)

struct PacketHeader {
    int32_t type;
    int32_t length;
};

// --- 3. PAYLOADS ---

struct PayloadHello {
    int32_t clientId;
    int32_t clientVersion;
    char    username[64];
};

struct PayloadWelcome {
    int32_t sessionId;
    int32_t serverVersion;
    char    status[64];
};

struct PayloadScanReq {
    int32_t priority;
    int32_t timeoutMs;
    wchar_t filePath[260]; // Windows MAX_PATH is usually 260
};

struct PayloadScanResp {
    int32_t jobId;
    bool    accepted;
};

struct PayloadQueryJob {
    int32_t jobId;
};

struct PayloadJobStatus {
    int32_t jobId;
    int32_t status;      // 0=Pending, 1=Running, 2=Completed, 3=Cancelled
    int32_t result;      // 0=Safe, 1=Suspicious, 2=Malicious
    int32_t progress;
    wchar_t message[128];
};

struct PayloadCancelJob {
    int32_t jobId;
};

#pragma pack(pop)
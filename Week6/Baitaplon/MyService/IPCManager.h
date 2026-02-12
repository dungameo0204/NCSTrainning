#pragma once
#include <windows.h>
#include <vector>
#include <functional>
#include <mutex>
#include <atomic>
#include <thread>
#include <deque>
#include <condition_variable>
#include "Protocol.h" 

// Struct nội bộ để lưu gói tin chờ gửi
struct OutboundPacket {
    MessageType type;
    std::vector<uint8_t> data;
    bool isCritical; // true = KHÔNG ĐƯỢC DROP
};

class IPCManager {
public:
    IPCManager();
    ~IPCManager();

    bool Initialize();
    void StartListening();
    void Stop();

    // Thêm tham số isCritical (mặc định false)
    bool Send(MessageType type, const void* data = nullptr, size_t size = 0, bool isCritical = false);

    using MessageCallback = std::function<void(uint16_t, const std::vector<uint8_t>&)>;
    void SetCallback(MessageCallback cb);

private:
    void ServerLoop();      // Luồng đọc (nhận lệnh từ Client)
    void SenderLoop();      // [MỚI] Luồng gửi (xử lý Queue)
    void ProcessBuffer();
    bool RawSend(MessageType type, const void* data, size_t size);

    HANDLE m_hPipe;
    std::thread m_workerThread;
    std::thread m_senderThread; // [MỚI]
    std::atomic<bool> m_isRunning;
    std::atomic<bool> m_isConnected;

    std::vector<uint8_t> m_readBuffer;
    std::mutex m_sendMutex;
    uint32_t m_currentSeqId;
    MessageCallback m_callback;

    // --- PHẦN BACKPRESSURE ---
    std::deque<OutboundPacket> m_outboundQueue;
    std::mutex m_queueMutex;
    std::condition_variable m_cvSender;

    const size_t MAX_QUEUE_SIZE = 500; // Ngưỡng trần: 500 tin
    bool m_isCongested = false;
    uint32_t m_droppedPackets = 0;
};
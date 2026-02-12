#include "IPCManager.h"
#include <iostream>
#include <sddl.h>

IPCManager::IPCManager() : m_hPipe(INVALID_HANDLE_VALUE), m_isRunning(false), m_isConnected(false), m_currentSeqId(0) {}
IPCManager::~IPCManager() { Stop(); }

bool IPCManager::Initialize() {
    SECURITY_ATTRIBUTES sa; ZeroMemory(&sa, sizeof(sa)); sa.nLength = sizeof(sa);
    ConvertStringSecurityDescriptorToSecurityDescriptor(L"D:P(A;;GA;;;WD)", SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL);
    m_hPipe = CreateNamedPipe(L"\\\\.\\pipe\\AvScanPipe", PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
        1024 * 1024, 1024 * 1024, 0, &sa);
    LocalFree(sa.lpSecurityDescriptor);
    return (m_hPipe != INVALID_HANDLE_VALUE);
}

void IPCManager::StartListening() {
    m_isRunning = true;
    m_workerThread = std::thread(&IPCManager::ServerLoop, this);
    m_workerThread.detach();

    // [MỚI] Khởi chạy luồng gửi
    m_senderThread = std::thread(&IPCManager::SenderLoop, this);
    m_senderThread.detach();
}

void IPCManager::Stop() {
    m_isRunning = false;
    m_cvSender.notify_all(); // Đánh thức Sender để thoát
    if (m_hPipe != INVALID_HANDLE_VALUE) { DisconnectNamedPipe(m_hPipe); CloseHandle(m_hPipe); m_hPipe = INVALID_HANDLE_VALUE; }
}

// [LOGIC BACKPRESSURE TẠI ĐÂY]
bool IPCManager::Send(MessageType type, const void* data, size_t size, bool isCritical) {
    std::unique_lock<std::mutex> lock(m_queueMutex);

    // 1. Kiểm tra ngưỡng
    if (m_outboundQueue.size() >= MAX_QUEUE_SIZE) {
        if (!isCritical) {
            // Tin rác -> Drop
            m_droppedPackets++;
            m_isCongested = true;
            return true; // Giả vờ gửi thành công để Worker chạy tiếp
        }
        // Tin Critical -> Vẫn cho vào dù đầy
    }

    OutboundPacket pkt; pkt.type = type; pkt.isCritical = isCritical;
    if (data && size > 0) {
        const uint8_t* p = (const uint8_t*)data;
        pkt.data.assign(p, p + size);
    }
    m_outboundQueue.push_back(pkt);
    m_cvSender.notify_one(); // Hú Sender dậy làm việc
    return true;
}

// [LUỒNG GỬI RIÊNG BIỆT]
void IPCManager::SenderLoop() {
    while (m_isRunning) {
        OutboundPacket pkt;
        bool needSendFlowControl = false;
        uint32_t dropsToReport = 0;

        {
            std::unique_lock<std::mutex> lock(m_queueMutex);
            // Ngủ đông nếu không có hàng
            m_cvSender.wait(lock, [this] { return !m_outboundQueue.empty() || !m_isRunning; });

            if (!m_isRunning) break;

            // Kiểm tra xem có cần báo cáo Drop không
            if (m_isCongested) {
                needSendFlowControl = true;
                dropsToReport = m_droppedPackets;
                m_droppedPackets = 0;
                m_isCongested = false;
            }

            pkt = m_outboundQueue.front();
            m_outboundQueue.pop_front();
        }

        // ƯU TIÊN 1: Gửi tin báo cáo Drop trước (nếu có)
        if (needSendFlowControl) {
            PayloadFlowControl pfc = { dropsToReport };
            RawSend(MSG_FLOW_CONTROL, &pfc, sizeof(pfc));
        }

        // ƯU TIÊN 2: Gửi gói tin chính
        RawSend(pkt.type, pkt.data.data(), pkt.data.size());
    }
}

bool IPCManager::RawSend(MessageType type, const void* data, size_t size) {
    std::lock_guard<std::mutex> lock(m_sendMutex);
    if (!m_isConnected || m_hPipe == INVALID_HANDLE_VALUE) return false;

    PacketHeader header = { PACKET_MAGIC, PROTOCOL_VERSION, (uint16_t)type, (uint32_t)size, ++m_currentSeqId, 0, 0 };
    DWORD w;
    if (!WriteFile(m_hPipe, &header, sizeof(header), &w, NULL)) return false;
    if (size > 0 && !WriteFile(m_hPipe, data, (DWORD)size, &w, NULL)) return false;

    // TUYỆT ĐỐI KHÔNG DÙNG FlushFileBuffers Ở ĐÂY
    return true;
}

void IPCManager::ServerLoop() {
    while (m_isRunning) {
        m_isConnected = false;
        bool connected = ConnectNamedPipe(m_hPipe, NULL) ? true : (GetLastError() == ERROR_PIPE_CONNECTED);
        if (connected) {
            m_isConnected = true;
            ProcessBuffer();
            DisconnectNamedPipe(m_hPipe);
        }
        else {
            DisconnectNamedPipe(m_hPipe);
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
}

void IPCManager::ProcessBuffer() {
    const size_t H_SIZE = sizeof(PacketHeader); std::vector<uint8_t> tmp(4096); m_readBuffer.clear();
    while (m_isRunning && m_isConnected) {
        DWORD bytesAvail = 0;
        if (!PeekNamedPipe(m_hPipe, NULL, 0, NULL, &bytesAvail, NULL)) break;
        if (bytesAvail > 0) {
            DWORD r = 0;
            if (!ReadFile(m_hPipe, tmp.data(), (DWORD)tmp.size(), &r, NULL) || r == 0) break;
            m_readBuffer.insert(m_readBuffer.end(), tmp.begin(), tmp.begin() + r);
            while (m_readBuffer.size() >= H_SIZE) {
                PacketHeader* h = reinterpret_cast<PacketHeader*>(m_readBuffer.data());
                if (h->magic != PACKET_MAGIC) { m_readBuffer.clear(); break; }
                size_t total = H_SIZE + h->payloadSize;
                if (m_readBuffer.size() >= total) {
                    std::vector<uint8_t> payload(m_readBuffer.begin() + H_SIZE, m_readBuffer.begin() + total);
                    if (m_callback) m_callback(h->type, payload);
                    m_readBuffer.erase(m_readBuffer.begin(), m_readBuffer.begin() + total);
                }
                else break;
            }
        }
        else std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}
void IPCManager::SetCallback(MessageCallback cb) { m_callback = cb; }
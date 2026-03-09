#ifndef PASSIVE_HANDSHAKE_H
#define PASSIVE_HANDSHAKE_H

#include <Arduino.h>
#include <WebServer.h>
#include <esp_wifi.h>
#include <freertos/semphr.h>
#include <LittleFS.h>
#include <vector>

struct TargetNetwork {
    String ssid;
    String bssid;
    uint8_t bssidBytes[6];
    int channel;
    bool beaconCaptured;
};

struct PcapPacket {
    unsigned long timestamp;
    uint16_t len;
    int8_t rssi;
    uint8_t channel;
    uint8_t payload[400]; // Original Value: 400 (For full packet capture)
};

class PassiveHandshakeModule {
public:
    void init(WebServer* server);
    void loop(); // Will be called continuously inside Main loop
    void stop(); // To stop the module externally

private:
    WebServer* server;
    bool isSniffing = false;
    
    // PSRAM Buffer
    char* logBuffer = nullptr;
    size_t logPos = 0;
    const size_t MAX_LOG_SIZE = 1024 * 1024; // 1MB Log Area

    SemaphoreHandle_t logMutex;
    std::vector<TargetNetwork> targets;
    
    // PCAP Management
    File pcapFile;
    QueueHandle_t pcapQueue;
    
    int apChannel = 1;
    unsigned long lastChannelHop = 0;
    unsigned long lastKeepAlive = 0;
    unsigned long lastPeriodicLog = 0;
    int currentTargetIndex = 0;
    bool onKeepAlive = false;
    volatile unsigned long handshakeWindowUntil = 0;

    void handleRoot();
    void handleScan();
    void handleStart();
    void handleStop();
    void handleStatus();
    void handleClear();
    void handleSave();
    
    static void wifiPromiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type);
    void logPacket(const char* fmt, ...);
    void processPcapQueue();
    void writePcapGlobalHeader();
};

#endif
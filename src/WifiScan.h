#ifndef WIFI_SCAN_H
#define WIFI_SCAN_H

#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <esp_wifi.h>

// Device State Enum
enum DeviceState {
    STATE_UNKNOWN,
    STATE_FIXED,    // Fixed
    STATE_MOVING,   // Moving
    STATE_NOISY,    // Noisy (Fixed but with interference)
    STATE_SLEEP     // Sleep Mode / Lost
};

// Device Classification Matrix
enum DeviceClass {
    DEV_UNKNOWN = 0,
    DEV_AP,             // Modem / Router
    DEV_PHONE_STATIC,   // Phone on Desk
    DEV_PHONE_MOVING,   // Phone in Pocket
    DEV_IOT,            // Smart Plug/Bulb
    DEV_LAPTOP          // Laptop / Tablet
};

// A. Data Structure (for PSRAM)
struct TrackedDevice {
    uint8_t mac[6];
    int8_t rssi_history[10]; // Circular buffer
    uint8_t buffer_index;
    uint8_t buffer_count;
    unsigned long last_seen;
    int8_t current_mean;     // Average RSSI
    float current_variance;  // Variance
    DeviceState state;
    
    // PROFILING DATA
    DeviceClass device_class;
    bool is_random_mac;      // Is Random MAC?
    uint16_t probe_count;    // How many Probe Requests sent?
    bool beacon_seen;        // Beacon packet seen?

    // Bonus: Channel Based Tracking
    uint8_t channel_counts[15]; // How many packets seen on which channel
    uint8_t primary_channel;    // Most seen channel

    // TRILATERATION DATA
    int8_t rssi_center; // RSSI at point (0,0)
    int8_t rssi_east;   // RSSI at point (2,0)
    int8_t rssi_north;  // RSSI at point (0,2)
    float pos_x;        // Calculated X (meters)
    float pos_y;        // Calculated Y (meters)
};

class WifiScannerModule {
public:
    WifiScannerModule();
    void init(WebServer* server); // Takes WebServer pointer and sets up routes
    void loop(); // Main loop (Hopping, Analysis, Logging)
    void stop(); // To stop the module externally
    
    // Sniffer Callback (Must be static)
    static void wifiPromiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type);

private:
    WebServer* _server;
    bool _scanning;
    int _mappingStep; // 0:None, 1:Center, 2:East, 3:North
    
    uint8_t _apMac[6];  // ESP32 AP MAC Address
    uint8_t _staMac[6]; // ESP32 Station MAC Address
    
    // Timers
    unsigned long _lastChannelHop;
    unsigned long _lastAnalysis;
    unsigned long _lastLog;
    int _currentChannel;
    
    String getAppPage(); // HTML Page
    String getVendor(uint8_t* mac); // Find Vendor from MAC Address
    float calculateDistance(int8_t rssi); // RSSI -> Meter conversion
};

#endif
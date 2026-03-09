#include "WifiScan.h"
#include "PassiveHandshake.h"

extern PassiveHandshakeModule myPassiveHandshake;

// For global access (Since Callback function is static)
static WifiScannerModule* instance = nullptr;

// Device List Pointer in PSRAM
static TrackedDevice* trackedDevices = nullptr;
static const int MAX_TRACKED_DEVICES = 20;
static int trackedDeviceCount = 0;

WifiScannerModule::WifiScannerModule() {
    _lastChannelHop = 0;
    _lastAnalysis = 0;
    _lastLog = 0;
    _currentChannel = 1;
    _scanning = false;
    _mappingStep = 0;
    instance = this;
}

void WifiScannerModule::init(WebServer* server) {
    _server = server;

    // 1. Memory Allocation
    // IMPORTANT: We DEFINITELY use Internal RAM instead of PSRAM.
    // Accessing PSRAM when Cache is disabled during Flash writing causes a crash.
    size_t size = sizeof(TrackedDevice) * MAX_TRACKED_DEVICES;
    trackedDevices = (TrackedDevice*) heap_caps_malloc(size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);

    if (trackedDevices == nullptr) {
        Serial.println("ERROR: RAM could not be allocated!");
    } else {
        Serial.printf("WIFI_SCAN: %u bytes RAM allocated.\n", size);
    }
    
    // Reset memory
    if (trackedDevices) {
        memset(trackedDevices, 0, size);
    }
    trackedDeviceCount = 0;

    // Learn our own MAC Addresses (For filtering)
    esp_read_mac(_apMac, ESP_MAC_WIFI_SOFTAP);
    esp_read_mac(_staMac, ESP_MAC_WIFI_STA);

    // 2. Wi-Fi Promiscuous Mode Settings
    // STA mode must be active for scanning (AP+STA)
    if (WiFi.getMode() == WIFI_MODE_NULL) {
        WiFi.mode(WIFI_AP_STA);
    }
    
    esp_wifi_set_promiscuous(false); // Initially off
    esp_wifi_set_promiscuous_rx_cb(&WifiScannerModule::wifiPromiscuousCallback);

    // 3. Web Routes (ALL ROUTES DEFINED HERE)
    // We define routes here without needing to write code in Main.cpp.
    
    // Main Interface
    _server->on("/wifi_app", HTTP_GET, [this]() {
        _server->send(200, "text/html", getAppPage());
    });

    // Start Route
    _server->on("/wifi_start", HTTP_GET, [this]() {
        // CONFLICT PREVENTION: Stop other module
        myPassiveHandshake.stop();

        if (!_scanning) {
            _scanning = true;
            // IMPORTANT: Reclaim Callback function (Other modules might have stolen it)
            esp_wifi_set_promiscuous_rx_cb(&WifiScannerModule::wifiPromiscuousCallback);
            esp_wifi_set_promiscuous(true);
            Serial.println("WIFI_SCAN: Started via Web request.");
        }
        _server->send(200, "text/plain", "OK");
    });

    // Stop Route
    _server->on("/wifi_stop", HTTP_GET, [this]() {
        stop();
        _server->send(200, "text/plain", "OK");
    });

    // JSON Data
    _server->on("/api/data", HTTP_GET, [this]() {
        String json = "[";
        for (int i = 0; i < trackedDeviceCount; i++) {
            if (i > 0) json += ",";
            TrackedDevice* d = &trackedDevices[i];
            char macStr[18];
            sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                d->mac[0], d->mac[1], d->mac[2], d->mac[3], d->mac[4], d->mac[5]);
            
            String stateStr = "Unknown";
            if (d->state == STATE_FIXED) stateStr = "Fixed";
            else if (d->state == STATE_MOVING) stateStr = "Moving";
            else if (d->state == STATE_NOISY) stateStr = "Noisy";
            else if (d->state == STATE_SLEEP) stateStr = "Sleep";
            
            // BRANDING LOGIC
            String vendor = getVendor(d->mac);
            String typeStr = "Unknown";
            
            if (d->is_random_mac) {
                // If Random MAC, brand cannot be known
                if (d->device_class == DEV_PHONE_STATIC) typeStr = "Hidden Phone (Desk)";
                else if (d->device_class == DEV_PHONE_MOVING) typeStr = "Hidden Phone (Pocket)";
                else typeStr = "Hidden Device";
            } else {
                // If Real MAC, Brand + Type
                String prefix = (vendor != "") ? vendor : "Unknown";
                if (d->device_class == DEV_AP) typeStr = prefix + " Modem";
                else if (d->device_class == DEV_IOT) typeStr = prefix + " IoT";
                else typeStr = prefix + " Device";
            }

            json += "{\"mac\":\"" + String(macStr) + "\",";
            json += "\"rssi\":" + String(d->current_mean) + ",";
            json += "\"var\":" + String(d->current_variance) + ",";
            json += "\"seen\":" + String(millis() - d->last_seen) + ",";
            json += "\"state\":\"" + stateStr + "\",";
            json += "\"type\":\"" + typeStr + "\"}";
        }
        json += "]";
        _server->send(200, "application/json", json);
    });

    // --- TRILATERATION ROUTES ---
    
    // Step by Step Measurement Taking
    _server->on("/api/map_step", HTTP_GET, [this]() {
        if (!_server->hasArg("step")) return;
        int step = _server->arg("step").toInt();
        _mappingStep = step;

        int count = 0;
        for (int i = 0; i < trackedDeviceCount; i++) {
            TrackedDevice* d = &trackedDevices[i];
            // Only take those seen recently and with logical RSSI values
            if (d->state == STATE_SLEEP || d->current_mean == 0) continue;

            if (step == 1) { // CENTER (0,0)
                d->rssi_center = d->current_mean;
            } else if (step == 2) { // EAST (2,0)
                d->rssi_east = d->current_mean;
            } else if (step == 3) { // NORTH (0,2)
                d->rssi_north = d->current_mean;
                
                // CALCULATION TIME
                // 1. Find Distances (r1, r2, r3)
                float r1 = calculateDistance(d->rssi_center);
                float r2 = calculateDistance(d->rssi_east);
                float r3 = calculateDistance(d->rssi_north);

                // 2. Calculate Coordinates (Grid: 2 meters)
                // x = (r1^2 - r2^2 + 4) / 4
                // y = (r1^2 - r3^2 + 4) / 4
                d->pos_x = (pow(r1, 2) - pow(r2, 2) + 4.0) / 4.0;
                d->pos_y = (pow(r1, 2) - pow(r3, 2) + 4.0) / 4.0;
            }
            count++;
        }
        _server->send(200, "text/plain", "Step " + String(step) + " Complete. (" + String(count) + " devices)");
    });

    // Map Data JSON
    _server->on("/api/map_data", HTTP_GET, [this]() {
        String json = "[";
        bool first = true;
        for (int i = 0; i < trackedDeviceCount; i++) {
            TrackedDevice* d = &trackedDevices[i];
            // Send only calculated data
            if (d->rssi_center == 0 || d->rssi_east == 0 || d->rssi_north == 0) continue;

            if (!first) json += ",";
            char macStr[18];
            sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                d->mac[0], d->mac[1], d->mac[2], d->mac[3], d->mac[4], d->mac[5]);
            
            json += "{\"mac\":\"" + String(macStr) + "\",";
            json += "\"x\":" + String(d->pos_x) + ",";
            json += "\"y\":" + String(d->pos_y) + ",";
            json += "\"r1\":" + String(calculateDistance(d->rssi_center)) + "}";
            first = false;
        }
        json += "]";
        _server->send(200, "application/json", json);
    });

    // Download Redirection
    _server->on("/indir", HTTP_GET, [this]() {
        _server->sendHeader("Location", "/rom_download?file=kayitlar.csv");
        _server->send(302, "text/plain", "Redirecting...");
    });

    Serial.println("WIFI_SCAN: Started and routes defined.");
}

// Distance Estimation with Log-Normal Shadowing Model
float WifiScannerModule::calculateDistance(int8_t rssi) {
    if (rssi == 0) return 99.0; // Invalid data
    int txPower = -40; // Reference RSSI at 1 meter (Average)
    float n = 2.5;     // Environmental factor (2.0: Free space, 3.0: Office/Home)
    
    return pow(10.0, (txPower - rssi) / (10.0 * n));
}

// Simple Brand Database (OUI - First 3 Bytes)
// NOT: Bu fonksiyon etrafta tespit edilen DIGER cihazlarin markasini bulmak icindir.
// ESP32'nin kendi MAC adresi degildir (O zaten main.cpp'de randomize ediliyor).
String WifiScannerModule::getVendor(uint8_t* mac) {
    // Random MAC check (If Bit 1 is set, it is random)
    // Eger karsi cihaz Random MAC kullaniyorsa markasi bilinemez.
    if (mac[0] & 0x02) return ""; 

    // Example OUI List (Expandable)
    if (mac[0]==0xAC && mac[1]==0xBC && mac[2]==0x32) return "Apple";
    if (mac[0]==0xF4 && mac[1]==0xF9 && mac[2]==0x51) return "Apple";
    if (mac[0]==0x40 && mac[1]==0x98 && mac[2]==0xAD) return "Apple";
    
    if (mac[0]==0x24 && mac[1]==0xF5 && mac[2]==0xAA) return "Samsung";
    if (mac[0]==0x38 && mac[1]==0x01 && mac[2]==0x97) return "Samsung";
    
    if (mac[0]==0x50 && mac[1]==0x80 && mac[2]==0x4A) return "Xiaomi";
    
    if (mac[0]==0x18 && mac[1]==0xFE && mac[2]==0x34) return "Espressif";
    if (mac[0]==0x24 && mac[1]==0x0A && mac[2]==0xC4) return "Espressif";
    if (mac[0]==0x30 && mac[1]==0xAE && mac[2]==0xA4) return "Espressif";
    
    if (mac[0]==0x60 && mac[1]==0x32 && mac[2]==0xB1) return "TP-Link";
    
    return "";
}

void WifiScannerModule::stop() {
    if (_scanning) {
        _scanning = false;
        esp_wifi_set_promiscuous(false);
        Serial.println("WIFI_SCAN: Stopped.");
    }
    // CHANNEL RESET: When scan finishes, pull AP to default channel (1).
    // This stabilizes the connection of connected devices (Archer T3U etc.).
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
}

// B. Listener Callback
void IRAM_ATTR WifiScannerModule::wifiPromiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    // Security: Do not process if memory is not ready
    if (trackedDevices == nullptr) return;

    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) return;

    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* data = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    int8_t rssi = pkt->rx_ctrl.rssi;

    // SECURITY: Header length check (min 24 bytes for Mgmt/Data)
    // Short packets can cause incorrect MAC matching and "0 sec" issue.
    if (len < 24) return;
    
    // MAC Address Decoding (Simply Source Address - SA - Addr2)
    // Frame Control (2 bytes) + Duration (2 bytes) + Addr1 (6 bytes) + Addr2 (6 bytes - SA)
    uint8_t* macAddr = data + 10; 

    // Packet Type Analysis (Frame Control - Byte 0)
    bool isBeacon = (data[0] == 0x80); // Type: 0 (Mgmt), Subtype: 8 (Beacon)
    bool isProbe  = (data[0] == 0x40); // Type: 0 (Mgmt), Subtype: 4 (Probe Req)

    // SECURITY: Filter our own MAC address (Prevents ghost devices)
    if (memcmp(macAddr, instance->_apMac, 6) == 0) return;
    if (memcmp(macAddr, instance->_staMac, 6) == 0) return;

    // SECURITY: Source address cannot be Multicast/Broadcast (Bit 0 check)
    if (macAddr[0] & 0x01) return;

    // Check if in list
    int index = -1;
    for (int i = 0; i < trackedDeviceCount; i++) {
        if (memcmp(trackedDevices[i].mac, macAddr, 6) == 0) {
            index = i;
            break;
        }
    }

    // If not present and space available, add (Auto Discovery)
    if (index == -1 && trackedDeviceCount < MAX_TRACKED_DEVICES) {
        // RACE CONDITION FIX: Write data first, then increment counter.
        // This ensures main loop doesn't read incomplete data.
        int newIndex = trackedDeviceCount;
        memcpy(trackedDevices[newIndex].mac, macAddr, 6);
        trackedDevices[newIndex].buffer_count = 0;
        trackedDevices[newIndex].buffer_index = 0;
        trackedDevices[newIndex].state = STATE_UNKNOWN;
        trackedDevices[newIndex].last_seen = millis(); // Ilk deger atamasi
        memset(trackedDevices[newIndex].channel_counts, 0, 15);
        trackedDevices[newIndex].primary_channel = 0;
        trackedDevices[newIndex].rssi_center = 0;
        trackedDevices[newIndex].rssi_east = 0;
        trackedDevices[newIndex].rssi_north = 0;
        trackedDevices[newIndex].pos_x = 0;
        trackedDevices[newIndex].pos_y = 0;
        
        // Profile Data Init
        trackedDevices[newIndex].is_random_mac = (macAddr[0] & 0x02); // Bit 1: Locally Administered
        trackedDevices[newIndex].probe_count = 0;
        trackedDevices[newIndex].beacon_seen = false;
        trackedDevices[newIndex].device_class = DEV_UNKNOWN;
        
        trackedDeviceCount++;
        index = newIndex;
    }

    // Update Data
    if (index != -1) {
        TrackedDevice* d = &trackedDevices[index];
        d->last_seen = millis();
        
        // Update Profile Data
        if (isBeacon) d->beacon_seen = true;
        if (isProbe && d->probe_count < 60000) d->probe_count++;

        // BONUS: Channel Analysis and Filtering
        uint8_t ch = pkt->rx_ctrl.channel;
        if (ch >= 1 && ch <= 14) {
            if (d->channel_counts[ch] < 255) d->channel_counts[ch]++;
            // Update most seen channel (Primary)
            if (d->channel_counts[ch] > d->channel_counts[d->primary_channel]) {
                d->primary_channel = ch;
            }
        }

        // Only analyze data from primary channel (Prevents channel hopping noise)
        if (d->primary_channel == 0 || ch == d->primary_channel) {
            d->rssi_history[d->buffer_index] = rssi;
            d->buffer_index = (d->buffer_index + 1) % 10;
            if (d->buffer_count < 10) d->buffer_count++;
        }
    }
}

void WifiScannerModule::loop() {
    if (!_scanning) return; // Do not process if scanning is not active

    unsigned long now = millis();

    // B. Channel Hopping (Every 200ms)
    if (now - _lastChannelHop > 200) {
        _lastChannelHop = now;
        _currentChannel++;
        if (_currentChannel > 13) _currentChannel = 1;
        esp_wifi_set_channel(_currentChannel, WIFI_SECOND_CHAN_NONE);
    }

    // C. Math and Analysis (Every 5 Seconds)
    if (now - _lastAnalysis > 5000) {
        _lastAnalysis = now;
        
        for (int i = 0; i < trackedDeviceCount; i++) {
            TrackedDevice* d = &trackedDevices[i];

            // SOLUTION 3: Sleep Mode Check (60 sec - More tolerant)
            if (now - d->last_seen > 60000) {
                d->state = STATE_SLEEP;
                continue;
            }

            // Skip if not enough data
            if (d->buffer_count < 2) continue;

            // Calculate Mean
            long sum = 0;
            for (int k = 0; k < d->buffer_count; k++) {
                sum += d->rssi_history[k];
            }
            d->current_mean = sum / d->buffer_count;

            // Calculate Variance
            float varSum = 0;
            for (int k = 0; k < d->buffer_count; k++) {
                float diff = d->rssi_history[k] - d->current_mean;
                varSum += (diff * diff);
            }
            d->current_variance = varSum / d->buffer_count;

            // SOLUTION 1: RSSI Trend Analysis (Mean Delta)
            // Read in chronological order since it's a circular buffer
            int deltaSum = 0;
            int prevRssi = 0;
            bool first = true;
            
            for (int k = 0; k < d->buffer_count; k++) {
                // If buffer is full, oldest data is at buffer_index.
                int idx = (d->buffer_count < 10) ? k : (d->buffer_index + k) % 10;
                int8_t val = d->rssi_history[idx];
                
                if (!first) deltaSum += abs(val - prevRssi);
                prevRssi = val;
                first = false;
            }
            
            float meanDelta = (d->buffer_count > 1) ? (float)deltaSum / (d->buffer_count - 1) : 0;

            // Decision Mechanism
            if (meanDelta > 3.0) {
                d->state = STATE_MOVING;
            } else {
                d->state = STATE_FIXED;
            }

            // SOLUTION 2: Noisy State (High Variance but Low Trend)
            if (d->current_variance > 6.0 && meanDelta < 2.0) {
                d->state = STATE_NOISY;
            }
            
            // --- 5. DEVICE PROFILING MATRIX ---
            
            // 0. Beacon -> AP (Certain)
            if (d->beacon_seen) {
                d->device_class = DEV_AP;
            }
            // 1. Random MAC + Probe -> Phone (Subclass based on movement)
            else if (d->is_random_mac && d->probe_count > 2) {
                if (d->state == STATE_MOVING) d->device_class = DEV_PHONE_MOVING;
                else d->device_class = DEV_PHONE_STATIC;
            }
            // 2. Fixed + Probe + Real MAC -> Laptop / Tablet
            else if (!d->is_random_mac && d->probe_count > 3 && d->state == STATE_FIXED) {
                d->device_class = DEV_LAPTOP;
            }
            // 3. Fixed + No Probe + Real MAC -> IoT (Simple assumption)
            else if (!d->is_random_mac && d->probe_count == 0 && d->state == STATE_FIXED) {
                d->device_class = DEV_IOT;
            }
            else {
                d->device_class = DEV_UNKNOWN;
            }
        }
    }

    // D. Save to ROM (Every 60 Seconds)
    if (now - _lastLog > 60000) {
        _lastLog = now;
        
        File f = LittleFS.open("/kayitlar.csv", "a"); // Append mode
        if (f) {
            for (int i = 0; i < trackedDeviceCount; i++) {
                TrackedDevice* d = &trackedDevices[i];
                
                // Save only active devices
                if (d->state == STATE_SLEEP) continue;

                char macStr[18];
                sprintf(macStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
                    d->mac[0], d->mac[1], d->mac[2], d->mac[3], d->mac[4], d->mac[5]);

                String line = String(now) + "," + String(macStr) + "," + 
                              String(d->current_mean) + "," + String(d->current_variance) + "," + 
                              String(d->state) + "," + String(d->device_class) + "\n";
                f.print(line);
            }
            f.close();
            Serial.println("LOG: kayitlar.csv updated.");
        }
    }
}

String WifiScannerModule::getAppPage() {
    return R"rawliteral(
<!DOCTYPE HTML><html>
<head>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>WIFI SNIFFER & ANALYSIS</title>
  <style>
    body { background-color: #121212; color: #e0e0e0; font-family: 'Courier New', monospace; text-align: center; margin: 0; padding: 10px; }
    h2 { color: #4cc9f0; margin-bottom: 5px; }
    table { width: 100%; max-width: 800px; margin: 20px auto; border-collapse: collapse; background: #1e1e1e; }
    th { background-color: #333; color: #fff; padding: 10px; border: 1px solid #444; }
    td { padding: 8px; border: 1px solid #333; }
    .st-fixed { color: #2ecc71; font-weight: bold; }
    .st-moving { color: #e74c3c; font-weight: bold; }
    .st-noisy { color: #fca311; font-weight: bold; font-style: italic; }
    .st-sleep { color: #555; }
    
    .type-ap { color: #4cc9f0; font-weight: bold; }
    .type-phone { color: #f72585; font-weight: bold; }
    .type-iot { color: #2ecc71; }
    .type-laptop { color: #fee440; }
    
    .btn { background: #0077b6; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin: 10px; }
    .btn-exit { background: #555; cursor: pointer; }
    
    /* IMPROVED MAP AND MODAL */
    .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.85); z-index: 100; backdrop-filter: blur(4px); }
    .modal-content { background: #1e1e1e; margin: 15% auto; padding: 25px; width: 90%; max-width: 400px; border-radius: 12px; border: 1px solid #4cc9f0; box-shadow: 0 0 20px rgba(76, 201, 240, 0.2); text-align: center; }
    
    #mapContainer { position: relative; width: 100%; max-width: 500px; margin: 20px auto; }
    #mapCanvas { background: radial-gradient(circle at center, #222 0%, #111 100%); border: 1px solid #333; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); width: 100%; height: auto; aspect-ratio: 1/1; cursor: crosshair; }
    
    .tooltip { position: absolute; background: rgba(20, 20, 20, 0.95); color: #fff; padding: 8px 12px; border-radius: 6px; border: 1px solid #f72585; font-size: 12px; display: none; pointer-events: none; z-index: 50; box-shadow: 0 2px 10px rgba(0,0,0,0.5); text-align: left; white-space: nowrap; }
    .legend { display: flex; justify-content: center; gap: 15px; margin-top: 10px; font-size: 12px; color: #888; }
    .dot { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 5px; }
  </style>
  <script>
    // Start when page loads
    window.onload = function() {
        fetch('/wifi_start');
        setInterval(updateTable, 1000);
    };

    // Stop when leaving page (tab close etc.)
    window.onbeforeunload = function() {
        fetch('/wifi_stop');
    };

    function updateTable() {
        fetch('/api/data')
            .then(res => res.json())
            .then(data => {
                let html = "";
                data.forEach(d => {
                    let cls = "";
                    if(d.state == "Fixed") cls = "st-fixed";
                    else if(d.state == "Moving") cls = "st-moving";
                    else if(d.state == "Noisy") cls = "st-noisy";
                    else cls = "st-sleep";

                    let typeCls = "";
                    if(d.type.includes("Modem")) typeCls = "type-ap";
                    else if(d.type.includes("Phone")) typeCls = "type-phone";
                    else if(d.type.includes("IoT")) typeCls = "type-iot";
                    else if(d.type.includes("Laptop")) typeCls = "type-laptop";

                    html += `<tr>
                        <td>${d.mac}</td>
                        <td>${d.rssi}</td>
                        <td>${d.var.toFixed(2)}</td>
                        <td class="${cls}">${d.state}</td>
                        <td class="${typeCls}">${d.type}</td>
                        <td>${(d.seen/1000).toFixed(1)}s</td>
                    </tr>`;
                });
                document.getElementById('tbody').innerHTML = html;
            });
    }
    
    function exitApp() {
        fetch('/wifi_stop').then(() => {
            window.location.href = "/";
        });
    }

    // --- MAPPING LOGIC ---
    let mapStep = 0;
    let countdownTimer;

    function startMapping() {
        document.getElementById('mapModal').style.display = 'block';
        showStep(1);
    }

    function showStep(step) {
        mapStep = step;
        let title = "", desc = "";
        if(step === 1) { title = "STEP 1: CENTER"; desc = "Place device at (0,0)."; }
        else if(step === 2) { title = "STEP 2: EAST"; desc = "Move device 2 meters EAST (Right)."; }
        else if(step === 3) { title = "STEP 3: NORTH"; desc = "Move device 2 meters NORTH (Forward) from CENTER."; }
        
        document.getElementById('mTitle').innerText = title;
        document.getElementById('mDesc').innerText = desc;
        
        // Start countdown (To fill buffer)
        let sec = 5;
        let btn = document.getElementById('mBtn');
        btn.disabled = true;
        btn.style.opacity = 0.5;
        btn.innerText = "Wait (" + sec + ")";
        
        clearInterval(countdownTimer);
        countdownTimer = setInterval(() => {
            sec--;
            if(sec <= 0) {
                clearInterval(countdownTimer);
                btn.disabled = false;
                btn.style.opacity = 1;
                btn.innerText = "CONFIRM & MEASURE";
            } else {
                btn.innerText = "Wait (" + sec + ")";
            }
        }, 1000);
    }

    function confirmStep() {
        fetch('/api/map_step?step=' + mapStep)
            .then(res => res.text())
            .then(msg => {
                alert(msg);
                if(mapStep < 3) {
                    showStep(mapStep + 1);
                } else {
                    document.getElementById('mapModal').style.display = 'none';
                    drawMap(); // Draw map
                }
            });
    }

    function drawMap() {
        const canvas = document.getElementById('mapCanvas');
        const ctx = canvas.getContext('2d');
        
        // Update Canvas size (Responsive)
        const rect = canvas.getBoundingClientRect();
        canvas.width = rect.width;
        canvas.height = rect.height;
        
        const w = canvas.width;
        const h = canvas.height;
        const cx = w / 2;
        const cy = h / 2;
        const scale = w / 10; // Fit 5 meter radius (w/2 / 5)

        // Clear
        ctx.clearRect(0, 0, w, h);
        
        // Grid - 1 Meter intervals
        ctx.strokeStyle = '#333'; ctx.lineWidth = 1;
        ctx.setLineDash([5, 5]); // Dashed line
        
        // Circles (1m, 2m, 3m...)
        for(let r=1; r<=5; r++) {
            ctx.beginPath(); ctx.arc(cx, cy, r*scale, 0, 2*Math.PI); ctx.stroke();
            ctx.fillStyle = '#444'; ctx.font = "10px Arial"; ctx.fillText(r+"m", cx+5, cy - (r*scale) + 10);
        }
        ctx.setLineDash([]); // Back to solid line

        // Axes
        ctx.strokeStyle = '#444'; 
        ctx.beginPath(); ctx.moveTo(cx, 0); ctx.lineTo(cx, h); ctx.stroke();
        ctx.beginPath(); ctx.moveTo(0, cy); ctx.lineTo(w, cy); ctx.stroke();
        
        // Reference Points (Anchor)
        drawAnchor(ctx, cx, cy, "C", "#4cc9f0"); // Center
        drawAnchor(ctx, cx + 2*scale, cy, "E", "#4cc9f0"); // East
        drawAnchor(ctx, cx, cy - 2*scale, "N", "#4cc9f0"); // North

        // Fetch and Draw Devices
        fetch('/api/map_data')
            .then(res => res.json())
            .then(data => {
                window.mapDevices = data; // Assign to global variable for clicking
                data.forEach(d => {
                    let x = cx + (d.x * scale);
                    let y = cy - (d.y * scale); // Y axis inverted
                    drawDevice(ctx, x, y, d);
                });
            });
    }

    function drawAnchor(ctx, x, y, label, color) {
        ctx.fillStyle = color;
        ctx.beginPath(); ctx.arc(x, y, 6, 0, 2*Math.PI); ctx.fill();
        ctx.fillStyle = '#fff'; ctx.font = "bold 12px Arial"; ctx.textAlign = "center";
        ctx.fillText(label, x, y - 10);
    }

    function drawDevice(ctx, x, y, d) {
        // Pulse Effect (Ring)
        ctx.strokeStyle = 'rgba(247, 37, 133, 0.4)';
        ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(x, y, 12, 0, 2*Math.PI); ctx.stroke();
        
        // Dot
        ctx.fillStyle = '#f72585';
        ctx.beginPath(); ctx.arc(x, y, 5, 0, 2*Math.PI); ctx.fill();
        
        // Label (Short MAC)
        ctx.fillStyle = '#ccc'; ctx.font = "10px monospace"; ctx.textAlign = "left";
        ctx.fillText(d.mac.substring(9), x+8, y+3); 
    }

    // Map Click Event
    document.addEventListener('DOMContentLoaded', () => {
        const canvas = document.getElementById('mapCanvas');
        const tooltip = document.getElementById('mapTooltip');
        
        canvas.addEventListener('mousedown', function(e) {
            const rect = canvas.getBoundingClientRect();
            const scaleX = canvas.width / rect.width;
            const scaleY = canvas.height / rect.height;
            const x = (e.clientX - rect.left) * scaleX;
            const y = (e.clientY - rect.top) * scaleY;

            let found = false;
            const w = canvas.width;
            const scale = w / 10;
            const cx = w / 2;
            const cy = w / 2;

            if(window.mapDevices) {
                window.mapDevices.forEach(d => {
                    let dx = cx + (d.x * scale);
                    let dy = cy - (d.y * scale);
                    let dist = Math.sqrt((x-dx)*(x-dx) + (y-dy)*(y-dy));
                    
                    if(dist < 20) { 
                        tooltip.style.left = (e.pageX + 10) + 'px';
                        tooltip.style.top = (e.pageY + 10) + 'px';
                        tooltip.style.display = 'block';
                        tooltip.innerHTML = `<strong>${d.mac}</strong><br>X: ${d.x.toFixed(2)}m<br>Y: ${d.y.toFixed(2)}m<br>R1: ${d.r1.toFixed(2)}m`;
                        found = true;
                    }
                });
            }
            if(!found) tooltip.style.display = 'none';
        });
    });
  </script>
</head>
<body>
  <h2>WIFI MOTION ANALYSIS</h2>
  <button onclick="exitApp()" class="btn btn-exit">MAIN MENU (STOP)</button>
  <a href="/indir" class="btn" style="background:#ff006e">DOWNLOAD LOGS (CSV)</a>
  <button onclick="startMapping()" class="btn" style="background:#6f2dbd">START MAPPING</button>
  
  <br>
  <div id="mapContainer">
      <canvas id="mapCanvas" width="500" height="500"></canvas>
      <div id="mapTooltip" class="tooltip"></div>
  </div>
  <div class="legend">
      <span><div class="dot" style="background:#4cc9f0"></div> Reference (C, E, N)</span>
      <span><div class="dot" style="background:#f72585"></div> Detected Device</span>
  </div>
  
  <table>
    <thead>
        <tr><th>MAC</th><th>AVG. RSSI</th><th>VARIANCE</th><th>STATE</th><th>TYPE</th><th>LAST SEEN</th></tr>
    </thead>
    <tbody id="tbody">
        <tr><td colspan="6">Waiting for data...</td></tr>
    </tbody>
  </table>

  <!-- MODAL -->
  <div id="mapModal" class="modal">
    <div class="modal-content">
        <h3 id="mTitle" style="color:#4cc9f0">STEP 1</h3>
        <p id="mDesc">Description...</p>
        <button id="mBtn" onclick="confirmStep()" class="btn">CONFIRM</button>
    </div>
  </div>
</body></html>
)rawliteral";
}
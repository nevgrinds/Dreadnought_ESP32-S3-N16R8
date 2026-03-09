#include "PassiveHandshake.h"
#include "WifiScan.h"

extern WifiScannerModule myWifiScanner;

// Static pointer for access within Callback
static PassiveHandshakeModule* instance = nullptr;

void PassiveHandshakeModule::init(WebServer* s) {
    server = s;
    instance = this;
    logMutex = xSemaphoreCreateMutex();

    // Ensure LittleFS is started (If RomManager didn't start it)
    if (!LittleFS.begin(true)) {
        Serial.println("Handshake: LittleFS failed to start!");
    }

    // Allocate space from PSRAM
    logBuffer = (char*) ps_malloc(MAX_LOG_SIZE);
    if (!logBuffer) {
        logBuffer = (char*) malloc(10240); // 10KB normal RAM if no PSRAM
        Serial.println("Handshake: No PSRAM, using Heap.");
    }
    if (logBuffer) logBuffer[0] = '\0';
    handshakeWindowUntil = 0;

    // SETTINGS REVERTED: Payload set to 400 bytes.
    // Queue reduced to 60 to prevent RAM overflow (60 * 420 bytes = ~25 KB).
    // This allows capturing large packets without crashing the device.
    pcapQueue = xQueueCreate(60, sizeof(PcapPacket));

    server->on("/handshake", [this]() { handleRoot(); });
    server->on("/handshake_scan", [this]() { handleScan(); });
    server->on("/handshake_start", [this]() { handleStart(); });
    server->on("/handshake_stop", [this]() { handleStop(); });
    server->on("/handshake_status", [this]() { handleStatus(); });
    server->on("/handshake_clear", [this]() { handleClear(); });
    server->on("/handshake_save", [this]() { handleSave(); });
}

void PassiveHandshakeModule::handleRoot() {
    String html = R"rawliteral(
<!DOCTYPE HTML><html>
<head>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>PASSIVE HANDSHAKE</title>
  <style>
    body { background-color: #121212; color: #e0e0e0; font-family: 'Courier New', monospace; text-align: center; margin: 0; padding: 20px; }
    h2 { color: #e74c3c; border-bottom: 1px solid #333; padding-bottom: 10px; }
    .btn { padding: 12px 25px; margin: 10px; cursor: pointer; color: white; border: none; border-radius: 5px; font-weight: bold; font-size: 14px; }
    .btn-start { background-color: #2ecc71; }
    .btn-stop { background-color: #e74c3c; }
    .btn-clear { background-color: #f39c12; }
    .btn-save { background-color: #9b5de5; }
    .btn-menu { background-color: #555; text-decoration: none; display: inline-block; padding: 10px 20px; color: white; border-radius: 5px; }
    #log { width: 90%; max-width: 800px; height: 300px; background: #000; color: #0f0; margin: 20px auto; overflow-y: scroll; text-align: left; padding: 10px; border: 1px solid #333; font-size: 12px; white-space: pre-wrap; }
    .scan-list { text-align: left; max-width: 500px; margin: 20px auto; background: #1e1e1e; padding: 10px; border-radius: 8px; }
    .net-item { padding: 8px; border-bottom: 1px solid #333; display: flex; align-items: center; }
    input[type=checkbox] { transform: scale(1.5); margin-right: 10px; }
  </style>
  <script>
    var isSubmitting = false; // Check if form is submitting

    // Stop WifiScan when page loads (Prevents channel conflict and adapter crash)
    window.onload = function() { fetch('/wifi_stop'); };

    setInterval(() => {
        fetch('/handshake_status').then(r => r.text()).then(d => {
            const logDiv = document.getElementById('log');
            if(logDiv.innerText !== d) {
                logDiv.innerText = d;
                logDiv.scrollTop = logDiv.scrollHeight;
            }
        });
    }, 1000);
    
    function scan() {
        document.getElementById('scanResult').innerHTML = "Scanning...";
        fetch('/handshake_scan').then(r => r.text()).then(h => {
            document.getElementById('scanResult').innerHTML = h;
        });
    }
    function clearLog() { fetch('/handshake_clear').then(r => r.text()).then(alert); }
    function stop() { fetch('/handshake_stop').then(r => r.text()).then(alert); }
    function savePcap() { fetch('/handshake_save').then(r => r.text()).then(alert); }
    
    // Automatically stop Sniffer when leaving or refreshing the page
    // This prevents other applications (WifiScan) from locking up.
    // keepalive: true -> Ensures request reaches server even if tab is closed.
    window.onbeforeunload = function() { 
        if (!isSubmitting) { // If form is not submitting (i.e. really leaving), stop
            fetch('/handshake_stop', { keepalive: true }); 
        }
    };
  </script>
</head>
<body>
  <h2>WIFI HANDSHAKE SNIFFER</h2>
  <a href="/" class="btn-menu">MAIN MENU</a>
  <br><br>
  
  <button class="btn btn-start" onclick="scan()">SCAN NETWORKS</button>
  <button class="btn btn-stop" onclick="stop()">STOP</button>
  <button class="btn btn-clear" onclick="clearLog()">CLEAR LOG</button>
  <button class="btn btn-save" onclick="savePcap()">SAVE PCAP (ROM)</button>
  
  <form action="/handshake_start" method="POST" onsubmit="isSubmitting=true">
    <div id="scanResult" class="scan-list">Waiting for networks...</div>
  </form>

  <div id="log">Waiting for log...</div>
</body></html>
)rawliteral";
    server->send(200, "text/html", html);
}

void PassiveHandshakeModule::handleScan() {
    // CONFLICT PREVENTION: Stop WifiScan module if running
    myWifiScanner.stop();

    // SECURITY: Promiscuous mode must be disabled before scanning.
    // Otherwise WiFi.scanNetworks() returns error or 0.
    bool promiscuous = false;
    esp_wifi_get_promiscuous(&promiscuous);
    if (isSniffing || promiscuous) {
         esp_wifi_set_promiscuous(false);
         isSniffing = false;
         esp_wifi_set_promiscuous_rx_cb(NULL);
    }

    int n = WiFi.scanNetworks();
    String html = "";
    if (n == 0) {
        html = "No networks found.";
    } else {
        html += "<p style='color:#aaa; font-size:12px'>Select targets and press START:</p>";
        for (int i = 0; i < n; ++i) {
            String ssid = WiFi.SSID(i);
            int ch = WiFi.channel(i);
            int rssi = WiFi.RSSI(i);
            String bssid = WiFi.BSSIDstr(i);
            String val = String(ch) + "|" + bssid + "|" + ssid;
            
            html += "<div class='net-item'>";
            html += "<input type='radio' name='targets' value='" + val + "'>";
            html += "<span><b>" + ssid + "</b> <span style='color:#fca311'>(CH: " + String(ch) + " | RSSI: " + String(rssi) + "dBm)</span><br>";
            html += "<span style='color:#888; font-size:10px'>" + bssid + "</span></span>";
            html += "</div>";
        }
        html += "<br><input type='submit' value='LISTEN TO SELECTED (START)' class='btn btn-start' style='width:100%'>";
    }
    server->send(200, "text/html", html);
}

void PassiveHandshakeModule::handleStart() {
    // CONFLICT PREVENTION: Stop WifiScan module if running
    myWifiScanner.stop();

    targets.clear();
    
    // Parse form data
    // WebServer can take multiple parameters with same name (targets) via loop
    for (int i = 0; i < server->args(); i++) {
        if (server->argName(i) == "targets") {
            String val = server->arg(i);
            int firstPipe = val.indexOf('|');
            int lastPipe = val.lastIndexOf('|');
            
            if (firstPipe > 0 && lastPipe > firstPipe) {
                TargetNetwork t;
                t.channel = val.substring(0, firstPipe).toInt();
                t.bssid = val.substring(firstPipe + 1, lastPipe);
                t.ssid = val.substring(lastPipe + 1);
                t.beaconCaptured = false;
                
                // BSSID String to Bytes
                sscanf(t.bssid.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", 
                    &t.bssidBytes[0], &t.bssidBytes[1], &t.bssidBytes[2], &t.bssidBytes[3], &t.bssidBytes[4], &t.bssidBytes[5]);
                
                targets.push_back(t);
            }
        }
    }
    
    if (targets.empty()) {
        server->send(200, "text/html", "No network selected! <a href='/handshake'>Go Back</a>");
        return;
    }
    
    // --- FORCE SINGLE TARGET (For High Accuracy) ---
    if (targets.size() > 1) {
        logPacket("[WARN] Multiple selection made. Only FIRST target (%s) will be listened for high accuracy.\n", targets[0].ssid.c_str());
        targets.resize(1);
    }

    // Save AP Channel (For return)
    // We fix AP channel to 1 for stability of devices like Archer T3U.
    // Even if WifiScan changed channel, we must return to 1.
    apChannel = 1;

    // Close file if open (To prevent Rename error)
    if (pcapFile) pcapFile.close();

    // If there is an unsaved file from previous session, auto backup it (No data loss)
    if (LittleFS.exists("/handshake.pcap")) {
        String autoSaveName = "/hs_autosave_" + String(millis()) + ".pcap";
        if (LittleFS.rename("/handshake.pcap", autoSaveName)) {
            logPacket("[SYS] Previous recording auto-backed up: %s\n", autoSaveName.c_str());
        } else {
            logPacket("[ERR] Auto backup failed! (File might be locked)\n");
        }
    }

    // Prepare PCAP File
    pcapFile = LittleFS.open("/handshake.pcap", FILE_WRITE);
    if (pcapFile) {
        writePcapGlobalHeader();
        logPacket("[SYS] PCAP file created.\n");
    } else {
        logPacket("[ERR] PCAP file could not be created!\n");
        Serial.println("Handshake: File open error!");
    }

    // Start Promiscuous mode
    // wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA }; // Only data
    // esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&PassiveHandshakeModule::wifiPromiscuousCallback);
    
    // Fix channel directly to target channel (No Hopping)
    esp_wifi_set_channel(targets[0].channel, WIFI_SECOND_CHAN_NONE);

    isSniffing = true;
    lastKeepAlive = millis();
    lastChannelHop = millis();
    lastPeriodicLog = millis();
    currentTargetIndex = 0;
    handshakeWindowUntil = 0;
    
    logPacket("[INFO] Sniffer started. Target count: %d\n", targets.size());
    logPacket("[INFO] Main AP Channel: %d (Will return every 4s)\n", apChannel);

    server->sendHeader("Location", "/handshake");
    server->send(303);
}

void PassiveHandshakeModule::handleStop() {
    stop();
    server->send(200, "text/plain", "Stopped");
}

void PassiveHandshakeModule::handleStatus() {
    if(xSemaphoreTake(logMutex, 100)) {
        server->send(200, "text/plain", logBuffer);
        xSemaphoreGive(logMutex);
    } else {
        server->send(200, "text/plain", "Log busy...");
    }
}

void PassiveHandshakeModule::handleClear() {
    if(xSemaphoreTake(logMutex, portMAX_DELAY)) {
        logBuffer[0] = '\0';
        logPos = 0;
        xSemaphoreGive(logMutex);
    }
    server->send(200, "text/plain", "Log cleared");
}

void PassiveHandshakeModule::handleSave() {
    if (isSniffing) {
        stop(); // Stop before saving
    } else {
        if (pcapFile) pcapFile.close(); // To be sure
    }

    String newName = "/hs_" + String(millis()) + ".pcap";
    if (LittleFS.exists("/handshake.pcap")) {
        LittleFS.rename("/handshake.pcap", newName);
        server->send(200, "text/plain", "Saved: " + newName);
    } else {
        server->send(200, "text/plain", "No data to save.");
    }
}

void PassiveHandshakeModule::stop() {
    if (isSniffing) {
        esp_wifi_set_promiscuous(false);
        isSniffing = false;
        esp_wifi_set_promiscuous_rx_cb(NULL); // Nullify Callback
        
        // Close file
        if (pcapFile) pcapFile.close();
        
        // Return to AP channel
        esp_wifi_set_channel(apChannel, WIFI_SECOND_CHAN_NONE);
        
        logPacket("[INFO] Sniffer stopped.\n");
    }
}

void PassiveHandshakeModule::loop() {
    processPcapQueue(); // Write packets from queue to file

    if (!isSniffing || targets.empty()) return;

    unsigned long now = millis();

    // --- HANDSHAKE WINDOW CONTROL ---
    // If M2 captured, stay locked on channel for a while (Cancel Keep-Alive and Hopping)
    if (now < handshakeWindowUntil) {
        return; 
    }

    // --- KEEP ALIVE LOGIC (Return to AP channel every 4 seconds) ---
    if (!onKeepAlive && (now - lastKeepAlive > 4000)) {
        // Switch to AP channel
        esp_wifi_set_channel(apChannel, WIFI_SECOND_CHAN_NONE);
        onKeepAlive = true;
        lastKeepAlive = now;
        // logPacket("[SYS] Keep-Alive: CH %d\n", apChannel);
        return;
    }

    // Keep-Alive time up? (200ms sufficient)
    if (onKeepAlive) {
        if (now - lastKeepAlive > 200) {
            onKeepAlive = false; // Return to Sniffing mode
            // FIX: We must return to target channel when Keep-Alive ends!
            if (!targets.empty()) {
                esp_wifi_set_channel(targets[0].channel, WIFI_SECOND_CHAN_NONE);
            }
        } else {
            return; // Still wait on AP channel
        }
    }

    // --- HOPPING LOGIC (Fast scan) ---
    // Switch to next target channel every 150ms
    /* HOPPING DISABLED FOR SINGLE TARGET MODE
    if (now - lastChannelHop > 150) {
        currentTargetIndex = (currentTargetIndex + 1) % targets.size();
        int ch = targets[currentTargetIndex].channel;
        
        esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
        lastChannelHop = now;
    }
    */

    // Status notification every 5 minutes (300000 ms)
    if (now - lastPeriodicLog > 300000) {
        logPacket("[INFO] Waiting continues...\n");
        lastPeriodicLog = now;
    }
}

void PassiveHandshakeModule::wifiPromiscuousCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    uint8_t* data = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    if (len < 36 || !instance || instance->targets.empty()) return;

    // --- 1. BEACON CAPTURE (Required for SSID Context) ---
    // Frame Control (2 bytes): Type 0 (Mgmt), Subtype 8 (Beacon) -> 0x80
    if (data[0] == 0x80) {
        // Beacon Frame: Addr1(Dst), Addr2(Src), Addr3(BSSID)
        // Usually Addr2 and Addr3 are the same (AP MAC)
        // Addr3 Offset: 16
        for (auto &t : instance->targets) {
            if (!t.beaconCaptured && memcmp(t.bssidBytes, &data[16], 6) == 0) {
                // Target Beacon found, save
                t.beaconCaptured = true;
                
                PcapPacket p;
                p.timestamp = millis();
                p.len = (len > 400) ? 400 : len; // Truncate (Original value)
                p.rssi = pkt->rx_ctrl.rssi;
                p.channel = pkt->rx_ctrl.channel;
                memcpy(p.payload, data, p.len);
                // If queue could not be created, do not send (Prevent crash)
                if (instance->pcapQueue) {
                    xQueueSendFromISR(instance->pcapQueue, &p, NULL);
                }
                
                return;
            }
        }
        return; // Ignore other beacons
    }

    // --- 2. EAPOL CAPTURE ---
    // Only Data packets (Type 2 -> 0x08 or 0x88 QoS)
    if ((data[0] & 0x0C) != 0x08) return;
    
    // --- BSSID FILTERING (CPU and Queue Saving) ---
    uint8_t flags = data[1];
    bool toDS = (flags & 0x01) != 0;
    bool fromDS = (flags & 0x02) != 0;
    uint8_t* bssidPtr = nullptr;

    if (!toDS && !fromDS) bssidPtr = data + 16;       // Addr3 (AdHoc/Mgmt)
    else if (toDS && !fromDS) bssidPtr = data + 4;    // Addr1 (Dst=BSSID)
    else if (!toDS && fromDS) bssidPtr = data + 10;   // Addr2 (Src=BSSID)
    
    // If not matching target BSSID, discard packet
    if (!bssidPtr || memcmp(bssidPtr, instance->targets[0].bssidBytes, 6) != 0) {
        return;
    }

    // LLC SNAP Header for EAPOL: AA AA 03 00 00 00 88 8E
    // Usually searched in payload after header.
    for (int i = 0; i < len - 8; i++) {
        if (data[i] == 0xAA && data[i+1] == 0xAA && data[i+2] == 0x03 &&
            data[i+6] == 0x88 && data[i+7] == 0x8E) {
            
            // --- M2 DETECTION AND HANDSHAKE WINDOW ---
            // Key Info after EAPOL Header (Offset +13)
            if (i + 14 < len) {
                uint16_t keyInfo = (data[i+13] << 8) | data[i+14];
                bool isPairwise = (keyInfo & 0x0008) != 0;
                bool hasMic     = (keyInfo & 0x0100) != 0;
                bool hasAck     = (keyInfo & 0x0080) != 0;
                bool hasSecure  = (keyInfo & 0x0200) != 0;

                // M2: Pairwise + MIC + !Ack + !Secure
                if (isPairwise && hasMic && !hasAck && !hasSecure) {
                    instance->handshakeWindowUntil = millis() + 3000; // Lock for 3 seconds
                }
            }

            // EAPOL Found, get details
            if (instance) {
                // Add to PCAP Queue
                PcapPacket p;
                p.timestamp = millis();
                p.len = (len > 400) ? 400 : len; // Truncate
                p.rssi = pkt->rx_ctrl.rssi;
                p.channel = pkt->rx_ctrl.channel;
                memcpy(p.payload, data, p.len);
                if (instance->pcapQueue) {
                    xQueueSendFromISR(instance->pcapQueue, &p, NULL);
                }
            }
            break; 
        }
    }
}

void PassiveHandshakeModule::processPcapQueue() {
    if (!pcapFile || !pcapQueue) return;
    
    PcapPacket pkt;
    int processedCount = 0;
    // If data in queue, take and write to file.
    // Limit increased (10 -> 50) because queue fills fast, if not emptied data is lost.
    while (processedCount < 50 && xQueueReceive(pcapQueue, &pkt, 0)) {
        processedCount++;

        // BSSID Offset Calculation and MAC String conversion (Same as your old code)
        // Byte 1: Flags (ToDS: bit 0, FromDS: bit 1)
        uint8_t flags = pkt.payload[1];
        bool toDS = (flags & 0x01) != 0;
        bool fromDS = (flags & 0x02) != 0;
        int bssidOffset = 16; // Default (Mgmt / AdHoc: Addr3)
        if (toDS && !fromDS) bssidOffset = 4;       // STA -> AP (Addr1 = BSSID)
        else if (!toDS && fromDS) bssidOffset = 10; // AP -> STA (Addr2 = BSSID)
        
        char bssidStr[18];
        sprintf(bssidStr, "%02X:%02X:%02X:%02X:%02X:%02X", 
            pkt.payload[bssidOffset], pkt.payload[bssidOffset+1], pkt.payload[bssidOffset+2], 
            pkt.payload[bssidOffset+3], pkt.payload[bssidOffset+4], pkt.payload[bssidOffset+5]);

        // --- PRINT LOGIC BASED ON PACKET TYPE ---
        if (pkt.payload[0] == 0x80) {
            // BEACON: We will write to file but NOT LOG TO SCREEN (Avoid clutter)
        } else {
            // EAPOL PACKET: Let's go inside and find if it is M1, M2, M3, M4
            int eapolOffset = -1;
            // Find LLC SNAP Header
            for (int i = 0; i < pkt.len - 14; i++) {
                if (pkt.payload[i] == 0xAA && pkt.payload[i+1] == 0xAA && pkt.payload[i+2] == 0x03 &&
                    pkt.payload[i+6] == 0x88 && pkt.payload[i+7] == 0x8E) {
                    eapolOffset = i;
                    break;
                }
            }

            const char* msgType = "Unknown EAPOL";
            
            if (eapolOffset != -1 && (eapolOffset + 14) < pkt.len) {
                // Read Key Information field (9th and 10th bytes after EAPOL header, total 13 and 14)
                uint16_t keyInfo = (pkt.payload[eapolOffset+13] << 8) | pkt.payload[eapolOffset+14];
                
                bool isPairwise = (keyInfo & 0x0008) != 0;
                bool hasInstall = (keyInfo & 0x0040) != 0;
                bool hasAck     = (keyInfo & 0x0080) != 0;
                bool hasMic     = (keyInfo & 0x0100) != 0;
                bool hasSecure  = (keyInfo & 0x0200) != 0;

                // Determining packet identity by looking at flags
                if (isPairwise) {
                    if (hasAck && !hasMic) msgType = "M1";
                    else if (!hasAck && hasMic && !hasSecure) msgType = "M2";
                    else if (hasAck && hasMic && hasInstall) msgType = "M3";
                    else if (!hasAck && hasMic && hasSecure) msgType = "M4";
                } else {
                    msgType = "Group M1/M2"; 
                }
            }

            // LOG ONLY EAPOL PACKETS TO SCREEN!
            logPacket("🔥 [CAPTURED] %s | CH:%d | RSSI:%d | BSSID:%s\n", msgType, pkt.channel, pkt.rssi, bssidStr);
            Serial.printf("🔥 [CAPTURED] %s | CH:%d | RSSI:%d | BSSID:%s\n", msgType, pkt.channel, pkt.rssi, bssidStr);
        }

        // --- FILE WRITING OPERATION (PCAP) ---
        uint32_t ts_sec = pkt.timestamp / 1000;
        uint32_t ts_usec = (pkt.timestamp % 1000) * 1000;
        uint32_t incl_len = pkt.len;
        uint32_t orig_len = pkt.len;

        pcapFile.write((uint8_t*)&ts_sec, 4);
        pcapFile.write((uint8_t*)&ts_usec, 4);
        pcapFile.write((uint8_t*)&incl_len, 4);
        pcapFile.write((uint8_t*)&orig_len, 4);
        pcapFile.write(pkt.payload, pkt.len);
    }
}

void PassiveHandshakeModule::writePcapGlobalHeader() {
    if (!pcapFile) return;
    // Magic Number (d4 c3 b2 a1)
    uint32_t magic = 0xa1b2c3d4;
    // Version Major (2)
    uint16_t major = 2;
    // Version Minor (4)
    uint16_t minor = 4;
    // Zone (0)
    uint32_t zone = 0;
    // SigFigs (0)
    uint32_t sigfigs = 0;
    // SnapLen (65535)
    uint32_t snaplen = 65535;
    // Network (105 = IEEE 802.11)
    uint32_t network = 105; 

    pcapFile.write((uint8_t*)&magic, 4);
    pcapFile.write((uint8_t*)&major, 2);
    pcapFile.write((uint8_t*)&minor, 2);
    pcapFile.write((uint8_t*)&zone, 4);
    pcapFile.write((uint8_t*)&sigfigs, 4);
    pcapFile.write((uint8_t*)&snaplen, 4);
    pcapFile.write((uint8_t*)&network, 4);
}

void PassiveHandshakeModule::logPacket(const char* fmt, ...) {
    if(xSemaphoreTake(logMutex, 0)) { // Non-blocking attempt
        if (logBuffer) {
            va_list args;
            va_start(args, fmt);
            
            // Append to buffer end
            size_t len = vsnprintf(logBuffer + logPos, MAX_LOG_SIZE - logPos - 1, fmt, args);
            logPos += len;
            
            // If buffer full, reset (Not circular buffer, resetting for simplicity)
            if (logPos >= MAX_LOG_SIZE - 256) {
                logPos = 0;
                sprintf(logBuffer, "[SYS] Log buffer full, cleared.\n");
                logPos = strlen(logBuffer);
            }
            
            va_end(args);
        }
        xSemaphoreGive(logMutex);
    }
}
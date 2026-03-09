#include "GattDiscovery.h"

// --- GUVENLIK CALLBACK SINIFI ---
// Eslestirme (Pairing) sureclerini takip etmek icin
class GattSecurityCallback : public NimBLEClientCallbacks {
    void onAuthenticationComplete(ble_gap_conn_desc* desc) override {
        if(desc->sec_state.encrypted) {
            Serial.println("GATT: Security (Pairing) Successful! - Connection Encrypted.");
        } else {
            Serial.println("GATT: Security (Pairing) Failed or Not Required.");
        }
    }
};

void GattDiscoveryModule::init(WebServer* server) {
    // Mutex'i baslat
    logMutex = xSemaphoreCreateMutex();

    server->on("/gatt_scan", [this, server]() {
        server->send(200, "text/html", scanAndList());
    });

    server->on("/connect", [this, server]() {
        String mac = server->arg("mac");
        // Adres tipini al (Varsayilan: 0 = Public)
        uint8_t type = server->hasArg("type") ? server->arg("type").toInt() : 0;
        bool inject = server->hasArg("inject");
        server->send(200, "text/html", connectAndAnalyze(mac, type, inject));
    });

    server->on("/gatt_write", [this, server]() {
        String mac = server->arg("mac");
        uint8_t type = server->arg("type").toInt();
        String srv = server->arg("srv");
        String chr = server->arg("chr");
        String val = server->arg("val");
        bool isHex = server->hasArg("is_hex");
        server->send(200, "text/html", writeCharacteristic(mac, type, srv, chr, val, isHex));
    });

    server->on("/gatt_clear_log", [this, server]() {
        clearLog();
        server->send(200, "text/plain", "Log Cleared");
    });

    server->on("/gatt_read_log", [this, server]() {
        String logData = "No data yet...";
        if(xSemaphoreTake(logMutex, portMAX_DELAY)) {
            if(injectionLog.length() > 0) logData = injectionLog;
            xSemaphoreGive(logMutex);
        }
        server->send(200, "text/plain", logData);
    });

    server->on("/gatt_subscribe", [this, server]() {
        String mac = server->arg("mac");
        uint8_t type = server->arg("type").toInt();
        String srv = server->arg("srv");
        String chr = server->arg("chr");
        server->send(200, "text/plain", subscribeCharacteristic(mac, type, srv, chr));
    });

    // --- GUVENLIK VE MTU AYARLARI (PRO MOD) ---
    // MTU'yu global olarak en basta ayarla
    NimBLEDevice::setMTU(512); 
    // Guvenlik: Bonding=Evet, MITM=Hayir (PIN yok), SecureConnection=Evet
    NimBLEDevice::setSecurityAuth(true, false, true); 
    // IO Yetenegi: Ekran/Klavye yok (Just Works modu icin)
    NimBLEDevice::setSecurityIOCap(BLE_HS_IO_NO_INPUT_OUTPUT);
    Serial.println("GATT: Security (Just Works) and MTU 512 activated.");
}

String GattDiscoveryModule::scanAndList() {
    // Tarama baslamadan once mevcut baglanti varsa kopar (Kaynaklari serbest birak)
    if (pClient != nullptr && pClient->isConnected()) {
        pClient->disconnect();
        Serial.println("GATT: Existing connection closed for new scan.");
    }

    NimBLEScan* pScan = NimBLEDevice::getScan();
    pScan->setActiveScan(true);
    pScan->setInterval(97);
    pScan->setWindow(97);

    // 5 Saniyelik Bloklayan Tarama
    NimBLEScanResults results = pScan->start(5, false);

    // --- PSRAM BUFFER KULLANIMI (N16R8 Ozel) ---
    // Her satir icin ortalama 512 byte ayiralim (fazlasiyla yeterli)
    size_t estimatedSize = 4096 + (results.getCount() * 512);
    char* htmlBuf = (char*) ps_malloc(estimatedSize);
    
    if (!htmlBuf) {
        // PSRAM yoksa veya dolduysa normal heap kullan
        htmlBuf = (char*) malloc(estimatedSize);
    }
    
    // Header'i kopyala
    strcpy(htmlBuf, R"rawliteral(
<!DOCTYPE HTML><html>
<head>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>GATT DISCOVERY</title>
  <style>
    body { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; text-align: center; margin: 0; padding: 10px; }
    h2 { color: #00b4d8; margin-bottom: 10px; }
    table { width: 100%; max-width: 800px; margin: 20px auto; border-collapse: collapse; background: #1e1e1e; border-radius: 8px; overflow: hidden; }
    th { background-color: #333; color: #fff; padding: 10px; }
    td { padding: 10px; border-bottom: 1px solid #333; text-align: left; }
    .btn { background-color: #0077b6; color: white; padding: 8px 15px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block; font-size: 12px; }
    .btn-scan { background-color: #fca311; color: #121212; margin-left: 5px; }
    .btn-inj { background-color: #ff006e; margin-left: 5px; }
    .btn-menu { background-color: #555; padding: 10px 20px; margin-bottom: 15px; font-size: 14px; text-decoration: none; color: white; display: inline-block; border-radius: 5px; }
    .rssi { font-weight: bold; color: #fca311; }
  </style>
</head>
<body>
  <h2>GATT DEVICE DISCOVERY</h2>
  <a href="/" class="btn-menu">RETURN TO MAIN MENU</a>
  <a href="/gatt_scan" class="btn-menu btn-scan">ACTIVE SCAN</a>
  <table>
    <tr><th>Device Name</th><th>RSSI</th><th>MAC</th><th>Action</th></tr>)rawliteral");

    char* ptr = htmlBuf + strlen(htmlBuf);

    for(int i=0; i<results.getCount(); i++) {
        NimBLEAdvertisedDevice device = results.getDevice(i);
        String name = device.getName().c_str();
        String displayName = name;
        
        if (name.isEmpty()) {
            // --- ADVANCED NAME PARSING (Raw Data Analizi) ---
            uint8_t* payload = device.getPayload();
            size_t payloadLen = device.getPayloadLength();
            size_t offset = 0;
            
            while(offset < payloadLen) {
                uint8_t len = payload[offset];
                if(len == 0 || offset + 1 + len > payloadLen) break;
                
                uint8_t type = payload[offset + 1];
                // 0x08: Shortened Local Name, 0x09: Complete Local Name
                if(type == 0x08 || type == 0x09) {
                    String extracted = "";
                    for(int k=0; k < len - 1; k++) {
                        char c = (char)payload[offset + 2 + k];
                        if(isprint(c)) extracted += c;
                    }
                    if(extracted.length() > 0) {
                        name = extracted;
                        displayName = name + " <span style='color:#4cc9f0; font-size:10px'>(Raw)</span>";
                    }
                    break; 
                }
                offset += (len + 1);
            }
            
            if (name.isEmpty()) {
                displayName = "<span style='color:gray'>Hidden SSID</span>";
            }
        }

        // Uretici ismini her durumda (isim olsa da olmasa da) sari renk ile sona ekle
        if (device.haveManufacturerData()) {
            std::string md = device.getManufacturerData();
            if (md.length() >= 2) {
                uint16_t mfgId = (uint8_t)md[0] | ((uint8_t)md[1] << 8);
                String vendor = "";
                
                if (mfgId == 0x004C) vendor = "Apple";
                else if (mfgId == 0x0075) vendor = "Samsung";
                else if (mfgId == 0x0006) vendor = "Microsoft";
                
                if (vendor != "") displayName += " <span style='color:yellow; font-size:10px'>(" + vendor + ")</span>";
            }
        }
        
        String macAddr = device.getAddress().toString().c_str();
        uint8_t addrType = device.getAddress().getType();
        
        ptr += sprintf(ptr, "<tr><td>%s</td><td class='rssi'>%d dBm</td>", displayName.c_str(), device.getRSSI());
        ptr += sprintf(ptr, "<td style='font-family:monospace; color:#aaa'>%s%s</td>", macAddr.c_str(), (addrType ? " (Rnd)" : " (Pub)"));
        ptr += sprintf(ptr, "<td><a href='/connect?mac=%s&type=%d' class='btn'>SELECT</a></td></tr>", macAddr.c_str(), addrType);
    }

    strcat(ptr, "</table></body></html>");
    String result = String(htmlBuf);
    free(htmlBuf);
    return result;
}

void GattDiscoveryModule::clearLog() {
    if(xSemaphoreTake(logMutex, portMAX_DELAY)) {
        injectionLog = "";
        xSemaphoreGive(logMutex);
    }
}

String GattDiscoveryModule::connectAndAnalyze(String macStr, uint8_t type, bool isInjection) {
    if (macStr.length() == 0) return "Error: MAC Address empty!";

    // Olası cakismalari onlemek icin taramayi durdur
    if(NimBLEDevice::getScan()->isScanning()) NimBLEDevice::getScan()->stop();

    // --- KALICI BAGLANTI YONETIMI ---
    if (pClient == nullptr) {
        pClient = NimBLEDevice::createClient();
        if (pClient == nullptr) {
            Serial.println("GATT: Client could not be created!");
            return "ERROR: Client could not be created.";
        }
        // Guvenlik callback'ini ekle (Otomatik silinmesi icin true)
        pClient->setClientCallbacks(new GattSecurityCallback(), true);
    }

    // Eger baska bir cihaza bagliysak once onu kopar
    if (pClient->isConnected() && connectedMac != macStr) {
        Serial.println("GATT: Connected to another device, disconnecting...");
        pClient->disconnect();
        delay(100);
    }

    if (!pClient->isConnected()) {
        Serial.printf("GATT: Starting connection -> MAC: %s, Type: %d\n", macStr.c_str(), type);
        NimBLEAddress targetAddr(macStr.c_str(), type);
        pClient->setConnectTimeout(5);
        if (!pClient->connect(targetAddr)) {
             Serial.println("GATT: Connection FAILED! (Timeout or Refused)");
             return R"rawliteral(
<!DOCTYPE HTML><html>
<head>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>CONNECTION ERROR</title>
  <style>
    body { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; text-align: center; padding-top: 50px; }
    h2 { color: #ff4d4d; }
    .btn { background-color: #333; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block; margin-top: 20px; }
    .btn:hover { background-color: #555; }
  </style>
</head>
<body>
  <h2>CONNECTION FAILED!</h2>
  <p>Target device not responding or connection refused.</p>
  <p style='color:#888; font-size:12px'>Check device distance and battery status.</p>
  <a href='/gatt_scan' class='btn'>RETURN TO LIST</a>
</body></html>
)rawliteral";
        }
        
        connectedMac = macStr;
        Serial.println("GATT: Connected. Scanning Services and Characteristics...");
    } else {
        Serial.println("GATT: Reusing existing connection.");
    }

    String html = R"rawliteral(
<!DOCTYPE HTML><html>
<head>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>GATT ANALYSIS</title>
  <style>
    body { background-color: #121212; color: #e0e0e0; font-family: monospace; padding: 10px; }
    h2 { color: #ff006e; text-align: center; }
    table { width: 100%; border-collapse: collapse; background: #1e1e1e; margin-top: 10px; font-size: 12px; }
    th { background-color: #333; color: #fff; padding: 8px; text-align: left; border: 1px solid #444; }
    td { padding: 8px; border: 1px solid #333; vertical-align: top; word-break: break-all; }
    .svc-row { background-color: #2b2d42; color: #fff; font-weight: bold; }
    .val { color: #4cc9f0; }
    .props { color: #fca311; }
    .btn { background-color: #555; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; display: inline-block; margin-bottom: 10px; font-family: sans-serif; }
    .btn-inj { background-color: #ff006e; }
    .inj-form { margin-top: 5px; display: flex; gap: 5px; }
    .inj-input { padding: 5px; border-radius: 4px; border: 1px solid #555; background: #222; color: white; width: 120px; }
    .log-box { background: #000; color: #0f0; font-family: 'Courier New', monospace; padding: 10px; margin: 10px 0; border: 1px solid #333; height: 150px; overflow-y: scroll; font-size: 11px; white-space: pre-wrap; }
  </style>
</head>
<body>
  <a href="/gatt_scan" class="btn">GO BACK</a>
  <a href="/connect?mac=)rawliteral" + macStr + "&type=" + String(type) + R"rawliteral(&inject=1" class="btn btn-inj">INJECTION</a>
  <h2>CONNECTION: )rawliteral" + macStr + "</h2>";

    // --- LOG PENCERESI (Enjeksiyon Modunda) ---
    if (isInjection) {
        html += "<div style='text-align:left; max-width:800px; margin:0 auto;'>";
        html += "<strong>INCOMING DATA LOG (Notify/Indicate):</strong> <button onclick='fetch(\"/gatt_clear_log\").then(()=>location.reload())' style='float:right; font-size:10px; cursor:pointer;'>CLEAR</button>";
        html += "<div id='logBox' class='log-box'>Loading...</div>";
        html += "</div>";

        // --- CANLI LOG GUNCELLEME SCRIPT ---
        html += "<script>";
        html += "function updateLog() {";
        html += "  fetch('/gatt_read_log').then(r => r.text()).then(data => {";
        html += "    const box = document.getElementById('logBox');";
        html += "    if(box.innerText !== data) {"; 
        html += "      box.innerText = data;";
        html += "      box.scrollTop = box.scrollHeight;"; // Otomatik asagi kaydir
        html += "    }";
        html += "  });";
        html += "}";
        html += "setInterval(updateLog, 1000);"; // 1 saniyede bir guncelle
        html += "updateLog();"; 
        html += "function sub(mac,type,srv,chr) { fetch('/gatt_subscribe?mac='+mac+'&type='+type+'&srv='+srv+'&chr='+chr).then(r=>r.text()).then(m=>alert(m)); }";
        html += "</script>";
    }

    // Generic Access Service (0x1800) uzerinden Device Name (0x2A00) okuma denemesi
    String realName = "";
    NimBLERemoteService* pSvc = pClient->getService("1800");
    if (pSvc) {
        NimBLERemoteCharacteristic* pChr = pSvc->getCharacteristic("2A00");
        if (pChr && pChr->canRead()) {
            realName = pChr->readValue().c_str();
        }
    }
    if (realName.length() > 0) html += "<h3 style='color:#4cc9f0; text-align:center'>Device Name: " + realName + "</h3>";

    html += "<table><tr><th>UUID</th><th>Permissions</th><th>Value (Hex / ASCII)</th></tr>";

    // Servisleri Kesfet
    std::vector<NimBLERemoteService*>* services = pClient->getServices(true);
    if (services == nullptr) {
        Serial.println("GATT: Services could not be retrieved (NULL).");
        return html + "<h3 style='color:red; text-align:center'>Services could not be retrieved! Connection might be lost.</h3></body></html>";
    }

    for(auto* service : *services) {
        html += "<tr class='svc-row'><td colspan='3'>SERVICE: " + String(service->getUUID().toString().c_str()) + "</td></tr>";
        
        std::vector<NimBLERemoteCharacteristic*>* chars = service->getCharacteristics(true);
        for(auto* ch : *chars) {
            String uuid = ch->getUUID().toString().c_str();
            String props = propsToString(ch);
            String valueStr = "-";

            // Okunabilir ise oku
            if(ch->canRead()) {
                std::string val = ch->readValue();
                valueStr = valueToString(val);
            }

            html += "<tr>";
            html += "<td>" + uuid + "</td>";
            html += "<td class='props'>" + props + "</td>";
            html += "<td class='val'>" + valueStr + "</td>";
            
            // Enjeksiyon Modu Aktif ve Yazilabilir ise Form Goster
            if (isInjection && (ch->canWrite() || ch->canWriteNoResponse())) {
                html += "<td><form action='/gatt_write' method='POST' class='inj-form'>";
                html += "<input type='hidden' name='mac' value='" + macStr + "'>";
                html += "<input type='hidden' name='type' value='" + String(type) + "'>";
                // --- DUZELTME: String Birlestirme Hatasi Giderildi ---
                html += "<input type='hidden' name='srv' value='" + String(service->getUUID().toString().c_str()) + "'>";
                html += "<input type='hidden' name='chr' value='" + uuid + "'>";
                html += "<input type='text' name='val' class='inj-input' placeholder='Data (Text/Hex)'>";
                html += "<label style='font-size:10px'><input type='checkbox' name='is_hex' value='1'>Hex</label>";
                html += "<input type='submit' value='WRITE' style='cursor:pointer; background:#0077b6; color:white; border:none; padding:5px;'>";
                html += "</form></td>";
            } else if (isInjection && (ch->canNotify() || ch->canIndicate())) {
                // Sadece dinlenebilir karakteristikler icin DINLE butonu
                html += "<td>";
                html += "<button onclick=\"fetch('/gatt_subscribe?mac=" + macStr + "&type=" + String(type) + "&srv=" + String(service->getUUID().toString().c_str()) + "&chr=" + uuid + "').then(r=>r.text()).then(m=>alert(m))\"";
                html += " style='cursor:pointer; background:#2a9d8f; color:white; border:none; padding:5px; border-radius:3px;'>LISTEN</button>";
                html += "</td>";
            } else if (isInjection) {
                html += "<td>-</td>";
            }
            
            html += "</tr>";
        }
    }

    // Eger Enjeksiyon modunda degilsek baglantiyi kapat (Kaynak tasarrufu)
    // Enjeksiyon modundaysak ACIK TUT (Notify dinlemek icin)
    if (!isInjection) {
        Serial.println("GATT: Analysis finished, closing connection.");
        pClient->disconnect();
    } else {
        Serial.println("GATT: Injection mode -> Connection kept OPEN.");
    }

    html += "</table></body></html>";
    return html;
}

String GattDiscoveryModule::writeCharacteristic(String mac, uint8_t type, String srvUuid, String chrUuid, String value, bool isHex) {
    Serial.printf("GATT WRITE: %s -> %s (Hex: %d)\n", mac.c_str(), value.c_str(), isHex);
    Serial.printf("UUIDs -> SRV: %s, CHR: %s\n", srvUuid.c_str(), chrUuid.c_str());

    // --- KALICI BAGLANTI KONTROLU ---
    if (pClient == nullptr || !pClient->isConnected() || connectedMac != mac) {
        Serial.println("GATT WRITE: Connection lost, reconnecting...");
        // Baglanti yoksa yeniden baglanmayi dene (connectAndAnalyze mantigiyla)
        // Ancak burada basitce hata donelim, kullanici arayuzden tekrar baglansin
        return "ERROR: Connection lost! Please 'Go Back' and reconnect.";
    }

    String msg = "Starting...";
    bool success = false;

    // Baglanti zaten var, dogrudan servislere eris
    NimBLERemoteService* pSvc = (srvUuid.length() > 0) ? pClient->getService(srvUuid.c_str()) : nullptr;
    
    if (pSvc) {
        NimBLERemoteCharacteristic* pChr = (chrUuid.length() > 0) ? pSvc->getCharacteristic(chrUuid.c_str()) : nullptr;
        
        if (pChr) {
                std::string dataToWrite;
                
                if (isHex) {
                    // Hex String Parse (Orn: "A1 B2 FF" -> {0xA1, 0xB2, 0xFF})
                    String cleanVal = value;
                    cleanVal.replace(" ", ""); // Bosluklari temizle
                    if (cleanVal.length() % 2 != 0) cleanVal = "0" + cleanVal; // Tek karakterse basina 0 ekle (Orn: "F" -> "0F")
                    for (unsigned int i = 0; i < cleanVal.length(); i += 2) {
                        String byteStr = cleanVal.substring(i, i + 2);
                        dataToWrite += (char) strtol(byteStr.c_str(), NULL, 16);
                    }
                } else {
                    dataToWrite = value.c_str();
                }

                // --- NOTIFY ABONELIGI (Veri Donutu Icin) ---
                if (pChr->canNotify() || pChr->canIndicate()) {
                    if(pChr->subscribe(true, [this](NimBLERemoteCharacteristic* pBLERemoteCharacteristic, uint8_t* pData, size_t length, bool isNotify){
                        // Callback: Gelen veriyi loga ekle
                        String hexVal = "";
                        String asciiVal = "";
                        for(size_t i=0; i<length; i++) {
                            char buf[3]; sprintf(buf, "%02X ", pData[i]);
                            hexVal += buf;
                            char c = (char)pData[i];
                            asciiVal += (isprint(c) ? c : '.');
                        }
                        // Zaman damgasi (basit millis)
                        String logEntry = "[" + String(millis()) + "] RX: " + hexVal + " | " + asciiVal + "\n";
                        
                        // Thread-Safe Loglama (Core 0 -> Core 1)
                        if(xSemaphoreTake(this->logMutex, portMAX_DELAY)) {
                            // Log cok buyurse kirp (PSRAM olsa bile sinir koyalim)
                            if (this->injectionLog.length() > 10000) this->injectionLog = "";
                            this->injectionLog += logEntry;
                            xSemaphoreGive(this->logMutex);
                        }
                        
                        Serial.printf("GATT RX (Notify): %s\n", hexVal.c_str()); // Seri porta aninda bas
                    })) {
                        if(xSemaphoreTake(this->logMutex, portMAX_DELAY)) {
                            this->injectionLog += "[INFO] Subscribed (Notify/Indicate)...\n";
                            xSemaphoreGive(this->logMutex);
                        }
                        Serial.println("GATT: Subscribed.");
                    }
                }

                // Write or WriteNR
                bool response = pChr->canWrite(); 
                Serial.printf("GATT: Writing... (Response: %d)\n", response);
                if(pChr->writeValue(dataToWrite, response)) {
                    msg = "DATA WRITTEN SUCCESSFULLY!<br>Value: " + value + (isHex ? " (Hex)" : " (Text)");
                    
                    if(xSemaphoreTake(this->logMutex, portMAX_DELAY)) {
                        this->injectionLog += "[TX] Sent: " + value + "\n";
                        xSemaphoreGive(this->logMutex);
                    }
                    
                    success = true;
                    Serial.println("GATT: Write SUCCESSFUL.");
                    
                } else {
                    msg = "Write operation failed.";
                    if(xSemaphoreTake(this->logMutex, portMAX_DELAY)) {
                        this->injectionLog += "[ERR] Write failed.\n";
                        xSemaphoreGive(this->logMutex);
                    }
                    Serial.println("GATT: Write FAILED.");
                }
            } else {
                msg = "Characteristic not found!";
                Serial.println("GATT: No Characteristic.");
            }
        } else {
            msg = "Service not found!";
            Serial.println("GATT: No Service.");
        }
    
    // Baglantiyi KAPATMIYORUZ (pClient->disconnect() KALDIRILDI)

    // Geri donus sayfasi
    String html = "<html><body style='background-color:#121212; color:white; font-family:sans-serif; text-align:center; padding-top:50px;'>";
    html += "<h2 style='color:" + String(success ? "#2ecc71" : "#e74c3c") + "'>" + msg + "</h2>";
    html += "<a href='/connect?mac=" + mac + "&type=" + String(type) + "&inject=1' style='color:#4cc9f0; font-size:20px;'>Go Back (Injection)</a>";
    html += "<script>setTimeout(function(){ window.location.href='/connect?mac=" + mac + "&type=" + String(type) + "&inject=1'; }, 2000);</script>";
    html += "</body></html>";
    return html;
}

String GattDiscoveryModule::subscribeCharacteristic(String mac, uint8_t type, String srvUuid, String chrUuid) {
    if (pClient == nullptr || !pClient->isConnected() || connectedMac != mac) {
        return "ERROR: No connection!";
    }
    
    NimBLERemoteService* pSvc = pClient->getService(srvUuid.c_str());
    if(pSvc) {
        NimBLERemoteCharacteristic* pChr = pSvc->getCharacteristic(chrUuid.c_str());
        if(pChr) {
            if(pChr->canNotify() || pChr->canIndicate()) {
                if(pChr->subscribe(true, [this](NimBLERemoteCharacteristic* pBLERemoteCharacteristic, uint8_t* pData, size_t length, bool isNotify){
                    String hexVal = "";
                    String asciiVal = "";
                    for(size_t i=0; i<length; i++) {
                        char buf[3]; sprintf(buf, "%02X ", pData[i]);
                        hexVal += buf;
                        char c = (char)pData[i];
                        asciiVal += (isprint(c) ? c : '.');
                    }
                    String logEntry = "[" + String(millis()) + "] RX: " + hexVal + " | " + asciiVal + "\n";
                    
                    if(xSemaphoreTake(this->logMutex, portMAX_DELAY)) {
                        if (this->injectionLog.length() > 10000) this->injectionLog = "";
                        this->injectionLog += logEntry;
                        xSemaphoreGive(this->logMutex);
                    }
                    Serial.printf("GATT RX (Notify): %s\n", hexVal.c_str());
                })) {
                    if(xSemaphoreTake(this->logMutex, portMAX_DELAY)) {
                        this->injectionLog += "[INFO] Subscribed: " + String(pChr->getUUID().toString().c_str()) + "\n";
                        xSemaphoreGive(this->logMutex);
                    }
                    return "SUCCESS: Subscribed. Watch the log.";
                }
            } else {
                return "ERROR: This characteristic does not support Notify/Indicate.";
            }
        }
    }
    return "ERROR: Service or Characteristic not found.";
}

String GattDiscoveryModule::propsToString(NimBLERemoteCharacteristic* pChar) {
    String p = "";
    if (pChar->canRead()) p += "READ ";
    if (pChar->canWrite()) p += "WRITE ";
    if (pChar->canNotify()) p += "NOTIFY ";
    if (pChar->canIndicate()) p += "INDICATE ";
    if (pChar->canWriteNoResponse()) p += "WRITE_NR ";
    return p;
}

String GattDiscoveryModule::valueToString(std::string value) {
    if (value.length() == 0) return "(Empty)";
    
    String hex = "";
    String ascii = "";
    for (size_t i = 0; i < value.length(); i++) {
        char buf[3];
        sprintf(buf, "%02X", (uint8_t)value[i]);
        hex += buf;
        
        char c = value[i];
        if (isprint(c)) ascii += c;
        else ascii += '.';
    }
    return hex + "<br><span style='color:#aaa'>" + ascii + "</span>";
}
#include "BleScanner.h"
#include <algorithm> 
#include <vector>

void BleScannerModule::init(WebServer* server) {
    NimBLEDevice::init("ESP32-PRO");

    // Rotalari Tanimla
    server->on("/ble_app", HTTP_GET, [this, server]() {
        server->send(200, "text/html", getAppPage());
    });

    server->on("/apple_sniff", HTTP_GET, [this, server]() {
        bool keep = server->hasArg("keep");
        server->send(200, "text/html", appleSniffAction(keep));
    });

    server->on("/scan_json", HTTP_GET, [this, server]() {
        server->send(200, "application/json", getScanJSON());
    });
}

String BleScannerModule::getVendor(String mac) {
    mac.toUpperCase();
    if (mac.startsWith("40:98:AD") || mac.startsWith("48:D7:05") || mac.startsWith("BC:92:6B") || mac.startsWith("88:63:DF") || mac.startsWith("AC:BC:32") || mac.startsWith("F4:F9:51")) return "Apple";
    if (mac.startsWith("24:F5:AA") || mac.startsWith("38:01:97") || mac.startsWith("A0:B4:A5") || mac.startsWith("BC:8C:CD")) return "Samsung";
    if (mac.startsWith("50:80:4A") || mac.startsWith("F4:F5:DB")) return "Xiaomi";
    if (mac.startsWith("70:99:1C") || mac.startsWith("D8:1C:79")) return "JBL";
    if (mac.startsWith("24:0A:C4") || mac.startsWith("30:AE:A4")) return "Espressif";
    return "";
}

String BleScannerModule::getScanJSON() {
    NimBLEScan* pBLEScan = NimBLEDevice::getScan();
    pBLEScan->setActiveScan(true); 
    
    // 4 Saniye Tara
    NimBLEScanResults results = pBLEScan->start(4, false);
    int count = results.getCount();

    // --- DÜZELTME BURADA ---
    // Pointer (*) yerine doğrudan nesne listesi kullanıyoruz
    std::vector<NimBLEAdvertisedDevice> sortedDevices;
    
    for(int i=0; i<count; i++) {
        // Cihazı listeye kopyala
        sortedDevices.push_back(results.getDevice(i));
    }

    // Sıralama fonksiyonu (Referans & kullanarak)
    std::sort(sortedDevices.begin(), sortedDevices.end(), [](NimBLEAdvertisedDevice& a, NimBLEAdvertisedDevice& b) {
        return a.getRSSI() > b.getRSSI();
    });

    String json = "[";
    for(size_t i = 0; i < sortedDevices.size(); i++) {
        // Artık pointer olmadığı için "->" yerine "." kullanıyoruz
        NimBLEAdvertisedDevice device = sortedDevices[i];
        
        String mac = device.getAddress().toString().c_str();
        String name = device.getName().c_str();
        int rssi = device.getRSSI();
        String vendor = getVendor(mac);
        
        if (device.haveManufacturerData()) {
            std::string data = device.getManufacturerData();
            if (data.length() >= 2) {
                uint8_t* rawData = (uint8_t*)data.data();
                uint16_t companyId = (rawData[1] << 8) | rawData[0];
                String specificVendor = getManufacturerName(companyId);
                if (specificVendor != "") vendor = specificVendor;
                if (data.length() > 2) vendor += " [" + stringToHex(data.substr(2)) + "]";
            }
        }

        if (name == "" || name == " ") {
            if (vendor != "") name = vendor + " Device";
            else name = "Unknown";
        }

        if (i > 0) json += ",";
        json += "{";
        json += "\"name\":\"" + name + "\",";
        json += "\"mac\":\"" + mac + "\",";
        json += "\"rssi\":" + String(rssi) + ",";
        json += "\"vendor\":\"" + vendor + "\"";
        json += "}";
    }
    json += "]";
    return json;
}

String BleScannerModule::stringToHex(std::string data) {
    String hex = "";
    for (size_t i = 0; i < data.length(); i++) {
        char buf[3];
        sprintf(buf, "%02X", (uint8_t)data[i]);
        hex += buf;
    }
    return hex;
}

String BleScannerModule::getManufacturerName(uint16_t companyId) {
    switch (companyId) {
        case 0x004C: return "APPLE - iPhone/AirPods/AirTag"; // Names are universal
        case 0x0075: return "SAMSUNG - Galaxy Series";
        case 0x0006: return "MICROSOFT - Windows Device";
        case 0x00E0: return "GOOGLE - Android Fast Pair";
        case 0x027D: return "HUAWEI - Phone/Watch";
        case 0x038F: return "XIAOMI - Phone/Ecosystem";
        case 0x00E1: return "OPPO / VIVO / REALME";
        case 0x00D0: return "INTEL - Computer Bluetooth";
        case 0x0157: return "HUAMI - Mi Band / Amazfit"; // Brand names
        case 0x00AD: return "FITBIT - Activity Tracker";
        case 0x0087: return "GARMIN - GPS Watch";
        case 0x0057: return "JBL / HARMAN - Speaker";
        case 0x002D: return "SONY - Headphones";
        case 0x0398: return "ANKER - Soundcore";
        case 0x009E: return "BOSE - Headphones";
        case 0x0067: return "JABRA - Headphones";
        case 0x010E: return "SENNHEISER - Headphones";
        case 0x0031: return "PHILIPS - Hue Lighting";
        case 0x07D0: return "TUYA - Smart Bulb/Plug";
        case 0x0231: return "ARCELIK - Home Appliances";
        case 0x00DC: return "ORAL-B - Toothbrush";
        case 0x0080: return "LOGITECH - Keyboard/Mouse";
        case 0x0196: return "TILE - Tracker";
        default: return "";
    }
}

String BleScannerModule::appleSniffAction(bool keep) {
    if (!keep) {
        sniffHistory.clear();
        appleSignatures.clear();
    }

    NimBLEScan* pBLEScan = NimBLEDevice::getScan();
    pBLEScan->setActiveScan(true); // Active Scan: True
    pBLEScan->setInterval(45);
    pBLEScan->setWindow(15);

    // 4 Saniyelik Tarama (Daha hizli dongu icin)
    NimBLEScanResults results = pBLEScan->start(4, false);

    String timerHtml = "";
    String scriptHtml = "";
    if (keep) {
        timerHtml = "<div id='timer' style='color:#fca311; font-weight:bold; margin:10px; font-size:18px;'>Next scan: 10 sec</div>";
        scriptHtml = "<script>let s=10; let t=setInterval(function(){ s--; if(s<=0){ clearInterval(t); document.getElementById('timer').innerText='Refreshing...'; window.location.href='/apple_sniff?keep=1'; } else { document.getElementById('timer').innerText='Next scan: '+s+' sec'; } }, 1000);</script>";
    }

    // HTML Header ve Stil
    String header = R"rawliteral(
<!DOCTYPE HTML><html>
<head>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>APPLE SNIFF</title>
  <style>
    body { background-color: #121212; color: #e0e0e0; font-family: 'Courier New', monospace; padding: 10px; text-align: center; }
    h2 { color: #6f2dbd; margin-bottom: 10px; }
    .btn { display: inline-block; padding: 10px 20px; background: #333; color: white; text-decoration: none; border-radius: 5px; margin-bottom: 20px; }
    .btn-cont { background-color: #2a9d8f; margin-left: 10px; }
    table { width: 100%; border-collapse: collapse; font-size: 11px; text-align: left; margin: 0 auto; max-width: 800px; }
    th { background-color: #2b2b2b; color: #fff; padding: 8px; border-bottom: 2px solid #444; }
    td { border-bottom: 1px solid #333; padding: 8px; vertical-align: top; }
    tr:nth-child(even) { background-color: #1a1a1a; }
    .alert { color: #ff4d4d; font-weight: bold; display: block; margin-top: 4px; }
    .hex { color: #888; font-size: 10px; word-break: break-all; }
    .type-airpods { color: #4cc9f0; font-weight: bold; }
    .type-nearby { color: #fca311; font-weight: bold; }
    .type-findmy { color: #ff006e; font-weight: bold; }
    .type-other { color: #aaa; }
  </style>
</head>
<body>
  <h2>APPLE SNIFF RESULTS</h2>
  )rawliteral" + timerHtml + R"rawliteral(
  <div>
    <a href="/ble_app" class="btn">GO BACK</a>
    <a href="/apple_sniff?keep=1" class="btn btn-cont">CONTINUE SCANNING</a>
  </div>
  <table>
    <tr>
      <th>MAC / RSSI</th>
      <th>TIP / DETAY</th>
      <th>PAYLOAD (HEX)</th>
    </tr>
)rawliteral";

    for(int i=0; i<results.getCount(); i++) {
        NimBLEAdvertisedDevice device = results.getDevice(i);
        if (device.haveManufacturerData()) {
            std::string data = device.getManufacturerData();
            // Apple ID (0x004C) kontrolü (Little Endian: 4C 00)
            if (data.length() > 3 && (uint8_t)data[0] == 0x4C && (uint8_t)data[1] == 0x00) {
                uint8_t type = (uint8_t)data[2];
                String typeStr = "";
                String detailStr = "";
                String cssClass = "type-other";
                
                // Tip Cozucu
                switch(type) {
                    case 0x02: typeStr = "iBeacon"; detailStr = "Store/Location Signal"; break;
                    case 0x05: typeStr = "AirDrop"; detailStr = "File Sharing Active"; break;
                    case 0x07: 
                        typeStr = "AirPods"; 
                        cssClass = "type-airpods";
                        detailStr = "Lid Open/Headphones";
                        
                        // AirPods Model ve Pil Cozucu
                        if (data.length() >= 8) {
                            int baseShift = 0;
                            uint8_t firstByte = (uint8_t)data[3];

                            // Eger ilk byte bilinen bir model degilse, uzunluk bilgisidir (atla).
                            bool isModel = (firstByte == 0x02 || firstByte == 0x03 || firstByte == 0x0E || 
                                            firstByte == 0x0F || firstByte == 0x13 || firstByte == 0x0A || 
                                            firstByte == 0x0B || firstByte == 0x1B);

                            if (!isModel) baseShift = 1;
                            uint8_t modelByte = (uint8_t)data[3 + baseShift];
                            
                            switch(modelByte) {
                                case 0x02: detailStr = "AirPods (1st Gen)"; break;
                                case 0x03: detailStr = "AirPods Max"; break;
                                case 0x0E: detailStr = "AirPods Pro (1st Gen)"; break;
                                case 0x0F: detailStr = "AirPods (2nd Gen)"; break;
                                case 0x13: detailStr = "AirPods (3rd Gen)"; break;
                                case 0x0A: 
                                case 0x0B: 
                                case 0x1B: detailStr = "AirPods Pro (2nd Gen)"; break;
                                default: detailStr = "AirPods (Model: " + String(modelByte, HEX) + ")"; break;
                            }

                            // Pil Verisi Offset Tespiti
                            // Standart Yapi: [Model] [Status] [Counter] [BatLR] [BatCase]
                            // Model index: 3 + baseShift -> BatLR index: 6 + baseShift
                            int offset = 6 + baseShift;

                            if (data.length() >= offset + 2) {
                                uint8_t batLR = (uint8_t)data[offset];
                                uint8_t batCase = (uint8_t)data[offset + 1];

                                int left = (batLR >> 4) & 0x0F;
                                int right = batLR & 0x0F;

                                String lStr = (left == 0x0F) ? "-" : String(left * 10) + "%";
                                String rStr = (right == 0x0F) ? "-" : String(right * 10) + "%";
                                String bStr;
                                
                                int box = batCase & 0x0F;
                                bool isCaseCharging = (batCase & 0x80) != 0; // Bit 7 genelde sarj durumudur
                                bool isLeftCharging = (batCase & 0x20) != 0; // Sol kulaklik sarj oluyor mu?
                                bool isRightCharging = (batCase & 0x40) != 0; // Sag kulaklik sarj oluyor mu?

                                if (isLeftCharging) lStr += "+";
                                if (isRightCharging) rStr += "+";

                                bStr = (box == 0x0F) ? "-" : String(box * 10) + "%";
                                if (isCaseCharging && box != 0x0F) bStr += " (Charging)";

                                detailStr += "<br><span style='color:#fff; font-size:10px'>L:" + lStr + " R:" + rStr + " Case:" + bStr + "</span>";
                            }
                        }
                        break;
                    case 0x09: typeStr = "AirPlay"; detailStr = "Screen Mirroring Target"; break;
                    case 0x0C: typeStr = "Handoff"; detailStr = "Mac/iPhone Handoff Signal"; break;
                    case 0x10: typeStr = "Nearby Info"; cssClass = "type-nearby"; detailStr = "iPhone/Watch/iPad Status"; break;
                    case 0x12: typeStr = "Find My"; cssClass = "type-findmy"; detailStr = "AirTag / Lost Device"; break;
                    default: typeStr = "Unknown (0x" + String(type, HEX) + ")"; break;
                }

                String currentMac = device.getAddress().toString().c_str();
                std::string payload = data.substr(2); // ID hariç veri
                String payloadHex = stringToHex(payload);
                
                String alertHtml = "";
                // Fingerprinting Kontrolü
                if (appleSignatures.find(payload) != appleSignatures.end()) {
                    String oldMac = appleSignatures[payload];
                    if (oldMac != currentMac) {
                        alertHtml = "<span class='alert'>[!!! SAME DEVICE - MAC CHANGED !!!]</span>";
                        sniffHistory.erase(oldMac); // Eski MAC adresini listeden sil
                    }
                }
                appleSignatures[payload] = currentMac;

                // Tablo Satiri Ekle
                String row = "<tr>";
                row += "<td>" + currentMac + "<br><span style='color:#fca311'>" + String(device.getRSSI()) + " dBm</span></td>";
                row += "<td><span class='" + cssClass + "'>" + typeStr + "</span><br><span style='color:#ccc'>" + detailStr + "</span>" + alertHtml + "</td>";
                row += "<td><span class='hex'>" + payloadHex + "</span></td>";
                row += "</tr>";
                
                sniffHistory[currentMac] = row;
            }
        }
    }
    
    String footer = "</table><br><div style='color:#666; font-size:10px'>Scan Duration: 4 Seconds</div>" + scriptHtml + "</body></html>";

    // --- PSRAM BUFFER KULLANIMI ---
    // Toplam boyutu hesapla
    size_t totalSize = header.length() + footer.length() + 1;
    for (auto const& item : sniffHistory) {
        totalSize += item.second.length();
    }

    // PSRAM'den yer ayir
    char* psramBuf = (char*) ps_malloc(totalSize);
    
    if (psramBuf) {
        Serial.printf("PSRAM OK: %u byte buffer created. (Free PSRAM: %u bytes)\n", totalSize, ESP.getFreePsram());
        char* ptr = psramBuf;
        // Header kopyala
        memcpy(ptr, header.c_str(), header.length());
        ptr += header.length();
        
        // Satirlari kopyala
        for (auto const& item : sniffHistory) {
            size_t len = item.second.length();
            memcpy(ptr, item.second.c_str(), len);
            ptr += len;
        }
        
        // Footer kopyala
        memcpy(ptr, footer.c_str(), footer.length());
        ptr += footer.length();
        *ptr = '\0'; // String sonlandirici

        String result = String(psramBuf);
        free(psramBuf);
        return result;
    } else {
        Serial.println("ERROR: PSRAM allocation failed! Using Internal RAM (Heap).");
        // PSRAM basarisiz olursa normal String birlestirme (Fallback)
        String html = header;
        for (auto const& item : sniffHistory) {
            html += item.second;
        }
        html += footer;
        return html;
    }
}

String BleScannerModule::getAppPage() {
    return R"rawliteral(
<!DOCTYPE HTML><html>
<head>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>SCAN BLUETOOTH</title>
  <style>
    body { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; text-align: center; margin: 0; padding: 10px; }
    h2 { color: #fca311; margin-bottom: 5px; }
    
    .controls { background: #1e1e1e; padding: 10px; border-radius: 12px; margin-bottom: 15px; display: flex; justify-content: center; gap: 10px; }
    .btn { border: none; padding: 12px 20px; border-radius: 8px; font-weight: bold; cursor: pointer; color: white; transition: 0.2s; font-size: 14px; }
    .btn-single { background-color: #0077b6; }
    .btn-loop { background-color: #2a9d8f; }
    .btn-sniff { background-color: #6f2dbd; }
    .btn-stop { background-color: #d62828; opacity: 0.5; pointer-events: none;}
    .btn:active { transform: scale(0.95); }
    .search-input { padding: 12px; border-radius: 8px; border: none; width: 100px; background: #333; color: white; outline: none; }

    #radar-container { position: relative; width: 300px; height: 300px; margin: 0 auto; background: #000; border-radius: 50%; border: 2px solid #333; box-shadow: 0 0 20px rgba(0,0,0,0.5); }
    
    .list-container { margin-top: 20px; max-width: 600px; margin-left: auto; margin-right: auto; text-align: left; }
    .list-header { display: flex; justify-content: space-between; padding: 5px 10px; font-weight: bold; color: #888; border-bottom: 1px solid #333; }
    .device-item { background: #1e1e1e; padding: 12px; margin-bottom: 8px; border-radius: 8px; border-left: 4px solid #555; display: flex; justify-content: space-between; align-items: center; }
    .dev-info { display: flex; flex-direction: column; flex: 1; min-width: 0; margin-right: 10px; }
    .dev-name { font-weight: bold; color: #fff; font-size: 1.1rem; word-wrap: break-word; }
    .dev-mac { font-family: monospace; color: #aaa; font-size: 0.85rem; }
    .dev-rssi { font-weight: bold; color: #fca311; min-width: 60px; text-align: right; }
    
    .vendor-apple { border-left-color: #fff !important; }
    .vendor-samsung { border-left-color: #3a86ff !important; }
    .vendor-unknown { border-left-color: #555 !important; }
    #status { margin: 10px; color: #888; font-size: 14px; font-style: italic; }
  </style>
</head>
<body>

  <h2>SCAN BLUETOOTH</h2>
  
  <div class="controls">
    <button id="btnSingle" class="btn btn-single" onclick="singleScan()">SINGLE SCAN</button>
    <button id="btnLoop" class="btn btn-loop" onclick="startLoop()">CONTINUOUS SCAN</button>
    <button id="btnStop" class="btn btn-stop" onclick="stopLoop()">STOP</button>
    <input type="text" id="searchInput" class="search-input" placeholder="Search..." oninput="filterUpdate()">
  </div>
  <div class="controls">
    <a href="/apple_sniff"><button class="btn btn-sniff">APPLE SNIFF (Serial Log)</button></a>
  </div>

  <div id="status">Ready. Awaiting command.</div>

  <div id="radar-container">
    <canvas id="radar" width="300" height="300"></canvas>
  </div>

  <div class="list-container">
    <div class="list-header">
       <span>DEVICE (Nearest to Farthest)</span>
       <span>SIGNAL</span>
    </div>
    <div id="deviceList"></div>
  </div>

  <br><a href="/" style="color:#666; text-decoration:none">RETURN TO MAIN MENU</a>

<script>
  const canvas = document.getElementById('radar');
  const ctx = canvas.getContext('2d');
  const listDiv = document.getElementById('deviceList');
  const statusDiv = document.getElementById('status');
  const centerX = 150; const centerY = 150;
  
  let isLooping = false;
  let scannedData = [];

  function drawGrid() {
    ctx.clearRect(0, 0, 300, 300);
    ctx.strokeStyle = '#333'; ctx.lineWidth = 1;
    for(let r=35; r<150; r+=35) { ctx.beginPath(); ctx.arc(centerX, centerY, r, 0, 2*Math.PI); ctx.stroke(); }
    ctx.beginPath(); ctx.moveTo(0, centerY); ctx.lineTo(300, centerY); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(centerX, 0); ctx.lineTo(centerX, 300); ctx.stroke();
    ctx.fillStyle = '#0077b6'; ctx.beginPath(); ctx.arc(centerX, centerY, 5, 0, 2*Math.PI); ctx.fill();
  }

  function filterUpdate() {
    const term = document.getElementById('searchInput').value.toLowerCase();
    const filtered = scannedData.filter(d => 
        d.name.toLowerCase().includes(term) || 
        d.mac.toLowerCase().includes(term) ||
        d.vendor.toLowerCase().includes(term)
    );
    render(filtered);
  }

  function render(data) {
    drawGrid(); 
    listDiv.innerHTML = ""; 

    data.forEach(dev => {
            // RADAR
            let rssi = Math.max(-100, Math.min(-30, dev.rssi));
            let radius = ((rssi + 30) / -70) * 140; 
            if(radius < 10) radius = 10;
            
            let angleSeed = 0;
            for(let i=0; i<dev.mac.length; i++) angleSeed += dev.mac.charCodeAt(i);
            let angle = (angleSeed % 360) * (Math.PI / 180);
            let x = centerX + radius * Math.cos(angle);
            let y = centerY + radius * Math.sin(angle);
            
            let color = '#0f0'; 
            let cssClass = 'vendor-unknown';
            if (dev.vendor === 'Apple') { color = '#fff'; cssClass = 'vendor-apple'; }
            else if (dev.vendor === 'Samsung') { color = '#3a86ff'; cssClass = 'vendor-samsung'; }

            ctx.fillStyle = color;
            ctx.beginPath(); ctx.arc(x, y, 5, 0, 2*Math.PI); ctx.fill();

            // LİSTE
            let item = `
            <div class="device-item ${cssClass}">
                <div class="dev-info">
                    <span class="dev-name">${dev.name}</span>
                    <span class="dev-mac">${dev.mac}</span>
                </div>
                <div class="dev-rssi">${dev.rssi} dBm</div>
            </div>`;
            listDiv.innerHTML += item;
    });
  }

  function fetchScan() {
    statusDiv.innerText = "Scanning (4 sec)...";
    
    fetch('/scan_json')
      .then(res => res.json())
      .then(data => {
        scannedData = data;
        statusDiv.innerText = data.length + " Devices Found.";
        filterUpdate();

        if(isLooping) {
            setTimeout(fetchScan, 100); 
        }
      })
      .catch(err => {
          console.log(err);
          statusDiv.innerText = "Error occurred!";
          stopLoop();
      });
  }

  function singleScan() {
    stopLoop();
    fetchScan();
  }

  function startLoop() {
    if(isLooping) return;
    isLooping = true;
    
    document.getElementById('btnLoop').style.opacity = '0.5';
    document.getElementById('btnLoop').style.pointerEvents = 'none';
    document.getElementById('btnStop').style.opacity = '1';
    document.getElementById('btnStop').style.pointerEvents = 'auto';
    
    fetchScan(); 
  }

  function stopLoop() {
    isLooping = false;
    statusDiv.innerText = "Stopped.";
    
    document.getElementById('btnLoop').style.opacity = '1';
    document.getElementById('btnLoop').style.pointerEvents = 'auto';
    document.getElementById('btnStop').style.opacity = '0.5';
    document.getElementById('btnStop').style.pointerEvents = 'none';
  }

  drawGrid();
</script>
</body></html>
)rawliteral";
}
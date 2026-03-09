#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <esp_mac.h>
#include "BleScanner.h" 
#include "WifiScan.h"
#include "RomManager.h"
#include "GattDiscovery.h"
#include "PassiveHandshake.h"
#include "BadUsb.h"

BleScannerModule myBleScanner;
RomManagerModule myRomManager;
PassiveHandshakeModule myPassiveHandshake;
WifiScannerModule myWifiScanner;
GattDiscoveryModule myGattDiscovery;
BadUsbModule myBadUsb;
WebServer server(80);

// --- WI-FI NAME FIXED ---
const char *ssid = "Dreadnought_2.4GHz";
const char *password = "ananas123";

const char index_html[] PROGMEM = R"rawliteral(
<!DOCTYPE HTML><html>
<head>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ESP MENU</title>
  <style>
    body { font-family: Arial, sans-serif; background-color: #121212; color: white; text-align: center; padding: 20px; }
    h2 { color: #fca311; border-bottom: 2px solid #333; display: inline-block; padding-bottom: 10px; }
    .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 15px; max-width: 500px; margin: 30px auto; }
    
    .box { 
        background: #1e1e1e; border: 2px solid #333; border-radius: 12px; height: 100px; 
        display: flex; align-items: center; justify-content: center; transition: 0.3s;
    }
    
    .active { border-color: #0077b6; background: #0f1c2e; cursor: pointer; }
    .active:hover { background: #0077b6; border-color: #fff; }
    
    a { color: #888; text-decoration: none; width: 100%; height: 100%; display: flex; flex-direction: column; align-items: center; justify-content: center; font-weight: bold; }
    .active a { color: #fff; }
    
    span { font-size: 12px; margin-top: 5px; opacity: 0.6; }
  </style>
</head>
<body>
  <h2>MAIN CONTROL</h2>
  
  <div class="grid">
    <div class="box active">
      <a href="/ble_app">SCAN<br>BLUETOOTH<span>(Click)</span></a>
    </div>
    
    <div class="box active"><a href="/wifi_app">SCAN<br>WIFI<span>(Click)</span></a></div>
    <div class="box active"><a href="/rom_app">ROM<br><span>(Files)</span></a></div>
    <div class="box active"><a href="/gatt_scan">GATT<br>DISCOVERY<span>(Analysis)</span></a></div>
    <div class="box active"><a href="/handshake">HANDSHAKE<br>SNIFFER<span>(Passive)</span></a></div>
    <div class="box active"><a href="/badusb_app">BAD USB<br><span>(Script & Format)</span></a></div>
  </div>
</body></html>
)rawliteral";

void handleRoot() {
  server.send(200, "text/html", index_html);
}

void randomizeMac() {
    uint8_t newMac[6];
    esp_fill_random(newMac, 6);
    
    // Unicast (b0=0) and Locally Administered (b1=1) setting
    // Example: First byte ending in x2, x6, xA, xE (Prevents OUI collision)
    newMac[0] = (newMac[0] & 0xFC) | 0x02;

    if (esp_base_mac_addr_set(newMac) == ESP_OK) {
        Serial.printf("New Base MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
            newMac[0], newMac[1], newMac[2], newMac[3], newMac[4], newMac[5]);
    }
}

void printResetReason() {
  esp_reset_reason_t reason = esp_reset_reason();
  Serial.print("BOOT REASON: ");
  switch (reason) {
    case ESP_RST_UNKNOWN:   Serial.println("UNKNOWN"); break;
    case ESP_RST_POWERON:   Serial.println("POWERON (Normal Boot)"); break;
    case ESP_RST_EXT:       Serial.println("EXT (Reset Pin)"); break;
    case ESP_RST_SW:        Serial.println("SW (Software Reset)"); break;
    case ESP_RST_PANIC:     Serial.println("PANIC (Crash/Exception)"); break;
    case ESP_RST_INT_WDT:   Serial.println("INT_WDT (Watchdog - Interrupt)"); break;
    case ESP_RST_TASK_WDT:  Serial.println("TASK_WDT (Watchdog - Task)"); break;
    case ESP_RST_WDT:       Serial.println("WDT (Other Watchdog)"); break;
    case ESP_RST_DEEPSLEEP: Serial.println("DEEPSLEEP (Wake from Deep Sleep)"); break;
    case ESP_RST_BROWNOUT:  Serial.println("BROWNOUT (Low Voltage)"); break;
    case ESP_RST_SDIO:      Serial.println("SDIO"); break;
    default:                Serial.println("OTHER"); break;
  }
}

void setup() {
  // Safe delay for USB to be recognized by computer
  delay(3000);

  Serial.begin(115200);
  Serial.setDebugOutput(true); // Show system error messages too
  delay(1000); // Short wait for Serial Monitor connection
  printResetReason(); // Print reset reason

  randomizeMac(); // Randomize device ID
  myBleScanner.init(&server);
  myRomManager.init(&server); // Start LittleFS and Setup Routes
  myGattDiscovery.init(&server);
  myPassiveHandshake.init(&server);
  myBadUsb.init(&server);

  WiFi.softAP(ssid, password);
  Serial.print("IP: "); Serial.println(WiFi.softAPIP());

  server.on("/", handleRoot);
  
  // Start WifiScanner
  myWifiScanner.init(&server);
  
  server.begin();
}

void loop() {
  server.handleClient();
  myWifiScanner.loop();
  myPassiveHandshake.loop();
  myBadUsb.loop();
  
  delay(2);
}
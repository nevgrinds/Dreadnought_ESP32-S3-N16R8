#ifndef GATT_DISCOVERY_H
#define GATT_DISCOVERY_H

#include <Arduino.h>
#include <NimBLEDevice.h>
#include <WebServer.h>

class GattDiscoveryModule {
public:
    void init(WebServer* server);
    String scanAndList();
    String connectAndAnalyze(String macStr, uint8_t type, bool isInjection = false);
    String writeCharacteristic(String mac, uint8_t type, String srvUuid, String chrUuid, String value, bool isHex);
    String subscribeCharacteristic(String mac, uint8_t type, String srvUuid, String chrUuid);
    void clearLog();

private:
    String propsToString(NimBLERemoteCharacteristic* pChar);
    String valueToString(std::string value);
    String injectionLog; // Gelen verileri tutacak kalici log
    
    NimBLEClient* pClient = nullptr; // Kalici Client Nesnesi
    String connectedMac = "";        // Bagli olunan MAC
    SemaphoreHandle_t logMutex = NULL; // Thread Safety icin Mutex
};

#endif
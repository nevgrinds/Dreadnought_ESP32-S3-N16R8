#ifndef BLESCANNER_H
#define BLESCANNER_H

#include <Arduino.h>
#include <NimBLEDevice.h> 
#include <map>
#include <vector>
#include <WebServer.h>

class BleScannerModule {
public:
    void init(WebServer* server); 
    String getAppPage();   // Hem Radar hem Listeyi içeren Ana Sayfa
    String getScanJSON();  // Arka plan verisi
    
    // Yardımcılar
    String getVendor(String mac);
    String stringToHex(std::string data);
    String getManufacturerName(uint16_t companyId);
    String appleSniffAction(bool keep = false);

private:
    std::map<std::string, String> appleSignatures; // Payload -> MAC Eşleşmesi
    std::map<String, String> sniffHistory; // Gecmis tarama sonuclari (MAC -> HTML Row)
};

#endif
#ifndef ROMMANAGER_H
#define ROMMANAGER_H

#include <Arduino.h>
#include <LittleFS.h>
#include <vector>
#include <WebServer.h>

class RomManagerModule {
public:
    void init(WebServer* server);
    String getAppPage();
    String getFileListJSON();
    String saveWifiScan(String json); // JSON verisini dosyaya kaydeder
    bool overwriteFile(String filename, String json); // Varolan dosyanin uzerine yazar
    bool deleteFile(String path);
    File getFile(String path);

private:
    String getNextFilename(String baseName, String extension);
    String formatBytes(size_t bytes);
};

#endif
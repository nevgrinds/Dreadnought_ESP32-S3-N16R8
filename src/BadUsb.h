#ifndef BADUSB_H
#define BADUSB_H

#include <Arduino.h>
#include <WebServer.h>

class BadUsbModule {
public:
    void init(WebServer* server);
    void loop();

private:
    WebServer* _server;
    String getAppPage();
};

#endif
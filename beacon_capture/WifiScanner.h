#ifndef WIFI_SCANNER_H
#define WIFI_SCANNER_H

#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"
#include "Config.h"
#include "BeaconParser.h"
#include "LogStorage.h"

void initialize_wifi();
void update_channel_hopping();

#endif

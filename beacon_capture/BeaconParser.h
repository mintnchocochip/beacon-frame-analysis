#ifndef BEACON_PARSER_H
#define BEACON_PARSER_H

#include <Arduino.h>
#include "Config.h"

// Parse beacon frame and print details to Serial
// Parse beacon frame and return CSV data string
String parse_beacon_frame(uint8_t *payload, const wifi_ieee80211_mac_hdr_t *hdr, int packet_len, int rssi, int channel);

#endif

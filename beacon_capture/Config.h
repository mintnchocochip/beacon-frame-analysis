#ifndef CONFIG_H
#define CONFIG_H

#include <Arduino.h>

// === CONFIGURATION SETTINGS ===

// File Format Selection
#define SAVE_AS_PCAP true
#define SAVE_AS_CSV  false

// Channel Hopping Settings
#define ENABLE_CHANNEL_HOPPING true
#define HOP_INTERVAL_MS 250   // Time to stay on each channel

// Status LED Settings
#define LED_PIN 2

// SD Card Pin Definitions
#define SD_CS_PIN 5
#define SD_MOSI_PIN 23
#define SD_MISO_PIN 19
#define SD_SCK_PIN 18

// Initial Channel
#define WIFI_CHANNEL 1

// File limits
#define MAX_FILE_SIZE (10 * 1024 * 1024)  // 10MB per file
#define BUFFER_SIZE 512

// ==========================================
// SHARED DATA STRUCTURES
// ==========================================

// IEEE 802.11 MAC Header
typedef struct {
  uint8_t frame_ctrl[2];
  uint8_t duration[2];
  uint8_t destination[6];
  uint8_t source[6];
  uint8_t bssid[6];
  uint8_t seq_ctrl[2];
} wifi_ieee80211_mac_hdr_t;

// IEEE 802.11 Packet
typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; // Network data after header
} wifi_ieee80211_packet_t;

// PCAP Global Header
typedef struct {
  uint32_t magic_number;   // 0xa1b2c3d4
  uint16_t version_major;  // 2
  uint16_t version_minor;  // 4
  int32_t  thiszone;       // GMT to local correction (0)
  uint32_t sigfigs;        // Accuracy of timestamps (0)
  uint32_t snaplen;        // Max length of captured packets (65535)
  uint32_t network;        // Data link type (127 = 802.11 Radio)
} pcap_hdr_t;

// PCAP Packet Header
typedef struct {
  uint32_t ts_sec;         // Timestamp seconds
  uint32_t ts_usec;        // Timestamp microseconds
  uint32_t incl_len;       // Number of octets saved in file
  uint32_t orig_len;       // Actual length of packet
} pcaprec_hdr_t;

#endif

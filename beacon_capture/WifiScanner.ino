#include "WifiScanner.h"

// Channel Hopping Globals
unsigned long lastHopTime = 0;
uint8_t currentChannel = WIFI_CHANNEL;

// Beacon frame parsing callback
void IRAM_ATTR wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  // Only process management frames
  if (type != WIFI_PKT_MGMT) {
    return;
  }

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  // Check if this is a beacon frame
  // Frame type: bits 2-3 = 00 (management), subtype: bits 4-7 = 1000 (beacon)
  // This gives us 0x80 in the first byte of frame_ctrl
  uint8_t frame_type = hdr->frame_ctrl[0];
  
  if (frame_type != 0x80) {
    return; // Not a beacon frame, skip
  }

  // This is a beacon frame! Extract information
  int rssi = ppkt->rx_ctrl.rssi;
  int channel = ppkt->rx_ctrl.channel;
  int packet_len = ppkt->rx_ctrl.sig_len;
  
  // Parse the beacon payload to extract SSID
  uint8_t *payload = (uint8_t *)ipkt->payload;
  
  // Skip fixed parameters (12 bytes: timestamp + interval + capabilities)
  uint8_t *ssid_ptr = payload + 12;
  
  char ssid[33] = {0}; // Max SSID length is 32 + null terminator
  
  if (ssid_ptr[0] == 0) { // Check if first tag is SSID
    uint8_t ssid_len = ssid_ptr[1];
    if (ssid_len > 0 && ssid_len <= 32) {
      memcpy(ssid, &ssid_ptr[2], ssid_len);
      ssid[ssid_len] = '\0';
    }
  }
  
  // Print the basic beacon frame information
  DEBUG_PRINTLN("========== BEACON FRAME ==========");
  DEBUG_PRINTF("SSID: %s\n", strlen(ssid) > 0 ? ssid : "<Hidden SSID>");
  DEBUG_PRINTF("BSSID: %02X:%02X:%02X:%02X:%02X:%02X\n",
                hdr->bssid[0], hdr->bssid[1], hdr->bssid[2],
                hdr->bssid[3], hdr->bssid[4], hdr->bssid[5]);
  DEBUG_PRINTF("Channel: %d\n", channel);
  DEBUG_PRINTF("RSSI: %d dBm\n", rssi);
  DEBUG_PRINTF("Capture Time: %lu ms\n", millis());
  
  // Parse detailed beacon information and get CSV string
  String csvData = parse_beacon_frame(payload, hdr, packet_len, rssi, channel);

  // Save parsed data/packet
  if (sdCardReady) {
    // Get pointer to the full 802.11 frame
    uint8_t *raw_frame = (uint8_t *)ppkt->payload;
    
    if (save_packet(raw_frame, packet_len, csvData)) {
      DEBUG_PRINTF("✓ Saved [Packet #%u, File: %s]\n", packetCount, filename);
      // Blink LED
      digitalWrite(LED_PIN, HIGH);
      delayMicroseconds(500); // Very short blink
      digitalWrite(LED_PIN, LOW);
      
      if (packetCount % 10 == 0) {
        DEBUG_PRINTF(">>> Captured: %u | Size: %.2f MB <<<\n", 
                      packetCount, currentFileSize / 1024.0 / 1024.0);
      }
    } else {
      DEBUG_PRINTLN("✗ Save Failed!");
    }
  }
  
  DEBUG_PRINTLN("==================================\n");
}

void initialize_wifi() {
  Serial.println("Initializing WiFi in promiscuous mode...");
  
  // Set WiFi mode to station (required before promiscuous mode)
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  delay(100);

  // Initialize WiFi with default configuration
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  
  // Set storage to RAM (we don't need to save WiFi config)
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  
  // Set WiFi mode to NULL (no station/AP, just monitor)
  esp_wifi_set_mode(WIFI_MODE_NULL);
  
  // Start WiFi
  esp_wifi_start();
  
  // Set channel to monitor
  esp_wifi_set_channel(WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE);
  
  // Set promiscuous mode callback
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
  
  // Enable promiscuous mode
  esp_wifi_set_promiscuous(true);
  
  Serial.printf("WiFi initialized. Monitoring channel %d\n", WIFI_CHANNEL);
  Serial.println("Capturing beacon frames only...\n");
}

void update_channel_hopping() {
  if (ENABLE_CHANNEL_HOPPING) {
    unsigned long currentMillis = millis();
    
    if (currentMillis - lastHopTime >= HOP_INTERVAL_MS) {
      lastHopTime = currentMillis;
      
      // Increment channel
      currentChannel++;
      if (currentChannel > 13) currentChannel = 1;
      
      // Switch channel
      esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    }
  }
}

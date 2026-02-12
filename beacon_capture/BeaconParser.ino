#include "BeaconParser.h"

String parse_beacon_frame(uint8_t *payload, const wifi_ieee80211_mac_hdr_t *hdr, int packet_len, int rssi, int channel) {
  String csvLine = "";
  
  // === FIXED PARAMETERS (First 12 bytes after MAC header) ===
  
  // 1. Timestamp (8 bytes)
  uint64_t timestamp = 0;
  memcpy(&timestamp, payload, 8);
  
  // 2. Beacon Interval (2 bytes at offset 8)
  uint16_t beacon_interval = 0;
  memcpy(&beacon_interval, payload + 8, 2);
  
  // 3. Capability Info (2 bytes at offset 10)
  uint16_t capability = 0;
  memcpy(&capability, payload + 10, 2);
  
  // Extract capability flags
  bool privacy = capability & 0x0010;  // Bit 4: Privacy (WEP/WPA)
  
  // 4. Sequence Number (from MAC header)
  uint16_t seq_ctrl = (hdr->seq_ctrl[1] << 8) | hdr->seq_ctrl[0];
  uint16_t seq_num = (seq_ctrl >> 4) & 0x0FFF;  // Bits 4-15
  
  // === TAGGED PARAMETERS (Information Elements) ===
  
  // Start after fixed parameters (12 bytes)
  uint8_t *tag_ptr = payload + 12;
  int remaining = packet_len - 24 - 12; // Total - MAC header - fixed params
  
  bool found_rates = false;
  bool found_rsn = false;
  bool found_vendor = false;
  char encryption[50] = "Open";
  if (privacy) strcpy(encryption, "WEP"); // Default if privacy set but no RSN/WPA IE
  
  int rate_count = 0;
  char ssid[33] = {0};

  // Extract SSID first (Tag 0)
  // Note: In typical calling structure, SSID is parsed in WifiScanner, but we can re-parse/verify or pass it in.
  // For now, let's parse it here to ensure it's in the CSV string regardless of caller's buffer.
  // The payload passed here STARTS at the Fixed Parameters.
  // Tag parsing loop will hit it.
  
  // Actually, wait, the payload passed to this function is the standard 802.11 payload
  // which starts with Fixed Parameters (timestamp, etc.)
  // THEN tags start.
  // SSID is usually the first tag (Tag 0).
  // Let's iterate properly.
  
  while (remaining > 2) {
    uint8_t tag_number = tag_ptr[0];
    uint8_t tag_length = tag_ptr[1];
    
    if (tag_length == 0 || tag_length > remaining - 2) {
      break; // Invalid tag
    }
    
    uint8_t *tag_data = &tag_ptr[2];
    
    // Tag 0: SSID
    if (tag_number == 0) {
        if (tag_length > 0 && tag_length <= 32) {
            memcpy(ssid, tag_data, tag_length);
            ssid[tag_length] = '\0';
        } else {
             strcpy(ssid, "<Hidden>");
        }
    }
    
    // Tag 1: Supported Rates
    if (tag_number == 1 && !found_rates) {
      found_rates = true;
      DEBUG_PRINT("Supported Rates: ");
      for (int i = 0; i < tag_length; i++) {
        float rate = (tag_data[i] & 0x7F) * 0.5; // Remove MSB, multiply by 0.5
        DEBUG_PRINTF("%.1f%s ", rate, (tag_data[i] & 0x80) ? "*" : "");
        rate_count++;
      }
      DEBUG_PRINTLN("Mbps (* = basic rate)");
    }
    
    // Tag 48: RSN Information (WPA2/WPA3)
    else if (tag_number == 48 && !found_rsn) {
      found_rsn = true;
      
      // RSN structure is complex, but we can identify WPA2/WPA3
      if (tag_length >= 2) {
        // Check for SAE (WPA3) in AKM suite
        bool is_wpa3 = false;
        if (tag_length >= 14) {
          // Simple check for SAE OUI (00-0F-AC:08)
          for (int i = 0; i < tag_length - 4; i++) {
            if (tag_data[i] == 0x00 && tag_data[i+1] == 0x0F && 
                tag_data[i+2] == 0xAC && tag_data[i+3] == 0x08) {
              is_wpa3 = true;
              break;
            }
          }
        }
        
        snprintf(encryption, sizeof(encryption), "%s", 
                 is_wpa3 ? "WPA3" : "WPA2");
      }
    }
    
    // Tag 221: Vendor Specific
    else if (tag_number == 221 && !found_vendor) {
      found_vendor = true;
      
      if (tag_length >= 4) {
        uint32_t vendor_oui = (tag_data[0] << 16) | (tag_data[1] << 8) | tag_data[2];
        uint8_t vendor_type = tag_data[3];
        
        DEBUG_PRINTF("Vendor Tag: OUI=%02X:%02X:%02X, Type=%02X\n",
                      tag_data[0], tag_data[1], tag_data[2], vendor_type);
        
        // Check for common vendor types
        if (vendor_oui == 0x0050F2 && vendor_type == 0x01) {
          // Microsoft WPA IE
          if (!found_rsn) {
            snprintf(encryption, sizeof(encryption), "WPA");
          }
        }
      }
    }
    
    // Move to next tag
    tag_ptr += (2 + tag_length);
    remaining -= (2 + tag_length);
  }
  
  DEBUG_PRINTF("Encryption Type: %s\n", encryption);
  
  // Construct CSV Line efficiently using snprintf
  // Header: Timestamp_ms,SSID,BSSID,RSSI,Channel,SequenceNumber,Encryption,RateCount,OUI,FrameLength
  
  char csvBuffer[512];
  snprintf(csvBuffer, sizeof(csvBuffer), 
           "%lu,%s,%02X:%02X:%02X:%02X:%02X:%02X,%d,%d,%d,%s,%d,%02X:%02X:%02X,%d\n",
           millis(),
           ssid,
           hdr->bssid[0], hdr->bssid[1], hdr->bssid[2], hdr->bssid[3], hdr->bssid[4], hdr->bssid[5],
           rssi,
           channel,
           seq_num,
           encryption,
           rate_count,
           hdr->bssid[0], hdr->bssid[1], hdr->bssid[2],
           packet_len
  );
  
  return String(csvBuffer);
}

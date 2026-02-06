#include "BeaconParser.h"

void parse_beacon_frame(uint8_t *payload, const wifi_ieee80211_mac_hdr_t *hdr, int packet_len) {
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
  bool privacy = capability & 0x0010;          // Bit 4: Privacy (WEP/WPA)
  bool short_preamble = capability & 0x0020;   // Bit 5: Short Preamble
  bool pbcc = capability & 0x0040;             // Bit 6: PBCC
  bool channel_agility = capability & 0x0080;  // Bit 7: Channel Agility
  bool spectrum_mgmt = capability & 0x0100;    // Bit 8: Spectrum Management
  bool qos = capability & 0x0200;              // Bit 9: QoS
  bool short_slot = capability & 0x0400;       // Bit 10: Short Slot Time
  bool apsd = capability & 0x0800;             // Bit 11: APSD
  bool radio_measurement = capability & 0x1000; // Bit 12: Radio Measurement
  
  // 4. Sequence Number (from MAC header)
  uint16_t seq_ctrl = (hdr->seq_ctrl[1] << 8) | hdr->seq_ctrl[0];
  uint16_t seq_num = (seq_ctrl >> 4) & 0x0FFF;  // Bits 4-15
  uint16_t frag_num = seq_ctrl & 0x000F;        // Bits 0-3
  
  // 5. OUI (Organizationally Unique Identifier - first 3 bytes of BSSID)
  uint32_t oui = (hdr->bssid[0] << 16) | (hdr->bssid[1] << 8) | hdr->bssid[2];
  
  // Print fixed parameters
  Serial.println("--- Fixed Parameters ---");
  Serial.printf("Beacon Interval: %d TU (%d ms)\n", 
                beacon_interval, (beacon_interval * 1024) / 1000);
  Serial.printf("Sequence Number: %d (Fragment: %d)\n", seq_num, frag_num);
  Serial.printf("OUI: %02X:%02X:%02X ", hdr->bssid[0], hdr->bssid[1], hdr->bssid[2]);
  
  // OUI vendor lookup (common ones)
  if (oui == 0x001018 || oui == 0x7C5049 || oui == 0x001CB3) Serial.print("(Broadcom)");
  else if (oui == 0xB0C090 || oui == 0xF46D04) Serial.print("(Realtek)");
  else if (oui == 0xDC9FDB || oui == 0x0023DF) Serial.print("(Ubiquiti)");
  else if (oui == 0x001DD8 || oui == 0x001E52) Serial.print("(Cisco)");
  else if (oui == 0x0050F2) Serial.print("(Microsoft)");
  else if (oui == 0x8C8590 || oui == 0x001FF3) Serial.print("(TP-Link)");
  else Serial.print("(Unknown)");
  Serial.println();
  
  // Print capability flags
  Serial.println("--- Capability Flags ---");
  Serial.printf("Privacy (Encryption): %s\n", privacy ? "Yes" : "No");
  Serial.printf("Spectrum Management: %s\n", spectrum_mgmt ? "Yes" : "No");
  Serial.printf("QoS: %s\n", qos ? "Yes" : "No");
  Serial.printf("Short Slot Time: %s\n", short_slot ? "Yes" : "No");
  
  // === TAGGED PARAMETERS (Information Elements) ===
  Serial.println("--- Tagged Parameters ---");
  
  // Start after fixed parameters (12 bytes)
  uint8_t *tag_ptr = payload + 12;
  int remaining = packet_len - 24 - 12; // Total - MAC header - fixed params
  
  bool found_rates = false;
  bool found_rsn = false;
  bool found_vendor = false;
  char encryption[50] = "Open";
  
  // Parse all tags
  while (remaining > 2) {
    uint8_t tag_number = tag_ptr[0];
    uint8_t tag_length = tag_ptr[1];
    
    if (tag_length == 0 || tag_length > remaining - 2) {
      break; // Invalid tag
    }
    
    uint8_t *tag_data = &tag_ptr[2];
    
    // Tag 1: Supported Rates
    if (tag_number == 1 && !found_rates) {
      found_rates = true;
      Serial.print("Supported Rates: ");
      for (int i = 0; i < tag_length; i++) {
        float rate = (tag_data[i] & 0x7F) * 0.5; // Remove MSB, multiply by 0.5
        Serial.printf("%.1f%s ", rate, (tag_data[i] & 0x80) ? "*" : "");
      }
      Serial.println("Mbps (* = basic rate)");
    }
    
    // Tag 48: RSN Information (WPA2/WPA3)
    else if (tag_number == 48 && !found_rsn) {
      found_rsn = true;
      
      // RSN structure is complex, but we can identify WPA2/WPA3
      if (tag_length >= 2) {
        uint16_t rsn_version = (tag_data[1] << 8) | tag_data[0];
        
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
                 is_wpa3 ? "WPA3-Personal" : "WPA2-Personal");
      }
    }
    
    // Tag 221: Vendor Specific
    else if (tag_number == 221 && !found_vendor) {
      found_vendor = true;
      
      if (tag_length >= 4) {
        uint32_t vendor_oui = (tag_data[0] << 16) | (tag_data[1] << 8) | tag_data[2];
        uint8_t vendor_type = tag_data[3];
        
        Serial.printf("Vendor Tag: OUI=%02X:%02X:%02X, Type=%02X\n",
                      tag_data[0], tag_data[1], tag_data[2], vendor_type);
        
        // Check for common vendor types
        if (vendor_oui == 0x0050F2 && vendor_type == 0x01) {
          // Microsoft WPA IE
          if (!found_rsn) {
            snprintf(encryption, sizeof(encryption), "WPA-Personal");
          }
        }
      }
    }
    
    // Move to next tag
    tag_ptr += (2 + tag_length);
    remaining -= (2 + tag_length);
  }
  
  Serial.printf("Encryption Type: %s\n", encryption);
}

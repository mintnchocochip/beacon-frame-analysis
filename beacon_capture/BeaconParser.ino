#include "BeaconParser.h"

String parse_beacon_frame(uint8_t *payload, const wifi_ieee80211_mac_hdr_t *hdr, int packet_len, int rssi, int channel) {
  // === FIXED PARAMETERS (First 12 bytes after MAC header) ===
  
  // 1. Timestamp (8 bytes)
  uint64_t beacon_timestamp = 0;
  memcpy(&beacon_timestamp, payload, 8);
  
  // 2. Beacon Interval (2 bytes at offset 8)
  uint16_t beacon_interval = 0;
  memcpy(&beacon_interval, payload + 8, 2);
  
  // 3. Capability Info (2 bytes at offset 10)
  uint16_t capability = 0;
  memcpy(&capability, payload + 10, 2);
  
  // Extract capability flags
  bool cap_privacy = capability & 0x0010;        // Bit 4: Privacy (WEP/WPA)
  bool cap_short_preamble = capability & 0x0020; // Bit 5: Short Preamble
  bool cap_short_slot = capability & 0x0400;     // Bit 10: Short Slot Time
  
  // 4. Sequence Number (from MAC header)
  uint16_t seq_ctrl = (hdr->seq_ctrl[1] << 8) | hdr->seq_ctrl[0];
  uint16_t seq_num = (seq_ctrl >> 4) & 0x0FFF;  // Bits 4-15
  
  // === TAGGED PARAMETERS (Information Elements) ===
  
  // Start after fixed parameters (12 bytes)
  uint8_t *tag_ptr = payload + 12;
  int remaining = packet_len - 24 - 12; // Total - MAC header - fixed params
  
  // Variables for extracted data
  char ssid[33] = {0};
  bool is_hidden = false;
  char encryption[50] = "Open";
  if (cap_privacy) strcpy(encryption, "WEP"); // Default if privacy set but no RSN/WPA IE
  
  // Supported Rates
  char supported_rates[128] = "";
  int rate_count = 0;
  
  // Extended Supported Rates
  int ext_rate_count = 0;
  
  // DS Parameter Set
  int ds_channel = 0;
  
  // Country Information
  char country_code[4] = "";
  
  // HT Capabilities (802.11n)
  bool has_ht = false;
  int ht_channel_width = 0;
  int ht_streams = 0;
  
  // Extended Capabilities
  bool has_ext_cap = false;
  
  // Vendor name lookup
  const char* vendor_name = "Unknown";
  
  // Parse all Information Elements
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
        is_hidden = false;
      } else {
        strcpy(ssid, "<Hidden>");
        is_hidden = true;
      }
    }
    
    // Tag 1: Supported Rates
    else if (tag_number == 1) {
      char rate_str[8];
      for (int i = 0; i < tag_length && i < 8; i++) {
        float rate = (tag_data[i] & 0x7F) * 0.5; // Remove MSB, multiply by 0.5
        snprintf(rate_str, sizeof(rate_str), "%.1f", rate);
        if (strlen(supported_rates) > 0) strcat(supported_rates, ";");
        strcat(supported_rates, rate_str);
        rate_count++;
      }
      DEBUG_PRINT("Supported Rates: ");
      DEBUG_PRINTLN(supported_rates);
    }
    
    // Tag 3: DS Parameter Set (Current Channel)
    else if (tag_number == 3 && tag_length >= 1) {
      ds_channel = tag_data[0];
      DEBUG_PRINTF("DS Channel: %d\n", ds_channel);
    }
    
    // Tag 7: Country Information
    else if (tag_number == 7 && tag_length >= 3) {
      country_code[0] = tag_data[0];
      country_code[1] = tag_data[1];
      country_code[2] = '\0';
      DEBUG_PRINTF("Country: %s\n", country_code);
    }
    
    // Tag 45: HT Capabilities (802.11n)
    else if (tag_number == 45 && tag_length >= 26) {
      has_ht = true;
      uint8_t ht_cap_info = tag_data[0];
      ht_channel_width = (ht_cap_info & 0x02) ? 40 : 20;
      
      // Parse MCS set to determine spatial streams
      // MCS set starts at offset 3, bytes 3-6
      uint8_t mcs_set[4];
      memcpy(mcs_set, tag_data + 3, 4);
      
      // Count spatial streams (simplified - check MCS 0-31)
      if (mcs_set[3] != 0) ht_streams = 4;
      else if (mcs_set[2] != 0) ht_streams = 3;
      else if (mcs_set[1] != 0) ht_streams = 2;
      else if (mcs_set[0] != 0) ht_streams = 1;
      
      DEBUG_PRINTF("HT: %dMHz, %d streams\n", ht_channel_width, ht_streams);
    }
    
    // Tag 48: RSN Information (WPA2/WPA3)
    else if (tag_number == 48) {
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
        snprintf(encryption, sizeof(encryption), "%s", is_wpa3 ? "WPA3" : "WPA2");
      }
    }
    
    // Tag 50: Extended Supported Rates
    else if (tag_number == 50) {
      char rate_str[8];
      for (int i = 0; i < tag_length && i < 8; i++) {
        float rate = (tag_data[i] & 0x7F) * 0.5;
        snprintf(rate_str, sizeof(rate_str), "%.1f", rate);
        if (strlen(supported_rates) > 0) strcat(supported_rates, ";");
        strcat(supported_rates, rate_str);
        ext_rate_count++;
      }
      DEBUG_PRINT("Extended Rates: ");
      DEBUG_PRINTLN(supported_rates);
    }
    
    // Tag 127: Extended Capabilities
    else if (tag_number == 127) {
      has_ext_cap = true;
      DEBUG_PRINTLN("Has Extended Capabilities");
    }
    
    // Tag 221: Vendor Specific
    else if (tag_number == 221 && tag_length >= 4) {
      uint32_t vendor_oui = (tag_data[0] << 16) | (tag_data[1] << 8) | tag_data[2];
      uint8_t vendor_type = tag_data[3];
      
      DEBUG_PRINTF("Vendor Tag: OUI=%02X:%02X:%02X, Type=%02X\n",
                    tag_data[0], tag_data[1], tag_data[2], vendor_type);
      
      // Check for Microsoft WPA IE
      if (vendor_oui == 0x0050F2 && vendor_type == 0x01) {
        if (strcmp(encryption, "Open") == 0 || strcmp(encryption, "WEP") == 0) {
          snprintf(encryption, sizeof(encryption), "WPA");
        }
      }
    }
    
    // Move to next tag
    tag_ptr += (2 + tag_length);
    remaining -= (2 + tag_length);
  }
  
  // Vendor name lookup from OUI
  uint32_t oui = (hdr->bssid[0] << 16) | (hdr->bssid[1] << 8) | hdr->bssid[2];
  
  // Common vendor OUIs
  if (oui == 0x001018 || oui == 0x00D0BC || oui == 0x001CF0) vendor_name = "Broadcom";
  else if (oui == 0x0050F2 || oui == 0x00155D) vendor_name = "Microsoft";
  else if (oui == 0x001B63 || oui == 0x001EC2) vendor_name = "Apple";
  else if (oui == 0x00037F || oui == 0x0004E2) vendor_name = "Atheros";
  else if (oui == 0x0024D7 || oui == 0x00259D) vendor_name = "Intel";
  else if (oui == 0x001DD8 || oui == 0x00248C) vendor_name = "Realtek";
  else if (oui == 0x00C0CA || oui == 0x001A70) vendor_name = "Ralink";
  else if (oui == 0x000C42 || oui == 0x0018E7) vendor_name = "Cisco";
  else if (oui == 0x001DE9 || oui == 0x001E52) vendor_name = "Netgear";
  else if (oui == 0x0014BF || oui == 0x001EA7) vendor_name = "D-Link";
  else if (oui == 0x00173F || oui == 0x001D7E) vendor_name = "Belkin";
  else if (oui == 0x000F66 || oui == 0x001B2F) vendor_name = "TP-Link";
  else if (oui == 0x001310 || oui == 0x002191) vendor_name = "Linksys";
  else if (oui == 0x000EA6 || oui == 0x001CDF) vendor_name = "Asus";
  
  DEBUG_PRINTF("Encryption: %s, Vendor: %s\n", encryption, vendor_name);
  
  // Construct CSV Line with all new features
  // Header: Timestamp_ms,SSID,BSSID,RSSI,Channel,SequenceNumber,BeaconInterval,BeaconTimestamp,
  //         Encryption,Privacy,ShortPreamble,ShortSlot,RateCount,SupportedRates,ExtRateCount,
  //         DSChannel,CountryCode,HasHT,HTChannelWidth,HTStreams,HasExtCap,OUI,VendorName,IsHidden,FrameLength
  
  char csvBuffer[768];
  snprintf(csvBuffer, sizeof(csvBuffer), 
           "%lu,%s,%02X:%02X:%02X:%02X:%02X:%02X,%d,%d,%d,%u,%llu,%s,%d,%d,%d,%d,%s,%d,%d,%s,%d,%d,%d,%d,%02X:%02X:%02X,%s,%d,%d\n",
           millis(),                    // Timestamp_ms
           ssid,                        // SSID
           hdr->bssid[0], hdr->bssid[1], hdr->bssid[2], 
           hdr->bssid[3], hdr->bssid[4], hdr->bssid[5],  // BSSID
           rssi,                        // RSSI
           channel,                     // Channel
           seq_num,                     // SequenceNumber
           beacon_interval,             // BeaconInterval
           beacon_timestamp,            // BeaconTimestamp
           encryption,                  // Encryption
           cap_privacy ? 1 : 0,         // Privacy
           cap_short_preamble ? 1 : 0,  // ShortPreamble
           cap_short_slot ? 1 : 0,      // ShortSlot
           rate_count,                  // RateCount
           supported_rates,             // SupportedRates
           ext_rate_count,              // ExtRateCount
           ds_channel,                  // DSChannel
           country_code,                // CountryCode
           has_ht ? 1 : 0,              // HasHT
           ht_channel_width,            // HTChannelWidth
           ht_streams,                  // HTStreams
           has_ext_cap ? 1 : 0,         // HasExtCap
           hdr->bssid[0], hdr->bssid[1], hdr->bssid[2],  // OUI
           vendor_name,                 // VendorName
           is_hidden ? 1 : 0,           // IsHidden
           packet_len                   // FrameLength
  );
  
  return String(csvBuffer);
}

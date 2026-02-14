#include "LogStorage.h"

// Globals
File captureFile;
uint32_t packetCount = 0;
uint32_t currentFileSize = 0;
uint8_t fileIndex = 0;
uint16_t sessionNumber = 1;
char filename[64];
char sessionFolder[48];
bool sdCardReady = false;

// Initialize SD card (ESP32-CAM uses SD_MMC, not SPI!)
bool initialize_sd_card() {
  Serial.println("Initializing SD card...");
  Serial.println("Using SD_MMC interface (ESP32-CAM built-in slot)");
  
  // ESP32-CAM uses SD_MMC in 1-bit mode
  // Pins are hardwired: CMD=15, CLK=14, DATA0=2
  // We don't need to specify pins - they're fixed in hardware
  
  // Try to initialize in 1-bit mode (more reliable than 4-bit for ESP32-CAM)
  if (!SD_MMC.begin("/sdcard", true)) {  // true = 1-bit mode
    Serial.println("ERROR: SD_MMC initialization failed in 1-bit mode!");
    Serial.println("Retrying with different settings...");
    delay(500);
    
    // Second attempt - try without mount point
    if (!SD_MMC.begin()) {
      Serial.println("ERROR: SD card initialization failed after retry!");
      Serial.println("Check:");
      Serial.println("  - SD card is inserted properly (push until it clicks)");
      Serial.println("  - Card is formatted as FAT32");
      Serial.println("  - Card is 32GB or smaller");
      Serial.println("  - Try a different SD card");
      Serial.println("  - Ensure good power supply (500mA+)");
      return false;
    }
  }
  
  // Check card type
  uint8_t cardType = SD_MMC.cardType();
  if (cardType == CARD_NONE) {
    Serial.println("ERROR: No SD card attached!");
    return false;
  }
  
  // Print card info
  Serial.print("SD Card Type: ");
  if (cardType == CARD_MMC) Serial.println("MMC");
  else if (cardType == CARD_SD) Serial.println("SDSC");
  else if (cardType == CARD_SDHC) Serial.println("SDHC");
  else Serial.println("UNKNOWN");
  
  uint64_t cardSize = SD_MMC.cardSize() / (1024 * 1024);
  Serial.printf("SD Card Size: %llu MB\n", cardSize);
  Serial.printf("Free Space: %llu MB\n", SD_MMC.totalBytes() / (1024 * 1024) - SD_MMC.usedBytes() / (1024 * 1024));
  
  Serial.println("SD card initialized successfully!");
  
  // Create base captures folder if it doesn't exist
  if (!SD_MMC.exists(CAPTURES_BASE_FOLDER)) {
    if (SD_MMC.mkdir(CAPTURES_BASE_FOLDER)) {
      Serial.printf("Created base folder: %s\n", CAPTURES_BASE_FOLDER);
    } else {
      Serial.println("WARNING: Failed to create base folder!");
    }
  }
  
  Serial.println();
  return true;
}

// Create a new session folder
bool create_session_folder() {
  // Find next available session number
  while (true) {
    snprintf(sessionFolder, sizeof(sessionFolder), "%s/session_%03d", CAPTURES_BASE_FOLDER, sessionNumber);
    if (!SD_MMC.exists(sessionFolder)) {
      break; // Found an unused session number
    }
    sessionNumber++;
    if (sessionNumber > 999) {
      Serial.println("ERROR: Maximum session number reached!");
      return false;
    }
  }
  
  // Create the session folder
  if (SD_MMC.mkdir(sessionFolder)) {
    Serial.printf("Created session folder: %s\n", sessionFolder);
    fileIndex = 0; // Reset file index for new session
    return true;
  } else {
    Serial.println("ERROR: Failed to create session folder!");
    return false;
  }
}

// Create a new Log file (PCAP or CSV)
bool create_log_file() {
  // Close previous file if open
  if (captureFile) {
    captureFile.close();
    Serial.printf("Closed previous file. Total packets: %u\n", packetCount);
  }
  
  // Generate filename with index based on format (inside session folder)
  if (SAVE_AS_PCAP) {
    snprintf(filename, sizeof(filename), "%s/beacon_%03d.pcap", sessionFolder, fileIndex);
  } else {
    snprintf(filename, sizeof(filename), "%s/beacon_%03d.csv", sessionFolder, fileIndex);
  }
  fileIndex++;
  
  Serial.printf("Creating new log file: %s\n", filename);
  
  // Open file for writing
  captureFile = SD_MMC.open(filename, FILE_WRITE);
  if (!captureFile) {
    Serial.println("ERROR: Failed to create log file!");
    return false;
  }
  
  currentFileSize = 0;
  
  // Write Header based on format
  if (SAVE_AS_PCAP) {
    // Write PCAP global header (24 bytes)
    pcap_hdr_t pcap_header;
    pcap_header.magic_number = 0xa1b2c3d4;
    pcap_header.version_major = 2;
    pcap_header.version_minor = 4;
    pcap_header.thiszone = 0;
    pcap_header.sigfigs = 0;
    pcap_header.snaplen = 65535;
    pcap_header.network = 127;  // 802.11 Radio
    
    size_t written = captureFile.write((uint8_t*)&pcap_header, sizeof(pcap_header));
    if (written != sizeof(pcap_header)) {
      Serial.println("ERROR: Failed to write PCAP header!");
      captureFile.close();
      return false;
    }
    currentFileSize += sizeof(pcap_header);
    
  } else if (SAVE_AS_CSV) {
    // Write CSV Header with all enhanced features
    String header = "Timestamp_ms,SSID,BSSID,RSSI,Channel,SequenceNumber,BeaconInterval,BeaconTimestamp,Encryption,Privacy,ShortPreamble,ShortSlot,RateCount,SupportedRates,ExtRateCount,DSChannel,CountryCode,HasHT,HTChannelWidth,HTStreams,HasExtCap,OUI,VendorName,IsHidden,FrameLength\n";
    size_t written = captureFile.print(header);
    if (written == 0) {
      Serial.println("ERROR: Failed to write CSV header!");
      captureFile.close();
      return false;
    }
    currentFileSize += header.length();
  }
  
  packetCount = 0;
  
  // Verify file is actually open
  if (!captureFile) {
    Serial.println("ERROR: File created but not open!");
    return false;
  }
  
  Serial.println("Log file created successfully.");
  Serial.printf("File status: %s, Size: %u bytes\n", 
                captureFile ? "OPEN" : "CLOSED", 
                currentFileSize);
  Serial.println();
  return true;
}

// Flush and close current file
void flush_and_close_file() {
  if (captureFile) {
    Serial.println("Flushing and closing current file...");
    captureFile.flush();
    captureFile.close();
    Serial.printf("File closed. Total packets captured: %u\n", packetCount);
    Serial.printf("File size: %.2f KB\n\n", currentFileSize / 1024.0);
  }
}

// Write a packet to PCAP file
bool write_pcap_packet(const uint8_t *packet_data, uint16_t packet_len) {
  pcaprec_hdr_t packet_header;
  uint32_t timestamp_ms = millis();
  
  packet_header.ts_sec = timestamp_ms / 1000;
  packet_header.ts_usec = (timestamp_ms % 1000) * 1000;
  packet_header.incl_len = packet_len;
  packet_header.orig_len = packet_len;
  
  size_t written = captureFile.write((uint8_t*)&packet_header, sizeof(packet_header));
  if (written != sizeof(packet_header)) return false;
  
  written = captureFile.write(packet_data, packet_len);
  return (written == packet_len);
}

// Write a packet to CSV file
bool write_csv_line(String csvLine) {
  size_t written = captureFile.print(csvLine);
  if (written > 0) {
    currentFileSize += written;
    return true;
  }
  return false;
}

// General write packet function
bool save_packet(const uint8_t *raw_packet, uint16_t packet_len, String csvData) {
  // Debug: Check SD card status
  if (!sdCardReady) {
    DEBUG_PRINTLN("ERROR: sdCardReady is false!");
    return false;
  }
  
  if (!captureFile) {
    DEBUG_PRINTLN("ERROR: captureFile is not open!");
    return false;
  }
  
  // Check max file size
  if (currentFileSize > MAX_FILE_SIZE) {
    Serial.println("Max file size reached. Rotating...");
    if (!create_log_file()) return false;
  }
  
  bool success = false;
  
  if (SAVE_AS_PCAP) {
    success = write_pcap_packet(raw_packet, packet_len);
    if (success) {
      currentFileSize += (16 + packet_len);
      DEBUG_PRINTLN("PCAP packet written successfully");
    } else {
      DEBUG_PRINTLN("ERROR: Failed to write PCAP packet!");
    }
    
  } else if (SAVE_AS_CSV) {
    success = write_csv_line(csvData);
    if (success) {
      DEBUG_PRINTLN("CSV line written successfully");
    } else {
      DEBUG_PRINTLN("ERROR: Failed to write CSV line!");
    }
  }
  
  if (success) {
    packetCount++;
    // Flush every 5 packets to ensure data is written to SD card (improved data integrity)
    if (packetCount % 5 == 0) {
      captureFile.flush();
      DEBUG_PRINTLN("File flushed to SD card");
    }
  }
  
  return success;
}

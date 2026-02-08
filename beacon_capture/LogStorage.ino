#include "LogStorage.h"

// Globals
File captureFile;
uint32_t packetCount = 0;
uint32_t currentFileSize = 0;
uint8_t fileIndex = 0;
char filename[32];
bool sdCardReady = false;

// Initialize SD card
bool initialize_sd_card() {
  Serial.println("Initializing SD card...");
  
  // Initialize SPI with custom pins
  SPI.begin(SD_SCK_PIN, SD_MISO_PIN, SD_MOSI_PIN, SD_CS_PIN);
  
  // Try to initialize SD card
  if (!SD.begin(SD_CS_PIN)) {
    Serial.println("ERROR: SD card initialization failed!");
    Serial.println("Check:");
    Serial.println("  - SD card is inserted");
    Serial.println("  - Card is formatted as FAT32");
    Serial.println("  - Wiring is correct");
    return false;
  }
  
  // Check card type
  uint8_t cardType = SD.cardType();
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
  
  uint64_t cardSize = SD.cardSize() / (1024 * 1024);
  Serial.printf("SD Card Size: %llu MB\n", cardSize);
  Serial.printf("Free Space: %llu MB\n", SD.totalBytes() / (1024 * 1024) - SD.usedBytes() / (1024 * 1024));
  
  Serial.println("SD card initialized successfully!\n");
  return true;
}

// Create a new Log file (PCAP or CSV)
bool create_log_file() {
  // Close previous file if open
  if (captureFile) {
    captureFile.close();
    Serial.printf("Closed previous file. Total packets: %u\n", packetCount);
  }
  
  // Generate filename with index based on format
  if (SAVE_AS_PCAP) {
    snprintf(filename, sizeof(filename), "/beacon_%03d.pcap", fileIndex);
  } else {
    snprintf(filename, sizeof(filename), "/beacon_%03d.csv", fileIndex);
  }
  fileIndex++;
  
  Serial.printf("Creating new log file: %s\n", filename);
  
  // Open file for writing
  captureFile = SD.open(filename, FILE_WRITE);
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
    // Write CSV Header
    String header = "Timestamp_ms,SSID,BSSID,RSSI,Channel,Length,OUI,Encryption\n";
    size_t written = captureFile.print(header);
    if (written == 0) {
      Serial.println("ERROR: Failed to write CSV header!");
      captureFile.close();
      return false;
    }
    currentFileSize += header.length();
  }
  
  packetCount = 0;
  Serial.println("Log file created successfully.\n");
  return true;
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
  if (!sdCardReady || !captureFile) return false;
  
  // Check max file size
  if (currentFileSize > MAX_FILE_SIZE) {
    Serial.println("Max file size reached. Rotating...");
    if (!create_log_file()) return false;
  }
  
  bool success = false;
  
  if (SAVE_AS_PCAP) {
    success = write_pcap_packet(raw_packet, packet_len);
    if (success) currentFileSize += (16 + packet_len);
    
  } else if (SAVE_AS_CSV) {
    success = write_csv_line(csvData);
  }
  
  if (success) {
    packetCount++;
    // Flush every 10 packets
    if (packetCount % 10 == 0) captureFile.flush();
  }
  
  return success;
}

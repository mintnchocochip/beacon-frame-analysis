#ifndef LOG_STORAGE_H
#define LOG_STORAGE_H

#include <Arduino.h>
#include <SD.h>
#include <SPI.h>
#include "Config.h"

// Global SD card status
extern bool sdCardReady;
extern uint32_t packetCount;
extern uint32_t currentFileSize;
extern char filename[32];

// Core functions
bool initialize_sd_card();
bool create_log_file();
bool save_packet(const uint8_t *raw_packet, uint16_t packet_len, String csvData);

#endif

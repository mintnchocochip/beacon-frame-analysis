#ifndef LOG_STORAGE_H
#define LOG_STORAGE_H

#include <Arduino.h>
#include <SD_MMC.h>
#include "Config.h"

// Global SD card status
extern bool sdCardReady;
extern File captureFile;
extern uint32_t packetCount;
extern uint32_t currentFileSize;
extern uint16_t sessionNumber;
extern char filename[64];
extern char sessionFolder[48];

// Core functions
bool initialize_sd_card();
bool create_session_folder();
bool create_log_file();
void flush_and_close_file();
bool save_packet(const uint8_t *raw_packet, uint16_t packet_len, String csvData);

#endif

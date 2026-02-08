#include "Config.h"
#include "LogStorage.h"
#include "WifiScanner.h"

void setup() {
  Serial.begin(115200);
  delay(1000); // Wait for serial to initialize
  
  Serial.println("\n\n╔════════════════════════════════════════╗");
  Serial.println("║  ESP32 Beacon Frame Capture (Modular) ║");
  Serial.println("╚════════════════════════════════════════╝\n");
  
  // Status LED
  pinMode(LED_PIN, OUTPUT);
  digitalWrite(LED_PIN, LOW);
  
  // Initialize SD card
  sdCardReady = initialize_sd_card();
  
  if (sdCardReady) {
    // Create initial Log file
    if (!create_log_file()) {
      Serial.println("ERROR: Failed to create log file!");
      Serial.println("Continuing without SD card storage...\n");
      sdCardReady = false;
    }
  } else {
    Serial.println("WARNING: Continuing without SD card storage.");
    Serial.println("Beacon frames will only be displayed on Serial Monitor.\n");
  }
  
  // Initialize WiFi in promiscuous mode
  initialize_wifi();
  
  Serial.println("════════════════════════════════════════");
  Serial.printf("System ready! [Format: %s] [Hopping: %s]\n", 
                SAVE_AS_PCAP ? "PCAP" : "CSV",
                ENABLE_CHANNEL_HOPPING ? "ON" : "OFF"); 
  Serial.println("════════════════════════════════════════\n");
}

void loop() {
  // Update channel hopping
  update_channel_hopping();
  
  // No delay needed here as we use millis logic inside update_channel_hopping
}
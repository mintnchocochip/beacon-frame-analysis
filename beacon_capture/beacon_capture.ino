#include "Config.h"
#include "LogStorage.h"
#include "WifiScanner.h"
#include "ButtonHandler.h"

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
    // Create session folder
    if (!create_session_folder()) {
      Serial.println("ERROR: Failed to create session folder!");
      Serial.println("Continuing without SD card storage...\n");
      sdCardReady = false;
    } else {
      // Create initial Log file
      if (!create_log_file()) {
        Serial.println("ERROR: Failed to create log file!");
        Serial.println("Continuing without SD card storage...\n");
        sdCardReady = false;
      }
    }
  } else {
    Serial.println("WARNING: Continuing without SD card storage.");
    Serial.println("Beacon frames will only be displayed on Serial Monitor.\n");
  }
  
  // Initialize reset button
  initialize_button();
  
  // Initialize WiFi in promiscuous mode
  initialize_wifi();
  
  Serial.println("════════════════════════════════════════");
  Serial.printf("System ready! [Session: %03d] [Format: %s] [Hopping: %s]\n", 
                sessionNumber,
                SAVE_AS_PCAP ? "PCAP" : "CSV",
                ENABLE_CHANNEL_HOPPING ? "ON" : "OFF"); 
  Serial.println("════════════════════════════════════════\n");
}

void loop() {
  // Check for reset button press
  check_reset_button();
  
  // Update channel hopping
  update_channel_hopping();
  
  // No delay needed here as we use millis logic inside functions
}
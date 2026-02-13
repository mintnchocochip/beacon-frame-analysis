#include "ButtonHandler.h"

// Button state variables
volatile bool resetRequested = false;
unsigned long lastButtonPress = 0;
bool lastButtonState = HIGH;

// ISR for button press (IRAM_ATTR for interrupt safety)
void IRAM_ATTR button_isr() {
  unsigned long currentTime = millis();
  
  // Debounce check
  if (currentTime - lastButtonPress > BUTTON_DEBOUNCE_MS) {
    resetRequested = true;
    lastButtonPress = currentTime;
  }
}

// Initialize the reset button
void initialize_button() {
  pinMode(RESET_BUTTON_PIN, INPUT_PULLUP);
  
  // Attach interrupt (FALLING edge since button pulls to GND when pressed)
  attachInterrupt(digitalPinToInterrupt(RESET_BUTTON_PIN), button_isr, FALLING);
  
  Serial.printf("Reset button initialized on GPIO %d\n", RESET_BUTTON_PIN);
  Serial.println("Press reset button to flush data and start new capture session.\n");
}

// Check if reset was requested and handle it
void check_reset_button() {
  if (resetRequested) {
    resetRequested = false; // Clear flag
    handle_reset();
  }
}

// Handle reset button press
void handle_reset() {
  Serial.println("\n╔════════════════════════════════════════╗");
  Serial.println("║       RESET BUTTON PRESSED!           ║");
  Serial.println("╚════════════════════════════════════════╝\n");
  
  // Visual feedback - fast LED blinks
  for (int i = 0; i < 3; i++) {
    digitalWrite(LED_PIN, HIGH);
    delay(100);
    digitalWrite(LED_PIN, LOW);
    delay(100);
  }
  
  // Flush and close current file
  flush_and_close_file();
  
  // Create new session folder
  sessionNumber++; // Increment to next session
  if (create_session_folder()) {
    // Create new log file in the new session
    if (create_log_file()) {
      Serial.println("════════════════════════════════════════");
      Serial.printf("New session started! [Session: %03d]\\n", sessionNumber);
      Serial.println("════════════════════════════════════════\n");
    } else {
      Serial.println("ERROR: Failed to create new log file!");
      sdCardReady = false;
    }
  } else {
    Serial.println("ERROR: Failed to create new session folder!");
    sdCardReady = false;
  }
}

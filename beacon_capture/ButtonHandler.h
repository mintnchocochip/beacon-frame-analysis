#ifndef BUTTON_HANDLER_H
#define BUTTON_HANDLER_H

#include <Arduino.h>
#include "Config.h"
#include "LogStorage.h"

// Button state
extern volatile bool resetRequested;

// Functions
void initialize_button();
void check_reset_button();
void handle_reset();

#endif

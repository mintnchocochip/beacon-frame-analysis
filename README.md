# ESP32 Beacon Frame Capture Guide

## Overview
This project turns an ESP32 into a powerful **Beacon Frame Scanner** for rogue AP detection. It captures 802.11 beacon frames and saves them to an SD card for analysis.

## Features
- **Promiscuous Mode Capture**: Intercepts beacon frames from all nearby APs.
- **Auto Channel Hopping**: Scans channels 1-13 automatically (250ms/channel).
- **Dual File Format**: Sames as **PCAP** (Wireshark) OR **CSV** (Excel).
- **Rich Data Extraction**: SSID, BSSID, RSSI, Channel, Encryption, OUI, Vendor info.
- **Visual Feedback**: LED blinks on every packet capture.
- **Robust Storage**: Automatic file rotation (10MB limit) and buffered writes.

## Hardware Setup
- **ESP32 Dev Board**
- **MicroSD Card Module** (SPI)
- **Status LED** (Built-in GPIO 2 or external)

| SD Pin | ESP32 Pin |
|--------|-----------|
| CS     | GPIO 5    |
| MOSI   | GPIO 23   |
| MISO   | GPIO 19   |
| SCK    | GPIO 18   |

## Configuration
Open `beacon_capture.ino` to change settings at the top:

```cpp
// Choose Output Format (True/False)
#define SAVE_AS_PCAP true   // Best for Wireshark / Deep Analysis
#define SAVE_AS_CSV  false  // Best for Excel / Simple ML

// Channel Hopping
#define ENABLE_CHANNEL_HOPPING true
#define HOP_INTERVAL_MS 250    // Scan speed

// Hardware
#define LED_PIN 2              // Status LED
```

## Output Formats

### 1. PCAP Format (`.pcap`)
- Standard network capture format.
- **Tools**: Wireshark, Tcpdump, Scapy (Python).
- **Contains**: Full raw 802.11 frames with Radiotap headers.
- **Best for**: Deep packet inspection, validating protocol anomalies.

### 2. CSV Format (`.csv`)
- Comma-Separated Values.
- **Tools**: Excel, Pandas (Python), MATLAB.
- **Columns**: `Timestamp_ms, SSID, BSSID, RSSI, Channel, Length, OUI, Encryption`
- **Best for**: Rapid statistical analysis, time-series plotting, basic ML models.

## Usage
1. **Insert SD Card** (FAT32 formatted).
2. **Power on ESP32**.
3. **LED will blink** as packets are captured.
4. **Files created**: `/beacon_000.pcap` or `/beacon_000.csv`.
5. **Retrieve files** and analyze!

## Troubleshooting
- **No SD Card?**: System works in "Live Monitor" mode (Serial output only).
- **LED not blinking?**: Check `LED_PIN` and ensure traffic exists.
- **Capture failed?**: Ensure SD card is FAT32 and under 32GB (standard limit for some libs).

## ML Data Preparation
For rogue AP detection, use the CSV output or extract features from PCAP:
- **Features**: Signal strength variance (RSSI), Beacon Interval consistency, OUI mismatches.
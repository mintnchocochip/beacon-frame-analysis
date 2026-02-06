# PCAP File Storage Guide

## Overview
Your ESP32 beacon frame capture now saves data in **PCAP format**, which can be opened directly in **Wireshark** for analysis.

## Hardware Setup

### SD Card Module Wiring
Connect your SD card module to the ESP32:

| SD Card Pin | ESP32 Pin |
|-------------|-----------|
| CS (Chip Select) | GPIO 5 |
| MOSI | GPIO 23 |
| MISO | GPIO 19 |
| SCK (Clock) | GPIO 18 |
| VCC | 3.3V |
| GND | GND |

**⚠️ Important Notes:**
- Use **3.3V** power, NOT 5V (can damage the SD card)
- Format your SD card as **FAT32** before use
- Use a quality SD card (Class 10 or higher recommended)
- Keep wiring short to avoid signal issues

## SD Card Preparation

1. **Format the SD card:**
   - Windows: Right-click → Format → FAT32
   - Mac: Disk Utility → Erase → MS-DOS (FAT)
   - Linux: `sudo mkfs.vfat -F 32 /dev/sdX1`

2. **Insert into SD card module**

3. **Upload the code to ESP32**

## File Format

### PCAP Structure
The code creates standard PCAP files with:
- **Global Header:** 24 bytes (written once per file)
  - Magic number: `0xa1b2c3d4`
  - Version: 2.4
  - Link type: 127 (IEEE 802.11 Radio)
  
- **Packet Header:** 16 bytes per packet
  - Timestamp (seconds + microseconds)
  - Packet length
  
- **Packet Data:** Raw 802.11 beacon frame

### File Naming Convention
Files are automatically created with incremental naming:
```
/beacon_000.pcap
/beacon_001.pcap
/beacon_002.pcap
...
```

### File Rotation
- **Max file size:** 10 MB per file
- Files automatically rotate when limit is reached
- Prevents SD card corruption from large files

## Usage

### 1. Upload and Monitor
```arduino
1. Upload code to ESP32
2. Open Serial Monitor at 115200 baud
3. Watch for initialization messages
```

### Expected Serial Output
```
╔════════════════════════════════════════╗
║  ESP32 Beacon Frame Capture (PCAP)    ║
╚════════════════════════════════════════╝

Initializing SD card...
SD Card Type: SDHC
SD Card Size: 8192 MB
Free Space: 8100 MB
SD card initialized successfully!

Creating new PCAP file: /beacon_000.pcap
PCAP file created successfully. Header size: 24 bytes

Initializing WiFi in promiscuous mode...
WiFi initialized. Monitoring channel 1
Capturing beacon frames only...

════════════════════════════════════════
System ready! Capturing beacon frames...
════════════════════════════════════════
```

### 2. Capture Data
Let it run to collect beacon frames. You'll see:
```
========== BEACON FRAME ==========
SSID: MyWiFiNetwork
BSSID: AA:BB:CC:DD:EE:FF
Channel: 6
RSSI: -45 dBm
...
✓ Saved to PCAP [Packet #15, File: /beacon_000.pcap]

>>> Progress: 20 beacon frames captured <<<
>>> File size: 4096 bytes (0.00 MB) <<<
```

### 3. Retrieve PCAP Files
1. **Remove SD card** from ESP32 (power off first!)
2. **Insert into computer**
3. **Copy `.pcap` files** to your computer

## Opening PCAP Files in Wireshark

### Install Wireshark
- **Windows/Mac:** Download from https://www.wireshark.org/
- **Linux:** `sudo apt install wireshark`

### Open Your Capture
1. **Launch Wireshark**
2. **File → Open** → Select `beacon_000.pcap`
3. **View beacon frames!**

### Useful Wireshark Filters

#### Display Only Beacon Frames
```
wlan.fc.type_subtype == 0x08
```

#### Filter by SSID
```
wlan.ssid == "MyNetworkName"
```

#### Filter by BSSID (MAC address)
```
wlan.bssid == aa:bb:cc:dd:ee:ff
```

#### Find Specific Vendor (by OUI)
```
wlan.bssid[0:3] == 00:50:f2
```

#### Show Only Encrypted Networks
```
wlan.fc.protected == 1
```

### Wireshark Analysis Tips

1. **Statistics → Protocol Hierarchy**
   - See breakdown of frame types

2. **Statistics → WLAN Traffic**
   - See all detected access points

3. **Export Specific Packets**
   - File → Export Specified Packets

4. **Save Filtered View**
   - File → Export Packet Dissections → As CSV

## Troubleshooting

### SD Card Not Detected
```
ERROR: SD card initialization failed!
```
**Solutions:**
- Check wiring (especially CS, MOSI, MISO, SCK)
- Ensure 3.3V power (NOT 5V)
- Verify card is inserted correctly
- Try different SD card
- Format as FAT32

### Failed to Create PCAP File
```
ERROR: Failed to create PCAP file!
```
**Solutions:**
- SD card might be full
- SD card might be write-protected
- File system corruption - reformat card
- Check SD card is properly initialized

### No Beacon Frames Captured
**Solutions:**
- Check WiFi channel (change `WIFI_CHANNEL` define)
- Ensure there are WiFi APs nearby
- Try different channels (1-13)
- Check promiscuous mode is enabled

## Configuration Options

### Change WiFi Channel
```cpp
#define WIFI_CHANNEL 6  // Change to 1-13
```

### Modify Max File Size
```cpp
#define MAX_FILE_SIZE (10 * 1024 * 1024)  // 10 MB
// Change to e.g., 5 MB:
#define MAX_FILE_SIZE (5 * 1024 * 1024)
```

### Adjust SD Card Pins
If using different GPIO pins:
```cpp
#define SD_CS_PIN 5
#define SD_MOSI_PIN 23
#define SD_MISO_PIN 19
#define SD_SCK_PIN 18
```

## Data Analysis for ML

### Export to CSV from Wireshark
1. Open PCAP in Wireshark
2. **File → Export Packet Dissections → As CSV**
3. Select fields to export:
   - Frame time
   - SSID (wlan.ssid)
   - BSSID (wlan.bssid)
   - Signal strength (radiotap.dbm_antsignal)
   - Channel (wlan_radio.channel)
   - Encryption (wlan.fc.protected)

### Python Analysis with Scapy
```python
from scapy.all import *

# Read PCAP file
packets = rdpcap('beacon_000.pcap')

# Extract beacon frames
beacons = []
for pkt in packets:
    if pkt.haslayer(Dot11Beacon):
        ssid = pkt[Dot11Elt].info.decode()
        bssid = pkt[Dot11].addr3
        beacons.append({'ssid': ssid, 'bssid': bssid})

# Create DataFrame for ML
import pandas as pd
df = pd.DataFrame(beacons)
```

## Performance Notes

- **Write buffering:** Packets are flushed every 10 frames for data safety
- **Memory usage:** Minimal - packets written immediately
- **Speed:** Can capture hundreds of beacons per second
- **Storage:** ~300-500 bytes per beacon frame

## Next Steps

1. ✅ Capture beacon frames to PCAP
2. 📝 Implement channel hopping (scan all channels)
3. 📝 Add deduplication (avoid duplicate APs)
4. 📝 Create CSV export option
5. 📝 Add real-time statistics
6. 📝 Implement MAC address filtering

## Support

If you encounter issues:
1. Check Serial Monitor at 115200 baud for error messages
2. Verify SD card is properly formatted (FAT32)
3. Ensure correct wiring (especially 3.3V power)
4. Try a different SD card if problems persist

# Rogue AP Generator Deployment

## 1. Transfer to Raspberry Pi
Copy this entire folder to your Raspberry Pi:
```bash
scp -r rogue_ap_generator pi@<your-pi-ip>:~/
```

## 2. Setup Dependencies
SSH into your Pi and run:
```bash
cd ~/rogue_ap_generator
sudo apt-get update
sudo apt-get install python3-pip iw -y
sudo pip3 install -r requirements.txt
```

## 3. Enable Monitor Mode
**Important**: Your Wi-Fi chip must support monitor mode.
```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

## 4. Run the Generator
Run with sudo (required for raw socket access):
```bash
sudo python3 rogue_gen.py
```
Or specify interface if different:
```bash
sudo python3 rogue_gen.py -i wlan1
```

## 5. Dataset Labeling Guide
- **Evil Twin**: The script uses BSSID `10:27:F5:5C:C6:B4` by default. Mark any rows with this BSSID as `1` (Rogue).
- **Downgrade**: Look for your SSID ("Satz") with `Encryption=Open`. Mark as `1`.
- **Flood**: Mark any SSID starting with "FreeWiFi_" as `1`.

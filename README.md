
# Wi-Fi Security Assessment Tool

A Python-based ethical hacking tool for scanning Wi-Fi networks and testing WPA/WPA2 password strength. Developed as part of the *Ethical Hacking and Cyber Security* module.

## Features
- **Wi-Fi Scanner** – Detects nearby access points and extracts:
  - SSID (network name)
  - BSSID (MAC address)
  - Signal strength (dBm)
  - Encryption type (WPA2, WEP, Open, etc.)
- **Password Cracker** – Dictionary attack against WPA/WPA2 handshakes using `aircrack-ng`.

## Requirements
- Linux (tested on Kali Linux)
- Python 3.6+
- Wireless adapter supporting **monitor mode** and **packet injection**
- Root privileges

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/wifi-security-tool.git
   cd wifi-security-tool

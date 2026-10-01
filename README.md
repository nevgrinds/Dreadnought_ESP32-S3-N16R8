<div align="center">
  <img width="297" height="293" alt="Ekran görüntüsü 2026-10-01 172005 (1)_cleaned" src="https://github.com/user-attachments/assets/d28183f8-9812-48e9-9f02-4c693ec69176" />
</div>
#  ESP32-S3 Dreadnought

> **All-in-One Security Tool**

This project transforms an ESP32-S3-N16R8 into a powerful, standalone pentesting and monitoring toolkit. 
This project is a comprehensive, multi-functional toolkit designed for wireless reconnaissance, security testing, and hardware emulation. It equips users with advanced BLE scanning and GATT manipulation, passive Wi-Fi tracking and WPA/WPA2 handshake capture, and optimized BadUSB (HID & MSC) payload execution. Backed by web-based file management, it provides a powerful environment for authorized penetration testing.


**Disclaimer:** Before using this tool, please read the [Legal Disclaimer](#legal-disclaimer) at the bottom of this page.

---

### Educational Objectives
This firmware is designed to demonstrate core cybersecurity fundamentals in action. Through hands-on exploration, it helps answer:

* **Why a strong Wi-Fi password is your first line of defense?**
* **Why unattended devices must always be locked?** 
* **How much data you unintentionally broadcast?**
* **How your physical presence leaks into the air?**
* **Why unencrypted protocols are obsolete?**
* **Why device fingerprinting matters?**



---

##  Hardware Requirements
* **Board:** ESP32-S3-N16R8
* *Note: PSRAM is heavily utilized for the high-performance RAM Disk.*

---

##  Default Credentials
Connect to the device's SoftAP to access the WebUI:

| Key | Value |
| :--- | :--- |
| **SSID** | `Dreadnought_2.4GHz` |
| **Password** | `ananas123` |
| **Gateway/IP** | `192.168.4.1` |

---

##  Key Modules & Features

###  BLE Scanner & Apple Sniff
* **Visual Radar Interface:** Real-time UI for mapping nearby BLE devices.
* **Vendor Identification:** Accurately detects Apple, Samsung, Microsoft, and more.
* **Apple Sniff Mode:** Decodes raw Manufacturer Data to identify specific Apple ecosystem devices (AirPods Gen 1-3/Pro/Max, AirTags).
* Displays real-time battery status (L/R/Case) and lid state.

###  GATT Explorer
* **Deep Device Inspection:** Connects to BLE devices to list out Services and Characteristics.
* **Interactivity:** Full Read/Write/Notify support in both Hex and Text formats.
* **Injection Mode:** Built-in tool for testing vulnerabilities by injecting arbitrary data into characteristics.

###  Wi-Fi Sentinel (Passive Tracker)
* **Promiscuous Mode Tracking:** Tracks Wi-Fi devices in the vicinity without connecting to any network.
* **Behavioral Classification:** Categorizes devices (Fixed, Moving, AP, Phone, IoT) based on RSSI variance and movement patterns.
* **Experimental Trilateration:** Cutting-edge mapping feature to estimate device locations.
* **Data Logging:** Automatically saves tracked data to `kayitlar.csv` inside internal storage.

###  Passive Handshake Sniffer
* **EAPOL Capture:** Passively captures WPA/WPA2 handshakes from target networks.
* **Frame Detection:** Automatically detects M1, M2, M3, and M4 EAPOL frames.
* **.pcap Export:** Saves captures to LittleFS in standard `.pcap` format, fully compatible with Wireshark and Hashcat.

###  BadUSB (HID + MSC)
* **HID Emulation:** Executes "Rubber Ducky" style payloads stored directly in the flash memory (You need your text file to script!).
* Supports multi-language layouts (TR/EN) and human-like typing simulation to bypass basic heuristics.
* **MSC (Mass Storage):** Emulates a standard USB drive.
* Uses a highly optimized **RAM Disk (PSRAM)** backed by a Flash partition (`ffat`) for high-speed I/O and to prevent flash wear/lag.

###  System Managers
* **ROM Manager:** A comprehensive web-based file manager (Upload / Download / Delete / View) for easily handling logs, scripts, and captures.
* **Stealth Mode:** Automatically randomizes the device MAC address on every boot to prevent tracking and ensure anonymity.

### Screenshot From Firmware
<div align="center">


  <img width="529" height="446" alt="Ekran görüntüsü 2026-10-01 172025_cleaned" src="https://github.com/user-attachments/assets/0ec6882d-73c8-47da-b272-5be9be3ad019" />
  <br><br>
  
  <img width="365" height="341" alt="Ekran görüntüsü 2026-10-01 172316_cleaned" src="https://github.com/user-attachments/assets/bfb9ee68-c826-45fe-8288-f57aac0b563b" />
  <br><br>
  
  <img width="525" height="434" alt="Ekran görüntüsü 2026-10-01 171841_cleaned" src="https://github.com/user-attachments/assets/76e6c6d0-ef83-44b4-a335-24b4683b2bde" />
  <br><br>
  
  <img width="943" height="452" alt="Ekran görüntüsü 2026-10-01 171938 (1)_cleaned" src="https://github.com/user-attachments/assets/40764427-1fa5-4b2b-b8d5-4244f77313fb" />
  <br><br>
  
  <img width="525" height="434" alt="Ekran görüntüsü 2026-10-01 171841_cleaned" src="https://github.com/user-attachments/assets/b2382008-613d-4076-abcd-f0b14fa3e435" />

</div>







---

## 📥 Installation (Flashing the Firmware)
You can easily flash the firmware directly from your browser (Chrome/Edge) without installing any software:
1. Go to [Spacehuhn's ESP Web Tool](https://esptool.spacehuhn.com/).
2. Connect your ESP32-S3-N16R8 via USB and click **Connect**.
3. Add the 4 release binaries and type in their exact offsets (listed below).
4. Click **Program** and wait for the process to finish!
  
To install Dreadnought on your ESP32-S3-N16R8 offline, download the latest release binaries and flash them to the exact offsets below using `esptool.py` or the Espressif Flash Download Tool:

* `0x0000`  -> `bootloader.bin`
* `0x8000`  -> `partitions.bin`
* `0xE000`  -> `boot_app0.bin`
* `0x10000` -> `firmware.bin`

*(If you are compiling from source using PlatformIO, standard build tasks apply).*

---

##  Legal Disclaimer

Usage of the **Dreadnought** firmware and its modules (including but not limited to BadUSB payloads, Wi-Fi sniffing, and BLE injection) for attacking infrastructures, tracking individuals, or accessing networks without prior mutual consent is strictly illegal. 

This firmware is provided **"as is"**, purely for educational purposes, academic research, and authorized security auditing.

It is the end user's absolute responsibility to obey all applicable local, state, and federal laws. The author(s) and contributor(s) of this project assume **no liability** and are not responsible for any misuse, damage, or legal consequences caused by the utilization of this hardware/software. By downloading, compiling, or flashing this project, you agree to this disclaimer.

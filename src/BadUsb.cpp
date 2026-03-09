#include "BadUsb.h"
#include "esp_partition.h"
#include "USB.h"
#include "USBMSC.h"
#include "USBHID.h"
#include "USBHIDKeyboard.h"
#include "esp_vfs_fat.h"
#include <dirent.h>
#include <sys/stat.h>
#include <esp_task_wdt.h> // Added for Watchdog control
#include <esp_heap_caps.h> // For PSRAM control
#include <LittleFS.h> // Added for reading script from internal storage

// It works, do not touch anything!!!

// --- USB MSC OBJECTS AND VARIABLES ---
static USBMSC msc;
static USBHIDKeyboard Keyboard;
static const esp_partition_t* ffat_part = NULL;

// --- RAM DISK (PSRAM) VARIABLES ---
// Since Flash write operations are slow enough to break USB connection
// We load the entire disk into PSRAM (N16R8 model has 8MB PSRAM).
static uint8_t* ram_disk = NULL;      // Copy of the disk in RAM
static bool* dirty_sectors = NULL;    // Map keeping track of modified sectors
static uint32_t disk_size = 0;
static uint32_t total_sectors = 0;
static bool use_ram_disk = false;

// Old Cache variables (Can remain as fallback if no PSRAM, but RAM Disk is priority here)

// Function that writes cached data permanently to Flash
static void flushDiskCache() {
    // In RAM Disk mode, this function is not called manually, it is done automatically in loop().
    // However, for Format operation, we can clear all dirty flags.
    if (use_ram_disk && dirty_sectors) {
        memset(dirty_sectors, 0, total_sectors * sizeof(bool));
    }
}

// --- BACKGROUND WRITE OPERATION (STATIC) ---
// This function is called both inside loop() and during long wait times.
static void processBackgroundWrite() {
    if (use_ram_disk && dirty_sectors) {
        for (uint32_t i = 0; i < total_sectors; i++) {
            if (dirty_sectors[i]) {
                uint32_t addr = i * 4096;
                esp_partition_erase_range(ffat_part, addr, 4096);
                esp_partition_write(ffat_part, addr, ram_disk + addr, 4096);
                dirty_sectors[i] = false;
                break; // Write only 1 sector per call (Prevent freezing)
            }
        }
    }
}

// --- USB MSC CALLBACKS ---
// Handles Windows disk read request
static int32_t mscRead(uint32_t lba, uint32_t offset, void* buffer, uint32_t bufsize) {
    if (!ffat_part) return -1;
    uint32_t addr = lba * 512 + offset;

    // If RAM Disk is active, read directly from RAM (Very fast)
    if (use_ram_disk && ram_disk) {
        if (addr + bufsize > disk_size) return -1;
        memcpy(buffer, ram_disk + addr, bufsize);
        return bufsize;
    }
    
    // If no PSRAM, read from Flash (Slow)
    uint32_t bytes_read = 0;
    uint8_t* buf_ptr = (uint8_t*)buffer;

    while (bytes_read < bufsize) {
        uint32_t current_addr = addr + bytes_read;
        uint32_t sector_offset = current_addr % 4096;
        uint32_t bytes_to_read = 4096 - sector_offset;
        
        if (bytes_to_read > (bufsize - bytes_read)) {
            bytes_to_read = bufsize - bytes_read;
        }

        esp_partition_read(ffat_part, current_addr, buf_ptr + bytes_read, bytes_to_read);
        bytes_read += bytes_to_read;
    }
    return bufsize;
}

// Handles Windows disk write request (Boundary check protected)
static int32_t mscWrite(uint32_t lba, uint32_t offset, uint8_t* buffer, uint32_t bufsize) {
    if (!ffat_part) return -1;
    uint32_t addr = lba * 512 + offset;

    // If RAM Disk is active, write to RAM and mark as "Dirty"
    if (use_ram_disk && ram_disk) {
        if (addr + bufsize > disk_size) return -1;
        
        // Copy data to RAM
        memcpy(ram_disk + addr, buffer, bufsize);
        
        // Mark affected sectors (4KB sectors)
        uint32_t start_sector = addr / 4096;
        uint32_t end_sector = (addr + bufsize - 1) / 4096;
        
        for(uint32_t i = start_sector; i <= end_sector; i++) {
            if(i < total_sectors) dirty_sectors[i] = true;
        }
        return bufsize;
    }
    
    // Old method if no PSRAM (This part might be causing errors due to slowness)
    uint32_t bytes_written = 0;
    
    while (bytes_written < bufsize) {
        uint32_t current_addr = addr + bytes_written;
        // Fallback: Direct write (Very slow and risky)
        // This only runs if PSRAM init fails.
        return -1; // Safer to return error
    }
    return bufsize;
}

// --- KLAVYE (HID) FONKSIYONLARI ---

// TR-Q Klavye Cevirici (US Keycode -> TR Char Mapping)
static void typeKeyTR(char c) {
    // Bu fonksiyon, istenen karakteri (c) yazmak icin
    // TR klavyesinde hangi tusa (US layout karsiligi) basilmasi gerektigini bulur.
    
    switch(c) {
        // --- Requires AltGr ---
        case '$': Keyboard.press(KEY_RIGHT_ALT); Keyboard.write('4'); Keyboard.releaseAll(); break;
        case '\\': Keyboard.press(KEY_RIGHT_ALT); Keyboard.write('-'); Keyboard.releaseAll(); break; // US - key -> TR * -> AltGr+\ 
        case '|': Keyboard.press(KEY_RIGHT_ALT); Keyboard.write('='); Keyboard.releaseAll(); break;  // US = key -> TR - -> AltGr+|
        case '{': Keyboard.press(KEY_RIGHT_ALT); Keyboard.write('7'); Keyboard.releaseAll(); break;
        case '[': Keyboard.press(KEY_RIGHT_ALT); Keyboard.write('8'); Keyboard.releaseAll(); break;
        case ']': Keyboard.press(KEY_RIGHT_ALT); Keyboard.write('9'); Keyboard.releaseAll(); break;
        case '}': Keyboard.press(KEY_RIGHT_ALT); Keyboard.write('0'); Keyboard.releaseAll(); break;
        case '@': Keyboard.press(KEY_RIGHT_ALT); Keyboard.write('q'); Keyboard.releaseAll(); break;

        // --- Letter and Symbol Conversions ---
        case 'i': Keyboard.write('\''); break; // US ' key -> TR i
        case 'I': Keyboard.print("I"); break;  // US I key (Shift+i) -> TR I (Shift+ı). (Direct I works)
        case '\'': Keyboard.print('@'); break; // US @ (Shift+2) -> TR ' (Shift+2)
        case '.': Keyboard.write('/'); break;  // US / key -> TR .
        case ',': Keyboard.write('\\'); break; // US \ key -> TR ,
        case ':': Keyboard.print('?'); break;  // US ? (Shift+/) -> TR : (Shift+.)
        case ';': Keyboard.print('|'); break;  // US | (Shift+\) -> TR ; (Shift+,)
        case '-': Keyboard.write('='); break;  // US = key -> TR -
        case '_': Keyboard.print('+'); break;  // US + (Shift+=) -> TR _ (Shift+-)
        case '*': Keyboard.write('-'); break;  // US - key -> TR *
        case '?': Keyboard.print('_'); break;  // US _ (Shift+-) -> TR ? (Shift+*)
        case '=': Keyboard.print(')'); break;  // US ) (Shift+0) -> TR = (Shift+0)
        case '(': Keyboard.print('*'); break;  // US * (Shift+8) -> TR ( (Shift+8)
        case ')': Keyboard.print('('); break;  // US ( (Shift+9) -> TR ) (Shift+9)
        case '&': Keyboard.print('^'); break;  // US ^ (Shift+6) -> TR & (Shift+6)
        case '%': Keyboard.print("%"); break;  // Shift+5 -> % Same
        case '+': Keyboard.print('$'); break;  // US $ (Shift+4) -> TR + (Shift+4)
        case '"': Keyboard.write('`'); break;  // US ` (Tilde key) -> TR "
        case '/': Keyboard.print('&'); break;  // US & (Shift+7) -> TR / (Shift+7)
        
        default: Keyboard.print(c); break;
    }
}

// US Keyboard (Standard)
static void typeKeyEN(char c) {
    // TinyUSB's Keyboard.print() function is based on US layout.
    // Therefore, no special conversion is needed, it prints most characters directly.
    Keyboard.print(c);
}

// Human-like typing function (Makes mistakes, deletes, varies speed)
static void typeHuman(String text, String lang, bool allowMistakes = true) {
    for (int i = 0; i < text.length(); i++) {
        // ADDED: Prevents Watchdog from kicking in and freezing the device on long lines (like foreach loops).
        esp_task_wdt_reset();

        // 5% chance to press wrong key and delete (Only if allowed)
        if (allowMistakes && random(0, 100) < 1) { // Error rate reduced
            char wrongChar = text[i] + 1; // Wrong character
            // Write the wrong character with correct mapping too
            if (lang == "tr") typeKeyTR(wrongChar);
            else typeKeyEN(wrongChar);

            delay(random(150, 400)); // Error realization time (Human reaction)
            Keyboard.write(KEY_BACKSPACE);
            delay(random(100, 250)); // Correction time
        }
        
        // Write according to selected language
        if (lang == "tr") {
            typeKeyTR(text[i]);
        } else {
            typeKeyEN(text[i]);
        }
        
        // FIX: Yield to allow USB stack to process the key press/release
        yield();

        // Random wait between each key press (Human speed)
        // Human-like variable speed: Slightly sped up without breaking naturalness (Fast typist)
        delay(random(50, 120)); 
    }
    Keyboard.releaseAll(); // FIX: Ensure all keys are released at end of string
    delay(150); // End of line wait
}

// Helper function that waits after Enter for PowerShell to process the command
static void sendCommand(String cmd, String lang) {
    typeHuman(cmd, lang, false); // Print without mistakes
    esp_task_wdt_reset();
    Keyboard.write(KEY_RETURN);
    delay(1200); // SECURITY: Increase time slightly for PowerShell to process.
}

static void runScript(String filename, String lang) {
    // 1. Read Script from Internal Storage (LittleFS)
    // User requested to keep it in file directory (LittleFS) for now, not USB.
    if (!filename.startsWith("/")) filename = "/" + filename;

    File f = LittleFS.open(filename, "r");
    if (!f) {
        Serial.println("ERROR: Script file not found in LittleFS: " + filename);
        return;
    }

    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim(); // Remove whitespace/newlines

        if (line.length() == 0) continue;

        // Watchdog reset & Background Write
        esp_task_wdt_reset();
        processBackgroundWrite();

        // Simple Script Parser
        if (line.startsWith("DELAY ")) {
            int ms = line.substring(6).toInt();
            unsigned long start = millis();
            while (millis() - start < ms) {
                esp_task_wdt_reset();
                processBackgroundWrite();
                yield();
                delay(10);
            }
        } else if (line.startsWith("GUI ")) {
            String key = line.substring(4);
            Keyboard.press(KEY_LEFT_GUI);
            if (key.length() > 0) Keyboard.press(key[0]);
            delay(100);
            Keyboard.releaseAll();
        } else if (line.equals("ENTER")) {
            Keyboard.write(KEY_RETURN);
        } else if (line.startsWith("STRING ")) {
            String text = line.substring(7);
            typeHuman(text, lang, false);
        } else if (line.startsWith("REM ") || line.startsWith("//")) {
            // Comment, skip
        } else {
            // Type command
            sendCommand(line, lang);
            // FIX: Small delay after each command to let host buffer clear
            delay(50);
        }
    }
    
    f.close();
}

void BadUsbModule::init(WebServer* server) {
    _server = server;

    // Ana Arayuz
    _server->on("/badusb_app", HTTP_GET, [this]() {
        _server->send(200, "text/html", getAppPage());
    });

    // Script Runner Trigger
    _server->on("/badusb_run", HTTP_POST, [this]() {
        String lang = "tr"; // Default language Turkish
        String file = "";
        
        if (_server->hasArg("lang")) lang = _server->arg("lang");
        if (_server->hasArg("file")) file = _server->arg("file");

        if (file.length() == 0) {
            _server->send(400, "text/plain", "ERROR: No file specified.");
            return;
        }

        if (!file.startsWith("/")) file = "/" + file;
        if (!LittleFS.exists(file)) {
            _server->send(404, "text/plain", "ERROR: File not found: " + file);
            return;
        }

        runScript(file, lang);
        _server->send(200, "text/plain", "Commands sent. Watch the screen.");
    });

    // Formatting Operation (Manual Trigger)
    _server->on("/badusb_format", HTTP_GET, [this]() {
         // First clear the cache
        flushDiskCache();
        
        // We delete the partition directly instead of FFat library (RAW Format)
        const esp_partition_t* part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, "ffat");
        
        if (part) {
            // FIX: Deleting the entire disk (2MB) takes too long and causes Watchdog Reset.
            // Deleting only the first 4KB sector (Boot Sector) is sufficient.
            // Windows detects the disk as "Unformatted" when it sees this.
            esp_err_t err = esp_partition_erase_range(part, 0, 4096);
            
            if (err == ESP_OK) {
                _server->send(200, "text/plain", "SUCCESS: Disk Reset. Please unplug and replug the USB cable. Windows will ask to 'Format'.");
            } else {
                _server->send(500, "text/plain", "ERROR: Delete operation failed!");
            }
        } else {
            _server->send(500, "text/plain", "ERROR: 'ffat' partition not found! Partition table might not be loaded.");
        }
    });

    // --- USB FILE MANAGER (Via FFat) ---
    // Mount USB memory partition (FFat) to ESP32 file system (/usb)
    // Partition Label: "ffat" (must be same as partitions.csv)
    // FIX: We mount RAW FAT for Windows compatibility (instead of FFat library)
    const esp_vfs_fat_mount_config_t mount_config = {
        .format_if_mount_failed = true,
        .max_files = 5,
        .allocation_unit_size = 512
    };
    
    esp_err_t err = esp_vfs_fat_rawflash_mount("/usb", "ffat", &mount_config);
    if (err == ESP_OK) {
        Serial.println("USB (Raw FAT) File System Mounted: /usb");

        // --- ENSURE verify.txt EXISTS ON USB ---
        // Marker file for drive identification.
        FILE* fVerify = fopen("/usb/verify.txt", "r");
        if (!fVerify) {
            Serial.println("BadUsb: verify.txt missing on USB. Creating...");
            fVerify = fopen("/usb/verify.txt", "w");
            if (fVerify) {
                fprintf(fVerify, "VERIFICATION FILE");
                fclose(fVerify);
            }
        } else { fclose(fVerify); }

    } else {
        Serial.println("USB (Raw FAT) Mount Failed! Error code: " + String(err));
    }

    // File List JSON
    _server->on("/badusb_files", HTTP_GET, [this]() {
        String json = "[";
        DIR* dir = opendir("/usb");
        if (dir) {
            struct dirent* ent;
            bool first = true;
            while ((ent = readdir(dir)) != NULL) {
                // Skip . and .. folders
                if (String(ent->d_name) == "." || String(ent->d_name) == "..") continue;
                
                if (!first) json += ",";
                
                struct stat st;
                String path = "/usb/" + String(ent->d_name);
                stat(path.c_str(), &st);
                
                json += "{\"name\":\"" + String(ent->d_name) + "\", \"size\":\"" + String(st.st_size) + " B\"}";
                first = false;
            }
            closedir(dir);
        }
        json += "]";
        _server->send(200, "application/json", json);
    });

    // File Download
    _server->on("/badusb_download", HTTP_GET, [this]() {
        if (!_server->hasArg("file")) return _server->send(400, "text/plain", "Filename missing");
        String path = "/usb/" + _server->arg("file");
        
        FILE* f = fopen(path.c_str(), "rb");
        if (f) {
            // Read and send file in chunks
            char buf[512];
            size_t len;
            while ((len = fread(buf, 1, sizeof(buf), f)) > 0) {
                _server->client().write((const uint8_t*)buf, len);
            }
            fclose(f);
        } else {
            _server->send(404, "text/plain", "File not found");
        }
    });

    // --- USB STORAGE (MSC) INITIALIZATION ---
    // Uses 2MB area labeled "ffat" in partition table.
    ffat_part = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_FAT, "ffat");
    
    if (ffat_part) {
        Serial.printf("USB Storage: FFat Partition Found (Size: %d bytes)\n", ffat_part->size);
        
        // --- RAM DISK INITIALIZATION (PSRAM) ---
        disk_size = ffat_part->size;
        total_sectors = disk_size / 4096;
        
        // Allocate space from PSRAM
        ram_disk = (uint8_t*)heap_caps_malloc(disk_size, MALLOC_CAP_SPIRAM);
        dirty_sectors = (bool*)heap_caps_calloc(total_sectors, sizeof(bool), MALLOC_CAP_SPIRAM);
        
        if (ram_disk && dirty_sectors) {
            Serial.println("USB: RAM Disk created in PSRAM. Copying from Flash...");
            esp_partition_read(ffat_part, 0, ram_disk, disk_size);
            use_ram_disk = true;
        } else {
            Serial.println("ERROR: Not enough PSRAM for RAM Disk! USB might be unstable.");
        }
        
        msc.vendorID("ESP32");
        msc.productID("USB Drive");
        msc.onRead(mscRead);
        msc.onWrite(mscWrite);
        msc.mediaPresent(true);
        msc.begin(ffat_part->size / 512, 512); // Block Count, Block Size
    } else {
        Serial.println("ERROR: FFat Partition NOT FOUND! Partition table might not be loaded.");
    }
    
    // Start USB Stack
    USB.begin();
    Keyboard.begin(); // Start Keyboard
}

void BadUsbModule::loop() {
    // --- BACKGROUND FLASH SYNC ---
    // If RAM Disk is used, write changed data to Flash slowly in background.
    // This prevents USB disconnection and Windows "Device not ready" error.
    processBackgroundWrite();
}

String BadUsbModule::getAppPage() {
    return R"rawliteral(
<!DOCTYPE HTML><html>
<head>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>BAD USB CONTROL</title>
  <style>
    body { background-color: #121212; color: #e0e0e0; font-family: 'Courier New', monospace; text-align: center; padding: 20px; }
    h2 { color: #ff006e; border-bottom: 1px solid #333; padding-bottom: 10px; }
    .btn { color: white; padding: 15px 20px; text-decoration: none; border-radius: 5px; font-weight: bold; display: inline-block; margin: 5px; border: none; cursor: pointer; font-size: 14px; width: 400px; }
    .btn-fmt { background: #d62828; }
    .btn-hack { background: #0077b6; }
    .btn-menu { background: #555; padding: 10px 20px; font-size: 14px; margin-bottom: 20px; }
    .info { color: #888; font-size: 12px; margin: 20px auto; max-width: 400px; border: 1px solid #333; padding: 10px; }
    
    table { width: 100%; max-width: 500px; margin: 20px auto; border-collapse: collapse; background: #1e1e1e; font-size: 12px; }
    th { background: #333; padding: 8px; color: #fff; }
    td { border-bottom: 1px solid #333; padding: 8px; text-align: left; }
    .btn-sm { padding: 5px 10px; font-size: 10px; margin: 0; }
  </style>
  <script>
    function runSelectedScript() {
      // Send command via AJAX request (Prevents page reload)
      var chk = document.getElementById('chkConfirm');
      var sel = document.getElementById('scriptSelect');
      var lang = document.getElementById('langSelect').value;
      
      if (chk.checked) {
        fetch('/badusb_run?lang=' + lang + '&file=' + sel.value, {method: 'POST'}).then(r => r.text()).then(msg => alert(msg));
      } else {
        alert('Please check the box to proceed.');
      }
    }
    
    function formatDisk() {
      if(confirm('WARNING: All data on USB will be deleted and disk will be reset. Do you confirm?')) {
        fetch('/badusb_format').then(r => r.text()).then(msg => alert(msg));
      }
    }
    
    // Load scripts from ROM
    fetch('/rom_list').then(r=>r.json()).then(files => {
        let sel = document.getElementById('scriptSelect');
        files.forEach(f => {
            if(f.name.endsWith('.txt')) {
                let opt = document.createElement('option');
                opt.value = f.name;
                opt.innerText = f.name;
                sel.appendChild(opt);
            }
        });
    });
  </script>
</head>
<body>
  <h2>BAD USB CONTROL</h2>
  <a href="/" class="btn btn-menu" style="text-decoration:none; color:white;">MAIN MENU</a>
  
  <div class="info">
    <p>HID (Keyboard) and MSC (Storage) are active.</p>
    <p style="color:#fca311; font-weight:bold;">Select a script from ROM to execute.</p>
  </div>

  <div style="margin: 15px;">
    <label>Script:</label>
    <select id="scriptSelect" style="padding:5px; background:#333; color:white; border:1px solid #555;"></select>
    
    <label style="margin-left:10px;">Keyboard:</label>
    <select id="langSelect" style="padding:5px; background:#333; color:white; border:1px solid #555;">
        <option value="tr">TR (Turkish)</option>
        <option value="en">EN (English)</option>
    </select>
    <br><br>
    <input type="checkbox" id="chkConfirm" style="transform: scale(1.5);"> <label for="chkConfirm" style="font-size:14px; margin-left:5px;">I Confirm the Operation (Security)</label>
  </div>
  <button onclick="runSelectedScript()" class="btn btn-hack">RUN SELECTED SCRIPT</button>
  <button onclick="formatDisk()" class="btn btn-fmt">RESET USB STORAGE (FORMAT)</button>
</body></html>
)rawliteral";
}
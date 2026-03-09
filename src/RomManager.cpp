#include "RomManager.h"

static File fsUploadFile;

void RomManagerModule::init(WebServer* server) {
    // Start LittleFS (Format if failed = true)
    if (!LittleFS.begin(true)) {
        Serial.println("LittleFS Failed to Start!");
        return;
    }
    Serial.println("LittleFS Started (ROM).");

    // Define Routes
    server->on("/rom_app", [this, server]() {
        server->send(200, "text/html", getAppPage());
    });

    server->on("/rom_list", [this, server]() {
        server->send(200, "application/json", getFileListJSON());
    });

    server->on("/rom_delete", [this, server]() {
        if (!server->hasArg("file")) { server->send(400, "text/plain", "Filename missing"); return; }
        String path = server->arg("file");
        if (deleteFile(path)) server->send(200, "text/plain", "Deleted: " + path);
        else server->send(500, "text/plain", "Could not delete!");
    });

    server->on("/rom_download", [this, server]() {
        if (!server->hasArg("file")) { server->send(400, "text/plain", "Filename missing"); return; }
        String path = server->arg("file");
        File file = getFile(path);
        if (file) {
            server->streamFile(file, "application/octet-stream");
            file.close();
        } else {
            server->send(404, "text/plain", "File not found");
        }
    });

    server->on("/rom_view", [this, server]() {
        if (!server->hasArg("file")) { server->send(400, "text/plain", "Filename missing"); return; }
        String path = server->arg("file");
        File file = getFile(path);
        if (file) {
            server->streamFile(file, "text/plain");
            file.close();
        } else {
            server->send(404, "text/plain", "File not found");
        }
    });

    server->on("/rom_upload", HTTP_POST, [this, server]() {
        server->send(200, "text/plain", "File Uploaded Successfully!");
    }, [this, server]() {
        HTTPUpload& upload = server->upload();
        if (upload.status == UPLOAD_FILE_START) {
            String filename = upload.filename;
            if (!filename.startsWith("/")) filename = "/" + filename;
            fsUploadFile = LittleFS.open(filename, FILE_WRITE);
        } else if (upload.status == UPLOAD_FILE_WRITE) {
            if (fsUploadFile) fsUploadFile.write(upload.buf, upload.currentSize);
        } else if (upload.status == UPLOAD_FILE_END) {
            if (fsUploadFile) fsUploadFile.close();
        }
    });
}

String RomManagerModule::getNextFilename(String baseName, String extension) {
    String filename = "/" + baseName + "." + extension;
    if (!LittleFS.exists(filename)) return filename;

    int i = 1;
    while (i < 10000) { // Security limit: Prevent infinite loop
        filename = "/" + baseName + "_" + String(i) + "." + extension;
        if (!LittleFS.exists(filename)) return filename;
        i++;
    }
    // If security limit exceeded, return default name or empty string
    return "/" + baseName + "_overflow." + extension;
}

String RomManagerModule::saveWifiScan(String json) {
    String filename = getNextFilename("Wifi_Scan", "json");
    
    File file = LittleFS.open(filename, FILE_WRITE);
    if (!file) {
        Serial.println("File could not be opened!");
        return "";
    }
    file.print(json);
    file.close();
    return filename;
}

bool RomManagerModule::overwriteFile(String filename, String json) {
    File file = LittleFS.open(filename, FILE_WRITE); // FILE_WRITE overwrites content
    if (!file) {
        Serial.println("File could not be updated: " + filename);
        return false;
    }
    file.print(json);
    file.close();
    return true;
}

String RomManagerModule::formatBytes(size_t bytes) {
    if (bytes < 1024) return String(bytes) + " B";
    else if (bytes < (1024 * 1024)) return String(bytes / 1024.0, 2) + " KB";
    else return String(bytes / 1024.0 / 1024.0, 2) + " MB";
}

String RomManagerModule::getFileListJSON() {
    String json = "[";
    json.reserve(2048); // Pre-allocation to prevent memory fragmentation
    File root = LittleFS.open("/");
    if (!root) return "[]";

    File file = root.openNextFile();
    bool first = true;
    while (file) {
        if (!first) json += ",";
        json += "{\"name\":\"" + String(file.name()) + "\",";
        json += "\"size\":\"" + formatBytes(file.size()) + "\"}";
        first = false;
        file = root.openNextFile();
    }
    json += "]";
    return json;
}

bool RomManagerModule::deleteFile(String path) {
    if (!path.startsWith("/")) path = "/" + path;
    return LittleFS.remove(path);
}

File RomManagerModule::getFile(String path) {
    if (!path.startsWith("/")) path = "/" + path;
    if (!LittleFS.exists(path)) return File(); // Return empty if file doesn't exist without error
    return LittleFS.open(path, FILE_READ);
}

String RomManagerModule::getAppPage() {
    return R"rawliteral(
<!DOCTYPE HTML><html>
<head>
  <meta name='viewport' content='width=device-width, initial-scale=1'>
  <title>ROM MANAGER</title>
  <style>
    body { background-color: #121212; color: #e0e0e0; font-family: 'Segoe UI', sans-serif; text-align: center; margin: 0; padding: 10px; }
    h2 { color: #ff006e; margin-bottom: 5px; }
    .btn { border: none; padding: 8px 15px; border-radius: 5px; font-weight: bold; cursor: pointer; color: white; text-decoration: none; font-size: 12px; display: inline-block; margin: 2px; }
    .btn-del { background-color: #d62828; }
    .btn-down { background-color: #0077b6; }
    .btn-view { background-color: #2a9d8f; }
    .btn-menu { background-color: #555; padding: 10px 20px; font-size: 14px; margin-bottom: 15px; }
    
    table { width: 100%; max-width: 600px; margin: 20px auto; border-collapse: collapse; background: #1e1e1e; border-radius: 8px; overflow: hidden; }
    th { background-color: #333; color: #fff; padding: 10px; text-align: left; }
    td { padding: 10px; border-bottom: 1px solid #333; text-align: left; }
    tr:last-child td { border-bottom: none; }
    .size-col { text-align: right; color: #aaa; font-family: monospace; }
    .action-col { text-align: right; white-space: nowrap; }
    
    #status { margin: 10px; color: #888; font-style: italic; }
  </style>
</head>
<body>
  <h2>ROM FILE MANAGER</h2>
  <a href="/" class="btn btn-menu">RETURN TO MAIN MENU</a>
  
  <div style="margin: 10px auto; max-width: 400px; border: 1px dashed #555; padding: 10px;">
    <form method='POST' action='/rom_upload' enctype='multipart/form-data'>
      <input type='file' name='upload' style='color:white'> <input type='submit' value='UPLOAD' class='btn btn-down'>
    </form>
  </div>

  <div id="status">Loading files...</div>

  <table id="fileTable">
    <thead><tr><th>Filename</th><th class="size-col">Size</th><th class="action-col">Action</th></tr></thead>
    <tbody id="fileList"></tbody>
  </table>

<script>
  function loadFiles() {
    fetch('/rom_list')
      .then(res => res.json())
      .then(data => {
        const list = document.getElementById('fileList');
        list.innerHTML = "";
        document.getElementById('status').innerText = data.length + " files found.";
        
        if(data.length === 0) {
            list.innerHTML = "<tr><td colspan='3' style='text-align:center'>No files.</td></tr>";
            return;
        }

        data.forEach(f => {
            let row = `<tr>
                <td>${f.name}</td>
                <td class="size-col">${f.size}</td>
                <td class="action-col">
                    <a href="/rom_view?file=${f.name}" target="_blank" class="btn btn-view">VIEW</a>
                    <a href="/rom_download?file=${f.name}" class="btn btn-down">DOWNLOAD</a>
                    <button onclick="delFile('${f.name}')" class="btn btn-del">DELETE</button>
                </td>
            </tr>`;
            list.innerHTML += row;
        });
      });
  }

  function delFile(name) {
    if(confirm(name + " will be deleted. Are you sure?")) {
        fetch('/rom_delete?file=' + name)
            .then(res => res.text())
            .then(msg => {
                alert(msg);
                loadFiles();
            });
    }
  }

  loadFiles();
</script>
</body></html>
)rawliteral";
}
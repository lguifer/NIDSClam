### **What is `NIDSClam`?**
`nidsclam.py` is a Python script for analyzing network intrusion detection system (NIDS) logs (Suricata/Zeek) and scanning files for malware using ClamAV and YARA. It processes logs, detects threats, and generates detailed reports.

---

### **Features**
- Processes **Suricata** and **Zeek** logs for file-based events.
- Scans files using **ClamAV** and **YARA**.
- Supports multi-threading for efficient file processing.
- Logs events to a centralized log file.
- Allows direct file/directory scanning without log files.
- Tracks the last processed event timestamp to avoid reprocessing.

---

### **Dependencies**
Ensure the following tools and libraries are installed:
- **Python** (>=3.8)
- **ClamAV** (`clamdscan`)
- **YARA** (`yara`)
- **Zeek** (`zeek-cut`)
- **ThreadPoolExecutor** (Python built-in)
- **Other Python Libraries**: `os`, `socket`, `json`, `subprocess`, `argparse`, `logging`, `re`, `datetime`.

---

### **How to Use the Script?**
#### **Run the Script**
```bash
python3 nidsclam.py --suricata-log-file /path/to/suricata.log --filestore-path /path/to/filestore --threads 4
```

#### **Available Arguments**
- `--date-config-path`  
  Path to store the last processed date (default: `last_processed_date.txt`).
- `--filestore-path`  
  Path to file storage for scanning.
- `--suricata-log-file`  
  Path to the Suricata log file.
- `--zeek-log-file`  
  Path to the Zeek log file.
- `--recursive`  
  Enable recursive search in the filestore directory.
- `--file-or-dir`  
  Scan a specific file or directory directly.
- `--threads`  
  Number of threads to use for scanning files.

---

### **Configuration**
- **Log Path**: `/var/log/nidsclam/nidsclam.log`
- **YARA Rules Path**: `/home/kali/scripts/yara/all_rules.yar`
- **Default Date Config File**: `last_processed_date.txt`

Ensure the directories exist or are created before running the script.

---

### **Key Functions**
- `process_logs()`: Main function for handling logs or direct file/directory input.
- `process_suricata_log()`: Processes Suricata logs for file events.
- `process_zeek_log()`: Extracts and processes file events from Zeek logs.
- `process_direct_file_or_dir()`: Scans files or directories directly.
- `process_event()`: Executes ClamAV and YARA scans, and logs results.

---

### **Logging**
Logs are stored in `/var/log/nidsclam/nidsclam.log` with the format:
```
<timestamp> NAME_SERVER NIDS[1]: <log message>
```

---

### **Error Handling**
- **File not found**: Logs and skips non-existent files during scans.
- **JSON decode errors**: Skips invalid Suricata log lines.
- **Command errors**: Logs failures from `clamdscan`, `yara`, or `zeek-cut`.

---

### **Examples**
1. **Scan using Suricata logs**:
   ```bash
   python3 nidsclam.py --suricata-log-file /path/to/suricata.log --filestore-path /path/to/files
   ```
2. **Scan a specific directory with 10 threads**:
   ```bash
   python3 nidsclam.py --file-or-dir /path/to/files --threads 10
   ```
3. **Scan using Zeek logs**:
   ```bash
   python3 nidsclam.py --zeek-log-file /path/to/conn.log --filestore-path /path/to/files
   ```

---

### **FAQ**
#### **Q: How to add custom YARA rules?**  
Place your rules in the path defined by `YARA_RULES_PATH`.

#### **Q: How are results saved?**  
Scan results are logged in the defined log file (`nidsclam.log`).

#### **Q: Can I run it on Windows?**  
The script is designed for Unix-like systems due to dependencies (`find`, `clamdscan`, etc.).

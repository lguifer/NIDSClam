# NIDSClam - Frequently Asked Questions (FAQ)

## Table of Contents
- [What is NIDSClam?](#what-is-nidsclam)
- [Installation Requirements](#installation-requirements)
- [How to Install](#how-to-install)
- [How to Use NIDSClam](#how-to-use-nidsclam)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## What is NIDSClam?
NIDSClam is an advanced network intrusion detection system that integrates Zeek logs, ClamAV, and YARA rules to detect threats in network traffic.

## Installation Requirements
To run NIDSClam, you need:
- **Python 3.8+**
- The following dependencies:
  ```sh
  pip install -r requirements.txt
  ```
- Required tools installed:
  - **ClamAV** (`clamdscan` required)
  - **YARA** (`yara` command-line tool)
  - **Zeek** (if processing Zeek logs)
  - **Watchdog** for file monitoring

## How to Install
1. Clone the repository:
   ```sh
   git clone https://github.com/your-repo/nidsclam.git
   cd nidsclam
   ```
2. Install dependencies:
   ```sh
   pip install -r requirements.txt
   ```
3. Ensure ClamAV and YARA are installed and configured properly.

## How to Use NIDSClam
NIDSClam can operate in two main modes:
1. **Direct file scan**
   ```sh
   python nidsclam.py --direct-scan /path/to/file-or-directory
   ```
2. **Zeek log processing** (requires a file storage path for extracted files):
   ```sh
   python nidsclam.py --zeek-log /path/to/zeek/logs/conn.log --filestore /path/to/extracted/files
   ```

To display metrics:
```sh
python nidsclam.py --metrics
```

## Configuration
NIDSClam can use a YAML configuration file. By default, it expects:
```yaml
log_path: "/var/log/nidsclam/nidsclam.log"
yara_rules: "/home/user/nidsclam/yara-rules-filtered.yar"
timezone: "Europe/Madrid"
max_threads: 20
scan_timeout: 300
clamd_socket: "/var/run/clamav/clamd.ctl"
```
To specify a custom configuration file:
```sh
python nidsclam.py --config /path/to/config.yaml
```

## Troubleshooting
### 1. **Permission Denied Errors**
Ensure ClamAV and YARA have the necessary permissions. Try running:
```sh
sudo systemctl restart clamav-daemon
```

### 2. **File Not Found Errors**
Ensure the files exist in the specified paths and that `--filestore` is correctly set when processing Zeek logs.

### 3. **Zeek Logs Not Parsing Correctly**
Check that the log file contains structured entries and has correct field mappings.

## License
NIDSClam is released under the MIT License. See `LICENSE` for more details.

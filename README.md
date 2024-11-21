# NIDSClam

**NIDSClam** is an automated tool designed to enhance network security by integrating **Suricata** and **Zeek** logs with **ClamAV** file scanning. 

It processes network traffic files generated by these **Network Intrusion Detection Systems (NIDS)**, scans them for potential **malware**, and provides a streamlined way to detect and respond to **security threats**. 

By leveraging the combined power of **NIDS** and **antivirus technology**, **NIDSClam** helps secure network environments by identifying **malicious files** from network traffic efficiently.

## **Prerequisites for NIDSClam**

### 1. **Install Required Tools**

Before using **NIDSClam**, make sure the following tools are installed and properly configured:

#### **1.1 Install Python 3.x**
**NIDSClam** is written in Python, so you need Python 3.x installed on your system. Install it using:

```bash
sudo apt-get update
sudo apt-get install python3 python3-pip
```

#### **1.2 Install ClamAV**

ClamAV is used to scan files for malware. Install **ClamAV** and the `clamd` service:

```bash
sudo apt-get install clamav clamav-daemon
```

Start the ClamAV daemon:

```bash
sudo systemctl start clamav-daemon
```

Ensure it starts automatically on boot:

```bash
sudo systemctl enable clamav-daemon
```

#### **1.3 Install Suricata**

Suricata is a Network Intrusion Detection System (NIDS) that generates logs for network traffic. Install **Suricata**:

```bash
sudo apt-get install suricata
```

##### **Configure Suricata to Generate Logs and Store Files:**

In order to use **NIDSClam**, you'll need **Suricata** to generate logs in JSON format and also store files that it detects during network traffic analysis. Here's how to configure **Suricata** to do so:

- **Activate Filestore:**

  Suricata must be configured to store files related to network traffic. Edit the Suricata configuration file (`/etc/suricata/suricata.yaml`):

  ```yaml
  file-store:
    enabled: yes          # Enable file-store module
    force-file-store: yes # Force file-store to save all files detected
    dir: /var/log/suricata/filestore # Directory where files will be stored
  ```

  The `force-file-store: yes` option ensures that **Suricata** will store all files it detects, even if they aren't flagged as suspicious initially. 

- **Enable JSON Output:**

  Suricata generates detailed logs, which will be needed by **NIDSClam**. To output logs in JSON format, modify the `outputs` section in `suricata.yaml`:

  ```yaml
  outputs:
    - eve-log:
        enabled: yes
        filetype: json
        filename: /var/log/suricata/eve.json
  ```

  This configuration will store Suricata logs in the `/var/log/suricata/eve.json` file in JSON format.

- **Restart Suricata:**

  After modifying the configuration, restart Suricata to apply the changes:

  ```bash
  sudo systemctl restart suricata
  sudo systemctl enable suricata
  ```

  Suricata will now store network traffic files and log them in the specified directories.

#### **1.4 Install Zeek (formerly Bro)**

Zeek is a powerful network monitoring tool that generates logs related to network traffic. Install **Zeek** using:

```bash
sudo apt-get install zeek
```

##### **Configure Zeek to Generate Logs:**

By default, Zeek logs network events in its `logs/` directory. You can configure it to log specific network events like file transfers.

- **Configure Zeek to log network traffic:**

  Edit the configuration file (`/usr/local/zeek/etc/zeekctl.cfg`) if necessary, or run Zeek with default logging.

- **Start Zeek**:

  Run Zeek on your network interface (e.g., `eth0`):

  ```bash
  sudo zeekctl deploy
  ```

  This command starts Zeek and begins logging network events. You’ll find the log files in the `/usr/local/zeek/logs/` directory.

#### **1.5 Install Additional Python Dependencies**

To run **NIDSClam**, you may need additional Python packages. Create a `requirements.txt` file with the necessary libraries (or install them manually):

```bash
pip install -r requirements.txt
```

Example `requirements.txt`:

```
python-dateutil
requests
```

---

## **How to Use NIDSClam**

After installing and configuring all necessary tools, you can use **NIDSClam** to monitor and scan network traffic files generated by **Suricata** and **Zeek**, and detect potential threats.

### 2. **Usage**

#### **2.1 Running NIDSClam**

You can run **NIDSClam** by providing it with the log files from **Suricata** and **Zeek**.

```bash
python nidsclam.py --suricata-log-file /var/log/suricata/eve.json --zeek-log-file /usr/local/zeek/logs/current/conn.log --filestore-path /path/to/filestore
```

**Options:**

- `--suricata-log-file`: Path to the Suricata JSON log file (e.g., `/var/log/suricata/eve.json`).
- `--zeek-log-file`: Path to the Zeek log file (e.g., `/usr/local/zeek/logs/current/conn.log`).
- `--filestore-path`: Directory where files for scanning are stored (e.g., `/path/to/filestore`).
- `--recursive`: (Optional) Flag to recursively scan directories.
- `--file-or-dir`: (Optional) Directly specify a file or directory to scan.
- `--date-config-path`: (Optional) Path to store the last processed date for logs.

#### **2.2 Directly Scanning Files or Directories**

If you don’t have **Zeek** or **Suricata** logs, or want to scan files directly, use the `--file-or-dir` option:

```bash
python nidsclam.py --file-or-dir /path/to/directory
```

This will scan all files within the directory.

---

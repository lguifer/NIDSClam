#!/usr/bin/env python3

import os
import re
import sys
import json
import time
import signal
import socket
import logging
import argparse
import subprocess
import hashlib
import logging.handlers
import threading
from pathlib import Path
from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor, as_completed

# Third-party imports
import yaml
from pydantic import BaseModel, ValidationError, FilePath, DirectoryPath
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ###############
# Configuration #
# ###############
class AppConfig(BaseModel):
    log_path: FilePath = Path("/var/log/nidsclam/nidsclam.log")
    yara_rules: FilePath = Path("/root/NIDSClam/packages/full/yara-rules-filtered.yar")
    timezone: str = "Europe/Madrid"
    max_threads: int = 20
    scan_timeout: int = 300
    max_retries: int = 3
    clamd_socket: str = "/var/run/clamav/clamd.ctl"

# ###########
# Constants #
# ###########
VERSION = "2.0.0"
SERVICE_NAME = "nidsclam"
SIGNATURES = {
    "CLAMAV_FOUND": re.compile(r"FOUND\b"),
    "YARA_MATCH": re.compile(r"\bmatched\b")
}

# ###########
# Observability #
# ###########
class MetricsCollector:
    def __init__(self):
        self.scanned_files = 0
        self.threats_detected = 0
        self.processing_errors = 0

METRICS = MetricsCollector()

# ############
# Exceptions #
# ############
class NIDSClamError(Exception): pass
class ConfigurationError(NIDSClamError): pass
class SecurityViolation(NIDSClamError): pass

# ###########
# Utilities #
# ###########
def load_config(config_path: Optional[Path] = None) -> AppConfig:
    try:
        if config_path:
            with open(config_path) as f:
                config_data = yaml.safe_load(f)
        else:
            config_data = {}
        return AppConfig(**config_data)
    except (ValidationError, yaml.YAMLError) as e:
        raise ConfigurationError(f"Invalid configuration: {str(e)}") from e

def safe_command_execution(command: List[str], timeout: int = 30) -> str:
    if any(c in arg for arg in command for c in [';', '&&', '||']):
        raise SecurityViolation(f"Dangerous command detected: {' '.join(command)}")

    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout
        )

        if "clamdscan" in command[0] and result.returncode in [0, 1]:
            return result.stdout.strip()
        
        if result.returncode != 0:
            raise subprocess.CalledProcessError(
                result.returncode,
                command,
                output=result.stdout,
                stderr=result.stderr
            )
            
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        error_msg = f"""
        Command failed: {' '.join(command)}
        Exit code: {e.returncode}
        stdout: {e.stdout.strip()}
        stderr: {e.stderr.strip()}
        """
        raise NIDSClamError(error_msg) from e

# ################
# Core Functions #
# ################
class LogProcessor:
    def __init__(self, config: AppConfig):
        self.config = config
        self.timezone = ZoneInfo(config.timezone)
        self.executor = ThreadPoolExecutor(max_workers=config.max_threads)
        self.running = True
        self.zeek_separator = '\t'
        self.zeek_fields = []

        signal.signal(signal.SIGINT, self.graceful_shutdown)
        signal.signal(signal.SIGTERM, self.graceful_shutdown)
        self.logger = self._configure_logging()

    def _configure_logging(self) -> logging.Logger:
        logger = logging.getLogger(SERVICE_NAME)
        logger.setLevel(logging.DEBUG)

#        formatter = logging.Formatter(
#            f"%(asctime)s.%(msecs)03d {socket.gethostname()} {SERVICE_NAME}[%(process)d]: %(message)s",
#            datefmt="%Y-%m-%dT%H:%M:%S"
#        )
        formatter = logging.Formatter(f"%(asctime)s {socket.gethostname()} {SERVICE_NAME}[%(process)d]: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")


        file_handler = logging.FileHandler(self.config.log_path)
        file_handler.setFormatter(formatter)

        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)

        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        return logger

    def graceful_shutdown(self, signum, frame):
        self.running = False
        self.logger.info("Initiating graceful shutdown...")
        self.executor.shutdown(wait=False)
        sys.exit(0)

    class ZeekLogHandler(FileSystemEventHandler):
        def __init__(self, processor, log_path):
            self.processor = processor
            self.log_path = log_path
            self.position = 0
            self.current_inode = None
            self.running = True  # Control para detener el hilo de monitoreo

            self.check_inode()
            self.start_monitoring_thread()

        def check_inode(self):
            """Verifica y actualiza el inode del archivo."""
            try:
                new_inode = os.stat(self.log_path).st_ino
                if self.current_inode is None or new_inode != self.current_inode:
                    self.current_inode = new_inode
                    self.position = 0  # Reiniciar posición si el archivo cambia
                    self.processor.logger.info("Zeek log inode changed, resetting position.")
            except FileNotFoundError:
                self.processor.logger.warning("Zeek log file not found. Waiting for recreation...")

        def start_monitoring_thread(self):
            """Inicia un hilo independiente para verificar periódicamente el archivo."""
            thread = threading.Thread(target=self.monitor_file_changes, daemon=True)
            thread.start()

        def monitor_file_changes(self):
            """Verifica cada 5 segundos si el archivo ha cambiado y fuerza su procesamiento."""
            while self.running:
                self.check_inode()
                self.process_new_lines()
                time.sleep(5)

        def on_any_event(self, event):
            """Captura cualquier cambio en el archivo."""
            if event.src_path == str(self.log_path):
                self.processor.logger.debug(f"Event detected: {event.event_type} on {event.src_path}")
                self.check_inode()
                self.process_new_lines()

        def process_new_lines(self):
            """Lee nuevas líneas del archivo asegurando que la posición sea correcta."""
            try:
                with open(self.log_path, 'r') as f:
                    f.seek(self.position)
                    lines = f.readlines()
                    if lines:
                        self.position = f.tell()  # Actualizar la posición tras leer
                        for line in lines:
                            if line.strip():
                                self.processor.process_zeek_line(line.strip())
                    else:
                        pass
                        #self.processor.logger.debug("No new lines found.")
            except FileNotFoundError:
                self.processor.logger.warning(f"Zeek log file {self.log_path} not found.")
            except Exception as e:
                self.processor.logger.error(f"Error processing lines: {str(e)}", exc_info=True)


    def process_zeek_line(self, line: str):
        try:
            if line.startswith('#') or not line.strip():
                return

            if not self.zeek_fields:
                self.logger.warning("Zeek fields not parsed. Skipping line.")
                return

            fields = line.strip().split(self.zeek_separator)
            
            if len(fields) != len(self.zeek_fields):
                self.logger.warning(f"Field count mismatch: {len(fields)} vs {len(self.zeek_fields)}")
                return

            field_map = dict(zip(self.zeek_fields, fields))
            
            try:
                timestamp = datetime.fromtimestamp(float(field_map['ts']), tz=timezone.utc)
                filename = field_map['extracted']
                src_ip = field_map['id.orig_h']
                dest_ip = field_map['id.resp_h']
                src_port = field_map.get('id.orig_p', "N/A")  # ⬅️ Aquí se extrae el puerto origen
                dest_port = field_map.get('id.resp_p', "N/A")  # ⬅️ Aquí el puerto destino

            except KeyError as e:
                self.logger.error(f"Missing required field: {str(e)}")
                return

            if not filename or filename in ['-', '(empty)']:
                self.logger.debug(f"Skipping invalid filename: {filename}")
                return

            if not filename.startswith('extract-'):
                filename = f"extract-{filename}"

            resolved_path = Path(args.filestore) / filename

            if not resolved_path.exists():
                self.logger.error(f"File not found in filestore: {resolved_path}")
                return

            self.logger.info(f"Processing file: {filename}")
            self.logger.info(f"Full path: {resolved_path}")

            self.executor.submit(
                self.scan_file,
                file_path=resolved_path,
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_port=src_port,  # ⬅️ Ahora pasamos los puertos correctos
                dest_port=dest_port,
                timestamp=timestamp
            )

        except Exception as e:
            self.logger.error(f"Error processing line: {str(e)}\nLine: {line[:100]}", exc_info=True)

    def process_zeek_log(self, log_path: Path):
        """Monitor Zeek logs using watchdog with proper header handling"""
        self.logger.info(f"Starting Zeek log monitoring: {log_path}")
        
        while not log_path.exists():
            self.logger.warning(f"Zeek log file {log_path} not found. Retrying in 60 seconds...")
            time.sleep(60)


        # Parse headers first
        self._parse_zeek_headers(log_path)

        # Ensure headers were parsed
        if not self.zeek_fields:
            self.logger.error("Failed to parse Zeek log headers. Cannot proceed.")
            return

        event_handler = self.ZeekLogHandler(self, log_path)
        observer = Observer()
        observer.schedule(event_handler, path=str(log_path.parent), recursive=False)
        observer.start()

        try:
            # Process existing data
            event_handler.process_new_lines()
            
            # Keep the observer alive
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            observer.stop()
        finally:
            observer.join()

    def _parse_zeek_headers(self, log_path: Path):
        try:
            with open(log_path, 'r') as f:
                for line in f:
                    if line.startswith('#separator'):
                        sep_hex = line.split()[1]
                        self.zeek_separator = bytes.fromhex(sep_hex[2:]).decode('utf-8')
                        self.logger.debug(f"Detected separator: {self.zeek_separator}")
                    elif line.startswith('#fields'):
                        self.zeek_fields = line.strip().split(self.zeek_separator)[1:]
                        self.logger.debug(f"Detected fields: {self.zeek_fields}")
                    elif line.startswith('#types'):
                        break
        except Exception as e:
            self.logger.error(f"Error parsing Zeek headers: {str(e)}")
            raise

    def scan_file(self, file_path: Path, src_ip: str, dest_ip: str, timestamp: datetime,
                  src_port: Optional[str] = None, dest_port: Optional[str] = None):
        try:
            resolved_path = self._locate_file(file_path)

            if not resolved_path.exists():
                raise FileNotFoundError(f"File not found: {resolved_path}")

            if resolved_path.stat().st_size > 100 * 1024 * 1024:
                self.logger.warning(f"Skipping large file: {resolved_path} ({resolved_path.stat().st_size/1024/1024:.2f}MB)")
                return

            for attempt in range(self.config.max_retries):
                try:
                    clam_result = safe_command_execution(
                        ["clamdscan", "--fdpass", "--no-summary", str(resolved_path)],
                        timeout=self.config.scan_timeout
                    )

                    yara_result = safe_command_execution(
                        ["yara", "-r", "-w", str(self.config.yara_rules), str(resolved_path)],
                        timeout=self.config.scan_timeout
                    )

                    self._log_results(
                        clam_result,
                        yara_result,
                        resolved_path,
                        src_ip,
                        dest_ip,
                        src_port,
                        dest_port,
                        timestamp
                    )
                    METRICS.scanned_files += 1
                    return

                except NIDSClamError as e:
                    if "Exit code: 1" in str(e) and "FOUND" in str(e):
                        self.logger.info(f"Threat detected: {resolved_path}")
                        METRICS.threats_detected += 1
                        return
                    if attempt == self.config.max_retries - 1:
                        raise
                    time.sleep(2 ** attempt)

        except Exception as e:
            METRICS.processing_errors += 1
            self.logger.error(f"Scan failed: {str(e)}", exc_info=True)

    def _locate_file(self, filename: Path) -> Path:
        if args.direct_scan:
            target_path = filename.resolve()
            if not target_path.exists():
                raise FileNotFoundError(f"File not found in direct-scan path: {filename}")
            return target_path
        else:
            if not args.filestore:
                raise NIDSClamError("--filestore is required for Zeek processing")
            
            try:
                find_result = subprocess.check_output(
                    ["find", str(args.filestore), "-name", f"*{filename.name}*", "-print", "-quit"],
                    text=True,
                    stderr=subprocess.DEVNULL
                ).strip()
                
                if not find_result:
                    raise FileNotFoundError(f"File {filename} not found in filestore")
                    
                return Path(find_result).resolve()
            except subprocess.CalledProcessError:
                raise FileNotFoundError(f"File {filename} not found in filestore")

    def _log_results(self, clam_output: str, yara_output: str, file_path: Path,
                     src_ip: str, dest_ip: str, src_port: Optional[str],
                     dest_port: Optional[str], timestamp: datetime):
        log_data = {
            "timestamp": timestamp.astimezone(self.timezone).isoformat(),
            "src_ip": src_ip,
            "dest_ip": dest_ip,
            "file_path": str(file_path),
            "file_hash": self._generate_file_hash(file_path),
            "src_port": src_port or "N/A",
            "dest_port": dest_port or "N/A"
        }

        if SIGNATURES["CLAMAV_FOUND"].search(clam_output):
            log_data.update({
                "engine": "ClamAV",
                "signature": clam_output.split(": ")[-1],
                "threat_level": "CRITICAL"
            })
            self.logger.critical(json.dumps(log_data))

        if yara_output:
            log_data.update({
                "engine": "YARA",
                "signature": yara_output.split(" ")[0],
                "rule": yara_output.split(" ")[-1],
                "threat_level": "HIGH"
            })
            self.logger.critical(json.dumps(log_data))

    def _generate_file_hash(self, file_path: Path) -> str:
        try:
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except IOError as e:
            return f"ERROR: {str(e)}"

# #############
# Main Program #
# #############
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=f"{SERVICE_NAME} v{VERSION} - Enterprise Threat Detection",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--config", type=Path, help="Path to YAML config file")
    parser.add_argument("--zeek-log", type=Path, help="Path to Zeek log file")
    parser.add_argument("--filestore", type=Path, help="Path to file storage (required for Zeek processing)")
    parser.add_argument("--direct-scan", type=Path, help="Direct file/directory to scan")
    parser.add_argument("--metrics", action="store_true", help="Show performance metrics")
    args = parser.parse_args()

    if not args.direct_scan and not args.zeek_log:
        parser.error("You must specify either --direct-scan or --zeek-log")
    
    if args.zeek_log and not args.filestore:
        parser.error("--filestore is required when using --zeek-log")

    try:
        config = load_config(args.config)
        processor = LogProcessor(config)

        if args.direct_scan:
            scan_path = args.direct_scan.resolve()
            processor.logger.info(f"Starting direct scan of: {scan_path}")

            if scan_path.is_dir():
                file_count = 0
                for file_path in scan_path.rglob('*'):
                    if file_path.is_file():
                        try:
                            if not file_path.exists():
                                processor.logger.error(f"File not found: {file_path}")
                                continue
                                
                            processor.executor.submit(
                                processor.scan_file,
                                file_path=file_path,
                                src_ip="DIRECT-SCAN",
                                dest_ip="N/A",
                                timestamp=datetime.now(timezone.utc)
                            )
                            file_count += 1
                        except Exception as e:
                            processor.logger.error(f"Error submitting file: {str(e)}")
                processor.logger.info(f"Submitted {file_count} files for scanning")
            else:
                if not scan_path.exists():
                    processor.logger.error(f"File not found: {scan_path}")
                    sys.exit(1)
                    
                processor.scan_file(
                    file_path=scan_path,
                    src_ip="DIRECT-SCAN",
                    dest_ip="N/A",
                    timestamp=datetime.now(timezone.utc)
                )

            processor.executor.shutdown(wait=True)
            processor.logger.info("Direct scan completed")

        elif args.zeek_log:
            processor.process_zeek_log(args.zeek_log)

        if args.metrics:
            print("\n=== Scan Metrics ===")
            print(f"Scanned files: {METRICS.scanned_files}")
            print(f"Threats detected: {METRICS.threats_detected}")
            print(f"Processing errors: {METRICS.processing_errors}")

    except NIDSClamError as e:
        logging.error(f"Operational error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error: {str(e)}", exc_info=True)
        sys.exit(1)

# BPFDoor and Variant Detection Program PRD

## 1. Purpose
- Quickly and accurately detect BPFDoor and its variants (e.g., smartadm, dbus-srv, inode262394, rad, etc.) in Linux/Unix server environments.
- Minimize resource usage (CPU, memory, I/O) to avoid impacting operational services.

---

## 2. Main Features

### 2.1 Masqueraded Process Detection
- Detect BPFDoor and variants masquerading as at least 10 legitimate process names (including variants) in real-time/periodically using ps command or /proc parsing
- Manage the list of masqueraded process names via a configuration file for easy updates against new variants

### 2.2 Memory Mapping-Based Malware Detection
- Detect BPFDoor-specific memory mapping traces (e.g., /dev/shm/kdmtmpflush (deleted)) in /proc/<pid>/maps of suspicious processes
- Support for extended patterns used by variants (e.g., smartadm, dbus-srv, etc.)

### 2.3 File/Memory-Based Detection
- Detect based on IOC (Indicator of Compromise) such as filenames, hashes, sizes used by malware
- Consider cases where malware operates only in memory (deleted executables)

### 2.4 Resource Optimization
- Selectively scan only processes matching the masqueraded process name list, not all system processes
- Multi-threaded/asynchronous processing to reduce scan time, options to limit CPU/memory usage
- Target to complete detection within 1 minute even on large servers

### 2.5 Reporting and Alerts
- Notify administrators of detection results via syslog, file, email, etc.
- Provide immediate alerts and detailed logs in case of suspected infection

### 2.6 Extensibility and Maintenance
- Design structure for easy updates of new variant IOCs, process names, memory patterns, etc.
- Support for seamless updates via configuration/pattern files

---

## 3. Non-functional Requirements

- **Performance**: CPU usage below 5%, memory usage below 50MB (default), scan time within 1 minute (for 1,000 processes)
- **Compatibility**: Linux (kernel 3.x+), major distributions (RHEL, Ubuntu, CentOS, etc.), some Unix support
- **Security**: Minimize need for root privileges, prohibit unnecessary external communication
- **Deployment/Operation**: Single binary/script, easy installation and removal
- **Logging**: All detection/errors/warnings recorded in separate log files and syslog

---

## 4. Detection Logic Summary

1. **First Filter by Process Name**
   - Filter using the masqueraded process name list from ps or /proc

2. **Second Precision Detection by Memory Mapping**
   - Detect BPFDoor/variant memory traces (e.g., kdmtmpflush, smartadm, etc.) in /proc/<pid>/maps

3. **Third Detection by IOC**
   - Match with IOC such as filename, hash, size

4. **Alert and record detailed logs upon detection**

---

## 5. UI/UX and Usability

- CLI-based interface
- Command options such as --scan, --report, --update-patterns
- Results provided via standard output and file/log

---

## 6. Maintenance and Extension

- Manage IOCs, process names, memory patterns, etc. via external configuration files
- Enable quick pattern updates for new variants

---

## 7. Example Detection Scenario

1. `ps -ef | grep <masqueraded process name>` → Extract PID
2. `cat /proc/<PID>/maps | grep -E 'kdmtmpflush|smartadm|dbus-srv|inode262394|rad'`
3. If matched, suspect infection and alert administrator

---

## 8. Programming Language and Distribution

- Python3 (recommended, mainly standard library)
- Single file or minimal dependency package
- Support for system service (optional) or manual execution

---

## 9. Others

- Optionally link with IOC updates from KISA, BOHO, and other security agencies
- Provide administrator guide and response manual

---

**Contact and Feedback:**  
Contact the security team or responsible developer 
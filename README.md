# BPFDoor Quick-Check

BPFDoor Quick-Check is an advanced open-source detection tool for BPFDoor and its variants (e.g., dbus-srv, inode262394, rad, etc.) targeting Linux/Unix systems.  
It provides comprehensive detection capabilities for process masquerading, memory mapping, BPF code signatures, kernel modules, network anomalies, and suspicious files.

## Features

- **Accurate Detection**: Identifies BPFDoor and variants using process name, memory, and file patterns.
- **Variant Coverage**: Includes latest IoCs and detection logic from KISA/SKT and security advisories.
- **Extensible & Structured**: Easily update detection patterns, process names, and signatures.
- **Resource Efficient**: Fast, selective scanning with minimal impact on system performance.
- **Detailed Logging**: Outputs detailed logs to `/var/log` or `/tmp` for incident response and auditing.
- **Cross-Platform**: Designed for major Linux distributions and compatible Unix systems.

## Usage

1. Grant execute permission:
   ```bash
   chmod +x bpfdoor_quickcheck_v2.sh
   ```
2. Run as root for full detection:
   ```bash
   sudo ./bpfdoor_quickcheck_v2.sh
   ```
3. Review the log file:
   ```bash
   cat /var/log/bpfdoor_scan_$(date +%F).log
   ```

> **Note:**  
> If you edit the script on Windows, convert line endings to Unix format using `dos2unix` before running on Linux.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

## Contribution

Contributions, bug reports, and suggestions are welcome!  
Please open an issue or submit a pull request.

---

Copyright (c) 2025 Eastsun Security Corp

For questions or feedback, contact the security team or the project maintainer:
📧 sh.lee@eastsunsecurity.com 
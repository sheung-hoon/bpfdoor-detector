#!/usr/bin/env bash
# --- BPFDoor/Variant Detection Script v1.1.0 ---------------------------------
# - Comprehensive detection tool for BPFDoor and its variants (dbus-srv, inode262394, rad, etc.)
# - Process masquerading, memory pattern, BPF filter code signature check
# - Logic fixes, improved accuracy, structured design
# - Developed: 2025-05-07, Updated: 2025-05-08
# ---------------------------------------------------------------------
set +e; shopt -s nullglob

# ---- Function definitions for structure ----
log() {
  local level="$1"
  local message="$2"
  local timestamp=$(date +"%H:%M:%S")
  echo "[$timestamp] $level $message" | tee -a "$LOG_FILE"
}

check_dependencies() {
  log "*" "Checking dependencies..."
  for cmd in ps grep readlink sed awk; do
    command -v "$cmd" >/dev/null || { 
      log "ERROR" "$cmd command not found. Stopping script execution." 
      exit 1
    }
  done
  
  # Check for advanced analysis tools
  HEXDUMP_AVAILABLE=0
  STRINGS_AVAILABLE=0
  command -v hexdump >/dev/null && HEXDUMP_AVAILABLE=1
  command -v strings >/dev/null && STRINGS_AVAILABLE=1
  
  if [[ $HEXDUMP_AVAILABLE -eq 1 ]]; then
    log "*" "hexdump found: Binary signature detection enabled."
  else
    log "WARN" "hexdump not found: Binary signature detection disabled."
  fi
  
  if [[ $STRINGS_AVAILABLE -eq 1 ]]; then
    log "*" "strings found: Memory string search enabled."
  else
    log "WARN" "strings not found: Memory string search disabled."
  fi
}

init_log() {
  # Log setup
  LOG_DIR="/var/log"
  [[ -w "$LOG_DIR" ]] || LOG_DIR="/tmp"
  LOG_FILE="$LOG_DIR/bpfdoor_scan_$(date +%F).log"
  if [[ -f "$LOG_FILE" ]]; then
    mv "$LOG_FILE" "${LOG_FILE}.$(date +%s).bak"
  fi
  :> "$LOG_FILE" && chmod 600 "$LOG_FILE"
  
  log "*" "BPFDoor/Variant comprehensive detection scan $(date)"
  log "*" "Includes core BPF filter signature detection."
  
  # Root privilege warning
  if [[ $EUID -ne 0 ]]; then
    log "WARN" "Without root privileges, reading /proc/*/maps and /proc/*/mem is limited."
    log "WARN" "Run with sudo for more accurate detection."
  fi
}

check_crlf() {
  # Self-check for line ending format
  if grep -q $'\r' "$0"; then
    log "WARN" "This script contains Windows line endings (CRLF)."
    if command -v dos2unix >/dev/null; then
      log "*" "Attempting automatic conversion with dos2unix..."
      dos2unix "$0"
      log "*" "Conversion complete. Please re-run the script."
      exit 1
    else
      log "WARN" "dos2unix utility is not installed."
      log "WARN" "Please install and convert with the following commands:"
      log "WARN" "  sudo apt-get install dos2unix"
      log "WARN" "  dos2unix $0"
      exit 1
    fi
  fi
}

scan_processes() {
  log "*" "Scanning processes..."
  local sus_pids=()
  
  ps -eo pid,comm,args --no-headers | while read -r pid comm args; do
    local full_cmd="$comm $args"
    local is_suspicious=0
    
    # Check each masqueraded process name directly (precise filtering)
    for name in "${NAMES[@]}"; do
      if [[ "$full_cmd" == *"$name"* ]]; then
        # Suspicious process found
        local maps="/proc/$pid/maps"
        local mem="/proc/$pid/mem"
        local exe=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "unknown")
        
        # Path masquerading check
        if [[ -n "$exe" && "$exe" != "unknown" ]]; then
          # Check if the executable file exists in the expected path
          local expected_path=0
          local base_name=$(echo "$name" | awk '{print $1}' | xargs basename 2>/dev/null)
          
          if [[ -n "$base_name" && "$exe" =~ ^/(usr/(s)?bin|sbin)/$base_name$ ]]; then
            expected_path=1
          fi
          
          if [[ $expected_path -eq 0 ]]; then
            log "!" "Path mismatch: PID=$pid ($full_cmd) exe=$exe"
            sus_pids+=("$pid")
            is_suspicious=1
          fi
        fi
        
        # Memory mapping pattern check
        if [[ ! -r "$maps" ]]; then
          log "WARN" "Failed to access PID=$pid (/proc/$pid/maps)"
          ((ACCESS_FAIL++))
        elif grep -qEi "$PATTERNS" "$maps"; then
          log "!!" "Suspicious: PID=$pid ($full_cmd) — Pattern match in '$maps'"
          grep -Ei "$PATTERNS" "$maps" | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
          sus_pids+=("$pid")
          is_suspicious=1
        fi
        
        # Memory content BPF filter pattern check (using strings)
        if [[ -r "$mem" && $STRINGS_AVAILABLE -eq 1 ]]; then
          if strings "$mem" 2>/dev/null | grep -qEi "$BPF_PATTERNS"; then
            log "!!" "Suspicious: PID=$pid ($full_cmd) — BPF code pattern found in memory"
            strings "$mem" 2>/dev/null | grep -Ei "$BPF_PATTERNS" | head -5 | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
            sus_pids+=("$pid")
            is_suspicious=1
          fi
        fi
        
        # Memory content BPF code signature check (using hexdump)
        if [[ -r "$mem" && $HEXDUMP_AVAILABLE -eq 1 ]]; then
          for signature in "${BPF_SIGNATURES[@]}"; do
            if hexdump -C "$mem" 2>/dev/null | grep -q "$signature"; then
              log "!!" "Confirmed BPFDoor signature found: PID=$pid ($full_cmd)"
              log " " "BPF filter signature '$signature' found in memory"
              sus_pids+=("$pid")
              is_suspicious=1
              break  # Enough if one is found
            fi
          done
        fi
        
        if [[ $is_suspicious -eq 1 ]]; then
          ((SUSPECT_COUNT++))
        fi
        
        break  # Found matching name, move to next process
      fi
    done
  done
  
  # Remove duplicates (same PID can match multiple conditions)
  SUSPICIOUS_PIDS=($(echo "${sus_pids[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
  log "*" "Suspicious process count: ${#SUSPICIOUS_PIDS[@]}"
}

check_kernel_modules() {
  if [[ -r /proc/modules ]] && command -v lsmod >/dev/null; then
    log "*" "Checking kernel modules..."
    
    # Specific malicious module pattern search (general BPF/sock logging only)
    if lsmod | grep -qE "bpfdoor|inode262394|dbus_srv"; then
      log "!!" "Known BPFDoor related kernel modules found:"
      lsmod | grep -E "bpfdoor|inode262394|dbus_srv" | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
      ((SUSPECT_COUNT++))
    fi
    
    # General BPF/socket modules are logging only (high false positive possibility)
    if lsmod | grep -qEi "bpf|filter|sock"; then
      log "*" "BPF/socket related kernel modules (can exist on normal systems):"
      lsmod | grep -Ei "bpf|filter|sock" | head -5 | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
    fi
  fi
}

check_network() {
  if command -v ss >/dev/null; then
    log "*" "Checking network connection..."
    
    # Suspicious IP check (precise matching)
    for ip in "${SUSPICIOUS_IPS[@]}"; do
      # Precise IP address matching pattern
      if ss -tuln | grep -E "(^|[[:space:]])${ip//./\\.}([[:space:]]|$|:)" >/dev/null; then
        log "!!" "Suspicious IP ($ip) communication detected"
        ss -tuln | grep -E "(^|[[:space:]])${ip//./\\.}([[:space:]]|$|:)" | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
        ((SUSPECT_COUNT++))
      fi
      
      # Outbound connection check
      if ss -anp 2>/dev/null | grep -E "(^|[[:space:]])${ip//./\\.}([[:space:]]|$|:)" >/dev/null; then
        log "!!" "Suspicious IP ($ip) outbound connection detected"
        ss -anp 2>/dev/null | grep -E "(^|[[:space:]])${ip//./\\.}([[:space:]]|$|:)" | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
        ((SUSPECT_COUNT++))
      fi
    done
    
    # RAW socket check (related to BPF filter)
    if ss -a | grep -qi "raw"; then
      log "!" "RAW socket found (BPF filter suspicion)"
      ss -a | grep -i "raw" | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
      ((SUSPECT_COUNT++))
    fi
    
    # Protocol 4444 port (BPFDoor default port)
    if ss -tuln | grep -q ":4444 "; then
      log "!" "BPFDoor default port (4444) listening detected"
      ss -tuln | grep ":4444 " | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
      ((SUSPECT_COUNT++))
    fi
  else
    log "WARN" "ss command not found, skipping network check"
  fi
}

check_raw_sockets() {
  if [[ -r /proc/net/raw ]]; then
    log "*" "Checking RAW socket table..."
    local raw_active=$(grep -v "00000000:0000" /proc/net/raw 2>/dev/null || echo "")
    
    if [[ -n "$raw_active" ]]; then
      log "!" "Active RAW socket found (BPF filter suspicion)"
      echo "$raw_active" | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
      ((SUSPECT_COUNT++))
    fi
  fi
}

check_parent_processes() {
  if [[ ${#SUSPICIOUS_PIDS[@]} -gt 0 ]]; then
    log "*" "Checking parent processes of suspicious processes:"
    for pid in "${SUSPICIOUS_PIDS[@]}"; do
      local ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
      if [[ -n "$ppid" && "$ppid" != "1" ]]; then
        local parent_cmd=$(ps -o cmd= -p "$ppid" 2>/dev/null || echo "unknown")
        log " " "Parent PID=$ppid: $parent_cmd"
        
        # Check parent process's memory mapping
        local parent_maps="/proc/$ppid/maps"
        if [[ -r "$parent_maps" ]] && grep -qEi "$PATTERNS" "$parent_maps"; then
          log "!!" "BPFDoor pattern found in parent PID=$ppid"
          grep -Ei "$PATTERNS" "$parent_maps" | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
          SUSPICIOUS_PIDS+=("$ppid")
          ((SUSPECT_COUNT++))
        fi
        
        # BPF code signature check in parent process memory
        local parent_mem="/proc/$ppid/mem"
        if [[ -r "$parent_mem" && $HEXDUMP_AVAILABLE -eq 1 ]]; then
          for signature in "${BPF_SIGNATURES[@]}"; do
            if hexdump -C "$parent_mem" 2>/dev/null | grep -q "$signature"; then
              log "!!" "BPF signature found in parent PID=$ppid"
              SUSPICIOUS_PIDS+=("$ppid")
              ((SUSPECT_COUNT++))
              break
            fi
          done
        fi
      fi
    done
    
    # Remove duplicates again
    SUSPICIOUS_PIDS=($(echo "${SUSPICIOUS_PIDS[@]}" | tr ' ' '\n' | sort -u | tr '\n' ' '))
  fi
}

scan_filesystem() {
  if command -v find >/dev/null && [[ $EUID -eq 0 ]]; then
    log "*" "Searching for suspicious files in filesystem... (max 1 minute)"
    
    # General pattern search (modified grep -E option)
    local suspicious_files=$(find /dev/shm /tmp /var/tmp -type f -name "*" 2>/dev/null | 
                            xargs grep -lE "$PATTERNS" 2>/dev/null || true)
    
    if [[ -n "$suspicious_files" ]]; then
      log "!" "Suspicious files found:"
      echo "$suspicious_files" | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
      ((SUSPECT_COUNT++))
    fi
    
    # BPF filter related source code search
    local suspicious_source=$(find /root /home /tmp /var/tmp -type f \( -name "*.c" -o -name "*.h" \) 2>/dev/null | 
                             xargs grep -lE "sock_fprog|sock_filter|bpf_code" 2>/dev/null || true)
    
    if [[ -n "$suspicious_source" ]]; then
      log "!" "BPF filter code found in source files:"
      echo "$suspicious_source" | sed 's/^/     ↳ /' | tee -a "$LOG_FILE"
      ((SUSPECT_COUNT++))
    fi
    
    # BPF signature search in executable files
    if [[ $HEXDUMP_AVAILABLE -eq 1 ]]; then
      for dir in /dev/shm /tmp /var/tmp; do
        if [[ -d "$dir" ]]; then
          local executable_files=$(find "$dir" -type f -executable -size -10M 2>/dev/null || true)
          
          if [[ -n "$executable_files" ]]; then
            log "*" "Checking executable files in $dir directory..."
            
            for file in $executable_files; do
              for signature in "${BPF_SIGNATURES[@]}"; do
                if hexdump -C "$file" 2>/dev/null | grep -q "$signature"; then
                  log "!!" "BPF signature found in executable file: $file"
                  log " " "Signature: $signature"
                  ((SUSPECT_COUNT++))
                  break
                fi
              done
            done
          fi
        fi
      done
    fi
  else
    log "WARN" "Skipping filesystem scan (root privileges required)"
  fi
}

print_summary() {
  log "*" "Scan complete"
  log "*" "Suspect cases: $SUSPECT_COUNT, Access failure: $ACCESS_FAIL"
  log "*" "Log: $LOG_FILE"
  
  if [[ $SUSPECT_COUNT -gt 0 ]]; then
    log "!!" "BPFDoor infection suspicion! Recommend reporting to BOHO (boho.or.kr)"
    log " " "1. Isolate suspicious process (network isolation)"
    log " " "2. Collect memory dump (for future analysis)"
    log " " "3. Check BPF filter usage (raw socket, kernel module check)"
    log " " "4. Recommend full system backup and format (difficult to completely remove backdoor)"
    log " " "5. KISA call number: 118 without area code"
  else
    log "*" "No current BPFDoor infection suspicion found."
  fi
  
  log "*" "It's recommended to run this script regularly."
  log "*" "crontab example: 0 */4 * * * /path/to/this/script.sh"
  log "*" "@reboot /path/to/this/script.sh (Automatically run on system reboot)"
}

# ---- Main execution flow ----

# 0) Initialize global variables
SUSPECT_COUNT=0
ACCESS_FAIL=0

# 1) Masqueraded process names (10 from specification)
NAMES=(
  "/sbin/udevd -d" 
  "/sbin/mingetty /dev/tty7" 
  "/usr/sbin/console-kit-daemon --no-daemon"
  "hald-addon-acpi: listening on acpi kernel interface /proc/acpi/event"
  "dbus-daemon --system" 
  "hald-runner" 
  "pickup -l -t fifo -u"
  "avahi-daemon: chroot helper" 
  "/sbin/auditd -n" 
  "/usr/lib/systemd/systemd-journald"
)

# 2) Memory/file patterns (specification/KISA IoC)
PATTERNS='/dev/shm/kdmtmpflush|smartadm|dbus-srv|inode262394|rad|hald-addon-volume|hpasmmld|gm|File_in_Inode_#1900667'

# 3) BPF filter feature pattern (based on source code analysis)
BPF_PATTERNS='sock_fprog|sock_filter|bpf_code|filter\.len|sizeof\(bpf_code\)'

# 4) BPF code signature (hexadecimal pattern)
BPF_SIGNATURES=(
  "28 00 00 00 00 00 00 0c"  # 0x28, 0, 0, 0x0000000c
  "15 00 1b 00 00 00 00 00"  # 0x15, 0, 27, 0x00000000
  "30 00 00 00 00 00 00 17"  # 0x30, 0, 0, 0x00000017
  "15 00 05 00 00 00 00 11"  # 0x15, 0, 5, 0x00000011
  "45 00 00 00 00 00 01 ff"  # 0x45, 0, 0, 0x000001ff
)

# 5) Suspicious IP list
SUSPICIOUS_IPS=("165.232.174.130")

# 6) Main execution flow
check_crlf        # Line ending character check
init_log          # Log initialization
check_dependencies # Dependency check
scan_processes     # Process scan
check_kernel_modules # Kernel module check
check_network     # Network check
check_raw_sockets # RAW socket check
check_parent_processes # Parent process check
scan_filesystem   # Filesystem scan
print_summary     # Result summary

exit $SUSPECT_COUNT
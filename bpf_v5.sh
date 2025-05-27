#!/bin/bash

#####################################################################
# BPFDoor 악성코드 종합 점검 스크립트 (v5)
# - bpf.sh의 모든 탐지 로직 + bpf_v2.sh의 컬러/로깅/리포트 스타일
# - 점수/스코어링 없이 3단계 결과만 출력
#####################################################################

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 전역 변수
SCRIPT_VERSION="5.0"
HOSTNAME=$(hostname)
CHECK_DATE=$(date '+%Y-%m-%d %H:%M:%S')
REPORT_DIR="/tmp/bpfdoor_check_$(date +%Y%m%d_%H%M%S)"
REPORT_FILE="${REPORT_DIR}/bpfdoor_check_report.txt"
SUSPICIOUS_FILES="${REPORT_DIR}/suspicious_files.txt"
LOG_FILE="${REPORT_DIR}/check.log"
FOUND_SUSPICIOUS=0
FOUND_CONFIRMED=0

# 화이트리스트 정의
WHITELIST_PROCESSES=(
    "systemd" "init" "kernel" "NetworkManager" "systemd-networkd" "sshd" "chronyd" "rsyslogd" "kworker" "dbus-srv" "inode262394"
)
WHITELIST_PORTS=(
    "8000" "42391-43390"
)
WHITELIST_HUERISTIC_PATHS=(
    "/usr/lib/systemd/systemd" "/usr/bin/podman" "/usr/sbin/NetworkManager" "/usr/lib/systemd/systemd-networkd"
)

# 로그/리포트/진행 표시 함수
log_message() {
    local level=$1; local message=$2; local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[${timestamp}] [${level}] ${message}" >> "${LOG_FILE}"
    case ${level} in
        "INFO") echo -e "${BLUE}[*] ${message#*] }${NC}" ;;
        "WARNING") echo -e "${YELLOW}[!] ${message#*] }${NC}" ;;
        "ALERT") echo -e "${RED}[!] ${message#*] }${NC}"; FOUND_SUSPICIOUS=1 ;;
        "CONFIRM") echo -e "${RED}[!!] ${message#*] }${NC}"; FOUND_CONFIRMED=1 ;;
        "SUCCESS") echo -e "${GREEN}[✓] ${message#*] }${NC}" ;;
    esac
}
show_progress() {
    local current=$1; local total=$2; local message=$3
    local width=50; local progress=$((current * width / total)); local percentage=$((current * 100 / total))
    printf "\r[%-${width}s] %d%% %s" "$(printf '#%.0s' $(seq 1 $progress))" $percentage "$message"
}

init_check() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[!] 이 스크립트는 root 권한으로 실행해야 합니다.${NC}"; exit 1
    fi
    mkdir -p "${REPORT_DIR}" || { echo -e "${RED}[!] 보고서 디렉토리 생성 실패: ${REPORT_DIR}${NC}"; exit 1; }
    touch "${REPORT_FILE}" "${SUSPICIOUS_FILES}" "${LOG_FILE}"
    chmod 600 "${REPORT_FILE}" "${SUSPICIOUS_FILES}" "${LOG_FILE}"
    {
        echo "=================================================="
        echo "BPFDoor 점검 로그"
        echo "=================================================="
        echo "점검 시작 시간: $(date)"
        echo "시스템 정보:"
        echo "- 호스트명: $(hostname)"
        echo "- 커널 버전: $(uname -r)"
        echo "- OS 버전: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
        echo "=================================================="
        echo ""
    } > "${LOG_FILE}"
    {
        echo "=================================================="
        echo "BPFDoor 점검 보고서"
        echo "=================================================="
        echo "점검 시작 시간: $(date)"
        echo "시스템 정보:"
        echo "- 호스트명: $(hostname)"
        echo "- 커널 버전: $(uname -r)"
        echo "- OS 버전: $(cat /etc/os-release | grep PRETTY_NAME | cut -d'"' -f2)"
        echo "=================================================="
        echo ""
    } > "${REPORT_FILE}"
    echo -e "${BLUE}[*] BPFDoor/변종 종합 탐지 스캔 시작${NC}"
    echo -e "${BLUE}[*] 시스템 정보: $(uname -a)${NC}"
    echo -e "${BLUE}[*] 검사 시간: $(date)${NC}"
    echo -e "${BLUE}[*] 호스트명: $(hostname)${NC}"
    echo -e "${BLUE}[*] ----------------------------------------${NC}"
}

# --- 주요 탐지 함수 (bpf.sh에서 추출, log_message 스타일로 통일) ---
# 1. 뮤텍스/락 파일 점검
check_mutex_files() {
    log_message "INFO" "[1/11] 뮤텍스/락 파일 점검 시작..."
    echo -e "\n[1/11. 뮤텍스/락 파일 점검]" >> "${REPORT_FILE}"
    local suspicious_count=0; local files_checked=0
    while IFS= read -r file; do
        ((files_checked++))
        if [[ -f "$file" && $(stat -c "%s" "$file" 2>/dev/null) -eq 0 ]]; then
            local perms=$(stat -c "%a" "$file" 2>/dev/null)
            if [[ "$perms" == "644" ]]; then
                log_message "ALERT" "[1/11] 의심 파일 발견: $file (0 byte, 권한 644)"
                echo "의심 파일: $file (0 byte, 권한 644)" >> "${REPORT_FILE}"
                echo "$file" >> "${SUSPICIOUS_FILES}"
                ((suspicious_count++))
            fi
        fi
    done < <(find /var/run -name "*.pid" -o -name "*.lock" 2>/dev/null)
    if [[ $suspicious_count -eq 0 ]]; then
        log_message "SUCCESS" "[1/11] 뮤텍스/락 파일 점검 완료 - 이상 없음 (${files_checked}개 검사)"
        echo "결과: 이상 없음 (${files_checked}개 파일 검사)" >> "${REPORT_FILE}"
    else
        echo "결과: ${suspicious_count}개 의심 파일 발견" >> "${REPORT_FILE}"
    fi
}
# 2. 자동 실행 파일 점검
check_autostart_files() {
    log_message "INFO" "[2/11] 자동 실행 파일 점검 시작..."
    echo -e "\n[2/11. 자동 실행 파일 점검]" >> "${REPORT_FILE}"
    local suspicious_count=0
    if [[ -d "/etc/sysconfig" ]]; then
        while IFS= read -r file; do
            if grep -qE '\[\s*-f\s+/[^]]+\]\s*&&\s*/' "$file" 2>/dev/null; then
                local content=$(grep -E '\[\s*-f\s+/[^]]+\]\s*&&\s*/' "$file" 2>/dev/null)
                log_message "ALERT" "[2/11] 의심 자동실행 설정 발견: $file"
                echo "의심 파일: $file" >> "${REPORT_FILE}"
                echo "내용: $content" >> "${REPORT_FILE}"
                ((suspicious_count++))
            fi
        done < <(find /etc/sysconfig -type f 2>/dev/null)
    fi
    if [[ $suspicious_count -eq 0 ]]; then
        log_message "SUCCESS" "[2/11] 자동 실행 파일 점검 완료 - 이상 없음"
        echo "결과: 이상 없음" >> "${REPORT_FILE}"
    else
        echo "결과: ${suspicious_count}개 의심 설정 발견" >> "${REPORT_FILE}"
    fi
}
# 3. BPF 필터 점검
check_bpf_filters() {
    log_message "INFO" "[3/11] BPF 필터 점검 시작..."
    echo -e "\n[3/11. BPF 필터 점검]" >> "${REPORT_FILE}"
    if ! command -v ss &> /dev/null; then
        log_message "WARNING" "[3/11] ss 명령어가 없어 BPF 점검을 건너뜁니다."
        echo "결과: ss 명령어 없음 - 점검 생략" >> "${REPORT_FILE}"
        return
    fi
    local bpf_output=$(ss -0pb 2>/dev/null)
    local magic_numbers=("21139" "29269" "960051513" "36204" "40783")
    local found_suspicious=0
    for magic in "${magic_numbers[@]}"; do
        if echo "$bpf_output" | grep -q "$magic"; then
            log_message "ALERT" "[3/11] 의심 BPF 매직넘버 발견: $magic"
            echo "의심 매직넘버 발견: $magic" >> "${REPORT_FILE}"
            ((found_suspicious++))
        fi
    done
    if [[ $found_suspicious -eq 0 ]]; then
        log_message "SUCCESS" "[3/11] BPF 필터 점검 완료 - 이상 없음"
        echo "결과: 이상 없음" >> "${REPORT_FILE}"
    else
        echo "결과: ${found_suspicious}개 의심 패턴 발견" >> "${REPORT_FILE}"
        echo "$bpf_output" >> "${REPORT_FILE}"
    fi
}
# 4. RAW 소켓 사용 점검
check_raw_sockets() {
    log_message "INFO" "[4/11] RAW 소켓 사용 점검 시작..."
    echo -e "\n[4/11. RAW 소켓 사용 점검]" >> "${REPORT_FILE}"
    local suspicious_pids=()
    if command -v lsof &> /dev/null; then
        while IFS= read -r pid; do
            local proc_name=$(ps -p "$pid" -o comm= 2>/dev/null)
            local is_whitelisted=0
            for white_proc in "${WHITELIST_PROCESSES[@]}"; do
                if [[ "$proc_name" == *"$white_proc"* ]]; then is_whitelisted=1; break; fi
            done
            if [[ $is_whitelisted -eq 0 ]]; then suspicious_pids+=("$pid"); fi
        done < <(lsof 2>/dev/null | grep -E "IP type=SOCK_RAW|IP type=SOCK_DGRAM" | awk '{print $2}' | sort -u)
    fi
    if [[ ${#suspicious_pids[@]} -eq 0 ]]; then
        log_message "SUCCESS" "[4/11] RAW 소켓 점검 완료 - 이상 없음"
        echo "결과: 이상 없음" >> "${REPORT_FILE}"
    else
        log_message "ALERT" "[4/11] 의심 프로세스 ${#suspicious_pids[@]}개 발견 (추가 검증 필요)"
        echo "결과: ${#suspicious_pids[@]}개 의심 프로세스 발견" >> "${REPORT_FILE}"
        for pid in "${suspicious_pids[@]}"; do
            local exe_path=$(readlink -f /proc/$pid/exe 2>/dev/null)
            local proc_info=$(ps -fp $pid 2>/dev/null | tail -n 1)
            echo "PID: $pid, 경로: $exe_path" >> "${REPORT_FILE}"
            echo "프로세스 정보: $proc_info" >> "${REPORT_FILE}"
            if [[ "$exe_path" == *"(deleted)"* ]]; then log_message "CONFIRM" "[4/11] 삭제된 파일에서 실행 중: PID $pid"; fi
        done
    fi
}
# 5. 환경변수 점검
check_environment_vars() {
    log_message "INFO" "[5/11] 프로세스 환경변수 점검 시작..."
    echo -e "\n[5/11. 프로세스 환경변수 점검]" >> "${REPORT_FILE}"
    local check_envs=("HOME=/tmp" "HISTFILE=/dev/null" "MYSQL_HISTFILE=/dev/null")
    local suspicious_count=0; local total_procs=$(ls /proc/ | grep -E '^[0-9]+$' | wc -l); local current_proc=0
    for pid in $(ls /proc/ | grep -E '^[0-9]+$'); do
        ((current_proc++))
        if [[ $((current_proc % 100)) -eq 0 ]]; then show_progress $current_proc $total_procs "프로세스 환경변수 점검 진행 중..."; fi
        if [[ -r /proc/$pid/environ ]]; then
            local env_data=$(tr '\0' '\n' < /proc/$pid/environ 2>/dev/null)
            local match_count=0
            for check_env in "${check_envs[@]}"; do
                if echo "$env_data" | grep -q "$check_env"; then ((match_count++)); fi
            done
            if [[ $match_count -eq ${#check_envs[@]} ]]; then
                local proc_info=$(ps -p $pid -o user=,pid=,ppid=,cmd= 2>/dev/null)
                log_message "ALERT" "[5/11] 의심 환경변수 프로세스: PID $pid"
                echo "의심 프로세스: $proc_info" >> "${REPORT_FILE}"
                ((suspicious_count++))
            fi
        fi
    done
    printf "\r%-60s\r" " "
    if [[ $suspicious_count -eq 0 ]]; then
        log_message "SUCCESS" "[5/11] 환경변수 점검 완료 - 이상 없음"
        echo "결과: 이상 없음" >> "${REPORT_FILE}"
    else
        echo "결과: ${suspicious_count}개 의심 프로세스 발견" >> "${REPORT_FILE}"
    fi
}
# 6. 의심 포트 점검
check_suspicious_ports() {
    log_message "INFO" "[6/11] 의심 포트 점검 시작..."
    echo -e "\n[6/11. 의심 포트 점검]" >> "${REPORT_FILE}"
    local suspicious_ports=(); local port_range_start=42391; local port_range_end=43390; local specific_port=8000
    if command -v netstat &> /dev/null; then
        local net_output=$(netstat -tulpn 2>/dev/null)
    elif command -v ss &> /dev/null; then
        local net_output=$(ss -tulpn 2>/dev/null)
    else
        log_message "WARNING" "[6/11] netstat/ss 명령어가 없어 포트 점검을 건너뜁니다."
        echo "결과: 점검 도구 없음 - 점검 생략" >> "${REPORT_FILE}"
        return
    fi
    while IFS= read -r line; do
        if [[ "$line" =~ :([0-9]+)[[:space:]] ]]; then
            local port="${BASH_REMATCH[1]}"; local is_whitelisted=0
            for white_port in "${WHITELIST_PORTS[@]}"; do
                if [[ "$white_port" == *"-"* ]]; then
                    local start_port=${white_port%-*}; local end_port=${white_port#*-}
                    if [[ $port -ge $start_port && $port -le $end_port ]]; then is_whitelisted=1; break; fi
                elif [[ "$port" == "$white_port" ]]; then is_whitelisted=1; break; fi
            done
            if [[ $is_whitelisted -eq 0 ]]; then
                if [[ $port -ge $port_range_start && $port -le $port_range_end ]] || [[ $port -eq $specific_port ]]; then
                    suspicious_ports+=("$port"); echo "의심 포트 발견: $port" >> "${REPORT_FILE}"; echo "$line" >> "${REPORT_FILE}"
                fi
            fi
        fi
    done <<< "$net_output"
    if [[ ${#suspicious_ports[@]} -eq 0 ]]; then
        log_message "SUCCESS" "[6/11] 포트 점검 완료 - 이상 없음"
        echo "결과: 이상 없음" >> "${REPORT_FILE}"
    else
        log_message "ALERT" "[6/11] ${#suspicious_ports[@]}개 의심 포트 발견"
        echo "결과: ${#suspicious_ports[@]}개 의심 포트 발견" >> "${REPORT_FILE}"
    fi
}
# 7. 의심 프로세스명 점검
check_process_names() {
    log_message "INFO" "[7/11] 의심 프로세스명 점검 시작..."
    echo -e "\n[7/11. 의심 프로세스명 점검]" >> "${REPORT_FILE}"
    local suspicious_procs=("/usr/sbin/abrtd" "/sbin/udevd" "cmathreshd" "/sbin/sgaSolAgent" "/usr/sbin/atd" "pickup")
    local found_count=0
    for proc_name in "${suspicious_procs[@]}"; do
        local pids=$(pgrep -f "$proc_name" 2>/dev/null)
        if [[ -n "$pids" ]]; then
            for pid in $pids; do
                local exe_path=$(readlink -f /proc/$pid/exe 2>/dev/null)
                local proc_cmdline=$(ps -p $pid -o args= 2>/dev/null)
                if [[ -n "$exe_path" && "$exe_path" != "$proc_name" && "$exe_path" != *"$proc_name"* ]]; then
                    log_message "ALERT" "[7/11] 의심 프로세스 발견: PID $pid ($proc_name)"
                    echo "의심 프로세스: PID $pid" >> "${REPORT_FILE}"
                    echo "  표시명: $proc_name" >> "${REPORT_FILE}"
                    echo "  실제경로: $exe_path" >> "${REPORT_FILE}"
                    echo "$exe_path" >> "${SUSPICIOUS_FILES}"
                    ((found_count++))
                fi
            done
        fi
    done
    if [[ $found_count -eq 0 ]]; then
        log_message "SUCCESS" "[7/11] 프로세스명 점검 완료 - 이상 없음"
        echo "결과: 이상 없음" >> "${REPORT_FILE}"
    else
        echo "결과: ${found_count}개 의심 프로세스 발견" >> "${REPORT_FILE}"
    fi
}
# 8. 의심 파일 문자열 점검
check_suspicious_files_strings() {
    log_message "INFO" "[8/11] 의심 파일 문자열 점검 시작..."
    echo -e "\n[8/11. 의심 파일 문자열 점검]" >> "${REPORT_FILE}"
    if [[ ! -f "${SUSPICIOUS_FILES}" || ! -s "${SUSPICIOUS_FILES}" ]]; then
        log_message "INFO" "[8/11] 점검할 의심 파일이 없습니다."
        echo "결과: 점검 대상 없음" >> "${REPORT_FILE}"
        return
    fi
    local patterns=("MYSQL_HISTFILE=/dev/null" ":h:d:l:s:b:t:" ":f:wiunomc" ":f:x:wiuoc" "ttcompat" "/dev/ptmH")
    local detected_count=0
    while IFS= read -r file; do
        if [[ -f "$file" && -r "$file" ]]; then
            log_message "INFO" "[8/11] 파일 검사 중: $file"
            for pattern in "${patterns[@]}"; do
                if strings -a -n 5 "$file" 2>/dev/null | grep -q "$pattern"; then
                    log_message "CONFIRM" "[8/11] 악성 패턴 발견: $file (패턴: $pattern)"
                    echo "악성 패턴 발견: $file" >> "${REPORT_FILE}"
                    echo "  패턴: $pattern" >> "${REPORT_FILE}"
                    ((detected_count++))
                    break
                fi
            done
        fi
    done < "${SUSPICIOUS_FILES}"
    if [[ $detected_count -eq 0 ]]; then
        log_message "SUCCESS" "[8/11] 문자열 점검 완료 - 악성 패턴 없음"
        echo "결과: 악성 패턴 없음" >> "${REPORT_FILE}"
    else
        echo "결과: ${detected_count}개 파일에서 악성 패턴 발견" >> "${REPORT_FILE}"
    fi
}
# 9. (deleted) 상태 실행파일 점검
check_deleted_file() {
    log_message "INFO" "[9/11] 삭제된 파일에서 실행 중인 프로세스 검사 시작..."
    echo -e "\n[9/11. 삭제된 파일에서 실행 중인 프로세스 검사]" >> "${REPORT_FILE}"
    local found_count=0
    
    for pid in $(ls /proc | grep -E '^[0-9]+$'); do
        if [[ -L "/proc/$pid/exe" ]] && [[ "$(readlink "/proc/$pid/exe" 2>/dev/null)" == *"(deleted)"* ]]; then
            log_message "CONFIRM" "[9/11] 삭제된 파일에서 실행 중인 프로세스 발견: PID $pid"
            echo "의심 프로세스: PID $pid" >> "${REPORT_FILE}"
            echo "  실행파일: $(readlink "/proc/$pid/exe" 2>/dev/null)" >> "${REPORT_FILE}"
            ((found_count++))
        fi
    done
    
    if [[ $found_count -eq 0 ]]; then
        log_message "SUCCESS" "[9/11] 삭제된 파일 검사 완료 - 이상 없음"
        echo "결과: 이상 없음" >> "${REPORT_FILE}"
    else
        log_message "ALERT" "[9/11] 삭제된 파일 검사 완료 - ${found_count}개 의심 프로세스 발견"
        echo "결과: ${found_count}개 의심 프로세스 발견" >> "${REPORT_FILE}"
    fi
}
# 10. 커널 모듈 점검
check_kernel_modules() {
    log_message "INFO" "[10/11] 커널 모듈 점검 시작..."
    echo -e "\n[10/11. 커널 모듈 점검]" >> "${REPORT_FILE}"
    local suspicious_modules=(); local loaded_modules=$(lsmod | awk 'NR>1 {print $1}')
    for module in $loaded_modules; do
        if [[ ! -f "/lib/modules/$(uname -r)/kernel/drivers/$module.ko" ]] && \
           [[ ! -f "/lib/modules/$(uname -r)/kernel/net/$module.ko" ]]; then
            suspicious_modules+=("$module")
        fi
    done
    if [[ ${#suspicious_modules[@]} -eq 0 ]]; then
        log_message "SUCCESS" "[10/11] 커널 모듈 점검 완료 - 이상 없음"
        echo "결과: 이상 없음" >> "${REPORT_FILE}"
    else
        log_message "ALERT" "[10/11] ${#suspicious_modules[@]}개 의심 모듈 발견"
        echo "결과: ${#suspicious_modules[@]}개 의심 모듈 발견" >> "${REPORT_FILE}"
        for module in "${suspicious_modules[@]}"; do echo "- $module" >> "${REPORT_FILE}"; done
    fi
}
# 11. 네트워크 연결 점검
check_network() {
    log_message "INFO" "[11/11] 네트워크 연결 점검 시작..."
    echo -e "\n[11/11. 네트워크 연결 점검]" >> "${REPORT_FILE}"
    local suspicious_conns=(); local netstat_output
    if command -v netstat &> /dev/null; then
        netstat_output=$(netstat -tulpn 2>/dev/null)
    elif command -v ss &> /dev/null; then
        netstat_output=$(ss -tulpn 2>/dev/null)
    else
        log_message "WARNING" "[11/11] netstat/ss 명령어가 없어 네트워크 점검을 건너뜁니다."
        echo "결과: 점검 도구 없음 - 점검 생략" >> "${REPORT_FILE}"
        return
    fi

    # Whitelist common system services and localhost
    local whitelist_services=(
        "systemd-resolve"  # DNS resolver
        "chronyd"         # NTP service
        "ntpd"           # NTP service
        "dnsmasq"        # DNS service
        "named"          # BIND DNS service
    )
    local whitelist_ports=(
        "53"    # DNS
        "323"   # NTP
        "123"   # NTP
    )
    local whitelist_ips=(
        "127.0.0.1"
        "127.0.0.53"
        "127.0.0.54"
        "::1"
        "10.255.255.254"  # WSL2 DNS
    )

    while IFS= read -r line; do
        if [[ "$line" =~ :([0-9]+)[[:space:]] ]]; then
            local port="${BASH_REMATCH[1]}"
            local is_whitelisted=0
            
            # Check if port is whitelisted
            for white_port in "${whitelist_ports[@]}"; do
                if [[ "$port" == "$white_port" ]]; then
                    is_whitelisted=1
                    break
                fi
            done

            # Check if service is whitelisted
            for service in "${whitelist_services[@]}"; do
                if [[ "$line" == *"$service"* ]]; then
                    is_whitelisted=1
                    break
                fi
            done

            # Check if IP is whitelisted
            for ip in "${whitelist_ips[@]}"; do
                if [[ "$line" == *"$ip"* ]]; then
                    is_whitelisted=1
                    break
                fi
            done

            if [[ $is_whitelisted -eq 0 ]]; then
                suspicious_conns+=("$line")
            fi
        fi
    done <<< "$netstat_output"

    if [[ ${#suspicious_conns[@]} -eq 0 ]]; then
        log_message "SUCCESS" "[11/11] 네트워크 연결 점검 완료 - 이상 없음"
        echo "결과: 이상 없음" >> "${REPORT_FILE}"
    else
        log_message "ALERT" "[11/11] ${#suspicious_conns[@]}개 의심 연결 발견"
        echo "결과: ${#suspicious_conns[@]}개 의심 연결 발견" >> "${REPORT_FILE}"
        for conn in "${suspicious_conns[@]}"; do echo "$conn" >> "${REPORT_FILE}"; done
    fi
}

# --- 메인 실행 흐름 ---
main() {
    init_check
    check_mutex_files
    check_autostart_files
    check_bpf_filters
    check_raw_sockets
    check_environment_vars
    check_suspicious_ports
    check_process_names
    check_suspicious_files_strings
    check_deleted_file
    check_kernel_modules
    check_network
    echo -e "\n\n╔════════════════════════════════════════════════════════════╗"
    echo   "║                      BPFDoor 점검 결과                      ║"
    echo   "╠════════════════════════════════════════════════════════════╣"
    if [[ $FOUND_CONFIRMED -eq 1 ]]; then
        echo -e "║  ${RED}🛑 감염 확실, 전문가 진단 필요${NC}                      ║"
    elif [[ $FOUND_SUSPICIOUS -eq 1 ]]; then
        echo -e "║  ${YELLOW}⚠️ 감염 의심${NC}                                    ║"
    else
        echo -e "║  ${GREEN}✅ 감염 없음${NC}                                    ║"
    fi
    echo   "╚════════════════════════════════════════════════════════════╝"
    echo -e "\n상세 리포트: ${REPORT_FILE}"
    echo   "로그 파일: ${LOG_FILE}"
}

main 
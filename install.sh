#!/usr/bin/env bash
# install.sh – Install all core packages required by bpfdoor_scan.sh
# -----------------------------------------------------------------------------
# Supports    : apt (Debian/Ubuntu/Mint), yum (CentOS 7), dnf (RHEL 8+/Fedora),
#               apk (Alpine), pacman (Arch), zypper (openSUSE), offline mode
# Requires    : root privileges (or sudo) for online installation
# Usage       :
#   sudo ./install.sh <apt|yum|dnf|apk|pacman|zypper|offline>
#   # offline 모드에서는 ./deps/ 디렉터리에 패키지 파일을 미리 준비해둡니다.
# -----------------------------------------------------------------------------

# 스크립트 오류 발생 시 즉시 중단 (set -e), 정의되지 않은 변수 사용 시 오류 (set -u)
set -eu

# pipefail 옵션은 bash에서만 지원하므로, bash 환경인지 확인 후 설정 시도
if [ -n "$BASH_VERSION" ]; then
  set -o pipefail
fi

BASE_PKGS=(
  yara            # YARA engine
  jq              # JSON CLI utility
  lsof            # open file/socket list
  iproute2        # provides ss(8) on most distros (already present on many)
  net-tools       # legacy netstat(8)
  gzip            # log compression
  coreutils       # stat, readlink, etc.
  findutils       # find, xargs
  gawk            # awk
  grep sed procps # ps, etc.
)

usage() {
    echo "[사용법] sudo $0 <apt|yum|dnf|apk|pacman|zypper|offline>" >&2
    exit 1
}

# 인자 개수 확인
if [ "$#" -ne 1 ]; then #
    usage #
fi
MODE=$1 #

# 패키지 존재 여부 확인 함수 (패키지명, 명령어명)
check_pkg_installed() {
    local pkg="$1"; local cmd="$2"
    if command -v "$cmd" >/dev/null 2>&1; then return 0; fi
    return 1
}

# 각 패키지별 실제 명령어 매핑
PKG_CMDS=(
  "yara:yara"
  "jq:jq"
  "lsof:lsof"
  "iproute2:ss"
  "net-tools:netstat"
  "gzip:gzip"
  "coreutils:stat"
  "findutils:find"
  "gawk:awk"
  "grep:grep"
  "sed:sed"
  "procps:ps"
)

install_online() {
    local mgr="$1"; shift; local pkgs=()
    local missing_pkgs=()
    echo "[*] 패키지 설치 전, 누락된 패키지만 선별합니다."
    for entry in "${PKG_CMDS[@]}"; do
        pkg="${entry%%:*}"; cmd="${entry##*:}"
        if ! check_pkg_installed "$pkg" "$cmd"; then
            pkgs+=("$pkg")
            missing_pkgs+=("$pkg($cmd)")
        fi
    done
    if [ ${#pkgs[@]} -eq 0 ]; then
        echo "[+] 모든 필수 패키지가 이미 설치되어 있습니다."
        return 0
    fi
    echo "[*] 설치할 패키지: ${pkgs[*]}"
    case "$mgr" in
        apt)
            DEBIAN_FRONTEND=noninteractive apt-get update -y
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${pkgs[@]}"
            ;;
        yum)
            yum install -y "${pkgs[@]}"
            ;;
        dnf)
            dnf install -y "${pkgs[@]}"
            ;;
        apk)
            apk add --no-cache "${pkgs[@]}"
            ;;
        pacman)
            pacman -Syu --needed --noconfirm "${pkgs[@]}"
            ;;
        zypper)
            zypper --non-interactive install --no-recommends "${pkgs[@]}"
            ;;
        *)
            echo "[ERROR] 지원하지 않는 패키지 관리자: $mgr" >&2; exit 2
            ;;
    esac
    echo "[+] 패키지 설치 완료."
}

install_offline() {
    local DEPS_DIR="${DEPS_DIR:-./deps}" #
    if [ ! -d "$DEPS_DIR" ]; then #
      echo "[ERROR] Offline 디렉터리 $DEPS_DIR 없음" >&2; exit 3 #
    fi

    echo "[*] $DEPS_DIR에서 오프라인 설치 시도" >&2 #
    # nullglob: 매칭되는 파일이 없을 경우 패턴을 빈 문자열로 확장 (오류 방지)
    shopt -s nullglob #
    local debs=("$DEPS_DIR"/*.deb) rpms=("$DEPS_DIR"/*.rpm) #

    if [ ${#debs[@]} -gt 0 ]; then #
        dpkg -i "${debs[@]}" || (echo "[INFO] 의존성 해결: apt-get -f -y install" >&2 && apt-get -f -y install) #
    fi
    if [ ${#rpms[@]} -gt 0 ]; then #
        rpm -Uvh --quiet "${rpms[@]}" #
    fi
    echo "[+] 오프라인 설치 완료." >&2 #
}

case "$MODE" in
    apt|yum|dnf|apk|pacman|zypper)
        install_online "$MODE" "${BASE_PKGS[@]}" #
        ;;
    offline)
        install_offline #
        ;;
    *)
        usage #
        ;;
esac

echo "\n[+] 필수 명령어 설치/점검 결과 요약:"
ALL_OK=1
for entry in "${PKG_CMDS[@]}"; do
    pkg="${entry%%:*}"; cmd="${entry##*:}"
    if check_pkg_installed "$pkg" "$cmd"; then
        echo "  [OK] $pkg ($cmd)"
    else
        echo "  [경고] $pkg ($cmd) 미설치! 수동 설치 필요."
        ALL_OK=0
    fi
    # 버전 정보 출력(가능한 경우)
    if command -v "$cmd" >/dev/null 2>&1; then
        "$cmd" --version 2>&1 | head -n1 | sed 's/^/    > /'
    fi
    echo ""
done
if [ $ALL_OK -eq 1 ]; then
    echo "[+] 모든 필수 패키지/명령어가 정상적으로 설치되어 있습니다."
else
    echo "[!] 일부 필수 패키지가 누락되어 있습니다. OS 저장소 또는 외부 저장소/수동 설치를 확인하세요."
fi

echo "[+] install.sh 실행 완료."
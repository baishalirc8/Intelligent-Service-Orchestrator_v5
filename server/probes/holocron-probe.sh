#!/bin/bash
# =============================================================================
#  HOLOCRON AI — Linux Probe Agent v1.2.0
#  Collects system telemetry, security audit, software inventory.
#  Sends buffered data to server; executes AI-generated remediation tasks.
#
#  Usage:
#    bash holocron-probe.sh start --token hcn_xxx --api https://...
#    sudo bash holocron-probe.sh install --token hcn_xxx --api https://...
#    bash holocron-probe.sh status | uninstall | test
# =============================================================================

HOLOCRON_TOKEN="${HOLOCRON_TOKEN:-}"
HOLOCRON_API="${HOLOCRON_API:-}"
HOLOCRON_HMAC_SECRET="${HOLOCRON_HMAC_SECRET:-}"
HEARTBEAT_INTERVAL=60
PROBE_VERSION="1.2.0"
LOG_FILE="/var/log/holocron-probe.log"
PID_FILE="/var/run/holocron-probe.pid"
BUFFER_DIR="${HOLOCRON_BUFFER_DIR:-/var/lib/holocron/buffer}"
BUFFER_MAX_ENTRIES=10000
FLUSH_BATCH_SIZE=50

# Schedule intervals (seconds)
SCHED_METRICS=60
SCHED_NETWORK=60
SCHED_SECURITY=600
SCHED_SOFTWARE=600
SCHED_STORAGE=3600

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# =============================================================================
# Logging
# =============================================================================
log() {
    local level="${2:-INFO}"
    local ts
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    local color="$CYAN"
    case "$level" in
        SUCCESS) color="$GREEN" ;;
        WARN)    color="$YELLOW" ;;
        ERROR)   color="$RED" ;;
    esac
    echo -e "${color}[${ts}] $1${NC}"
    if [ -w "$(dirname "$LOG_FILE")" ] 2>/dev/null || [ -w "$LOG_FILE" ] 2>/dev/null; then
        echo "[${ts}] [${level}] $(echo "$1" | sed 's/\x1b\[[0-9;]*m//g')" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

banner() {
    echo -e "${CYAN}"
    echo "  ╔═══════════════════════════════════════════╗"
    echo "  ║          HOLOCRON AI Probe Agent           ║"
    echo "  ║              Linux v${PROBE_VERSION}                ║"
    echo "  ╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
}

# =============================================================================
# JSON helpers
# =============================================================================
json_str() {
    python3 -c "import json,sys; print(json.dumps(sys.argv[1]))" "$1" 2>/dev/null || printf '"%s"' "$1"
}

json_num() {
    local v="${1:-0}"
    echo "$v" | grep -qE '^-?[0-9]+(\.[0-9]+)?$' && echo "$v" || echo "0"
}

# =============================================================================
# System info
# =============================================================================
get_hostname() {
    hostname -f 2>/dev/null || hostname 2>/dev/null || echo "unknown"
}

get_ip() {
    ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' | head -1 || \
    hostname -I 2>/dev/null | awk '{print $1}' || echo "unknown"
}

get_mac_address() {
    local dev
    dev=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="dev") print $(i+1)}' | head -1)
    if [ -n "$dev" ]; then
        cat "/sys/class/net/${dev}/address" 2>/dev/null || ip link show "$dev" 2>/dev/null | awk '/ether/{print $2; exit}'
    else
        ip link show 2>/dev/null | awk '/ether/ {print $2; exit}'
    fi
    echo "unknown"
}

get_os_info() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        echo "${PRETTY_NAME:-${NAME} ${VERSION}}"
    elif [ -f /etc/redhat-release ]; then
        cat /etc/redhat-release
    else
        uname -s -r -m
    fi
}

get_manufacturer() {
    cat /sys/class/dmi/id/sys_vendor 2>/dev/null || \
    dmidecode -s system-manufacturer 2>/dev/null || echo "Unknown"
}

get_model() {
    cat /sys/class/dmi/id/product_name 2>/dev/null || \
    dmidecode -s system-product-name 2>/dev/null || echo "Unknown"
}

get_cpu_info() {
    grep -m1 "model name" /proc/cpuinfo 2>/dev/null | cut -d: -f2 | xargs || \
    lscpu 2>/dev/null | awk -F: '/Model name/ {gsub(/^[ \t]+/,"",$2); print $2}' || echo "Unknown"
}

get_total_memory_gb() {
    free -g 2>/dev/null | awk '/^Mem:/ {print $2}' || echo "0"
}

get_system_type() {
    if [ -d /proc/vz ] || [ -f /.dockerenv ] || grep -q "docker\|lxc\|kubepods" /proc/1/cgroup 2>/dev/null; then
        echo "container"
    elif dmidecode -s system-product-name 2>/dev/null | grep -qi "virtual\|vmware\|kvm\|qemu\|xen\|hyperv"; then
        echo "virtual-machine"
    else
        echo "physical"
    fi
}

# =============================================================================
# Metrics
# =============================================================================
get_cpu_usage() {
    top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print 100 - $8}' | head -1 || \
    awk '/^cpu / {usage=($2+$4)*100/($2+$4+$5); printf "%.1f", usage}' /proc/stat 2>/dev/null || echo "0"
}

get_memory_usage() {
    free 2>/dev/null | awk '/^Mem:/ {printf "%.1f", $3/$2 * 100}' || echo "0"
}

get_disk_usage() {
    df / 2>/dev/null | awk 'NR==2 {gsub(/%/,""); print $5}' || echo "0"
}

get_uptime_seconds() {
    awk '{print int($1)}' /proc/uptime 2>/dev/null || echo "0"
}

# =============================================================================
# Network interfaces (with bandwidth sampling)
# =============================================================================
get_network_interfaces_json() {
    local result="["
    local first=true
    for iface in /sys/class/net/*; do
        local name
        name=$(basename "$iface")
        [ "$name" = "lo" ] && continue
        local state
        state=$(cat "$iface/operstate" 2>/dev/null || echo "unknown")
        [ "$state" != "up" ] && continue

        local speed_mbps
        speed_mbps=$(cat "$iface/speed" 2>/dev/null || echo "0")
        [ "$speed_mbps" -le 0 ] 2>/dev/null && speed_mbps="0"
        local bandwidth="Unknown"
        if [ "$speed_mbps" -ge 1000 ]; then
            bandwidth="$(echo "$speed_mbps" | awk '{printf "%.1f Gbps", $1/1000}')"
        elif [ "$speed_mbps" -gt 0 ]; then
            bandwidth="${speed_mbps} Mbps"
        fi

        local rx1 tx1
        rx1=$(cat "/sys/class/net/$name/statistics/rx_bytes" 2>/dev/null || echo "0")
        tx1=$(cat "/sys/class/net/$name/statistics/tx_bytes" 2>/dev/null || echo "0")
        sleep 1
        local rx2 tx2
        rx2=$(cat "/sys/class/net/$name/statistics/rx_bytes" 2>/dev/null || echo "0")
        tx2=$(cat "/sys/class/net/$name/statistics/tx_bytes" 2>/dev/null || echo "0")
        local rx_rate=$((rx2 - rx1))
        local tx_rate=$((tx2 - tx1))
        local total_bits=$(( (rx_rate + tx_rate) * 8 ))
        local util_pct="0"
        if [ "$speed_mbps" -gt 0 ]; then
            local link_bps=$((speed_mbps * 1000000))
            util_pct=$(awk "BEGIN{if($link_bps>0) printf \"%.1f\", ($total_bits/$link_bps)*100; else print \"0\"}")
        fi

        local iface_type="ethernet"
        echo "$name" | grep -qi "wl" && iface_type="wireless"
        echo "$name" | grep -qi "wwan\|ppp" && iface_type="cellular"

        [ "$first" = true ] && first=false || result="$result,"
        result="$result{\"name\":$(json_str "$name"),\"type\":$(json_str "$iface_type"),\"status\":\"active\",\"bandwidth\":$(json_str "$bandwidth"),\"utilization\":\"${util_pct}%\",\"vlan\":\"N/A\",\"rxBytesPerSec\":$rx_rate,\"txBytesPerSec\":$tx_rate}"
    done
    echo "${result}]"
}

# =============================================================================
# Security audit — Linux-specific
# =============================================================================
get_security_audit_json() {
    # ── Firewall ──────────────────────────────────────────────────────────────
    local firewall="Not detected"
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1 || echo "")
        firewall="UFW: $(echo "$ufw_status" | awk '{print $2}')"
    elif command -v firewall-cmd &>/dev/null; then
        local fwd_state
        fwd_state=$(firewall-cmd --state 2>/dev/null || echo "not running")
        firewall="firewalld: $fwd_state"
    elif iptables -L INPUT 2>/dev/null | grep -q "ACCEPT\|DROP\|REJECT"; then
        local rule_count
        rule_count=$(iptables -L 2>/dev/null | grep -c "ACCEPT\|DROP\|REJECT" || echo "0")
        firewall="iptables: active ($rule_count rules)"
    else
        firewall="No firewall detected"
    fi

    # ── Antivirus ─────────────────────────────────────────────────────────────
    local antivirus="None detected"
    if command -v clamscan &>/dev/null || command -v clamav &>/dev/null || [ -f /usr/bin/clamd ]; then
        local clam_ver
        clam_ver=$(clamscan --version 2>/dev/null | head -1 | awk '{print $1,$2}' || echo "ClamAV")
        antivirus="${clam_ver}"
    fi
    if command -v rkhunter &>/dev/null; then
        antivirus="rkhunter$([ "$antivirus" != "None detected" ] && echo ", $antivirus" || echo "")"
    fi
    if command -v chkrootkit &>/dev/null; then
        antivirus="chkrootkit$([ "$antivirus" != "None detected" ] && echo ", $antivirus" || echo "")"
    fi
    [ "$antivirus" = "None detected" ] && command -v aide &>/dev/null && antivirus="AIDE"

    # ── Disk encryption ───────────────────────────────────────────────────────
    local encryption="Not detected"
    if lsblk -o TYPE 2>/dev/null | grep -q "crypt"; then
        local enc_devs
        enc_devs=$(lsblk -o NAME,TYPE 2>/dev/null | awk '$2=="crypt"{print $1}' | tr '\n' ',' | sed 's/,$//')
        encryption="LUKS: On (${enc_devs:-device})"
    elif cryptsetup status 2>/dev/null | grep -q "active"; then
        encryption="LUKS: Active"
    fi

    # ── Patches / last patched ────────────────────────────────────────────────
    local patch_count="0"
    local last_patched="Unknown"

    if command -v dpkg &>/dev/null; then
        patch_count=$(dpkg -l 2>/dev/null | awk 'NR>5 && /^ii/' | wc -l | tr -d ' ' || echo "0")
        if [ -f /var/log/dpkg.log ]; then
            last_patched=$(grep " install \| upgrade " /var/log/dpkg.log 2>/dev/null | tail -1 | awk '{print $1}' || echo "Unknown")
        fi
    elif command -v rpm &>/dev/null; then
        patch_count=$(rpm -qa 2>/dev/null | wc -l | tr -d ' ' || echo "0")
        last_patched=$(rpm -qa --last 2>/dev/null | head -1 | awk '{print $NF, $(NF-1), $(NF-2)}' || echo "Unknown")
    elif command -v apk &>/dev/null; then
        patch_count=$(apk info 2>/dev/null | wc -l | tr -d ' ' || echo "0")
    fi

    # ── Open ports ────────────────────────────────────────────────────────────
    local open_ports="0"
    if command -v ss &>/dev/null; then
        open_ports=$(ss -tuln 2>/dev/null | awk 'NR>1 && /LISTEN/' | wc -l | tr -d ' ' || echo "0")
    elif command -v netstat &>/dev/null; then
        open_ports=$(netstat -tuln 2>/dev/null | awk '/LISTEN/' | wc -l | tr -d ' ' || echo "0")
    fi

    # ── Auto-updates ──────────────────────────────────────────────────────────
    local auto_updates="Unknown"
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
        grep -q "1" /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null && auto_updates="Enabled" || auto_updates="Disabled"
    elif [ -f /etc/dnf/automatic.conf ]; then
        grep -q "apply_updates = yes" /etc/dnf/automatic.conf 2>/dev/null && auto_updates="Enabled" || auto_updates="Disabled"
    fi

    # ── SSH config ────────────────────────────────────────────────────────────
    local ssh_root="Unknown"
    if [ -f /etc/ssh/sshd_config ]; then
        grep -qi "^PermitRootLogin no\|^PermitRootLogin prohibit-password" /etc/ssh/sshd_config 2>/dev/null && \
            ssh_root="Disabled" || ssh_root="Enabled (risk)"
    fi

    # ── UAC equivalent (sudo nopasswd check) ─────────────────────────────────
    local sudo_nopasswd="Not detected"
    grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | grep -q "NOPASSWD" && \
        sudo_nopasswd="NOPASSWD sudoers found (risk)" || sudo_nopasswd="OK"

    # ── Local admin count ─────────────────────────────────────────────────────
    local admin_count="0"
    admin_count=$(getent group sudo wheel 2>/dev/null | awk -F: '{print $4}' | tr ',' '\n' | grep -v '^$' | sort -u | wc -l | tr -d ' ' || echo "0")

    echo "{\"firewall\":$(json_str "$firewall"),\"antivirus\":$(json_str "$antivirus"),\"diskEncryption\":$(json_str "$encryption"),\"installedPatches\":$(json_num "$patch_count"),\"lastPatched\":$(json_str "$last_patched"),\"openPortCount\":$(json_num "$open_ports"),\"autoUpdates\":$(json_str "$auto_updates"),\"sshRootLogin\":$(json_str "$ssh_root"),\"sudoNopasswd\":$(json_str "$sudo_nopasswd"),\"localAdminCount\":$(json_num "$admin_count")}"
}

# =============================================================================
# Software inventory
# =============================================================================
get_software_inventory_json() {
    local pkg_count="0"
    local os_info
    os_info=$(get_os_info)
    local apps_json="[]"

    if command -v dpkg &>/dev/null; then
        pkg_count=$(dpkg -l 2>/dev/null | awk 'NR>5 && /^ii/' | wc -l | tr -d ' ' || echo "0")
        apps_json=$(dpkg -l 2>/dev/null | awk 'NR>5 && /^ii/ {print $2, $3}' | head -60 | \
            python3 -c "
import sys, json
apps = []
for line in sys.stdin:
    parts = line.strip().split()
    if len(parts) >= 1:
        apps.append({'name': parts[0], 'version': parts[1] if len(parts)>1 else '', 'publisher': 'dpkg', 'installDate': '', 'sizeMB': 0})
print(json.dumps(apps))
" 2>/dev/null || echo "[]")
    elif command -v rpm &>/dev/null; then
        pkg_count=$(rpm -qa 2>/dev/null | wc -l | tr -d ' ' || echo "0")
        apps_json=$(rpm -qa --queryformat "%{NAME} %{VERSION}\n" 2>/dev/null | head -60 | \
            python3 -c "
import sys, json
apps = []
for line in sys.stdin:
    parts = line.strip().split()
    if len(parts) >= 1:
        apps.append({'name': parts[0], 'version': parts[1] if len(parts)>1 else '', 'publisher': 'rpm', 'installDate': '', 'sizeMB': 0})
print(json.dumps(apps))
" 2>/dev/null || echo "[]")
    elif command -v apk &>/dev/null; then
        pkg_count=$(apk info 2>/dev/null | wc -l | tr -d ' ' || echo "0")
        apps_json=$(apk info -v 2>/dev/null | head -60 | \
            python3 -c "
import sys, json
apps = []
for line in sys.stdin:
    line = line.strip()
    if line:
        apps.append({'name': line, 'version': '', 'publisher': 'apk', 'installDate': '', 'sizeMB': 0})
print(json.dumps(apps))
" 2>/dev/null || echo "[]")
    fi

    local kernel
    kernel=$(uname -r 2>/dev/null || echo "Unknown")

    echo "{\"os\":$(json_str "$os_info"),\"kernel\":$(json_str "$kernel"),\"installedPackages\":$(json_num "$pkg_count"),\"applications\":${apps_json}}"
}

# =============================================================================
# Storage info
# =============================================================================
get_storage_json() {
    python3 - <<'PYEOF' 2>/dev/null || echo "[]"
import subprocess, json
result = subprocess.run(['df', '-k', '--output=source,size,used,avail,pcent,target'],
    capture_output=True, text=True)
volumes = []
for line in result.stdout.strip().splitlines()[1:]:
    parts = line.split()
    if len(parts) < 6: continue
    if not parts[0].startswith('/dev/'): continue
    try:
        total_gb = round(int(parts[1]) * 1024 / 1e9, 1)
        free_gb  = round(int(parts[3]) * 1024 / 1e9, 1)
        used_pct = float(parts[4].rstrip('%'))
        mount    = parts[5]
    except (ValueError, IndexError):
        continue
    volumes.append({'drive': mount, 'totalGB': total_gb, 'freeGB': free_gb,
                    'usedPercent': used_pct, 'fileSystem': 'ext4/xfs'})
print(json.dumps(volumes))
PYEOF
}

# =============================================================================
# HMAC / API
# =============================================================================
generate_nonce() {
    command -v openssl &>/dev/null && openssl rand -hex 16 && return
    [ -f /dev/urandom ] && head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n' && return
    date +%s%N | sha256sum | head -c 32
}

get_timestamp_ms() {
    python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null || echo "$(date +%s)000"
}

compute_hmac_sha256() {
    echo -n "$2" | openssl dgst -sha256 -hmac "$1" -hex 2>/dev/null | sed 's/^.* //'
}

api_call() {
    local method="$1" endpoint="$2" data="$3"
    local url="${HOLOCRON_API}${endpoint}"
    local -a extra_args=()
    if [ -n "$HOLOCRON_HMAC_SECRET" ] && [ "$method" = "POST" ]; then
        local ts nonce sig
        ts=$(get_timestamp_ms)
        nonce=$(generate_nonce)
        sig=$(compute_hmac_sha256 "$HOLOCRON_HMAC_SECRET" "${ts}.${nonce}.${data}")
        extra_args=(
            -H "X-Holocron-Signature: ${sig}"
            -H "X-Holocron-Timestamp: ${ts}"
            -H "X-Holocron-Nonce: ${nonce}"
        )
    fi
    if [ "$method" = "POST" ]; then
        curl -s -X POST "$url" \
            -H "Content-Type: application/json" \
            "${extra_args[@]}" \
            --data-raw "$data" \
            --connect-timeout 10 --max-time 30 2>/dev/null
    else
        curl -s -X GET "$url" --connect-timeout 10 --max-time 30 2>/dev/null
    fi
}

# =============================================================================
# Buffer (file-based JSONL, mirrors Windows probe buffer strategy)
# =============================================================================
init_buffer() {
    mkdir -p "$BUFFER_DIR"
    touch "$BUFFER_DIR/buffer.jsonl"
}

buffer_count() {
    wc -l < "$BUFFER_DIR/buffer.jsonl" 2>/dev/null | tr -d ' ' || echo "0"
}

buffer_write() {
    local task_type="$1" data="$2"
    local ts hostname ip entry
    ts=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    hostname=$(get_hostname)
    ip=$(get_ip)
    entry="{\"taskType\":$(json_str "$task_type"),\"timestamp\":$(json_str "$ts"),\"hostname\":$(json_str "$hostname"),\"ipAddress\":$(json_str "$ip"),\"data\":${data}}"
    echo "$entry" >> "$BUFFER_DIR/buffer.jsonl"
    local count
    count=$(buffer_count)
    if [ "$count" -gt "$BUFFER_MAX_ENTRIES" ]; then
        local keep=$((BUFFER_MAX_ENTRIES / 2))
        tail -n "$keep" "$BUFFER_DIR/buffer.jsonl" > "$BUFFER_DIR/buffer.jsonl.tmp" && \
            mv "$BUFFER_DIR/buffer.jsonl.tmp" "$BUFFER_DIR/buffer.jsonl"
        log "Buffer trimmed to $keep entries" WARN
    fi
}

flush_buffer() {
    local count
    count=$(buffer_count)
    [ "$count" -eq 0 ] && return 0

    local flush_count=$count
    [ "$flush_count" -gt "$FLUSH_BATCH_SIZE" ] && flush_count=$FLUSH_BATCH_SIZE

    local batch
    batch=$(head -n "$flush_count" "$BUFFER_DIR/buffer.jsonl" | python3 -c "
import sys, json
entries = []
for line in sys.stdin:
    line = line.strip()
    if line:
        try: entries.append(json.loads(line))
        except: pass
print(json.dumps(entries))
" 2>/dev/null || echo "[]")

    local token_json
    token_json=$(json_str "$HOLOCRON_TOKEN")
    local payload="{\"siteToken\":${token_json},\"bufferedData\":${batch}}"
    local response
    response=$(api_call "POST" "/api/probe-heartbeat-buffered" "$payload")
    local success
    success=$(echo "$response" | grep -o '"success":true' || true)

    if [ -n "$success" ]; then
        local processed=$(echo "$response" | grep -o '"processed":[0-9]*' | cut -d: -f2 || echo "$flush_count")
        tail -n "+$((flush_count + 1))" "$BUFFER_DIR/buffer.jsonl" > "$BUFFER_DIR/buffer.jsonl.tmp" && \
            mv "$BUFFER_DIR/buffer.jsonl.tmp" "$BUFFER_DIR/buffer.jsonl"
        [ ! -s "$BUFFER_DIR/buffer.jsonl" ] && rm -f "$BUFFER_DIR/buffer.jsonl" && touch "$BUFFER_DIR/buffer.jsonl"
        log "Flushed ${processed} buffered entries" SUCCESS
        return 0
    else
        log "Buffer flush failed — will retry next cycle" WARN
        return 1
    fi
}

# =============================================================================
# Enrollment
# =============================================================================
enroll() {
    local hostname ip os mac manufacturer model cpu mem_gb sys_type
    hostname=$(get_hostname)
    ip=$(get_ip)
    os=$(get_os_info)
    mac=$(get_mac_address | head -1)
    manufacturer=$(get_manufacturer)
    model=$(get_model)
    cpu=$(get_cpu_info)
    mem_gb=$(get_total_memory_gb)
    sys_type=$(get_system_type)

    log "Enrolling probe with HOLOCRON AI..." WARN
    log "  Hostname:     $hostname"
    log "  IP:           $ip"
    log "  MAC:          $mac"
    log "  OS:           $os"
    log "  Manufacturer: $manufacturer"
    log "  Model:        $model"
    log "  CPU:          $cpu"
    log "  Memory:       $mem_gb GB"
    log "  System Type:  $sys_type"

    local payload
    payload=$(python3 -c "
import json, sys
print(json.dumps({'siteToken': sys.argv[1], 'hostname': sys.argv[2], 'ipAddress': sys.argv[3],
  'osInfo': sys.argv[4], 'probeVersion': sys.argv[5], 'deploymentType': 'bare-metal',
  'macAddress': sys.argv[6], 'manufacturer': sys.argv[7], 'model': sys.argv[8],
  'cpuInfo': sys.argv[9], 'totalMemoryGB': int(sys.argv[10]) if sys.argv[10].isdigit() else 0,
  'systemType': sys.argv[11]}))" \
  "$HOLOCRON_TOKEN" "$hostname" "$ip" "$os" "$PROBE_VERSION" \
  "$mac" "$manufacturer" "$model" "$cpu" "$mem_gb" "$sys_type" 2>/dev/null || \
    echo "{\"siteToken\":\"$HOLOCRON_TOKEN\",\"hostname\":\"$hostname\",\"ipAddress\":\"$ip\",\"osInfo\":\"$os\",\"probeVersion\":\"$PROBE_VERSION\",\"deploymentType\":\"bare-metal\"}"
    )

    local response
    response=$(api_call "POST" "/api/probe-enroll" "$payload")
    local success
    success=$(echo "$response" | grep -o '"success":true' || true)

    if [ -n "$success" ]; then
        local probe_id
        probe_id=$(echo "$response" | grep -o '"probeId":"[^"]*"' | cut -d'"' -f4)
        log "Probe enrolled successfully (ID: ${probe_id})" SUCCESS
        return 0
    else
        local err
        err=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        log "Enrollment failed: ${err:-unknown error}" ERROR
        return 1
    fi
}

# =============================================================================
# Remediation task execution
# =============================================================================
execute_remediation_task() {
    local task_json="$1"
    local task_id script_type script title

    task_id=$(echo "$task_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('id',''))" 2>/dev/null)
    script_type=$(echo "$task_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('scriptType','bash'))" 2>/dev/null)
    script=$(echo "$task_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('script','') or d.get('remediationScript',''))" 2>/dev/null)
    title=$(echo "$task_json" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('title',''))" 2>/dev/null || true)

    [ -z "$task_id" ] && return
    [ -z "$script" ] && { log "  [TASK] ${task_id}: empty script — skipping" WARN; return; }

    # Only run bash/sh scripts on Linux
    if [ "$script_type" != "bash" ] && [ "$script_type" != "shell" ] && [ "$script_type" != "sh" ]; then
        log "  [TASK] ${task_id}: script type '${script_type}' not supported on Linux — skipping" WARN
        local skip_payload
        skip_payload="{\"siteToken\":$(json_str "$HOLOCRON_TOKEN"),\"taskId\":$(json_str "$task_id"),\"status\":\"failed\",\"error\":$(json_str "Script type '${script_type}' not supported on Linux")}"
        api_call "POST" "/api/probe-task-report" "$skip_payload" > /dev/null 2>&1 || true
        return
    fi

    log "  [TASK] === REMEDIATION: ${title:-$task_id} ===" WARN
    log "  [TASK] ID: $task_id | Type: $script_type"

    local exec_payload
    exec_payload="{\"siteToken\":$(json_str "$HOLOCRON_TOKEN"),\"taskId\":$(json_str "$task_id"),\"status\":\"executing\"}"
    api_call "POST" "/api/probe-task-report" "$exec_payload" > /dev/null 2>&1 || true

    local tmp_script exit_code output
    tmp_script=$(mktemp /tmp/holocron_task_XXXXXX.sh)
    printf '%s\n' "$script" > "$tmp_script"
    chmod +x "$tmp_script"

    # Extended timeout for installs/updates
    local timeout_sec=1800
    echo "$title" | grep -qiE "install|update|patch|upgrade|download|deploy|setup|apt|yum|dnf" && timeout_sec=3600

    output=$(timeout "$timeout_sec" bash "$tmp_script" 2>&1) && exit_code=0 || exit_code=$?
    rm -f "$tmp_script"

    # Truncate long output
    if [ ${#output} -gt 4000 ]; then
        output="${output:0:4000}... [truncated]"
    fi

    if [ "$exit_code" -eq 0 ]; then
        log "  [TASK] ${task_id}: completed successfully" SUCCESS
        local done_payload
        done_payload="{\"siteToken\":$(json_str "$HOLOCRON_TOKEN"),\"taskId\":$(json_str "$task_id"),\"status\":\"completed\",\"result\":$(json_str "$output")}"
        api_call "POST" "/api/probe-task-report" "$done_payload" > /dev/null 2>&1 || true
    else
        log "  [TASK] ${task_id}: failed (exit ${exit_code})" ERROR
        local err_payload
        err_payload="{\"siteToken\":$(json_str "$HOLOCRON_TOKEN"),\"taskId\":$(json_str "$task_id"),\"status\":\"failed\",\"error\":$(json_str "Exit ${exit_code}: ${output}")}"
        api_call "POST" "/api/probe-task-report" "$err_payload" > /dev/null 2>&1 || true
    fi
}

# =============================================================================
# Heartbeat + scheduled collection loop
# =============================================================================
LAST_SECURITY=0
LAST_SOFTWARE=0
LAST_STORAGE=0
LAST_NETWORK=0
retry_count=0
max_retries=5

send_heartbeat() {
    local hostname ip os cpu mem disk uptime
    hostname=$(get_hostname)
    ip=$(get_ip)
    os=$(get_os_info)
    cpu=$(get_cpu_usage)
    mem=$(get_memory_usage)
    disk=$(get_disk_usage)
    uptime=$(get_uptime_seconds)

    local payload
    payload=$(python3 -c "
import json, sys
print(json.dumps({'siteToken': sys.argv[1], 'hostname': sys.argv[2], 'ipAddress': sys.argv[3],
  'osInfo': sys.argv[4], 'probeVersion': sys.argv[5],
  'cpuUsage': float(sys.argv[6]) if sys.argv[6] else 0,
  'memoryUsage': float(sys.argv[7]) if sys.argv[7] else 0,
  'diskUsage': float(sys.argv[8]) if sys.argv[8] else 0,
  'taskQueueDepth': int(sys.argv[9]) if sys.argv[9].isdigit() else 0,
  'activeTasks': 0, 'avgScanDurationMs': 0}))" \
  "$HOLOCRON_TOKEN" "$hostname" "$ip" "$os" "$PROBE_VERSION" \
  "$cpu" "$mem" "$disk" "$(buffer_count)" 2>/dev/null || \
  echo "{\"siteToken\":\"$HOLOCRON_TOKEN\",\"hostname\":\"$hostname\",\"ipAddress\":\"$ip\",\"probeVersion\":\"$PROBE_VERSION\",\"cpuUsage\":$cpu,\"memoryUsage\":$mem,\"diskUsage\":$disk}")

    local response
    response=$(api_call "POST" "/api/probe-heartbeat" "$payload")
    local success
    success=$(echo "$response" | grep -o '"success":true' || true)

    if [ -n "$success" ]; then
        local next
        next=$(echo "$response" | grep -o '"nextHeartbeat":[0-9]*' | cut -d: -f2)
        [ -n "$next" ] && [ "$next" -gt 0 ] 2>/dev/null && HEARTBEAT_INTERVAL=$next

        # Dispatch pending remediation tasks
        local tasks_json
        tasks_json=$(echo "$response" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for t in d.get('pendingTasks', []):
    print(json.dumps(t))
" 2>/dev/null || true)
        if [ -n "$tasks_json" ]; then
            while IFS= read -r task_line; do
                [ -z "$task_line" ] && continue
                execute_remediation_task "$task_line"
            done <<< "$tasks_json"
        fi

        # Dispatch pending rollbacks
        local rollbacks_json
        rollbacks_json=$(echo "$response" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for t in d.get('pendingRollbacks', []):
    print(json.dumps(t))
" 2>/dev/null || true)
        if [ -n "$rollbacks_json" ]; then
            while IFS= read -r task_line; do
                [ -z "$task_line" ] && continue
                execute_remediation_task "$task_line"
            done <<< "$rollbacks_json"
        fi

        # Server-requested immediate software inventory
        local req_sw
        req_sw=$(echo "$response" | python3 -c "import json,sys; d=json.load(sys.stdin); print('yes' if d.get('requestSoftwareInventory') else '')" 2>/dev/null || true)
        if [ "$req_sw" = "yes" ]; then
            log "  [SCHED] Server requested immediate software inventory" WARN
            (
                local inv
                inv=$(get_software_inventory_json)
                buffer_write "softwareInventory" "$inv"
                flush_buffer || true
                LAST_SOFTWARE=$(date +%s)
                log "  [SCHED] On-demand software inventory queued" SUCCESS
            ) &
            disown
        fi

        log "Heartbeat OK (CPU: ${cpu}%, Mem: ${mem}%, Disk: ${disk}%, Buf: $(buffer_count), Next: ${HEARTBEAT_INTERVAL}s)" SUCCESS
        return 0
    else
        local err
        err=$(echo "$response" | grep -o '"error":"[^"]*"' | cut -d'"' -f4)
        log "Heartbeat failed: ${err:-no response}" ERROR
        return 1
    fi
}

run_scheduled_collections() {
    local now
    now=$(date +%s)

    # Network interfaces — every SCHED_NETWORK seconds
    if [ $((now - LAST_NETWORK)) -ge $SCHED_NETWORK ]; then
        LAST_NETWORK=$now
        local net
        net=$(get_network_interfaces_json)
        buffer_write "networkInterfaces" "{\"interfaces\":${net}}"
    fi

    # Security audit — every SCHED_SECURITY seconds
    if [ $((now - LAST_SECURITY)) -ge $SCHED_SECURITY ]; then
        LAST_SECURITY=$now
        log "  [SCHED] Collecting security audit..." INFO
        local sec
        sec=$(get_security_audit_json)
        buffer_write "securityAudit" "$sec"
        log "  [SCHED] Security audit buffered" SUCCESS
    fi

    # Software inventory — every SCHED_SOFTWARE seconds
    if [ $((now - LAST_SOFTWARE)) -ge $SCHED_SOFTWARE ]; then
        LAST_SOFTWARE=$now
        log "  [SCHED] Collecting software inventory..." INFO
        (
            local sw
            sw=$(get_software_inventory_json)
            buffer_write "softwareInventory" "$sw"
            local pkg
            pkg=$(echo "$sw" | python3 -c "import json,sys; d=json.load(sys.stdin); print(d.get('installedPackages',0))" 2>/dev/null || echo "?")
            log "  [SCHED] Software inventory buffered (${pkg} packages)" SUCCESS
        ) &
        disown
    fi

    # Storage info — every SCHED_STORAGE seconds
    if [ $((now - LAST_STORAGE)) -ge $SCHED_STORAGE ]; then
        LAST_STORAGE=$now
        log "  [SCHED] Collecting storage info..." INFO
        local stor
        stor=$(get_storage_json)
        buffer_write "storageInfo" "{\"volumes\":${stor}}"
        log "  [SCHED] Storage info buffered" SUCCESS
    fi
}

run_daemon() {
    while true; do
        run_scheduled_collections

        if ! send_heartbeat; then
            retry_count=$((retry_count + 1))
            if [ $retry_count -ge $max_retries ]; then
                log "Max retries reached. Re-enrolling..." ERROR
                if enroll; then
                    retry_count=0
                fi
            fi
            local backoff=$((HEARTBEAT_INTERVAL * retry_count))
            [ $backoff -gt 300 ] && backoff=300
            sleep $backoff
        else
            retry_count=0
            flush_buffer || true
            sleep $HEARTBEAT_INTERVAL
        fi
    done
}

# =============================================================================
# Stop handler
# =============================================================================
stop_probe() {
    log "Shutting down HOLOCRON Probe..." WARN
    [ -f "$PID_FILE" ] && rm -f "$PID_FILE"
    exit 0
}

# =============================================================================
# Service management
# =============================================================================
install_service() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error: Installation requires root privileges. Run with sudo.${NC}"
        exit 1
    fi

    local script_path
    script_path=$(readlink -f "$0")
    cp "$script_path" /usr/local/bin/holocron-probe
    chmod +x /usr/local/bin/holocron-probe

    mkdir -p /opt/holocron /var/lib/holocron/buffer
    chmod 700 /opt/holocron

    cat > /opt/holocron/.env << ENVEOF
HOLOCRON_TOKEN=${HOLOCRON_TOKEN}
HOLOCRON_HMAC_SECRET=${HOLOCRON_HMAC_SECRET}
HOLOCRON_API=${HOLOCRON_API}
HOLOCRON_BUFFER_DIR=/var/lib/holocron/buffer
ENVEOF
    chmod 600 /opt/holocron/.env
    chown root:root /opt/holocron/.env

    cat > /etc/systemd/system/holocron-probe.service << SVCEOF
[Unit]
Description=HOLOCRON AI Probe Agent v${PROBE_VERSION}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/holocron-probe start
Restart=always
RestartSec=15
EnvironmentFile=/opt/holocron/.env
StartLimitIntervalSec=300
StartLimitBurst=5
StandardOutput=append:/var/log/holocron-probe.log
StandardError=append:/var/log/holocron-probe.log

[Install]
WantedBy=multi-user.target
SVCEOF

    systemctl daemon-reload
    systemctl enable holocron-probe
    systemctl start holocron-probe

    log "HOLOCRON Probe installed and started as a systemd service" SUCCESS
    log "  Check status: systemctl status holocron-probe"
    log "  View logs:    journalctl -u holocron-probe -f"
}

uninstall_service() {
    if [ "$(id -u)" -ne 0 ]; then
        echo -e "${RED}Error: Uninstall requires root privileges. Run with sudo.${NC}"
        exit 1
    fi
    systemctl stop holocron-probe 2>/dev/null || true
    systemctl disable holocron-probe 2>/dev/null || true
    rm -f /etc/systemd/system/holocron-probe.service
    rm -f /usr/local/bin/holocron-probe
    systemctl daemon-reload
    log "HOLOCRON Probe uninstalled" SUCCESS
}

check_status() {
    if systemctl is-active --quiet holocron-probe 2>/dev/null; then
        echo -e "${GREEN}● HOLOCRON Probe is running${NC}"
        systemctl status holocron-probe --no-pager
    else
        echo -e "${RED}● HOLOCRON Probe is not running${NC}"
    fi
}

test_connection() {
    log "Testing connection to ${HOLOCRON_API}..."
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "${HOLOCRON_API}/api/probe-heartbeat" \
        -X POST -H "Content-Type: application/json" \
        -d '{"siteToken":"test"}' \
        --connect-timeout 10 2>/dev/null)
    if [ "$code" = "404" ] || [ "$code" = "400" ] || [ "$code" = "200" ]; then
        log "API is reachable (HTTP $code)" SUCCESS
    else
        log "API returned HTTP ${code}" ERROR
    fi
}

# =============================================================================
# Argument parsing
# =============================================================================
COMMAND="start"

while [[ $# -gt 0 ]]; do
    case $1 in
        --token) HOLOCRON_TOKEN="$2"; shift 2 ;;
        --api)   HOLOCRON_API="$2";   shift 2 ;;
        start|install|uninstall|status|test|help) COMMAND="$1"; shift ;;
        *) echo "Unknown option: $1"; shift ;;
    esac
done

case $COMMAND in
    help)
        echo "Usage: $0 [start|install|uninstall|status|test] [--token TOKEN] [--api URL]"
        exit 0 ;;
    status)
        check_status; exit 0 ;;
    uninstall)
        uninstall_service; exit 0 ;;
    test)
        [ -z "$HOLOCRON_API" ] && { echo "Error: --api required"; exit 1; }
        HOLOCRON_API="${HOLOCRON_API%/}"
        test_connection; exit 0 ;;
esac

if [ -z "$HOLOCRON_TOKEN" ]; then
    echo -e "${RED}Error: Site token is required. Use --token or set HOLOCRON_TOKEN.${NC}"
    exit 1
fi

if [ -z "$HOLOCRON_API" ]; then
    echo -e "${RED}Error: API URL is required. Use --api or set HOLOCRON_API.${NC}"
    exit 1
fi

HOLOCRON_API="${HOLOCRON_API%/}"

banner

trap stop_probe SIGTERM SIGINT

case $COMMAND in
    start)
        init_buffer
        log "Starting HOLOCRON Probe Agent v${PROBE_VERSION}..."
        log "  Token:  ${HOLOCRON_TOKEN:0:10}...${HOLOCRON_TOKEN: -4}"
        log "  API:    ${HOLOCRON_API}"
        log "  Buffer: ${BUFFER_DIR}"
        log "  Schedule: Metrics=${SCHED_METRICS}s | Security=${SCHED_SECURITY}s | Software=${SCHED_SOFTWARE}s"
        log ""

        if enroll; then
            log "Probe is online. Starting collection loop." SUCCESS
            run_daemon
        else
            log "Failed to enroll. Check your token and API URL." ERROR
            exit 1
        fi
        ;;
    install)
        install_service ;;
esac

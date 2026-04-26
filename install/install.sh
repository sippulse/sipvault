#!/bin/bash
# sipvault-agent installer
# Usage: curl -sSL https://raw.githubusercontent.com/sippulse/sipvault/main/install/install.sh | \
#          bash -s -- --server 10.0.0.1:9060 --customer acme --token SECRET
set -euo pipefail

RELEASE_BASE="${SIPVAULT_RELEASE_BASE:-https://github.com/sippulse/sipvault/releases/latest/download}"

INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/sipvault"
BUFFER_DIR="/var/lib/sipvault"
SERVICE_USER="sipvault"

# Parse arguments
SERVER_ADDR=""
CUSTOMER_ID=""
TOKEN=""
SIP_PORTS="5060"
INTERFACE=""
LOG_FILE="/var/log/opensips.log"
CAPTURE_MODE="auto"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --server)    SERVER_ADDR="$2"; shift 2 ;;
        --customer)  CUSTOMER_ID="$2"; shift 2 ;;
        --token)     TOKEN="$2"; shift 2 ;;
        --sip-ports) SIP_PORTS="$2"; shift 2 ;;
        --interface) INTERFACE="$2"; shift 2 ;;
        --log-file)  LOG_FILE="$2"; shift 2 ;;
        --mode)      CAPTURE_MODE="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

if [[ -z "$SERVER_ADDR" || -z "$CUSTOMER_ID" || -z "$TOKEN" ]]; then
    echo "Usage: install.sh --server HOST:PORT --customer ID --token TOKEN [--mode auto|ebpf|pcap]"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ARCH="amd64" ;;
    aarch64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Detect OS and kernel version
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2 | cut -d- -f1)

echo "SIP VAULT Agent Installer"
echo "========================="
echo "OS: $(cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d'"' -f2 || uname -s)"
echo "Kernel: $(uname -r)"
echo "Arch: $ARCH"

# Determine binary variant
if [[ "$CAPTURE_MODE" == "auto" ]]; then
    if [[ "$KERNEL_MAJOR" -gt 4 ]] || [[ "$KERNEL_MAJOR" -eq 4 && "$KERNEL_MINOR" -ge 18 ]]; then
        BINARY_VARIANT="sipvault-agent-linux-${ARCH}"
        DETECTED_MODE="ebpf"
    else
        BINARY_VARIANT="sipvault-agent-pcap-linux-${ARCH}"
        DETECTED_MODE="pcap"
    fi
elif [[ "$CAPTURE_MODE" == "pcap" ]]; then
    BINARY_VARIANT="sipvault-agent-pcap-linux-${ARCH}"
    DETECTED_MODE="pcap"
else
    BINARY_VARIANT="sipvault-agent-linux-${ARCH}"
    DETECTED_MODE="ebpf"
fi

echo "Capture mode: $DETECTED_MODE"
echo ""

# Install libpcap if needed for pcap mode
if [[ "$DETECTED_MODE" == "pcap" ]]; then
    echo "Installing libpcap..."
    if command -v yum &>/dev/null; then
        yum install -y libpcap 2>/dev/null || true
    elif command -v apt-get &>/dev/null; then
        apt-get install -y libpcap0.8 2>/dev/null || true
    fi
fi

# Auto-detect interface if not specified
if [[ -z "$INTERFACE" ]]; then
    INTERFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}' || route -n 2>/dev/null | awk '/^0.0.0.0/{print $8; exit}')
    if [[ -z "$INTERFACE" ]]; then
        INTERFACE="eth0"
    fi
    echo "Auto-detected interface: $INTERFACE"
fi

# Create directories
mkdir -p "$CONFIG_DIR" "$BUFFER_DIR" "$INSTALL_DIR"

# Download binary from GitHub Releases
DOWNLOAD_URL="${RELEASE_BASE}/${BINARY_VARIANT}"
echo "Downloading ${BINARY_VARIANT} from ${DOWNLOAD_URL}..."
curl -fSL -o "${INSTALL_DIR}/sipvault-agent" "$DOWNLOAD_URL"
chmod +x "${INSTALL_DIR}/sipvault-agent"

# Write config
cat > "${CONFIG_DIR}/agent.conf" <<EOF
[server]
address = ${SERVER_ADDR}
customer_id = ${CUSTOMER_ID}
token = ${TOKEN}

[capture]
mode = ${DETECTED_MODE}
sip_ports = ${SIP_PORTS}
interface = ${INTERFACE}
log_file = ${LOG_FILE}
rtp_port_min = 10000
rtp_port_max = 30000

[buffer]
path = ${BUFFER_DIR}/buffer.dat
max_size = 104857600

[logging]
level = info
EOF

echo "Config written to ${CONFIG_DIR}/agent.conf"

# Create systemd service (if systemd available)
if command -v systemctl &>/dev/null; then
    cat > /etc/systemd/system/sipvault-agent.service <<EOF
[Unit]
Description=SIP VAULT Agent
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/sipvault-agent --config ${CONFIG_DIR}/agent.conf
Restart=always
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo "Systemd service created: sipvault-agent.service"
    echo "  Start with: systemctl start sipvault-agent"
    echo "  Enable at boot: systemctl enable sipvault-agent"
else
    # SysV init for CentOS 6
    cat > /etc/init.d/sipvault-agent <<'INITEOF'
#!/bin/bash
# chkconfig: 2345 90 10
# description: SIP VAULT Agent
DAEMON=/usr/local/bin/sipvault-agent
CONFIG=/etc/sipvault/agent.conf
PIDFILE=/var/run/sipvault-agent.pid

case "$1" in
    start)
        echo "Starting sipvault-agent..."
        nohup $DAEMON --config $CONFIG > /var/log/sipvault-agent.log 2>&1 &
        echo $! > $PIDFILE
        ;;
    stop)
        echo "Stopping sipvault-agent..."
        [ -f $PIDFILE ] && kill $(cat $PIDFILE) && rm -f $PIDFILE
        ;;
    restart)
        $0 stop
        sleep 1
        $0 start
        ;;
    status)
        [ -f $PIDFILE ] && kill -0 $(cat $PIDFILE) 2>/dev/null && echo "Running" || echo "Stopped"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac
INITEOF
    chmod +x /etc/init.d/sipvault-agent
    echo "SysV init script created: /etc/init.d/sipvault-agent"
    echo "  Start with: service sipvault-agent start"
    echo "  Enable at boot: chkconfig sipvault-agent on"
fi

echo ""
echo "Installation complete!"
echo "Capture mode: $DETECTED_MODE"

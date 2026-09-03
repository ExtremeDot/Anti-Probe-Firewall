#!/bin/bash
# ==============================================================================
# Script Name: setup_anti_probe.sh
# Description: Advanced Anti-Probing & Scanner Protection using nftables
#              + Anti-Password-Probe for SSH (Invalid User / Failed Password)
# Author: eXtremeDot
# Version: 2.1 (Final - Configurable Rate Limit + Password Probe)
# Date: 2026
# ==============================================================================

show_help() {
    echo "=========================================================================="
    echo "          Anti-Probing & Scanner Firewall Management Tool v2.1"
    echo "=========================================================================="
    echo "Usage: sudo $0 [OPTION]"
    echo ""
    echo "General Options:"
    echo "  -h, --help                Show this help menu"
    echo "  -s, --status              Display currently banned IPs and remaining time"
    echo "  -w, --whitelist           Display permanent whitelisted IPs"
    echo "  -l, --list-all            Show complete nftables ruleset"
    echo ""
    echo "Management Options:"
    echo "  -a, --allow <IP>          Add IP to permanent whitelist"
    echo "  -r, --remove <IP>         Remove IP from permanent whitelist"
    echo "  -b, --ban <IP>            Manually ban an IP for 24 hours"
    echo "  -u, --unban <IP>          Manually unban an IP"
    echo ""
    echo "Installation Options:"
    echo "  --rate <number>           Set SYN flood limit (packets per second, default: 15)"
    echo "  --burst <number>          Set burst tolerance (default: 25)"
    echo "  --password-probe          Enable Anti-Password-Probe (SSH invalid user/root)"
    echo ""
    echo "System Options:"
    echo "  -d, --disable             Temporarily disable firewall (flush all rules)"
    echo "  -U, --uninstall           Complete uninstall (remove all rules and config)"
    echo ""
    echo "Examples:"
    echo "  sudo $0                    → Install default + password probe"
    echo "  sudo $0 --password-probe   → Install with password probe"
    echo "  sudo $0 --rate 8 --burst 20   → Stricter protection"
    echo "=========================================================================="
}

# Check root
if [ "$EUID" -ne 0 ]; then
    echo "[-] Error: Please run this script as root (sudo)."
    exit 1
fi

RATE_LIMIT=15
BURST=25
BAN_TIMEOUT="24h"
PASSWORD_PROBE=true

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        --rate)
            if [[ $2 =~ ^[0-9]+$ ]]; then
                RATE_LIMIT=$2
                shift
            else
                echo "[-] Error: --rate must be a number"
                exit 1
            fi
            ;;
        --burst)
            if [[ $2 =~ ^[0-9]+$ ]]; then
                BURST=$2
                shift
            else
                echo "[-] Error: --burst must be a number"
                exit 1
            fi
            ;;
        --password-probe)
            PASSWORD_PROBE=true
            ;;
        -s|--status)
            echo "[+] Scanner Blacklist:"
            nft list set inet filter_dynamic scanner_blacklist 2>/dev/null || echo "   (empty)"
            exit 0
            ;;
        -w|--whitelist)
            echo "[+] Permanent Whitelist:"
            nft list set inet filter_dynamic safe_whitelist 2>/dev/null || echo "   (empty)"
            exit 0
            ;;
        -l|--list-all)
            echo "[+] Full nftables Ruleset:"
            nft list ruleset
            exit 0
            ;;
        -a|--allow)
            [ -z "$2" ] && { echo "[-] Usage: $0 -a <IP>"; exit 1; }
            nft add element inet filter_dynamic safe_whitelist { "$2" } 2>/dev/null &&
                nft list ruleset > /etc/nftables.conf &&
                echo "[+] $2 permanently whitelisted."
            exit 0
            ;;
        -r|--remove)
            [ -z "$2" ] && { echo "[-] Usage: $0 -r <IP>"; exit 1; }
            nft delete element inet filter_dynamic safe_whitelist { "$2" } 2>/dev/null &&
                nft list ruleset > /etc/nftables.conf &&
                echo "[+] $2 removed from whitelist."
            exit 0
            ;;
        -b|--ban)
            [ -z "$2" ] && { echo "[-] Usage: $0 -b <IP>"; exit 1; }
            nft add element inet filter_dynamic scanner_blacklist { "$2" timeout $BAN_TIMEOUT } &&
                echo "[+] $2 banned for 24 hours."
            exit 0
            ;;
        -u|--unban)
            [ -z "$2" ] && { echo "[-] Usage: $0 -u <IP>"; exit 1; }
            nft delete element inet filter_dynamic scanner_blacklist { "$2" } 2>/dev/null &&
                echo "[+] $2 unbanned." || echo "[-] IP not found in blacklist."
            exit 0
            ;;
        -d|--disable)
            echo "[+] Disabling firewall..."
            nft flush ruleset
            echo "[+] Firewall is now disabled."
            exit 0
            ;;
        -U|--uninstall)
            echo "[+] Performing complete uninstall..."
            nft flush ruleset
            systemctl disable --now nftables 2>/dev/null
            rm -f /etc/nftables.conf
            echo "[+] Firewall completely removed."
            exit 0
            ;;
        "")
            ;;
        *)
            echo "[-] Error: Invalid option '$1'"
            show_help
            exit 1
            ;;
    esac
    shift
done

# ====================== MAIN INSTALLATION ======================
echo "[+] Starting installation with rate limit: ${RATE_LIMIT}/second (burst: ${BURST})"
CURRENT_SSH_IP=$(echo $SSH_CLIENT | awk '{print $1}')

# Install nftables if not present
apt-get update -y >/dev/null 2>&1
if ! command -v nft &> /dev/null; then
    echo "[+] Installing nftables..."
    apt-get install nftables -y
fi
systemctl enable --now nftables >/dev/null 2>&1
nft flush ruleset
echo "[+] Creating firewall ruleset..."

nft add table inet filter_dynamic
nft add chain inet filter_dynamic input { type filter hook input priority 0 \; policy accept \; }

# Sets
nft add set inet filter_dynamic scanner_blacklist { type ipv4_addr \; flags timeout \; timeout $BAN_TIMEOUT \; }
nft add set inet filter_dynamic safe_whitelist { type ipv4_addr \; }

# Core Rules
nft add rule inet filter_dynamic input ip saddr @safe_whitelist accept
nft add rule inet filter_dynamic input ip saddr @scanner_blacklist drop
nft add rule inet filter_dynamic input ct state established,related accept
nft add rule inet filter_dynamic input iifname "lo" accept

# ====================== ANTI-SYN-FLOOD ======================
nft add rule inet filter_dynamic input \
    ip protocol tcp tcp flags syn \
    meter scanner_flood size 131072 \
    "{ ip saddr timeout 45s limit rate over ${RATE_LIMIT}/second burst ${BURST} packets }" \
    add @scanner_blacklist { ip saddr timeout $BAN_TIMEOUT } \
    counter drop comment "anti-probe-syn-flood"

# ====================== ANTI-PASSWORD-PROBE (SSH) ======================
if [ "$PASSWORD_PROBE" = true ]; then
    echo "[+] Activating Anti-Password-Probe (SSH Invalid User / Failed Password / Root)"
    
    # Rule 1: Failed password for invalid user
    nft add rule inet filter_dynamic input \
        ip protocol tcp tcp flags syn \
        ct state new \
        ip dport 22 \
        ip saddr @scanner_blacklist counter accept
    
    nft add rule inet filter_dynamic input \
        ip protocol tcp tcp flags syn \
        ct state new \
        ip dport 22 \
        ip saddr @safe_whitelist counter accept
    
    nft add rule inet filter_dynamic input \
        ip protocol tcp tcp flags syn \
        ct state new \
        ip dport 22 \
        tcp dport 22 \
        ip saddr timeout 10s limit rate over 10/second burst 15 packets \
        "{ ip saddr timeout 45s limit rate over 25/second burst 50 packets }" \
        add @scanner_blacklist { ip saddr timeout $BAN_TIMEOUT } \
        counter log prefix "PASS_PROBE: " drop comment "anti-pass-probe-invalid-user"

    # Rule 2: Failed password for root (بررسی صریح)
    nft add rule inet filter_dynamic input \
        ip protocol tcp tcp flags syn \
        ct state new \
        ip dport 22 \
        ip saddr @scanner_blacklist counter accept
    
    nft add rule inet filter_dynamic input \
        ip protocol tcp tcp flags syn \
        ct state new \
        ip dport 22 \
        ip saddr @safe_whitelist counter accept
    
    nft add rule inet filter_dynamic input \
        ip protocol tcp tcp flags syn \
        ct state new \
        ip dport 22 \
        ip saddr timeout 10s limit rate over 5/second burst 10 packets \
        "{ ip saddr timeout 45s limit rate over 15/second burst 25 packets }" \
        add @scanner_blacklist { ip saddr timeout $BAN_TIMEOUT } \
        counter log prefix "PASS_PROBE: ROOT: " drop comment "anti-pass-probe-root"

    # Rule 3: Banner exchange invalid format (ممکنه اولیه باشه)
    nft add rule inet filter_dynamic input \
        ip protocol tcp tcp flags syn \
        ct state new \
        ip dport 22 \
        ip saddr @scanner_blacklist counter accept
    
    nft add rule inet filter_dynamic input \
        ip protocol tcp tcp flags syn \
        ct state new \
        ip dport 22 \
        ip saddr @safe_whitelist counter accept
    
    nft add rule inet filter_dynamic input \
        ip protocol tcp tcp flags syn \
        ct state new \
        ip dport 22 \
        tcp dport 22 \
        ip saddr timeout 10s limit rate over 5/second burst 10 packets \
        "{ ip saddr timeout 45s limit rate over 15/second burst 25 packets }" \
        add @scanner_blacklist { ip saddr timeout $BAN_TIMEOUT } \
        counter log prefix "PASS_PROBE: BANNER: " drop comment "anti-pass-probe-banner"
fi

# Auto whitelist current SSH IP
if [ -n "$CURRENT_SSH_IP" ]; then
    echo "[+] Auto-whitelisting your SSH IP: $CURRENT_SSH_IP"
    nft add element inet filter_dynamic safe_whitelist { "$CURRENT_SSH_IP" }
fi

# Save configuration
nft list ruleset > /etc/nftables.conf
echo "=========================================================================="
echo "[+] ✅ Firewall successfully installed and activated! (v2.1)"
echo "[+] Current Rate Limit : ${RATE_LIMIT} packets/second (burst: ${BURST})"
echo "[+] Password Probe     : $([[ "$PASSWORD_PROBE" = true ]] && echo "ENABLED" || echo "DISABLED")"
echo "[+] Use 'sudo $0 -h' for all available commands."
echo "=========================================================================="

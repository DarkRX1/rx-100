#!/usr/bin/env bash
# rx-100 project 4: personal firewall in nftables
# own table, default-deny inbound, docker's tables untouched.

# --- dead man's switch: UNIQUE name per run so reruns never collide ---
UNIT="rx-rollback-$(date +%s)"
sudo systemd-run --on-active=120 --unit=$UNIT \
    sh -c 'nft delete table inet rx_firewall' \
    || echo "[!] WARNING: rollback NOT armed - supervise manually"
echo "[*] rollback armed as $UNIT (fires in 120s)"

# --- wipe any previous version of OUR table (ignore error if absent) ---
sudo nft delete table inet rx_firewall 2>/dev/null

# --- apply ---
sudo nft -f - <<'EOF'
table inet rx_firewall {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state invalid drop
        iifname "lo" accept
        ct state established,related accept
        udp sport 67 udp dport 68 accept
        meta l4proto ipv6-icmp accept
        limit rate 5/second burst 5 packets log prefix "rx_drop: "
        counter drop
    }
    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF

# --- verify our own effect: never trust, always check ---
if sudo nft list table inet rx_firewall >/dev/null 2>&1; then
    echo "[+] firewall CONFIRMED active"
else
    echo "[!!] FAILED TO APPLY - NO PROTECTION"
fi
echo "[*] to disarm: sudo systemctl stop $UNIT.timer"

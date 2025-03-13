#!/bin/bash
#
# Docker script to configure and start an IPsec VPN server
#
# DO NOT RUN THIS SCRIPT ON YOUR PC OR MAC! THIS IS ONLY MEANT TO BE RUN
# IN A CONTAINER!
#
# This file is part of IPsec VPN Docker image, available at:
# https://github.com/hwdsl2/docker-ipsec-vpn-server
#
# Copyright (C) 2016-2024 Lin Song <linsongui@gmail.com>
# Based on the work of Thomas Sarlandie (Copyright 2012)
#
# This work is licensed under the Creative Commons Attribution-ShareAlike 3.0
# Unported License: http://creativecommons.org/licenses/by-sa/3.0/
#
# Attribution required: please include my name in any derivative and let me
# know how you have improved it!

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

exiterr()  { echo "Error: $1" >&2; exit 1; }
nospaces() { printf '%s' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'; }
onespace() { printf '%s' "$1" | tr -s ' '; }
noquotes() { printf '%s' "$1" | sed -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'$/\1/"; }
noquotes2() { printf '%s' "$1" | sed -e 's/" "/ /g' -e "s/' '/ /g"; }

check_ip() {
  IP_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$IP_REGEX"
}

check_cidr() {
  CIDR_REGEX='^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(/(3[0-2]|[1-2][0-9]|[0-9]))$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$CIDR_REGEX"
}

check_dns_name() {
  FQDN_REGEX='^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
  printf '%s' "$1" | tr -d '\n' | grep -Eq "$FQDN_REGEX"
}

check_client_name() {
  ! { [ "${#1}" -gt "64" ] || printf '%s' "$1" | LC_ALL=C grep -q '[^A-Za-z0-9_-]\+' \
    || case $1 in -*) true ;; *) false ;; esac; }
}

if [ ! -f "/.dockerenv" ] && [ ! -f "/run/.containerenv" ] \
  && [ -z "$KUBERNETES_SERVICE_HOST" ] \
  && ! head -n 1 /proc/1/sched 2>/dev/null | grep -q '^run\.sh '; then
  exiterr "This script ONLY runs in a container (e.g. Docker, Podman)."
fi

if ip link add dummy0 type dummy 2>&1 | grep -q "not permitted"; then
cat 1>&2 <<'EOF'
Error: This Docker image should be run in privileged mode.
       See: https://github.com/hwdsl2/docker-ipsec-vpn-server

EOF
  exit 1
fi
ip link delete dummy0 >/dev/null 2>&1

os_type=debian
os_arch=$(uname -m | tr -dc 'A-Za-z0-9_-')
[ -f /etc/os-release ] && os_type=$(. /etc/os-release && printf '%s' "$ID")

if [ ! -e /dev/ppp ]; then
cat <<'EOF'

Warning: /dev/ppp is missing, and IPsec/L2TP mode may not work.
         Please use IKEv2 or IPsec/XAuth mode to connect.
         Debian 11/10 users, see https://vpnsetup.net/debian10
EOF
fi

NET_IFACE=$(route 2>/dev/null | grep -m 1 '^default' | grep -o '[^ ]*$')
[ -z "$NET_IFACE" ] && NET_IFACE=$(ip -4 route list 0/0 2>/dev/null | grep -m 1 -Po '(?<=dev )(\S+)')
[ -z "$NET_IFACE" ] && NET_IFACE=eth0

# Create IPsec config
cat > /etc/ipsec.conf <<EOF
EOF

cat >> /etc/ipsec.conf <<'EOF'
include /etc/ipsec.d/*.conf
EOF

if uname -r | grep -qi 'coreos'; then
  sed -i '/phase2alg/s/,aes256-sha2_512//' /etc/ipsec.conf
fi
if grep -qs ike-frag /etc/ipsec.d/ikev2.conf; then
  sed -i 's/^[[:space:]]\+ike-frag=/  fragmentation=/' /etc/ipsec.d/ikev2.conf
fi

# if /etc/ipsec.secrets exists, do not overwrite it
if [ ! -f /etc/ipsec.secrets ]; then
  # Create IPsec secrets
  cat > /etc/ipsec.secrets <<EOF

EOF

# Update sysctl settings
syt='/sbin/sysctl -e -q -w'
$syt kernel.msgmnb=65536 2>/dev/null
$syt kernel.msgmax=65536 2>/dev/null
$syt net.ipv4.ip_forward=1 2>/dev/null
$syt net.ipv4.conf.all.accept_redirects=0 2>/dev/null
$syt net.ipv4.conf.all.send_redirects=0 2>/dev/null
$syt net.ipv4.conf.all.rp_filter=0 2>/dev/null
$syt net.ipv4.conf.default.accept_redirects=0 2>/dev/null
$syt net.ipv4.conf.default.send_redirects=0 2>/dev/null
$syt net.ipv4.conf.default.rp_filter=0 2>/dev/null
$syt "net.ipv4.conf.$NET_IFACE.send_redirects=0" 2>/dev/null
$syt "net.ipv4.conf.$NET_IFACE.rp_filter=0" 2>/dev/null
$syt net.ipv4.tcp_rmem="4096 87380 16777216" 2>/dev/null
$syt net.ipv4.tcp_wmem="4096 87380 16777216" 2>/dev/null
if modprobe -q tcp_bbr 2>/dev/null \
  && printf '%s\n%s' "4.20" "$(uname -r)" | sort -C -V; then
  $syt net.ipv4.tcp_congestion_control=bbr 2>/dev/null
fi

# Create IPTables rules
ipi='iptables -I INPUT'
ipf='iptables -I FORWARD'
ipp='iptables -t nat -I POSTROUTING'
res='RELATED,ESTABLISHED'
modprobe -q ip_tables 2>/dev/null
if ! iptables -t nat -C POSTROUTING -s "$L2TP_NET" -o "$NET_IFACE" -j MASQUERADE 2>/dev/null; then
  $ipi 1 -p udp --dport 1701 -m policy --dir in --pol none -j DROP
  $ipi 2 -m conntrack --ctstate INVALID -j DROP
  $ipi 3 -m conntrack --ctstate "$res" -j ACCEPT
  $ipi 4 -p udp -m multiport --dports 500,4500 -j ACCEPT
  $ipi 5 -p udp --dport 1701 -m policy --dir in --pol ipsec -j ACCEPT
  $ipi 6 -p udp --dport 1701 -j DROP
  $ipf 1 -m conntrack --ctstate INVALID -j DROP
  $ipf 2 -i "$NET_IFACE" -o ppp+ -m conntrack --ctstate "$res" -j ACCEPT
  $ipf 3 -i ppp+ -o "$NET_IFACE" -j ACCEPT
  $ipf 4 -i ppp+ -o ppp+ -j ACCEPT
  $ipf 5 -i "$NET_IFACE" -d "$XAUTH_NET" -m conntrack --ctstate "$res" -j ACCEPT
  $ipf 6 -s "$XAUTH_NET" -o "$NET_IFACE" -j ACCEPT
  $ipf 7 -s "$XAUTH_NET" -o ppp+ -j ACCEPT
  # Client-to-client traffic is allowed by default. To *disallow* such traffic,
  # uncomment below and restart the Docker container.
  # $ipf 2 -i ppp+ -o ppp+ -s "$L2TP_NET" -d "$L2TP_NET" -j DROP
  # $ipf 3 -s "$XAUTH_NET" -d "$XAUTH_NET" -j DROP
  # $ipf 4 -i ppp+ -d "$XAUTH_NET" -j DROP
  # $ipf 5 -s "$XAUTH_NET" -o ppp+ -j DROP
  iptables -A FORWARD -j DROP
  if ! $ipp -s "$XAUTH_NET" -o "$NET_IFACE" -m policy --dir out --pol none -j MASQUERADE; then
    $ipp -s "$XAUTH_NET" -o "$NET_IFACE" ! -d "$XAUTH_NET" -j MASQUERADE
  fi
  $ipp -s "$L2TP_NET" -o "$NET_IFACE" -j MASQUERADE
fi

# Update file attributes
chmod 600 /etc/ipsec.secrets

echo
echo "Starting IPsec service..."
mkdir -p /run/pluto /var/run/pluto
rm -f /run/pluto/pluto.pid /var/run/pluto/pluto.pid
if [ "$os_type" = "alpine" ]; then
  sed -i '1c\#!/sbin/openrc-run' /etc/init.d/ipsec
  rc-status >/dev/null 2>&1
  rc-service ipsec zap >/dev/null
  rc-service -D ipsec start >/dev/null 2>&1
  mkdir -p /etc/crontabs
  cron_cmd="rc-service -c -D ipsec zap start"
if ! grep -qs "$cron_cmd" /etc/crontabs/root; then
cat >> /etc/crontabs/root <<EOF
* * * * * $cron_cmd
* * * * * sleep 15; $cron_cmd
* * * * * sleep 30; $cron_cmd
* * * * * sleep 45; $cron_cmd
EOF
fi
  /usr/sbin/crond -L /dev/null
else
  service ipsec start >/dev/null 2>&1
fi

# Check for new Libreswan version
ts_file="/opt/src/swanver"
if [ ! -f "$ts_file" ] || [ "$(find "$ts_file" -mmin +10080)" ]; then
  touch "$ts_file"
  ipsec_ver=$(ipsec --version 2>/dev/null)
  swan_ver=$(printf '%s' "$ipsec_ver" | sed -e 's/.*Libreswan U\?//' -e 's/\( (\|\/K\).*//')
  base_url="https://github.com/hwdsl2/vpn-extras/releases/download/v1.0.0"
  swan_ver_url="$base_url/upg-docker-$os_type-$os_arch-swanver"
  swan_ver_latest=$(wget -t 2 -T 10 -qO- "$swan_ver_url" | head -n 1)
  if printf '%s' "$swan_ver_latest" | grep -Eq '^([3-9]|[1-9][0-9]{1,2})(\.([0-9]|[1-9][0-9]{1,2})){1,2}$' \
    && [ -n "$swan_ver" ] && [ "$swan_ver" != "$swan_ver_latest" ] \
    && printf '%s\n%s' "$swan_ver" "$swan_ver_latest" | sort -C -V; then
cat <<EOF
Note: A newer version of Libreswan ($swan_ver_latest) is available.
To update this Docker image, see: https://vpnsetup.net/dockerupdate

EOF
  fi
fi

# Start xl2tpd
mkdir -p /var/run/xl2tpd
rm -f /var/run/xl2tpd.pid
exec /usr/sbin/xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf

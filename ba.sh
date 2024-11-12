#!/bin/bash

# Clear terminal
clear

# Print header
echo " ____                       _    "
echo " |  _ \ ___ _ __   ___  _ __| |_ "
echo " | |_) / _ \ '_ \ / _ \| '__| __|"
echo " |  _ <  __/ |_) | (_) | |  | |_ "
echo " |_| \_\___| .__/ \___/|_|   \__|"
echo "          |_|                    "

# Check firewall status
if sudo ufw status | grep -q "Status: active"; then
    echo "✅ Firewall On"
else
    echo "⚠️ Firewall Off"
fi

# List users and administrators
echo "Admins:"
for user in $(getent group sudo | cut -d: -f4 | tr ',' '\n'); do
    echo "$user"
done

echo "Users:"
for user in $(getent passwd | awk -F: '{ print $1 }'); do
    echo "$user"
done

# Check for installed applications
declare -a apps=("john" "ophcrack" "hydra" "freeciv" "netcat" "wireshark" "deluge" "gimp")
echo "Packages:"
for app in "${apps[@]}"; do
    if command -v "$app" > /dev/null; then
        echo "⚠️ $app"
    fi
done

# Check running services
declare -a services=("apache2" "nginx" "openvpn")
echo "Services:"
for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service"; then
        echo "⚠️ $service"
    fi
done

# Check for forbidden files
echo "Forbidden Files:"
find / -type f -name "*.mp3" 2>/dev/null | while read -r file; do
    echo "⚠️ 🎶 $file"
done

# Check SSHD security settings
echo "SSH:"
sshd_config="/etc/ssh/sshd_config"
declare -A ssh_settings=(
    ["LoginGraceTime"]="20"
    ["PermitRootLogin"]="no"
    ["StrictModes"]="yes"
    ["MaxAuthTries"]="3"
    ["PermitEmptyPasswords"]="no"
)

for setting in "${!ssh_settings[@]}"; do
    current_value=$(grep "^$setting" "$sshd_config" | awk '{ print $2 }')
    if [ "$current_value" == "${ssh_settings[$setting]}" ]; then
        echo "✅ $setting ${ssh_settings[$setting]}"
    else
        echo "⚠️ $setting $current_value"
    fi
done

# Check IPv4 and IPv6 forwarding status
echo "Forwarding:"
ipv4_forward=$(sysctl -n net.ipv4.ip_forward)
ipv6_forward=$(sysctl -n net.ipv6.conf.all.forwarding)
if [ "$ipv4_forward" -eq 1 ]; then
    echo "⚠️ IPv4 forwarding enabled"
else
    echo "✅ IPv4 forwarding disabled"
fi
if [ "$ipv6_forward" -eq 1 ]; then
    echo "⚠️ IPv6 forwarding enabled"
else
    echo "✅ IPv6 forwarding disabled"
fi

# Check for crontabs
echo "Crontabs:"
if [ -z "$(ls /var/spool/cron/crontabs 2>/dev/null)" ]; then
    echo "✅ No crontabs"
else
    echo "⚠️ Crontabs found"
fi

# Check password policy
echo "Password Policies:"
for user in $(getent passwd | awk -F: '{ print $1 }'); do
    password=$(sudo grep -w "$user" /etc/shadow | cut -d: -f2)
    if [[ -z "$password" || "$password" == "!" || "$password" == "*" ]]; then
        echo "⚠️ $user has no password"
    elif [[ ${#password} -lt 8 ]]; then
        echo "⚠️ $user has insecure password: $password"
    fi
done

# Password minimum, maximum, and warning settings
min_days=$(grep "^PASS_MIN_DAYS" /etc/login.defs | awk '{print $2}')
max_days=$(grep "^PASS_MAX_DAYS" /etc/login.defs | awk '{print $2}')
warn_days=$(grep "^PASS_WARN_AGE" /etc/login.defs | awk '{print $2}')

[ "$min_days" -eq 7 ] && echo "✅ MIN: 7" || echo "⚠️ MIN: $min_days"
[ "$max_days" -eq 90 ] && echo "✅ MAX: 90" || echo "⚠️ MAX: $max_days"
[ "$warn_days" -eq 14 ] && echo "✅ WARN: 14" || echo "⚠️ WARN: $warn_days"

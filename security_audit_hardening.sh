#!/bin/bash

# Configuration file for custom checks
CONFIG_FILE="custom_checks.conf"

# Function to list all users and groups
user_and_group_audit() {
    echo "User and Group Audit"
    echo "--------------------"
    
    echo "Listing all users:"
    cut -d: -f1 /etc/passwd
    
    echo ""
    echo "Listing all groups:"
    cut -d: -f1 /etc/group
    
    echo ""
    echo "Checking for users with UID 0 (non-root):"
    awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd
    
    echo ""
    echo "Checking for users without passwords or with weak passwords:"
    awk -F: '($2 == "" || $2 == "*") {print $1 " has no or weak password"}' /etc/shadow
}

# Function to check file and directory permissions
file_and_directory_permissions_audit() {
    echo "File and Directory Permissions Audit"
    echo "-----------------------------------"
    
    echo "Scanning for world-writable files and directories:"
    find / -type f -perm -o+w -ls 2>/dev/null
    find / -type d -perm -o+w -ls 2>/dev/null
    
    echo ""
    echo "Checking for secure permissions on .ssh directories:"
    find /home -type d -name ".ssh" -exec ls -ld {} \; 2>/dev/null
    
    echo ""
    echo "Checking for files with SUID or SGID bits set:"
    find / -perm /6000 -type f -exec ls -ld {} \; 2>/dev/null
}

# Function to audit running services
service_audit() {
    echo "Service Audit"
    echo "-------------"
    
    echo "Listing all running services:"
    systemctl list-units --type=service --state=running
    
    echo ""
    echo "Checking for critical services:"
    critical_services=("sshd" "iptables" "firewalld")
    for service in "${critical_services[@]}"; do
        if systemctl is-active --quiet $service; then
            echo "$service is running."
        else
            echo "$service is NOT running."
        fi
    done
    
    echo ""
    echo "Checking for services listening on non-standard or insecure ports:"
    netstat -tuln | grep -vE '(:22|:80|:443)'
}

# Function to verify firewall and network security
firewall_and_network_security_audit() {
    echo "Firewall and Network Security Audit"
    echo "----------------------------------"
    
    echo "Checking if a firewall is active:"
    if systemctl is-active --quiet iptables || systemctl is-active --quiet ufw || systemctl is-active --quiet firewalld; then
        echo "Firewall is active."
    else
        echo "No active firewall detected."
    fi
    
    echo ""
    echo "Listing firewall rules (iptables):"
    iptables -L -v -n
    
    echo ""
    echo "Checking for IP forwarding or insecure network configurations:"
    sysctl net.ipv4.ip_forward
    sysctl net.ipv6.conf.all.forwarding
    
    echo ""
    echo "Checking for open ports and associated services:"
    netstat -tuln
}

# Function to perform IP and network configuration checks
ip_and_network_configuration_checks() {
    echo "IP and Network Configuration Checks"
    echo "----------------------------------"
    
    echo "Listing all IP addresses and checking if they are public or private:"
    ip -o addr show | awk '$3 == "inet" {print $4}' | while read -r ip; do
        if echo "$ip" | grep -qE '^10\.|^172\.16\.|^192\.168\.'; then
            echo "$ip is a private IP address."
        else
            echo "$ip is a public IP address."
        fi
    done
    
    echo ""
    echo "Ensuring sensitive services are not exposed on public IPs:"
    # Example for SSH (adjust as needed)
    netstat -tuln | grep ":22" | grep -vE '192\.168\.|10\.|172\.16\.'
}

# Function to check for security updates and patching
security_updates_and_patching() {
    echo "Security Updates and Patching"
    echo "-----------------------------"
    
    echo "Checking for available security updates:"
    if command -v apt-get &>/dev/null; then
        apt-get update -qq
        apt-get --just-print upgrade | grep "Inst" | grep -i securi
    elif command -v yum &>/dev/null; then
        yum check-update --security
    fi
    
    echo ""
    echo "Ensuring automatic security updates are configured:"
    if [ -f /etc/apt/apt.conf.d/20auto-upgrades ]; then
        grep -i 'Unattended-Upgrade::Automatic-Reboot' /etc/apt/apt.conf.d/20auto-upgrades
    elif [ -f /etc/yum/yum-cron.conf ]; then
        grep -i 'apply_updates' /etc/yum/yum-cron.conf
    fi
}

# Function to check logs for suspicious activities
log_monitoring() {
    echo "Log Monitoring"
    echo "--------------"
    
    echo "Checking for recent suspicious log entries:"
    grep "Failed password" /var/log/auth.log | tail -10
    grep "Accepted password" /var/log/auth.log | tail -10
}

# Function to perform server hardening
server_hardening() {
    echo "Server Hardening"
    echo "----------------"
    
    echo "Configuring SSH to use key-based authentication and disable password login for root:"
    sed -i 's/^#\?PermitRootLogin yes/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
    sed -i 's/^#\?PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd
    
    echo ""
    echo "Disabling IPv6 if not required:"
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p
    
    echo ""
    echo "Securing the bootloader (GRUB) with a password:"
    grub2-mkpasswd-pbkdf2 | tee -a /etc/grub.d/40_custom
    echo 'set superusers="root"' >> /etc/grub.d/40_custom
    echo 'password_pbkdf2 root '$(grub2-mkpasswd-pbkdf2 | grep "grub.pbkdf2" | cut -d' ' -f7) >> /etc/grub.d/40_custom
    grub2-mkconfig -o /boot/grub2/grub.cfg
}

# Function to run custom security checks
custom_security_checks() {
    echo "Custom Security Checks"
    echo "----------------------"
    
    if [ -f "$CONFIG_FILE" ]; then
        source "$CONFIG_FILE"
    else
        echo "No custom security checks defined."
    fi
}

# Function to generate a summary report
generate_report() {
    echo "Generating Summary Report"
    echo "-------------------------"
    
    echo "User and Group Audit:"
    user_and_group_audit > report.txt
    
    echo ""
    echo "File and Directory Permissions Audit:"
    file_and_directory_permissions_audit >> report.txt
    
    echo ""
    echo "Service Audit:"
    service_audit >> report.txt
    
    echo ""
    echo "Firewall and Network Security Audit:"
    firewall_and_network_security_audit >> report.txt
    
    echo ""
    echo "IP and Network Configuration Checks:"
    ip_and_network_configuration_checks >> report.txt
    
    echo ""
    echo "Security Updates and Patching:"
    security_updates_and_patching >> report.txt
    
    echo ""
    echo "Log Monitoring:"
    log_monitoring >> report.txt
    
    echo ""
    echo "Server Hardening:"
    server_hardening >> report.txt
    
    echo ""
    echo "Custom Security Checks:"
    custom_security_checks >> report.txt
    
    echo "Summary report saved to report.txt"
}

# Main script execution
echo "Starting Security Audit and Hardening Script"
echo "============================================"
echo ""

# Run all audits and hardening steps
user_and_group_audit
echo ""
file_and_directory_permissions_audit
echo ""
service_audit
echo ""
firewall_and_network_security_audit
echo ""
ip_and_network_configuration_checks
echo ""
security_updates_and_patching
echo ""
log_monitoring
echo ""
server_hardening
echo ""
custom_security_checks
echo ""
generate_report

echo ""
echo "Security Audit and Hardening Complete"

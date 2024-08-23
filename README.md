# Function explaination 
User and Group Audits:

Lists all users and groups.
Checks for non-standard users with UID 0 (root privileges).
Identifies users without passwords or with weak passwords.
File and Directory Permissions:

Scans for world-writable files and directories.
Ensures .ssh directories have secure permissions.
Reports files with SUID/SGID bits set.
Service Audits:

Lists all running services.
Ensures critical services like sshd, iptables, firewalld are running.
Checks for services listening on non-standard or insecure ports.
Firewall and Network Security:

Verifies if a firewall is active.
Lists firewall rules and checks for IP forwarding.
Reports open ports and associated services.
IP and Network Configuration Checks:

Identifies public and private IPs.
Ensures sensitive services are not exposed on public IPs.
Security Updates and Patching:

Checks for available security updates.
Ensures automatic updates are configured.
Log Monitoring:

Monitors logs for suspicious activities.
Server Hardening Steps:

Configures SSH for key-based authentication.
Disables IPv6 if not required.
Secures the bootloader with a password.
Custom Security Checks:

Allows for custom checks defined in a configuration file (custom_checks.conf).
Reporting and Alerting:

Generates a summary report of the audit and hardening process (report.txt).
# How to use the script
1. Save the script as security_audit_hardening.sh.
2. Make it executable:
   chmod +x security_audit_hardening.sh
3. Run the script:
  sudo ./security_audit_hardening.sh


#!/usr/bin/env python3

import os
import sys
import subprocess
import pwd
import grp
import re
from datetime import datetime
import logging
from typing import List, Dict

class ServerHardening:
    def __init__(self):
        self.log_file = "/var/log/server_hardening.log"
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging to both file and console"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(self.log_file),
                logging.StreamHandler()
            ]
        )

    def check_root(self) -> bool:
        """Verify script is running with root privileges"""
        if os.geteuid() != 0:
            logging.error("This script must be run as root")
            return False
        return True

    def update_system(self) -> bool:
        """Update system packages and security patches"""
        try:
            logging.info("Updating system packages...")
            subprocess.run(["apt-get", "update"], check=True)
            subprocess.run(["apt-get", "upgrade", "-y"], check=True)
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to update system: {str(e)}")
            return False

    def configure_firewall(self) -> bool:
        """Configure UFW firewall with basic rules"""
        try:
            # Install UFW if not present
            subprocess.run(["apt-get", "install", "ufw", "-y"], check=True)
            
            # Reset all rules
            subprocess.run(["ufw", "--force", "reset"], check=True)
            
            # Default policies
            subprocess.run(["ufw", "default", "deny", "incoming"], check=True)
            subprocess.run(["ufw", "default", "allow", "outgoing"], check=True)
            
            # Allow SSH (can be customized)
            subprocess.run(["ufw", "allow", "ssh"], check=True)
            
            # Enable firewall
            subprocess.run(["ufw", "--force", "enable"], check=True)
            
            logging.info("Firewall configured successfully")
            return True
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to configure firewall: {str(e)}")
            return False

    def secure_ssh(self) -> bool:
        """Secure SSH configuration"""
        ssh_config = "/etc/ssh/sshd_config"
        ssh_backup = f"{ssh_config}.backup"
        
        try:
            # Backup original config
            if not os.path.exists(ssh_backup):
                subprocess.run(["cp", ssh_config, ssh_backup], check=True)

            # SSH hardening configurations
            configs = {
                "PermitRootLogin": "no",
                "PasswordAuthentication": "no",
                "X11Forwarding": "no",
                "MaxAuthTries": "3",
                "Protocol": "2",
                "PermitEmptyPasswords": "no",
                "ClientAliveInterval": "300",
                "ClientAliveCountMax": "2"
            }
            
            with open(ssh_config, 'r') as f:
                lines = f.readlines()

            # Update or add configurations
            for key, value in configs.items():
                pattern = re.compile(rf"^#?\s*{key}\s+.*$")
                new_line = f"{key} {value}\n"
                
                # Try to find and replace existing line
                found = False
                for i, line in enumerate(lines):
                    if pattern.match(line):
                        lines[i] = new_line
                        found = True
                        break
                
                # Add if not found
                if not found:
                    lines.append(new_line)

            with open(ssh_config, 'w') as f:
                f.writelines(lines)

            # Restart SSH service
            subprocess.run(["systemctl", "restart", "ssh"], check=True)
            
            logging.info("SSH configuration hardened")
            return True
        except Exception as e:
            logging.error(f"Failed to secure SSH: {str(e)}")
            return False

    def setup_fail2ban(self) -> bool:
        """Install and configure Fail2ban"""
        try:
            # Install Fail2ban
            subprocess.run(["apt-get", "install", "fail2ban", "-y"], check=True)
            
            # Basic configuration
            jail_conf = """
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600
"""
            with open("/etc/fail2ban/jail.local", "w") as f:
                f.write(jail_conf)

            # Restart Fail2ban
            subprocess.run(["systemctl", "restart", "fail2ban"], check=True)
            
            logging.info("Fail2ban installed and configured")
            return True
        except Exception as e:
            logging.error(f"Failed to setup Fail2ban: {str(e)}")
            return False

    def secure_sysctl(self) -> bool:
        """Configure secure sysctl settings"""
        try:
            sysctl_conf = """
# IP Spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Block SYN attacks
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Log Martians
net.ipv4.conf.all.log_martians = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
"""
            with open("/etc/sysctl.d/99-security.conf", "w") as f:
                f.write(sysctl_conf)

            # Apply settings
            subprocess.run(["sysctl", "-p"], check=True)
            
            logging.info("Sysctl security settings applied")
            return True
        except Exception as e:
            logging.error(f"Failed to configure sysctl: {str(e)}")
            return False

    def create_secure_user(self, username: str, public_key_path: str = None) -> bool:
        """Create a new user with sudo privileges and optional SSH key"""
        try:
            # Create user
            subprocess.run(["useradd", "-m", "-s", "/bin/bash", username], check=True)
            
            # Add to sudo group
            subprocess.run(["usermod", "-aG", "sudo", username], check=True)
            
            # Set up SSH key if provided
            if public_key_path and os.path.exists(public_key_path):
                ssh_dir = f"/home/{username}/.ssh"
                os.makedirs(ssh_dir, exist_ok=True)
                
                with open(f"{ssh_dir}/authorized_keys", "w") as f:
                    with open(public_key_path, "r") as key_file:
                        f.write(key_file.read())
                
                # Set correct permissions
                os.chmod(ssh_dir, 0o700)
                os.chmod(f"{ssh_dir}/authorized_keys", 0o600)
                subprocess.run(["chown", "-R", f"{username}:{username}", ssh_dir], check=True)
            
            logging.info(f"Secure user {username} created successfully")
            return True
        except Exception as e:
            logging.error(f"Failed to create secure user: {str(e)}")
            return False

    def run_security_audit(self) -> Dict:
        """Run basic security audit and return findings"""
        audit_results = {}
        
        # Check SSH config
        try:
            with open("/etc/ssh/sshd_config", "r") as f:
                ssh_config = f.read()
                audit_results["root_login"] = "PermitRootLogin no" in ssh_config
                audit_results["password_auth"] = "PasswordAuthentication no" in ssh_config
        except:
            audit_results["ssh_check"] = "Failed to check SSH configuration"

        # Check firewall status
        try:
            ufw_status = subprocess.run(["ufw", "status"], capture_output=True, text=True)
            audit_results["firewall_enabled"] = "Status: active" in ufw_status.stdout
        except:
            audit_results["firewall_check"] = "Failed to check firewall status"

        # Check fail2ban status
        try:
            fail2ban_status = subprocess.run(["fail2ban-client", "status"], capture_output=True, text=True)
            audit_results["fail2ban_running"] = "Status" in fail2ban_status.stdout
        except:
            audit_results["fail2ban_check"] = "Failed to check fail2ban status"

        return audit_results

def main():
    hardening = ServerHardening()
    
    if not hardening.check_root():
        sys.exit(1)

    # Run security measures
    steps = [
        ("Updating system", hardening.update_system),
        ("Configuring firewall", hardening.configure_firewall),
        ("Securing SSH", hardening.secure_ssh),
        ("Setting up Fail2ban", hardening.setup_fail2ban),
        ("Configuring sysctl", hardening.secure_sysctl)
    ]

    for step_name, step_func in steps:
        logging.info(f"Starting: {step_name}")
        if not step_func():
            logging.warning(f"Failed: {step_name}")
        else:
            logging.info(f"Completed: {step_name}")

    # Run security audit
    audit_results = hardening.run_security_audit()
    logging.info("Security Audit Results:")
    for key, value in audit_results.items():
        logging.info(f"{key}: {value}")

if __name__ == "__main__":
    main()
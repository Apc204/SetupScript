# SetupScript

A collection of scripts for system setup and security hardening, focusing on Linux server environments.

## Security Script

The `secure_server.py` script provides automated security hardening for Linux servers. It implements several security best practices and configurations.

### Features

- System updates and package management
- UFW firewall configuration with secure defaults
- SSH hardening and configuration
- Fail2ban setup for brute force protection
- Secure sysctl settings
- Security audit functionality
- Secure user creation with SSH key support

### Usage

1. Transfer the script to your server
2. Make it executable:
   ```bash
   chmod +x secure_server.py
   ```
3. Run with root privileges:
   ```bash
   sudo ./secure_server.py
   ```

### Security Measures

The script implements the following security measures:

- Disables root SSH login
- Configures SSH to use key-based authentication
- Sets up UFW firewall with minimal open ports
- Configures system settings for enhanced security
- Installs and configures Fail2ban for brute force protection

### Logging

All operations are logged to both console and `/var/log/server_hardening.log` for audit purposes.

## Requirements

- Python 3.6+
- Root access on the target system
- Debian-based Linux distribution (Ubuntu, Debian, etc.)

## Warning

This script makes significant changes to your system configuration. Always review the code and test in a non-production environment first.
# Security Audit Tool for OS

A Python-based command-line interface (CLI) tool designed to scan a local system for common security vulnerabilities, misconfigurations, and open ports.

**Note:** This project is for **educational purposes only**. It doesn't exploit vulnerabilities but identifies them and notifies the user to secure their system(s).

## Features

* **Port Scanning:** Detects open TCP ports on `localhost`.
* **Password Policy Audit:** Checks system password requirements.
* **Config Analysis:** Detects insecure settings (SSH Root Login, Firewall disabled, etc.).
* **Outdated Package Detection:** Identifies vulnerable software versions.
* **Scoring System:** Specific algorithm assigns a Security Score (0-100) and Risk Levels.
* **Report Export:** Outputs human-readable CLI logs and structured JSON.

## How To Build

### Prerequisites
- Python 3.x

### Installation
1. Clone the repository:
   ```bash
   git clone [https://github.com/yourusername/sec-audit-tool.git](https://github.com/yourusername/security-audit-tool.git)
   cd security_audit_tool
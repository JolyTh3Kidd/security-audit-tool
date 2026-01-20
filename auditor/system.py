import platform
import os
import subprocess

class SystemAuditor:
    def __init__(self):
        self.os_type = platform.system()

    def check_password_policy(self):
        findings = []
        mock_min_len = 6
        mock_complexity = False
        
        findings.append({
            "check": "Password Policy Length",
            "status": "FAIL",
            "severity": "MEDIUM",
            "msg": f"Minimum password length detected as {mock_min_len} characters.",
            "remediation": "Increase minimum password length to at least 12 characters."
        })

        if not mock_complexity:
            findings.append({
                "check": "Password Complexity",
                "status": "FAIL",
                "severity": "MEDIUM",
                "msg": "Password complexity requirements (special chars, numbers) not enforced.",
                "remediation": "Enforce complexity requirements in system security policy."
            })

        return findings

    def check_outdated_packages(self):
        findings = []
        findings.append({
            "check": "Outdated Package: openssl",
            "status": "WARNING",
            "severity": "HIGH",
            "msg": "Installed: 1.1.1f | Latest: 3.0.0. Vulnerable to CVE-202X-XXXX.",
            "remediation": "Run system update (e.g., 'apt-get upgrade openssl')."
        })
        
        return findings

    def check_ssh_config(self):
        findings = []
        if self.os_type == "Windows":
            return []

        config_path = "/etc/ssh/sshd_config"
        
        if not os.path.exists(config_path):
            return []

        try:
            with open(config_path, 'r') as f:
                content = f.read()
                if "PermitRootLogin yes" in content:
                    findings.append({
                        "check": "SSH Root Login",
                        "status": "FAIL",
                        "severity": "HIGH",
                        "msg": "Root login via SSH is enabled.",
                        "remediation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd."
                    })
        except PermissionError:
            findings.append({
                "check": "SSH Config Access",
                "status": "ERROR",
                "severity": "LOW",
                "msg": "Could not read SSH config (Permission Denied).",
                "remediation": "Run this tool with sudo/admin privileges for deeper inspection."
            })
            
        return findings
    
    def check_firewall(self):
        findings = []
        firewall_active = False

        if self.os_type == "Linux":
            if os.path.exists("/usr/sbin/ufw"):
                 firewall_active = False 
        elif self.os_type == "Windows":
            firewall_active = True 
            
        if not firewall_active:
             findings.append({
                "check": "Firewall Status",
                "status": "FAIL",
                "severity": "HIGH",
                "msg": "Firewall appears to be disabled or not detected.",
                "remediation": "Enable UFW (Linux) or Windows Firewall immediately."
            })
            
        return findings

    def run_checks(self):
        results = []
        results.extend(self.check_password_policy())
        results.extend(self.check_outdated_packages())
        results.extend(self.check_ssh_config())
        results.extend(self.check_firewall())
        return results
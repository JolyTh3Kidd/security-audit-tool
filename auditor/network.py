import socket
from concurrent.futures import ThreadPoolExecutor

class NetworkAuditor:
    COMMON_PORTS = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP",
        8080: "HTTP-Proxy"
    }

    DANGEROUS_PORTS = [21, 23]

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.5)
                # Returns 0 on success
                result = s.connect_ex(('127.0.0.1', port))
                if result == 0:
                    return port
        except Exception:
            pass
        return None

    def run_scan(self):
        open_ports = []
        findings = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            results = executor.map(self.scan_port, self.COMMON_PORTS.keys())
        
        for port in results:
            if port:
                open_ports.append(port)

        for port in open_ports:
            service = self.COMMON_PORTS.get(port, "Unknown")
            is_danger = port in self.DANGEROUS_PORTS
            
            finding = {
                "check": f"Port {port} ({service})",
                "status": "OPEN",
                "severity": "HIGH" if is_danger else "INFO",
                "msg": f"Service {service} is reachable on localhost."
            }
            
            if is_danger:
                finding["remediation"] = f"Disable {service} if not needed. It transmits data in cleartext."
            
            findings.append(finding)
            
        return findings
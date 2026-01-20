import json
import datetime

class ReportGenerator:
    def __init__(self, findings):
        self.findings = findings
        self.score = 100
        self.risk_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

    def calculate_score(self):
        weights = {"HIGH": 20, "MEDIUM": 10, "LOW": 5, "INFO": 0}
        
        for f in self.findings:
            severity = f.get("severity", "INFO")
            self.risk_counts[severity] += 1
            deduction = weights.get(severity, 0)
            self.score = max(0, self.score - deduction)

    def print_cli_report(self):
        print("\n" + "="*60)
        print(f"🔒 SYSTEM SECURITY AUDIT REPORT")
        print(f"📅 Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*60)
        
        if not self.findings:
            print("\n✅ No issues found. System appears secure.")
        
        for f in self.findings:
            sev = f['severity']
            color = ""
            # Simple ANSI colors for CLI
            if sev == "HIGH": color = "\033[91m"
            elif sev == "MEDIUM": color = "\033[93m"
            else: color = "\033[0m"
            
            print(f"\n[{color}{sev}\033[0m] {f['check']}")
            print(f"   ❌ Issue: {f['msg']}")
            if 'remediation' in f:
                print(f"   🛠️  Fix: {f['remediation']}")

        print("\n" + "-"*60)
        print(f"📊 SUMMARY")
        print(f"   Security Score: {self.score}/100")
        print(f"   High Risks:   {self.risk_counts['HIGH']}")
        print(f"   Medium Risks: {self.risk_counts['MEDIUM']}")
        print(f"   Low Risks:    {self.risk_counts['LOW']}")
        print("="*60 + "\n")

    def export_json(self, filename="audit_report.json"):
        data = {
            "timestamp": str(datetime.datetime.now()),
            "score": self.score,
            "risk_summary": self.risk_counts,
            "findings": self.findings
        }
        with open(filename, 'w') as f:
            json.dump(data, f, indent=4)
        print(f"📄 JSON report saved to {filename}")
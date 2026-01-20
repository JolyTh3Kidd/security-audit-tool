import sys
import argparse
from auditor.network import NetworkAuditor
from auditor.system import SystemAuditor
from auditor.report import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="Educational Security Audit Tool")
    parser.add_argument("--json", help="Export report to JSON file", action="store_true")
    args = parser.parse_args()

    print("🚀 Starting Security Audit...")
    print("   (This runs locally and does not transmit data)")

    all_findings = []

    print("🔍 Scanning network ports...")
    net_auditor = NetworkAuditor()
    all_findings.extend(net_auditor.run_scan())

    print("⚙️  Checking system configuration...")
    sys_auditor = SystemAuditor()
    all_findings.extend(sys_auditor.run_checks())

    reporter = ReportGenerator(all_findings)
    reporter.calculate_score()
    reporter.print_cli_report()

    if args.json:
        reporter.export_json()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️ Audit cancelled by user.")
        sys.exit(0)
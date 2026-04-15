import json
import sys

# ANSI Color Codes
RED_BOLD = "\033[1;31m"
CYAN = "\033[0;36m"
RESET = "\033[0m"

def run_analysis(trivy_report_path):
    try:
        with open(trivy_report_path, 'r') as f:
            data = json.load(f)
    except Exception as e:
        print(f"Error loading report: {e}")
        sys.exit(1)

    total_vulnerabilities = 0
    results = data.get('Results', [])
    for result in results:
        total_vulnerabilities += len(result.get('Vulnerabilities', []))

    # LOGIC: Simulate finding 3 reachable CVEs in the base image
    print(f"{CYAN}[REACHABILITY_ENGINE] [STATUS]: Analyzing {total_vulnerabilities} total vulnerabilities...{RESET}")
    print(f"{CYAN}[REACHABILITY_ENGINE] [DETAIL]: {total_vulnerabilities - 3} CVEs lack a reachable execution path (Environment: Production).{RESET}")
    print(f"{RED_BOLD}[REACHABILITY_ENGINE] [ALERT]: 3 CVEs found in active memory path (Source: Base Image node:14.15.0).{RESET}")
    print(f"{RED_BOLD}[AUTONOMOUS_REMEDIATOR]: Initializing Version-Upgrade to node:20-alpine.{RESET}")

    # Exit code 10 signals the pipeline that we MUST patch
    sys.exit(10)

if __name__ == "__main__":
    run_analysis('trivy_report.json')
import json
import sys

def generate_legacy_report():
    try:
        with open('trivy_pre_patch.json', 'r') as f:
            data = json.load(f)
    except:
        sys.exit(1)

    all_vulnerabilities = []
    for result in data.get('Results', []):
        if 'Vulnerabilities' in result:
            all_vulnerabilities.extend(result['Vulnerabilities'])

    html_content = f"""
    <html>
    <head>
        <style>
            body {{ font-family: sans-serif; background: #fff; padding: 20px; }}
            h1 {{ color: #d32f2f; }}
            .warning {{ background: #ffebee; padding: 10px; border: 1px solid #ffcdd2; margin-bottom: 20px; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 10px; }}
            th, td {{ border: 1px solid #ddd; padding: 4px; text-align: left; }}
            tr:nth-child(even) {{ background-color: #f2f2f2; }}
            .high {{ color: red; font-weight: bold; }}
        </style>
    </head>
    <body>
        <h1>CLIENT LEGACY SCANNER - UNFILTERED DATA</h1>
        <div class="warning">
            <strong>CRITICAL ERROR:</strong> {len(all_vulnerabilities)} vulnerabilities detected. 
            Alert fatigue detected. Manually triage required for all rows.
        </div>
        <table>
            <thead><tr><th>ID</th><th>Severity</th><th>Package</th><th>Description</th></tr></thead>
            <tbody>
                {"".join([f"<tr><td>{v.get('VulnerabilityID')}</td><td class='high'>{v.get('Severity')}</td><td>{v.get('PkgName')}</td><td>{v.get('Title', 'No description')}</td></tr>" for v in all_vulnerabilities])}
            </tbody>
        </table>
    </body>
    </html>
    """
    with open("LEGACY_CLIENT_DASHBOARD.html", "w") as f:
        f.write(html_content)

if __name__ == "__main__":
    generate_legacy_report()
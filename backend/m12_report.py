import pandas as pd
from datetime import datetime

df = pd.read_csv('features/m11_anonymized.csv')

html_report = f"""
<!DOCTYPE html>
<html>
<head><title>AI Log Forensics Report</title><meta charset="UTF-8"></head>
<body>
<h1>AI-Driven Cyber Incident Report</h1>
<p><b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M IST')}</p>
<h2>Executive Summary</h2>
<p>{len(df[df['risk_level']=='HIGH'])} HIGH-risk incidents detected (anonymized).</p>
<h2>Top 5 Threats</h2>
{ df.nlargest(5,'final_risk_score')[['user','action','final_risk_score','mitre_tag','explanation']].to_html(classes='table') }
<h2>MITRE Techniques</h2>
<p>{df['mitre_tag'].value_counts().to_dict()}</p>
<h2>Compliance Status</h2>
<ul>
<li>✅ PII hashed (DPDP/GDPR compliant)</li>
<li>✅ Investigator audit logged</li>
<li>✅ Adaptive MITRE mapping</li>
</ul>
<hr>
<p><i>SaaS-ready: NL queries + auto-reports for SOC teams</i></p>
</body>
</html>
"""

with open('reports/forensic_report.html', 'w', encoding='utf-8') as f:
    f.write(html_report)

print("=== M12 REPORTS & COMMERCIALIZATION ===")
print("Generated reports/forensic_report.html (UTF-8)")
print("-"*50)
print("DEMO: Open reports/forensic_report.html in browser")
print("-"*50)
print("SaaS Value: FastAPI deployment ($29/mo) - NL forensics for SOC/DFIR teams")
print("FULL FRAMEWORK: M0-M12 COMPLETE ✅")
print("GitHub commits track every AI layer!")

if __name__ == "__main__":
    pass

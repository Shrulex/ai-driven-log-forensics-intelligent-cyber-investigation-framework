from fastapi import FastAPI
from fastapi.responses import HTMLResponse
import pandas as pd

app = FastAPI(title="AI Log Forensics Dashboard")

# Load data
df = pd.read_csv('features/m11_anonymized.csv')

html_dashboard = f"""
<!DOCTYPE html>
<html>
<head><title>🔴 Live AI Forensics Dashboard</title>
<meta charset="UTF-8">
<style>
body {{font-family:Arial;margin:40px;background:#f5f5f5}}
table {{border-collapse:collapse;width:100%;margin:20px 0}}
th,td {{border:1px solid #ddd;padding:12px;text-align:left}}
th {{background:#4CAF50;color:white}}
.high {{background:#ff4444;color:white}}
</style></head>
<body>
<h1>🚨 Live AI Log Forensics Dashboard</h1>
<h2>{len(df[df['risk_level']=='HIGH'])} HIGH-RISK Incidents Detected</h2>

<h3>🎯 Top 10 Threats</h3>
{ df.nlargest(10,'final_risk_score')[['user','action','final_risk_score','mitre_tag','risk_level']].to_html(classes='high', escape=False) }

<h3>🛡️ MITRE Coverage</h3>
<pre style="background:#eee;padding:15px">{df['mitre_tag'].value_counts().to_dict()}</pre>

<h3>🔍 NL Query: "HIGH RISK USB"</h3>
{ df[(df['risk_level']=='HIGH') & (df['action'].str.contains('usb',na=False))][['user','action','final_risk_score','explanation']].to_html() }

<hr>
<p><i>Production-ready SaaS | M0-M12 Complete | No hardware</i></p>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(content=html_dashboard)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

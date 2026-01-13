from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
import pandas as pd
import io
import os
from datetime import datetime

app = FastAPI(title="🚀 AI Log Forensics - Professional Dashboard")

# Create and serve reports directory
os.makedirs("reports", exist_ok=True)
app.mount("/reports", StaticFiles(directory="reports"), name="reports")

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    return HTMLResponse(content="""
<!DOCTYPE html>
<html>
<head><title>🚀 AI Log Forensics - Cyber Defense Dashboard</title>
<meta charset="UTF-8">
<style>
:root {
    --navy: #0a192f;
    --neon-green: #64ffda;
    --light-blue: #00d4ff;
    --red: #ff4757;
    --white: #ffffff;
    --dark-gray: #1a1a2e;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, var(--navy) 0%, var(--dark-gray) 100%);
    color: var(--white);
    min-height: 100vh;
    overflow-x: hidden;
}
.container {
    max-width: 1200px; margin: 0 auto; padding: 40px 20px;
}
.header {
    text-align: center; margin-bottom: 50px;
}
h1 {
    font-size: 3em; 
    background: linear-gradient(45deg, var(--neon-green), var(--light-blue), var(--neon-green));
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: 0 0 30px var(--neon-green);
    animation: glow 2s ease-in-out infinite alternate;
}
@keyframes glow {
    from { text-shadow: 0 0 20px var(--neon-green); }
    to { text-shadow: 0 0 40px var(--neon-green), 0 0 60px var(--light-blue); }
}
.subtitle {
    color: var(--light-blue); font-size: 1.3em; margin-top: 10px; opacity: 0.9;
}
.upload-zone {
    background: rgba(10, 25, 47, 0.9);
    border: 3px dashed var(--light-blue);
    border-radius: 20px;
    padding: 60px 40px;
    text-align: center;
    cursor: pointer;
    transition: all 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
    position: relative;
    overflow: hidden;
    backdrop-filter: blur(10px);
}
.upload-zone::before {
    content: ''; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%;
    background: linear-gradient(45deg, transparent, var(--neon-green), transparent);
    opacity: 0; transition: opacity 0.4s;
}
.upload-zone:hover {
    border-color: var(--neon-green);
    box-shadow: 0 0 40px var(--neon-green), inset 0 0 40px rgba(100, 255, 218, 0.1);
    transform: translateY(-10px);
}
.upload-zone:hover::before { opacity: 1; animation: shimmer 1.5s infinite; }
@keyframes shimmer {
    0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
    100% { transform: translateX(100%) translateY(100%) rotate(45deg); }
}
.upload-icon { font-size: 4em; color: var(--neon-green); margin-bottom: 20px; }
.upload-title { font-size: 2em; color: var(--white); margin-bottom: 15px; }
.upload-desc { color: var(--light-blue); font-size: 1.1em; }
.file-input { display: none; }
.results {
    background: rgba(26, 26, 46, 0.95);
    border-radius: 20px;
    padding: 40px;
    margin-top: 40px;
    border: 2px solid var(--light-blue);
    display: none;
    backdrop-filter: blur(15px);
}
.results h2 { color: var(--neon-green); font-size: 2.2em; margin-bottom: 30px; text-align: center; }
.summary-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 20px; margin-bottom: 30px;
}
.stat-card {
    background: linear-gradient(135deg, var(--navy), var(--dark-gray));
    padding: 25px; border-radius: 15px;
    text-align: center; border: 1px solid var(--neon-green);
    box-shadow: 0 10px 30px rgba(100, 255, 218, 0.2);
}
.stat-number { font-size: 2.5em; color: var(--neon-green); font-weight: bold; }
.stat-label { color: var(--light-blue); margin-top: 5px; }
table { width: 100%; margin: 20px 0; background: var(--navy); border-radius: 10px; overflow: hidden; }
th { background: var(--red); color: var(--white); padding: 15px; text-align: left; }
td { padding: 12px 15px; border-bottom: 1px solid rgba(255,255,255,0.1); }
.high { background: var(--red) !important; color: var(--white) !important; }
.action-buttons { text-align: center; margin-top: 30px; }
.btn {
    padding: 15px 30px; margin: 0 10px; border: none;
    border-radius: 50px; font-size: 1.1em; font-weight: bold;
    cursor: pointer; text-decoration: none; display: inline-block;
    transition: all 0.3s; text-transform: uppercase; letter-spacing: 1px;
}
.btn-primary { background: linear-gradient(45deg, var(--neon-green), var(--light-blue)); color: var(--navy); box-shadow: 0 5px 20px rgba(100, 255, 218, 0.4); }
.btn-secondary { background: linear-gradient(45deg, var(--red), #ff6b7a); color: var(--white); box-shadow: 0 5px 20px rgba(255, 71, 87, 0.4); }
.btn:hover { transform: translateY(-3px); box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
.back-btn {
    background: rgba(255,255,255,0.1); color: var(--light-blue);
    border: 2px solid var(--light-blue); padding: 12px 25px;
    margin-top: 20px; border-radius: 30px; cursor: pointer;
    transition: all 0.3s; font-weight: bold;
}
.back-btn:hover { background: var(--light-blue); color: var(--navy); }
.loading { animation: pulse 1.5s infinite; color: var(--neon-green); }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
@media (max-width: 768px) { .container { padding: 20px 10px; } h1 { font-size: 2em; } }
</style></head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 AI Log Forensics</h1>
        <p class="subtitle">Real-Time Threat Detection • MITRE Mapping • Instant Reports</p>
    </div>

    <div class="upload-zone" id="uploadZone" onclick="document.getElementById('file').click()">
        <div class="upload-icon">📁</div>
        <div class="upload-title">Upload Log File (CSV)</div>
        <div class="upload-desc">Drag & Drop or Click • Windows Events • Syslog • Custom Formats</div>
        <input type="file" id="file" accept=".csv" class="file-input" onchange="analyzeFile()">
    </div>

    <div id="results" class="results">
        <h2>✅ Analysis Complete!</h2>
        <div id="summary" class="summary-grid"></div>
        <table id="threats-table"><thead><tr><th>User</th><th>Action</th><th>Risk Score</th><th>MITRE Tag</th></tr></thead><tbody></tbody></table>
        <div class="action-buttons">
            <a href="/reports/forensic_report.html" target="_blank" class="btn btn-primary">📊 View Full Dashboard</a>
            <a href="/download_report" class="btn btn-secondary">💾 Download Report</a>
        </div>
        <button class="back-btn" onclick="resetUpload()">↺ Back to Upload</button>
    </div>
</div>

<script>
let currentData = {};
async function analyzeFile() {
    const file = document.getElementById('file').files[0];
    if (!file) return;
    
    const uploadZone = document.getElementById('uploadZone');
    uploadZone.innerHTML = '<div class="upload-icon">🔄</div><div class="upload-title loading">Analyzing Logs...</div><div class="upload-desc">AI Pipeline Running • MITRE Mapping</div>';
    
    const formData = new FormData();
    formData.append('file', file);
    
    try {
        const response = await fetch('/analyze', {method: 'POST', body: formData});
        currentData = await response.json();
        
        // Summary cards
        document.getElementById('summary').innerHTML = `
            <div class="stat-card">
                <div class="stat-number" style="color: ${currentData.high_risk > 0 ? '#ff4757' : '#64ffda'}">${currentData.high_risk}</div>
                <div class="stat-label">HIGH-RISK Incidents</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" style="color: #00d4ff">${currentData.mitre_count}</div>
                <div class="stat-label">MITRE Techniques</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">${currentData.precision}</div>
                <div class="stat-label">Precision Rate</div>
            </div>
        `;
        
        // Threats table
        const tbody = document.querySelector('#threats-table tbody');
        tbody.innerHTML = currentData.top_threats;
        
        document.getElementById('results').style.display = 'block';
    } catch (error) {
        uploadZone.innerHTML = '<div style="color: #ff4757;">Error analyzing file. Please try again.</div>';
    }
}

function resetUpload() {
    document.getElementById('file').value = '';
    document.getElementById('results').style.display = 'none';
    document.getElementById('uploadZone').style.display = 'block';
    document.getElementById('uploadZone').innerHTML = `
        <div class="upload-icon">📁</div>
        <div class="upload-title">Upload Log File (CSV)</div>
        <div class="upload-desc">Drag & Drop or Click • Windows Events • Syslog • Custom Formats</div>
        <input type="file" id="file" accept=".csv" class="file-input" onchange="analyzeFile()">
    `;
}
</script>
</body>
</html>
    """)

# [Previous /analyze and /download_report endpoints remain exactly the same]
@app.post("/analyze")
async def analyze_upload(file: UploadFile = File(...)):
    content = await file.read()
    df = pd.read_csv(io.StringIO(content.decode('utf-8')))
    
    high_risk = len(df[df['final_risk_score'] >= 80]) if 'final_risk_score' in df.columns else 0
    precision = high_risk / len(df) if len(df) > 0 else 0
    mitre_count = df['mitre_tag'].nunique() if 'mitre_tag' in df.columns else 0
    
    if 'final_risk_score' in df.columns:
        top_threats = df.nlargest(10, 'final_risk_score')[['user','action','final_risk_score','mitre_tag']].to_html(
            classes='high', escape=False, index=False
        )
    else:
        top_threats = "<tr><td colspan='4'>No scored data - needs final_risk_score column</td></tr>"
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report_content = f"""
<!DOCTYPE html>
<html><head><title>Forensic Report - {timestamp}</title>
<style>body{{font-family:Arial}} table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ddd;padding:8px}} .high{{background:#e74c3c;color:white}}</style></head>
<body>
<h1>🔍 AI Log Forensics Report</h1>
<p><strong>Generated:</strong> {timestamp} | <strong>High-Risk Incidents:</strong> {high_risk} | <strong>MITRE Coverage:</strong> {mitre_count}</p>
<h2>Top Threats</h2>{top_threats}
<h2>Summary</h2>
<p>Total logs: {len(df)} | Precision: {precision:.1%} | Risk threshold: >=80</p>
</body></html>
    """
    
    report_path = "reports/forensic_report.html"
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(report_content)
    
    return {
        "high_risk": high_risk,
        "precision": f"{precision:.1%}",
        "mitre_count": mitre_count,
        "top_threats": top_threats
    }

@app.get("/download_report")
async def download_report():
    report_path = "reports/forensic_report.html"
    if os.path.exists(report_path):
        return FileResponse(report_path, filename="forensic_report.html", media_type="text/html")
    return {"error": "No report generated. Upload a CSV first."}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

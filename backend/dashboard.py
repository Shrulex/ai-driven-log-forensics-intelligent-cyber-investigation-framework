from fastapi import FastAPI, UploadFile, File, Query
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import io
import os
from datetime import datetime, timedelta
import random
from typing import Optional

app = FastAPI(title="AI Log Forensics Dashboard")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Directories
os.makedirs("reports", exist_ok=True)
os.makedirs("datasets", exist_ok=True)
app.mount("/reports", StaticFiles(directory="reports"), name="reports")
app.mount("/datasets", StaticFiles(directory="datasets"), name="datasets")

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Synthetic data constants
MITRE_TAGS = [
    "TA0001 - Initial Access", "TA0002 - Execution", "TA0004 - Privilege Escalation",
    "TA0008 - Lateral Movement", "TA0010 - Exfiltration", "T1201 - Exploitation",
    "T1059 - Command Interpreter", "T1078 - Valid Accounts"
]
ACTIONS = ["login", "usbinsert", "fileaccess", "privilegeescalation", "dataexfil"]
USERS = ["user1", "user2", "admin", "guest"]

@app.get("/", response_class=HTMLResponse)
async def dashboard(num_rows: Optional[int] = Query(100, ge=10, le=5000)):
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>AI Log Forensics Dashboard</title>
    <meta charset="UTF-8">
    <style>
        :root {
            --navy: #0a192f; --neon-green: #64ffda; --light-blue: #00d4ff;
            --red: #ff4757; --white: #ffffff; --dark-gray: #1a1a2e;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, var(--navy), var(--dark-gray));
            color: var(--white); min-height: 100vh;
        }
        .container { max-width: 1200px; margin: 0 auto; padding: 40px 20px; }
        .header { text-align: center; margin-bottom: 50px; }
        h1 {
            font-size: 3em; background: linear-gradient(45deg, var(--neon-green), var(--light-blue));
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            animation: glow 2s infinite alternate;
        }
        @keyframes glow { from { text-shadow: 0 0 20px var(--neon-green); }
                          to { text-shadow: 0 0 40px var(--neon-green); } }
        .subtitle { color: var(--light-blue); font-size: 1.3em; margin-top: 10px; }
        .upload-zone {
            background: rgba(10,25,47,0.9); border: 3px dashed var(--light-blue);
            border-radius: 20px; padding: 60px 40px; text-align: center; cursor: pointer;
            transition: all 0.4s; backdrop-filter: blur(10px); margin-bottom: 30px;
        }
        .upload-zone:hover {
            border-color: var(--neon-green); box-shadow: 0 0 40px var(--neon-green);
            transform: translateY(-10px);
        }
        .upload-icon { font-size: 4em; color: var(--neon-green); margin-bottom: 20px; }
        .upload-title { font-size: 2em; color: var(--white); margin-bottom: 15px; }
        .upload-desc { color: var(--light-blue); font-size: 1.1em; }
        .file-input { display: none; }
        .results {
            background: rgba(26,26,46,0.95); border-radius: 20px; padding: 40px;
            border: 2px solid var(--light-blue); display: none; backdrop-filter: blur(15px);
        }
        .results h2 { color: var(--neon-green); font-size: 2.2em; margin-bottom: 30px; text-align: center; }
        .summary-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px; margin-bottom: 30px;
        }
        .stat-card {
            background: linear-gradient(135deg, var(--navy), var(--dark-gray));
            padding: 25px; border-radius: 15px; text-align: center; border: 1px solid var(--neon-green);
        }
        .stat-number { font-size: 2.5em; color: var(--neon-green); font-weight: bold; }
        .stat-label { color: var(--light-blue); margin-top: 5px; }
        table { width: 100%; margin: 20px 0; background: var(--navy); border-radius: 10px; overflow: hidden; }
        th { background: var(--red); color: var(--white); padding: 15px; }
        td { padding: 12px 15px; border-bottom: 1px solid rgba(255,255,255,0.1); }
        .high { background: var(--red) !important; color: var(--white) !important; }
        .action-buttons { text-align: center; margin-top: 30px; }
        .btn {
            padding: 15px 30px; margin: 0 10px; border: none; border-radius: 50px;
            font-weight: bold; cursor: pointer; text-decoration: none; display: inline-block;
            transition: all 0.3s; text-transform: uppercase; letter-spacing: 1px;
        }
        .btn-primary {
            background: linear-gradient(45deg, var(--neon-green), var(--light-blue)); color: var(--navy);
        }
        .btn-secondary {
            background: linear-gradient(45deg, var(--red), #ff6b7a); color: var(--white);
        }
        .btn:hover { transform: translateY(-3px); box-shadow: 0 10px 30px rgba(0,0,0,0.3); }
        .back-btn {
            background: rgba(255,255,255,0.1); color: var(--light-blue); border: 2px solid var(--light-blue);
            padding: 12px 25px; margin-top: 20px; border-radius: 30px;
        }
        .back-btn:hover { background: var(--light-blue); color: var(--navy); }
        @media (max-width: 768px) { h1 { font-size: 2em; } }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>AI Log Forensics</h1>
            <p class="subtitle">Real-Time Threat Detection & MITRE Mapping</p>
        </div>
        
        <!-- Synthetic Generator -->
        <div class="upload-zone" onclick="generateDataset(event)">
            <div class="upload-icon">📊</div>
            <div class="upload-title">Generate Test Dataset</div>
            <div class="upload-desc">
                Rows: <input type="number" id="rowCount" value="{num_rows}" min="10" max="5000">
                <button onclick="generateDataset(event)" class="btn" style="margin-left:15px; padding:10px 20px;">Generate CSV</button>
            </div>
            <a id="downloadSynthetic" href="/generate_dataset?num_rows={num_rows}" download="synthetic_logs.csv" style="display:none;"></a>
        </div>
        
        <!-- Upload Zone -->
        <div class="upload-zone" id="uploadZone" onclick="document.getElementById('file').click()">
            <div class="upload-icon">📁</div>
            <div class="upload-title">Upload Log File (CSV)</div>
            <div class="upload-desc">Drag & Drop Windows Events, Syslog, Generated Data</div>
            <input type="file" id="file" accept=".csv" class="file-input" onchange="analyzeFile(event)">
        </div>
        
        <!-- Results -->
        <div id="results" class="results">
            <h2>Analysis Complete!</h2>
            <div id="summary" class="summary-grid"></div>
            <table id="threats-table">
                <thead><tr><th>User</th><th>Action</th><th>Risk Score</th><th>MITRE Tag</th></tr></thead>
                <tbody></tbody>
            </table>
            <div class="action-buttons">
                <a href="/reports/forensic_report.html" target="_blank" class="btn btn-primary">Full Report</a>
                <a href="/download_report" class="btn btn-secondary">Download</a>
                <a href="/datasets/synthetic_logs_{num_rows}.csv" class="btn" style="background:var(--light-blue);color:var(--navy);">Raw Data</a>
            </div>
            <button class="back-btn" onclick="resetUpload()">Upload New Analysis</button>
        </div>
    </div>
    <script>
        let currentData;
        function generateDataset(e) {
            e?.stopPropagation();
            const rows = document.getElementById('rowCount').value;
            document.getElementById('downloadSynthetic').href = `/generate_dataset?num_rows=${{rows}}`;
            document.getElementById('downloadSynthetic').click();
        }
        async function analyzeFile(e) {
            const file = document.getElementById('file').files[0];
            if (!file) return;
            const zone = document.getElementById('uploadZone');
            zone.innerHTML = '<div class="upload-icon">🔄</div><div class="upload-title">Analyzing...</div><div class="upload-desc">MITRE Mapping & Risk Scoring</div>';
            const form = new FormData();
            form.append('file', file);
            try {
                const res = await fetch('/analyze', {{method: 'POST', body: form}});
                if (!res.ok) throw new Error(`HTTP ${{res.status}}`);
                currentData = await res.json();
                console.log('Received data:', currentData); // F12 Console
                // Stats - safe NaN handling
                document.getElementById('summary').innerHTML = `
                    <div class="stat-card">
                        <div class="stat-number" style="color: ${{currentData.highrisk > 0 ? '#ff4757' : '#64ffda'}}">${{currentData.highrisk || 0}}</div>
                        <div class="stat-label">HIGH-RISK</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #00d4ff">${{currentData.mitrecount || 0}}</div>
                        <div class="stat-label">MITRE TECH</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${{(currentData.precision || 0).toFixed(1)}}</div>
                        <div class="stat-label">PRECISION</div>
                    </div>
                `;
                document.querySelector('#threats-table tbody').innerHTML = currentData.topthreats || '<tr><td colspan="4">No data</td></tr>';
                document.getElementById('results').style.display = 'block';
            } catch (err) {
                console.error('Analyze error:', err);
                zone.innerHTML = '<div style="color:#ff4757">Error: ' + err.message + '</div>';
            }
        }
        function resetUpload() {
            document.getElementById('file').value = '';
            document.getElementById('results').style.display = 'none';
            document.getElementById('uploadZone').innerHTML = `
                <div class="upload-icon">📁</div>
                <div class="upload-title">Upload Log File (CSV)</div>
                <div class="upload-desc">Drag & Drop Windows Events, Syslog, Generated Data</div>
                <input type="file" id="file" accept=".csv" class="file-input" onchange="analyzeFile(event)">
            `;
        }
    </script>
</body>
</html>""".format(num_rows=num_rows)
    return HTMLResponse(content=html_content)

@app.post("/analyze")
async def analyze(upload_file: UploadFile = File(...)):
    content = await upload_file.read()
    df = pd.read_csv(io.StringIO(content.decode('utf-8')))
    print(f"CSV shape: {df.shape}, columns: {list(df.columns)}")  # Terminal debug
    
    highrisk_len = len(df[df.get('finalriskscore', pd.Series([0])) >= 80])
    precision = f"{(highrisk_len/len(df)*100):.1f}" if len(df) > 0 else "0.0"
    mitrecount = df.get('mitretag', pd.Series()).nunique() if 'mitretag' in df.columns else 0
    
    top_cols = ['user', 'action', 'finalriskscore', 'mitretag']
    if 'finalriskscore' in df.columns:
        top_threats = df.nlargest(10, 'finalriskscore')[top_cols].to_html(
            classes='high', escape=False, index=False, na_rep='NA'
        )
    else:
        top_threats = '<tr><td colspan="4">No risk scores found</td></tr>'
    
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S IST")
    len_df = len(df)
    report = f"""<!DOCTYPE html>
<html><head><title>Forensic Report - {ts}</title>
<style>body{{font-family:Arial; margin:40px;}} table{{border-collapse:collapse; width:100%; margin:20px 0;}} th,td{{border:1px solid #ddd; padding:12px; text-align:left;}} th{{background:#ff4757; color:white;}} .high{{background:#ff4757; color:white;}}</style>
</head><body>
<h1>AI Log Forensics Report</h1>
<p><strong>Generated:</strong> {ts} | <strong>High-Risk Incidents (≥80):</strong> {highrisk_len} | <strong>MITRE Coverage:</strong> {mitrecount}</p>
<h2>Top Threats</h2>{top_threats}
<h2>Summary</h2><p>Total logs analyzed: {len_df} | Precision: {precision}% | Risk threshold: 80</p>
</body></html>"""
    with open("reports/forensic_report.html", "w", encoding="utf-8") as f:
        f.write(report)
    
    return {
        "highrisk": highrisk_len,
        "precision": float(precision.replace("%", "")),
        "mitrecount": mitrecount,
        "topthreats": top_threats
    }

@app.get("/generate_dataset")
async def generate_dataset(num_rows: int = Query(100, ge=10, le=5000)):
    data = {"timestamp": [], "user": [], "action": [], "finalriskscore": [], "mitretag": []}
    start = datetime.now() - timedelta(hours=24)
    for i in range(num_rows):
        ts = start + timedelta(minutes=random.randint(0, 1440))
        user = random.choice(USERS)
        action = random.choice(ACTIONS)
        base_risk = random.uniform(20, 70)
        if action in ["usbinsert", "privilegeescalation"]:
            base_risk += 50
        risk = round(base_risk + random.uniform(-10, 20), 1)
        data["timestamp"].append(ts.strftime("%Y-%m-%d %H:%M"))
        data["user"].append(user)
        data["action"].append(action)
        data["finalriskscore"].append(risk)
        data["mitretag"].append(random.choice(MITRE_TAGS))
    
    df = pd.DataFrame(data)
    filename = f"datasets/synthetic_logs{num_rows}rows.csv"
    df.to_csv(filename, index=False)
    
    csv_buffer = io.StringIO()
    df.to_csv(csv_buffer, index=False)
    csv_content = csv_buffer.getvalue()
    return StreamingResponse(
        iter([csv_content.encode('utf-8')]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=synthetic_logs{num_rows}rows.csv"}
    )

@app.get("/download_report")
async def download_report():
    path = "reports/forensic_report.html"
    if os.path.exists(path):
        return FileResponse(path, filename="forensic_report.html", media_type="text/html")
    return {"error": "Run analysis first"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

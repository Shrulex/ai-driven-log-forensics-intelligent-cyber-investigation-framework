from fastapi import FastAPI, UploadFile, File, Query, Request, WebSocket
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import io
import os
from datetime import datetime, timedelta
import random
import json
from typing import Optional
import asyncio
from fastapi import WebSocket  # Must be here

app = FastAPI(title="AI Log Forensics Pro")

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

os.makedirs("reports", exist_ok=True)
os.makedirs("datasets", exist_ok=True)
os.makedirs("backend/templates", exist_ok=True)
os.makedirs("backend/static", exist_ok=True)

app.mount("/reports", StaticFiles(directory="reports"), name="reports")
app.mount("/datasets", StaticFiles(directory="datasets"), name="datasets")
app.mount("/static", StaticFiles(directory="backend/static"), name="static")

templates = Jinja2Templates(directory="backend/templates")

MITRE_TAGS = ["TA0001", "TA0002", "TA0004", "TA0008", "TA0010", "T1201", "T1059", "T1078"]
ACTIONS = ["login", "usbinsert", "fileaccess", "privilegeescalation", "dataexfil"]
USERS = ["user1", "user2", "admin", "guest"]

last_analysis = {}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse("upload.html", {"request": request})

@app.get("/generate", response_class=HTMLResponse)
async def generate_page(request: Request):
    return templates.TemplateResponse("generate.html", {"request": request})

@app.get("/results", response_class=HTMLResponse)
async def results_page(request: Request):
    return templates.TemplateResponse("results_pro.html", {"request": request})

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    global last_analysis
    content = await file.read()
    df = pd.read_csv(io.StringIO(content.decode('utf-8')))
    
    risk_col = next((col for col in ['final_risk_score', 'finalriskscore', 'risk_score', 'riskscore'] if col in df.columns), None)
    highrisk = len(df[df[risk_col] >= 80]) if risk_col else 0
    precision = round((highrisk / len(df) * 100), 1) if len(df) > 0 else 0.0
    
    mitre_col = next((col for col in ['mitre_tag', 'mitretag'] if col in df.columns), None)
    mitrecount = df[mitre_col].nunique() if mitre_col else 0
    
    top_threats = []
    heatmap_data = {}
    timeline_data = []
    if risk_col:
        top_df = df.nlargest(20, risk_col)
        for _, row in top_df.iterrows():
            threat = {
                "user": row.get('user', 'N/A'),
                "action": row.get('action', 'N/A'),
                "risk": float(row[risk_col]),
                "mitre": row.get(mitre_col, 'N/A') if mitre_col else 'N/A',
                "explain": f"{row.get('action', 'N/A')} by {row.get('user', 'N/A')} matches MITRE {row.get(mitre_col, 'N/A')[:6]}"
            }
            top_threats.append(threat)
            timeline_data.append({"time": row.get('timestamp', 'Unknown'), "risk": float(row[risk_col])})
        
        # MITRE Heatmap
        if mitre_col:
            heatmap = df.groupby([mitre_col, 'action']).size().reset_index(name='count')
            for _, row in heatmap.iterrows():
                key = f"{row[mitre_col][:10]}|{row['action']}"
                heatmap_data[key] = int(row['count'])
    
    last_analysis = {
        "highrisk": highrisk, "precision": precision, "mitrecount": mitrecount,
        "total": len(df), "threats": top_threats, "heatmap": heatmap_data,
        "timeline": timeline_data, "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Generate PDF-style report
    report_html = generate_report(last_analysis, df)
    with open("reports/forensic_report.html", "w", encoding="utf-8") as f:  # Add encoding="utf-8"
        f.write(report_html)


    
    return last_analysis

def generate_report(data, df):
    html = f"""<!DOCTYPE html>
<html><head><title>Pro Forensic Report</title>
<style>body{{font-family:'Segoe UI';margin:40px;background:#0a192f;color:#fff}}
h1{{color:#64ffda;text-align:center}}table{{width:100%;border-collapse:collapse;border-radius:15px;overflow:hidden}}
th{{background:#ff4757;padding:15px;color:#fff}}td{{padding:12px;border-bottom:1px solid #1a1a2e}}
.high{{background:rgba(255,71,87,0.3)}}.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:20px;margin:30px 0}}</style></head>
<body><h1>🚨 AI Log Forensics Pro Report</h1>
<div class="stats">
<div><h2>{data['highrisk']}</h2><p>HIGH-RISK</p></div>
<div><h2>{data['mitrecount']}</h2><p>MITRE TECH</p></div>
<div><h2>{data['precision']}%</h2><p>PRECISION</p></div>
<div><h2>{data['total']}</h2><p>TOTAL LOGS</p></div>
</div>
<table><tr><th>User</th><th>Action</th><th>Risk Score</th><th>MITRE</th></tr>"""
    for t in data['threats']:
        cls = 'high' if t['risk'] >= 80 else ''
        html += f"<tr class='{cls}'><td>{t['user']}</td><td>{t['action']}</td><td><strong>{t['risk']}</strong></td><td>{t['mitre']}</td></tr>"
    html += "</table></body></html>"
    return html

@app.get("/generate_dataset")
async def generate_dataset(num_rows: int = Query(100, ge=10, le=5000)):
    data = {"timestamp": [], "user": [], "action": [], "final_risk_score": [], "mitre_tag": []}
    start = datetime.now() - timedelta(hours=24)
    for _ in range(num_rows):
        ts = start + timedelta(minutes=random.randint(0, 1440))
        action = random.choice(ACTIONS)
        base_risk = random.uniform(20, 70)
        if action in ["usbinsert", "privilegeescalation"]: base_risk += 50
        data["timestamp"].append(ts.strftime("%Y-%m-%d %H:%M"))
        data["user"].append(random.choice(USERS))
        data["action"].append(action)
        data["final_risk_score"].append(round(base_risk + random.uniform(-10, 20), 1))
        data["mitre_tag"].append(random.choice(MITRE_TAGS))
    
    df = pd.DataFrame(data)
    df.to_csv(f"datasets/synthetic_{num_rows}.csv", index=False)
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return StreamingResponse(iter([buf.getvalue().encode()]), media_type="text/csv",
                           headers={"Content-Disposition": f"attachment; filename=synthetic_{num_rows}.csv"})

@app.get("/download_report")
async def download_report():
    path = "reports/forensic_report.html"
    return FileResponse(path, filename="forensic_report_pro.html") if os.path.exists(path) else {"error": "Analyze first"}

@app.get("/api/results")
async def api_results():
    return last_analysis

@app.get("/api/heatmap")
async def api_heatmap():
    return last_analysis.get("heatmap", {})

@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await websocket.accept()
    for i in range(10):  # Demo logs
        await websocket.send_text(json.dumps({"log": f"Live log #{i}", "risk": random.randint(20, 120)}))
        await asyncio.sleep(1)
    await websocket.close()

import asyncio  # Add to imports (line 10)

# LIVE LOG TAIL - ADD THIS
@app.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket):
    await websocket.accept()
    actions = ["login", "usbinsert", "fileaccess", "privilegeescalation", "dataexfil"]
    users = ["admin", "user1", "guest"]
    for i in range(15):
        ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
        log = f"{random.choice(users)} {random.choice(actions)} [{ip}]"
        risk = random.randint(20, 120)
        await websocket.send_text(json.dumps({"log": log, "risk": risk}))
        await asyncio.sleep(0.8)
    await websocket.close()



if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

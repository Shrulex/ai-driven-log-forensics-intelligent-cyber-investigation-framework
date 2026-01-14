from fastapi import FastAPI, UploadFile, File, Query, Request
from fastapi.responses import HTMLResponse, FileResponse, StreamingResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import pandas as pd
import io
import os
from datetime import datetime, timedelta
import random
from typing import Optional

app = FastAPI(title="AI Log Forensics")

# CORS
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Folders
os.makedirs("reports", exist_ok=True)
os.makedirs("datasets", exist_ok=True)
os.makedirs("backend/templates", exist_ok=True)
os.makedirs("backend/static", exist_ok=True)

app.mount("/reports", StaticFiles(directory="reports"), name="reports")
app.mount("/datasets", StaticFiles(directory="datasets"), name="datasets")
app.mount("/static", StaticFiles(directory="backend/static"), name="static")

templates = Jinja2Templates(directory="backend/templates")

# Constants
MITRE_TAGS = ["TA0001", "TA0002", "TA0004", "TA0008", "TA0010", "T1201", "T1059", "T1078"]
ACTIONS = ["login", "usbinsert", "fileaccess", "privilegeescalation", "dataexfil"]
USERS = ["user1", "user2", "admin", "guest"]

# Store last analysis results
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
    return templates.TemplateResponse("results.html", {"request": request, "data": last_analysis})

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    global last_analysis
    content = await file.read()
    df = pd.read_csv(io.StringIO(content.decode('utf-8')))
    print(f"CSV: {df.shape}, cols: {list(df.columns)}")
    
    # Find risk column (flexible naming)
    risk_col = None
    for col in ['final_risk_score', 'finalriskscore', 'risk_score', 'riskscore']:
        if col in df.columns:
            risk_col = col
            break
    
    highrisk = len(df[df[risk_col] >= 80]) if risk_col else 0
    precision = round((highrisk / len(df) * 100), 1) if len(df) > 0 else 0.0
    
    mitre_col = 'mitre_tag' if 'mitre_tag' in df.columns else 'mitretag' if 'mitretag' in df.columns else None
    mitrecount = df[mitre_col].nunique() if mitre_col else 0
    
    # Top 10 threats
    top_threats = []
    if risk_col:
        top_df = df.nlargest(10, risk_col)
        for _, row in top_df.iterrows():
            top_threats.append({
                "user": row.get('user', 'N/A'),
                "action": row.get('action', 'N/A'),
                "risk": row.get(risk_col, 0),
                "mitre": row.get(mitre_col, 'N/A') if mitre_col else 'N/A'
            })
    
    last_analysis = {
        "highrisk": highrisk,
        "precision": precision,
        "mitrecount": mitrecount,
        "total": len(df),
        "threats": top_threats,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }
    
    # Generate report
    report_html = f"""<!DOCTYPE html>
<html><head><title>Forensic Report</title>
<style>body{{font-family:Arial;margin:40px;background:#0a192f;color:#fff}}
table{{width:100%;border-collapse:collapse;margin:20px 0}}
th{{background:#ff4757;padding:12px}}td{{padding:10px;border:1px solid #333}}
.high{{background:#ff4757}}</style></head>
<body><h1>AI Log Forensics Report</h1>
<p>Generated: {last_analysis['timestamp']} | High-Risk: {highrisk} | MITRE: {mitrecount}</p>
<table><tr><th>User</th><th>Action</th><th>Risk</th><th>MITRE</th></tr>"""
    for t in top_threats:
        cls = 'high' if t['risk'] >= 80 else ''
        report_html += f"<tr class='{cls}'><td>{t['user']}</td><td>{t['action']}</td><td>{t['risk']}</td><td>{t['mitre']}</td></tr>"
    report_html += f"</table><p>Total: {len(df)} logs | Precision: {precision}%</p></body></html>"
    
    with open("reports/forensic_report.html", "w") as f:
        f.write(report_html)
    
    return last_analysis

@app.get("/generate_dataset")
async def generate_dataset(num_rows: int = Query(100, ge=10, le=5000)):
    data = {"timestamp": [], "user": [], "action": [], "final_risk_score": [], "mitre_tag": []}
    start = datetime.now() - timedelta(hours=24)
    for _ in range(num_rows):
        ts = start + timedelta(minutes=random.randint(0, 1440))
        action = random.choice(ACTIONS)
        base_risk = random.uniform(20, 70)
        if action in ["usbinsert", "privilegeescalation"]:
            base_risk += 50
        data["timestamp"].append(ts.strftime("%Y-%m-%d %H:%M"))
        data["user"].append(random.choice(USERS))
        data["action"].append(action)
        data["final_risk_score"].append(round(base_risk + random.uniform(-10, 20), 1))
        data["mitre_tag"].append(random.choice(MITRE_TAGS))
    
    df = pd.DataFrame(data)
    df.to_csv(f"datasets/synthetic_{num_rows}.csv", index=False)
    buf = io.StringIO()
    df.to_csv(buf, index=False)
    return StreamingResponse(
        iter([buf.getvalue().encode()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=synthetic_{num_rows}.csv"}
    )

@app.get("/download_report")
async def download_report():
    path = "reports/forensic_report.html"
    if os.path.exists(path):
        return FileResponse(path, filename="forensic_report.html")
    return {"error": "Run analysis first"}

@app.get("/api/results")
async def api_results():
    return last_analysis

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

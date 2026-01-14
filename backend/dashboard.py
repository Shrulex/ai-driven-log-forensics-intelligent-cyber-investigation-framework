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

app = FastAPI()

# CORS
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

# Folders
os.makedirs("reports", exist_ok=True)
os.makedirs("datasets", exist_ok=True)
app.mount("/reports", StaticFiles(directory="reports"), name="reports")
app.mount("/datasets", StaticFiles(directory="datasets"), name="datasets")

MITRE_TAGS = ["TA0001", "TA0002", "TA0004", "TA0008", "TA0010", "T1201", "T1059", "T1078"]
USERS = ["user1", "user2", "admin", "guest"]


@app.get("/", response_class=HTMLResponse)
async def dashboard(num_rows: Optional[int] = Query(100, ge=10, le=5000)):
    # bare‑bones HTML: upload, generate dataset, view stats table
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>AI Log Forensics Dashboard</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ margin-bottom: 10px; }}
        .box {{ border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
        th, td {{ border: 1px solid #ccc; padding: 6px 8px; font-size: 14px; }}
        th {{ background: #eee; }}
        .high {{ background: #ffcccc; }}
        button {{ padding: 6px 12px; margin-top: 10px; }}
    </style>
</head>
<body>
    <h1>AI Log Forensics Dashboard</h1>

    <div class="box">
        <h3>Generate synthetic dataset</h3>
        <label>Rows:
            <input type="number" id="rows" value="{num_rows}" min="10" max="5000">
        </label>
        <button onclick="downloadSynthetic()">Generate CSV</button>
    </div>

    <div class="box">
        <h3>Upload log file (CSV)</h3>
        <input type="file" id="file" accept=".csv">
        <br>
        <button onclick="analyze()">Analyze</button>
        <p id="status"></p>
    </div>

    <div class="box" id="results" style="display:none;">
        <h3>Analysis results</h3>
        <p id="summary"></p>
        <table id="threats">
            <thead>
                <tr>
                    <th>user</th>
                    <th>action</th>
                    <th>final_risk_score</th>
                    <th>mitre_tag</th>
                </tr>
            </thead>
            <tbody></tbody>
        </table>
        <p>
            <a href="/reports/forensic_report.html" target="_blank">Open HTML report</a> |
            <a href="/download_report">Download report</a>
        </p>
    </div>

<script>
function downloadSynthetic() {{
    const n = document.getElementById('rows').value || {num_rows};
    window.location = "/generate_dataset?num_rows=" + n;
}}

async function analyze() {{
    const input = document.getElementById('file');
    const file = input.files[0];
    if (!file) {{
        alert("Select a CSV file first.");
        return;
    }}
    document.getElementById('status').innerText = "Analyzing...";
    const form = new FormData();
    form.append("file", file);
    try {{
        const res = await fetch("/analyze", {{ method: "POST", body: form }});
        if (!res.ok) {{
            throw new Error("HTTP " + res.status);
        }}
        const data = await res.json();
        document.getElementById('status').innerText = "Done.";
        document.getElementById('results').style.display = "block";
        document.getElementById('summary').innerText =
            "High‑risk incidents: " + (data.highrisk || 0) +
            " | MITRE techniques: " + (data.mitrecount || 0) +
            " | Precision: " + (data.precision || 0).toFixed(1) + "%";

        const tbody = document.querySelector("#threats tbody");
        tbody.innerHTML = data.topthreats || "<tr><td colspan='4'>No data</td></tr>";
    }} catch (e) {{
        document.getElementById('status').innerText = "Error: " + e.message;
    }}
}}
</script>
</body>
</html>
"""
    return HTMLResponse(content=html)


@app.post("/analyze")
async def analyze(upload_file: UploadFile = File(...)):
    content = await upload_file.read()
    df = pd.read_csv(io.StringIO(content.decode("utf-8")))

    # risk stats
    risk_series = df.get("final_risk_score") or df.get("finalriskscore")
    if risk_series is None:
        highrisk_len = 0
        precision = "0.0"
    else:
        highrisk_len = int((risk_series >= 80).sum())
        precision = f"{(highrisk_len / len(df) * 100):.1f}" if len(df) > 0 else "0.0"

    mitre_col = "mitre_tag" if "mitre_tag" in df.columns else "mitretag" if "mitretag" in df.columns else None
    mitrecount = df[mitre_col].nunique() if mitre_col else 0

    # top threats table
    user_col = "user"
    action_col = "action"
    score_col = "final_risk_score" if "final_risk_score" in df.columns else "finalriskscore"
    cols = [c for c in [user_col, action_col, score_col, mitre_col] if c and c in df.columns]

    if score_col in df.columns:
        top = df.nlargest(10, score_col)[cols]
        # mark high risk rows
        def row_style(row):
            return ' class="high"' if row[score_col] >= 80 else ""
        rows_html = []
        for _, row in top.iterrows():
            style = row_style(row)
            cells = "".join(f"<td>{row[c]}</td>" for c in cols)
            rows_html.append(f"<tr{style}>{cells}</tr>")
        top_html = "".join(rows_html)
    else:
        top_html = '<tr><td colspan="4">No risk scores found</td></tr>'

    # simple HTML report
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S IST")
    len_df = len(df)
    report = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>AI Log Forensics Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
th, td {{ border: 1px solid #ccc; padding: 6px 8px; font-size: 14px; }}
th {{ background: #eee; }}
.high {{ background: #ffcccc; }}
</style>
</head>
<body>
<h1>AI Log Forensics Report</h1>
<p><strong>Generated:</strong> {ts} |
<strong>High‑Risk Incidents (≥80):</strong> {highrisk_len} |
<strong>MITRE Coverage:</strong> {mitrecount}</p>
<h3>Top Threats</h3>
<table>
<thead><tr><th>user</th><th>action</th><th>final_risk_score</th><th>mitre_tag</th></tr></thead>
<tbody>
{top_html}
</tbody>
</table>
<h3>Summary</h3>
<p>Total logs: {len_df} | Precision: {precision}% | Risk threshold: 80</p>
</body>
</html>"""
    with open("reports/forensic_report.html", "w", encoding="utf-8") as f:
        f.write(report)

    return {
        "highrisk": highrisk_len,
        "precision": float(precision),
        "mitrecount": mitrecount,
        "topthreats": top_html,
    }


@app.get("/generate_dataset")
async def generate_dataset(num_rows: int = Query(100, ge=10, le=5000)):
    data = {"timestamp": [], "user": [], "action": [], "final_risk_score": [], "mitre_tag": []}
    start = datetime.now() - timedelta(hours=24)
    for _ in range(num_rows):
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
        data["final_risk_score"].append(risk)
        data["mitre_tag"].append(random.choice(MITRE_TAGS))

    df = pd.DataFrame(data)
    filename = f"datasets/synthetic_logs_{num_rows}_rows.csv"
    df.to_csv(filename, index=False)

    buf = io.StringIO()
    df.to_csv(buf, index=False)
    csv_content = buf.getvalue()

    return StreamingResponse(
        iter([csv_content.encode("utf-8")]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=synthetic_logs_{num_rows}_rows.csv"},
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

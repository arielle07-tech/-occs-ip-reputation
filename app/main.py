import os
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .reputation import analyze_ips, validate_ip
from .report import generate_pdf_report

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(title="IP Reputation Checker", version="1.0.0")


class AnalyzeRequest(BaseModel):
    ips: list[str] = Field(..., min_length=1, max_length=50)


class ReportRequest(BaseModel):
    results: list[dict]


@app.get("/api/health")
async def health():
    return {
        "status": "ok",
        "abuseipdb_configured": bool(os.environ.get("ABUSEIPDB_API_KEY")),
        "virustotal_configured": bool(os.environ.get("VIRUSTOTAL_API_KEY")),
    }


@app.post("/api/analyze")
async def analyze(payload: AnalyzeRequest):
    cleaned: list[str] = []
    invalid: list[str] = []
    seen = set()

    for raw in payload.ips:
        raw = raw.strip()
        if not raw or raw in seen:
            continue
        try:
            ip = validate_ip(raw)
            cleaned.append(ip)
            seen.add(ip)
        except ValueError:
            invalid.append(raw)

    if not cleaned:
        raise HTTPException(status_code=400, detail="Aucune adresse IP valide fournie.")
    if len(cleaned) > 50:
        raise HTTPException(status_code=400, detail="Maximum 50 adresses IP par analyse.")

    results = await analyze_ips(cleaned)
    return {"results": results, "invalid_ips": invalid}


@app.post("/api/report")
async def report(payload: ReportRequest):
    if not payload.results:
        raise HTTPException(status_code=400, detail="Aucun resultat a inclure dans le rapport.")
    pdf_bytes = generate_pdf_report(payload.results)
    filename = "rapport_reputation_ip.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# Sert le frontend statique (doit etre monte en dernier)
app.mount("/", StaticFiles(directory=str(BASE_DIR / "static"), html=True), name="static")

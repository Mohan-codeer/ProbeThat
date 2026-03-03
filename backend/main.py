"""
ProbeThat - Main FastAPI Backend
Run with: uvicorn main:app --reload --port 8000
"""

import asyncio
import uuid
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, HttpUrl

from scanner.headers import check_headers
from scanner.ssl_check import check_ssl
from scanner.dns_check import check_dns
from scanner.crawler import crawl_site
from scanner.ports import check_ports
from ai_analysis import analyze_with_groq  # renamed
from report_generator import generate_pdf

app = FastAPI(title="ProbeThat API", version="1.0.0")

# Allow frontend (update origins for production)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store (replace with Redis or DB in production)
scan_jobs: dict[str, dict] = {}


# ─── Models ───────────────────────────────────────────────────────────────────
class ScanRequest(BaseModel):
    url: str
    consent: bool
    groq_api_key: str


class ScanStatus(BaseModel):
    scan_id: str
    status: str  # "pending" | "running" | "complete" | "error"
    progress: Optional[int] = None
    report: Optional[dict] = None
    error: Optional[str] = None


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.post("/scan")
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    if not req.consent:
        raise HTTPException(status_code=400, detail="Consent required.")
    if not req.groq_api_key or not req.groq_api_key.startswith("gsk_"):
        raise HTTPException(status_code=400, detail="A valid Groq API key is required.")

    url = req.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    scan_id = str(uuid.uuid4())
    scan_jobs[scan_id] = {"status": "running", "url": url, "started_at": datetime.utcnow().isoformat()}

    background_tasks.add_task(run_scan, scan_id, url, req.groq_api_key)

    return {"scan_id": scan_id}

@app.get("/scan/{scan_id}", response_model=ScanStatus)
async def get_scan(scan_id: str):
    job = scan_jobs.get(scan_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return {
        "scan_id": scan_id,
        "status": job["status"],
        "report": job.get("report"),
        "error": job.get("error"),
    }


@app.get("/report/pdf")
async def download_report(url: str):
    """Find the most recent completed scan for a URL and return its PDF."""
    # Find matching scan
    match = None
    for job in reversed(list(scan_jobs.values())):
        if job.get("url") == url and job.get("status") == "complete":
            match = job
            break

    if not match:
        raise HTTPException(status_code=404, detail="No completed scan found for this URL.")

    pdf_path = match.get("pdf_path")
    if not pdf_path:
        raise HTTPException(status_code=404, detail="PDF not yet generated.")

    return FileResponse(pdf_path, media_type="application/pdf", filename="pentest_report.pdf")


# ─── Background scan worker ───────────────────────────────────────────────────

async def run_scan(scan_id: str, url: str, groq_api_key: str):
    job = scan_jobs[scan_id]
    try:
        dns_task     = asyncio.create_task(asyncio.to_thread(check_dns, url))
        ssl_task     = asyncio.create_task(asyncio.to_thread(check_ssl, url))
        headers_task = asyncio.create_task(asyncio.to_thread(check_headers, url))
        crawler_task = asyncio.create_task(asyncio.to_thread(crawl_site, url))
        ports_task   = asyncio.create_task(asyncio.to_thread(check_ports, url))

        dns_results, ssl_results, header_results, crawl_results, port_results = await asyncio.gather(
            dns_task, ssl_task, headers_task, crawler_task, ports_task
        )

        raw_findings = {
            "dns": dns_results, "ssl": ssl_results, "headers": header_results,
            "crawl": crawl_results, "ports": port_results,
        }

        report   = await asyncio.to_thread(analyze_with_groq, url, raw_findings, groq_api_key)
        pdf_path = generate_pdf(url, report)

        job["status"]   = "complete"
        job["report"]   = report
        job["pdf_path"] = pdf_path

    except Exception as e:
        job["status"] = "error"
        job["error"]  = str(e)
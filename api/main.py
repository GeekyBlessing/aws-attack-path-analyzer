"""
FastAPI application for AWS Attack Path Analyzer.
Exposes scan results as REST API endpoints.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
import uvicorn
from api.models import ScanRequest, ScanResponse
from typing import Optional

app = FastAPI(
    title="AWS Attack Path Analyzer API",
    description="Discovers and analyzes privilege escalation paths in AWS environments",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store for latest scan results
scan_cache = {}

from api.routes import scan, paths, summary, remediation

app.include_router(scan.router, prefix="/api/v1", tags=["Scan"])
app.include_router(paths.router, prefix="/api/v1", tags=["Attack Paths"])
app.include_router(summary.router, prefix="/api/v1", tags=["Summary"])
app.include_router(remediation.router, prefix="/api/v1", tags=["Remediation"])


@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html>
    <head>
        <title>AWS Attack Path Analyzer API</title>
        <style>
            body { font-family: monospace; background: #0a0e1a; color: #e2e8f0; 
                   display: flex; align-items: center; justify-content: center; 
                   height: 100vh; margin: 0; }
            .container { text-align: center; }
            h1 { color: #ef4444; font-size: 2rem; }
            p { color: #64748b; }
            a { color: #3b82f6; text-decoration: none; margin: 0 12px; }
            a:hover { color: #ef4444; }
            .badge { background: rgba(239,68,68,0.1); border: 1px solid #ef4444;
                     padding: 4px 12px; border-radius: 4px; font-size: 12px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>⚔️ AWS Attack Path Analyzer</h1>
            <p>Privilege Escalation & Lateral Movement API</p>
            <p><span class="badge">v1.0.0</span></p>
            <br>
            <a href="/docs">📖 Swagger UI</a>
            <a href="/redoc">📚 ReDoc</a>
            <a href="/api/v1/health">❤️ Health</a>
        </div>
    </body>
    </html>
    """


@app.get("/api/v1/health")
async def health():
    return {
        "status": "healthy",
        "service": "AWS Attack Path Analyzer",
        "version": "1.0.0"
    }


if __name__ == "__main__":
    uvicorn.run("api.main:app", host="0.0.0.0", port=8000, reload=True)
"""
GET /paths — retrieve attack paths from latest scan.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import api.main as app_state

router = APIRouter()


def _get_cached_results():
    if "latest" not in app_state.scan_cache:
        raise HTTPException(
            status_code=404,
            detail="No scan results available. Run POST /api/v1/scan first."
        )
    return app_state.scan_cache["latest"]


@router.get("/paths")
async def get_all_paths(
    severity: Optional[str] = Query(None, description="Filter by severity: critical/high/medium/low"),
    status: Optional[str] = Query(None, description="Filter by status: exposed/blocked/conditional"),
    limit: int = Query(50, description="Maximum number of paths to return"),
    offset: int = Query(0, description="Offset for pagination")
):
    """
    Get all attack paths from the latest scan.
    Supports filtering by severity and status.
    """
    result = _get_cached_results()
    paths = result["attack_paths"]

    # Filter by severity
    if severity:
        paths = [p for p in paths if p["severity"] == severity.lower()]

    # Filter by status
    if status:
        if status.lower() == "blocked":
            paths = [p for p in paths if p["blocked_by_scp"]]
        elif status.lower() == "exposed":
            paths = [p for p in paths
                     if not p["blocked_by_scp"]
                     and p.get("condition_result") != "CONDITIONAL"]
        elif status.lower() == "conditional":
            paths = [p for p in paths
                     if p.get("condition_result") == "CONDITIONAL"]

    total = len(paths)
    paths = paths[offset:offset + limit]

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "paths": paths
    }


@router.get("/paths/top")
async def get_top_paths(
    limit: int = Query(10, description="Number of top paths to return")
):
    """
    Get top attack paths ranked by risk score.
    """
    result = _get_cached_results()
    paths = result["attack_paths"]

    # Already sorted by risk score from analyzer
    exposed = [p for p in paths if not p["blocked_by_scp"]]
    top = exposed[:limit]

    return {
        "total": len(exposed),
        "top_paths": top
    }


@router.get("/paths/critical")
async def get_critical_paths():
    """Get only critical severity exposed paths."""
    result = _get_cached_results()
    paths = [
        p for p in result["attack_paths"]
        if p["severity"] == "critical" and not p["blocked_by_scp"]
    ]
    return {
        "total": len(paths),
        "paths": paths
    }


@router.get("/paths/cross-account")
async def get_cross_account_paths():
    """Get cross-account attack paths."""
    result = _get_cached_results()
    return {
        "total": len(result["cross_account_paths"]),
        "paths": result["cross_account_paths"]
    }


@router.get("/paths/by-technique/{technique}")
async def get_paths_by_technique(technique: str):
    """Get all paths for a specific technique."""
    result = _get_cached_results()
    paths = [
        p for p in result["attack_paths"]
        if p["technique"].lower() == technique.lower()
    ]
    if not paths:
        raise HTTPException(
            status_code=404,
            detail=f"No paths found for technique: {technique}"
        )
    return {
        "technique": technique,
        "total": len(paths),
        "paths": paths
    }
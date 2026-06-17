"""
GET /summary — retrieve scan summary and executive report.
"""

from fastapi import APIRouter, HTTPException
import api.main as app_state

router = APIRouter()


def _get_cached_results():
    if "latest" not in app_state.scan_cache:
        raise HTTPException(
            status_code=404,
            detail="No scan results available. Run POST /api/v1/scan first."
        )
    return app_state.scan_cache["latest"]


@router.get("/summary")
async def get_summary():
    """Get full scan summary including severity breakdown and SCP coverage."""
    result = _get_cached_results()
    return {
        "account_id": result["account_id"],
        "region": result["region"],
        "summary": result["summary"]
    }


@router.get("/summary/executive")
async def get_executive_summary():
    """
    Get executive summary — non-technical overview for leadership reporting.
    Includes overall risk rating, key findings, business impact,
    and immediate actions required.
    """
    result = _get_cached_results()
    return result["executive_summary"]


@router.get("/summary/risk")
async def get_risk_overview():
    """Get overall risk score and rating for the scanned account."""
    result = _get_cached_results()
    overall = result["overall_risk"]
    paths = result["attack_paths"]

    # Risk breakdown by severity
    breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for path in paths:
        if not path["blocked_by_scp"]:
            sev = path["severity"]
            breakdown[sev] = breakdown.get(sev, 0) + 1

    # Top scoring paths
    top_scored = sorted(
        [p for p in paths if p.get("risk_score")],
        key=lambda p: p["risk_score"]["total"],
        reverse=True
    )[:5]

    return {
        "overall_score": overall.get("overall_score", 0),
        "overall_rating": overall.get("overall_rating", "UNKNOWN"),
        "highest_path_score": overall.get("highest_path_score", 0),
        "average_score": overall.get("average_score", 0),
        "severity_breakdown": breakdown,
        "top_scored_paths": [
            {
                "technique": p["technique"],
                "source": p["source"].split("/")[-1],
                "severity": p["severity"],
                "risk_score": p["risk_score"]["total"],
                "rating": p["risk_score"]["rating"]
            }
            for p in top_scored
        ]
    }


@router.get("/summary/sensitive-resources")
async def get_sensitive_resources():
    """Get all sensitive resources discovered during scan."""
    result = _get_cached_results()
    sensitive = result["sensitive_resources"]
    return {
        "secrets_manager": sensitive.get("secrets", []),
        "s3_buckets": sensitive.get("s3_buckets", []),
        "ssm_parameters": sensitive.get("ssm_params", []),
        "totals": {
            "secrets": len(sensitive.get("secrets", [])),
            "s3_buckets": len(sensitive.get("s3_buckets", [])),
            "ssm_params": len(sensitive.get("ssm_params", []))
        }
    }
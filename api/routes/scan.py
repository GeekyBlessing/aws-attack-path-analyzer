"""
POST /scan — triggers a full AWS account scan.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from api.models import ScanRequest
import api.main as app_state

router = APIRouter()


def _run_scan(request: ScanRequest) -> dict:
    """Run the full attack path analysis and cache results."""
    from modules.analyzer import AttackPathAnalyzer
    from modules.executive_summary import generate_executive_summary

    analyzer = AttackPathAnalyzer(
        profile=request.profile,
        region=request.region,
        start_identity=request.identity,
        min_severity=request.severity
    )

    results = analyzer.run()

    if not results:
        raise HTTPException(
            status_code=400,
            detail="Scan failed — check AWS credentials and profile"
        )

    overall_risk = results.summary.get("overall_risk", {})
    exec_summary = generate_executive_summary(results, overall_risk)

    # Serialize attack paths
    attack_paths = []
    for path in results.attack_paths:
        risk_score = None
        if hasattr(path, "risk_score") and path.risk_score:
            risk_score = {
                "total": path.risk_score.total,
                "rating": path.risk_score.rating,
                "rationale": path.risk_score.rationale
            }
        attack_paths.append({
            "source": path.source,
            "target": path.target,
            "technique": path.technique,
            "description": path.description,
            "severity": path.severity,
            "permissions_used": path.permissions_used,
            "mitre_id": path.mitre_id,
            "path_steps": path.path_steps,
            "blocked_by_scp": path.blocked_by_scp,
            "blocking_scp": path.blocking_scp,
            "condition_result": path.condition_result,
            "condition_explanation": path.condition_explanation,
            "risk_score": risk_score
        })

    # Serialize cross-account paths
    cross_paths = []
    for path in (results.cross_account_paths or []):
        cross_paths.append({
            "source_account": path.source_account,
            "source_identity": path.source_identity,
            "target_account": path.target_account,
            "target_role": path.target_role,
            "target_role_arn": path.target_role_arn,
            "severity": path.severity,
            "description": path.description,
            "path_steps": path.path_steps,
            "target_is_admin": path.target_is_admin
        })

    scan_result = {
        "account_id": results.account_id,
        "region": results.region,
        "start_identity": results.start_identity,
        "summary": results.summary,
        "attack_paths": attack_paths,
        "cross_account_paths": cross_paths,
        "sensitive_resources": results.sensitive_resources,
        "overall_risk": overall_risk,
        "executive_summary": exec_summary
    }

    # Cache results
    app_state.scan_cache["latest"] = scan_result
    return scan_result


@router.post("/scan")
async def trigger_scan(request: ScanRequest):
    """
    Trigger a full AWS attack path scan.

    - **profile**: AWS profile name from ~/.aws/credentials
    - **region**: AWS region to scan
    - **identity**: Optional specific IAM identity ARN to start from
    - **severity**: Minimum severity threshold (low/medium/high/critical)
    """
    try:
        result = _run_scan(request)
        return {
            "status": "success",
            "message": f"Scan complete — {len(result['attack_paths'])} paths found",
            "data": result
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scan/status")
async def scan_status():
    """Check if a scan result is cached."""
    if "latest" not in app_state.scan_cache:
        return {"status": "no_scan", "message": "No scan results available. Run POST /scan first."}
    result = app_state.scan_cache["latest"]
    return {
        "status": "available",
        "account_id": result["account_id"],
        "region": result["region"],
        "total_paths": len(result["attack_paths"]),
        "overall_rating": result["overall_risk"].get("overall_rating")
    }
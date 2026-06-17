"""
GET /remediation — retrieve remediation guidance for attack paths.
"""

from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import api.main as app_state
from modules.remediation import get_remediation, get_top_remediations

router = APIRouter()


def _get_cached_results():
    if "latest" not in app_state.scan_cache:
        raise HTTPException(
            status_code=404,
            detail="No scan results available. Run POST /api/v1/scan first."
        )
    return app_state.scan_cache["latest"]


@router.get("/remediation")
async def get_all_remediations(
    limit: int = Query(10, description="Number of remediations to return")
):
    """
    Get prioritized remediation guidance for all discovered attack paths.
    Sorted by risk score — highest risk fixes first.
    """
    result = _get_cached_results()

    # Reconstruct path objects with risk scores for remediation module
    from types import SimpleNamespace
    paths = []
    for p in result["attack_paths"]:
        path = SimpleNamespace(**p)
        if p.get("risk_score"):
            path.risk_score = SimpleNamespace(**p["risk_score"])
        paths.append(path)

    remediations = get_top_remediations(paths, limit=limit)

    return {
        "total": len(remediations),
        "remediations": [
            {
                "rank": i + 1,
                "technique": r["technique"],
                "risk_score": r["risk_score"],
                "severity": r["severity"],
                "title": r["guidance"].get("title", ""),
                "risk": r["guidance"].get("risk", ""),
                "steps": r["guidance"].get("steps", []),
                "scp_fix": r["guidance"].get("scp_fix", ""),
                "effort": r["guidance"].get("effort", ""),
                "priority": r["guidance"].get("priority", 3)
            }
            for i, r in enumerate(remediations)
        ]
    }


@router.get("/remediation/{technique}")
async def get_technique_remediation(technique: str):
    """
    Get detailed remediation guidance for a specific technique.
    Example: /remediation/CreatePolicyVersion
    """
    guidance = get_remediation(technique)
    if not guidance:
        raise HTTPException(
            status_code=404,
            detail=f"No remediation found for technique: {technique}"
        )
    return {
        "technique": technique,
        "title": guidance.get("title", ""),
        "risk": guidance.get("risk", ""),
        "steps": guidance.get("steps", []),
        "scp_fix": guidance.get("scp_fix", ""),
        "effort": guidance.get("effort", ""),
        "priority": guidance.get("priority", 3)
    }


@router.get("/remediation/export/scp-bundle")
async def export_scp_bundle():
    """
    Export a ready-to-deploy SCP bundle for all discovered techniques.
    Returns a JSON SCP document you can apply directly to your AWS Org.
    """
    result = _get_cached_results()

    seen = set()
    deny_statements = []

    for path in result["attack_paths"]:
        technique = path["technique"]
        if technique in seen:
            continue
        seen.add(technique)

        guidance = get_remediation(technique)
        scp_fix = guidance.get("scp_fix", "")
        if not scp_fix:
            continue

        try:
            import json
            stmt = json.loads(scp_fix)
            stmt["Sid"] = f"Deny{technique.replace('+', 'And').replace('→', 'To').replace('-', '')}"
            deny_statements.append(stmt)
        except Exception:
            continue

    scp_document = {
        "Version": "2012-10-17",
        "Statement": deny_statements
    }

    return {
        "description": "Ready-to-deploy SCP bundle — apply to your AWS Organization root or target OU",
        "statement_count": len(deny_statements),
        "scp_document": scp_document,
        "instructions": [
            "1. Go to AWS Organizations → Policies → Service Control Policies",
            "2. Create new policy and paste the scp_document",
            "3. Attach to target OU or account",
            "4. Test in non-production first using a sandbox OU"
        ]
    }
"""
Executive Summary — non-technical overview for leadership/boardroom reporting.
"""

from datetime import datetime


RISK_DESCRIPTIONS = {
    "CRITICAL": (
        "The AWS environment has critical security vulnerabilities that require "
        "immediate attention. An attacker with initial access to a low-privileged "
        "identity can escalate to full administrator access with minimal effort."
    ),
    "HIGH": (
        "The AWS environment has significant security gaps. Multiple privilege "
        "escalation paths exist that could allow an attacker to gain elevated "
        "access to sensitive resources and data."
    ),
    "MEDIUM": (
        "The AWS environment has moderate security concerns. Some privilege "
        "escalation paths exist but may require additional steps or conditions "
        "to exploit successfully."
    ),
    "LOW": (
        "The AWS environment has a low risk profile. Few or no significant "
        "privilege escalation paths were detected. Continue monitoring and "
        "maintaining current security controls."
    )
}

BUSINESS_IMPACTS = {
    "CRITICAL": [
        "Complete compromise of AWS environment possible within minutes",
        "All data, secrets, and resources accessible to attacker",
        "Potential for data exfiltration, ransomware, or service disruption",
        "Regulatory compliance violations (SOC 2, PCI DSS, ISO 27001)",
        "Reputational damage and potential financial penalties"
    ],
    "HIGH": [
        "Significant portions of the environment at risk of compromise",
        "Sensitive data and credentials potentially accessible",
        "Service disruption or data manipulation possible",
        "Compliance gaps that may trigger audit findings"
    ],
    "MEDIUM": [
        "Limited but real risk of privilege escalation",
        "Some sensitive resources potentially accessible",
        "May trigger compliance concerns during audits"
    ],
    "LOW": [
        "Minimal business risk from privilege escalation",
        "Continue monitoring for new attack vectors",
        "Maintain current security posture"
    ]
}


def generate_executive_summary(results, overall_risk: dict) -> dict:
    """Generate a structured executive summary from analysis results."""
    summary = results.summary
    rating = overall_risk.get("overall_rating", "LOW")
    score = overall_risk.get("overall_score", 0)

    # Count exploitable vs blocked
    exploitable = summary.get("exploitable_paths", 0)
    blocked = summary.get("blocked_by_scp", 0)
    total_paths = summary.get("total_attack_paths", 0)
    identities = summary.get("total_identities", 0)

    # Cross-account exposure
    cross = summary.get("cross_account_summary", {})
    cross_accounts = cross.get("accounts_reachable", [])

    # Sensitive resources
    sensitive = summary.get("sensitive_resources", {})
    secrets_count = sensitive.get("secrets", 0)

    # Top techniques
    technique_counts = {}
    for path in results.attack_paths:
        if not path.blocked_by_scp:
            t = path.technique
            technique_counts[t] = technique_counts.get(t, 0) + 1

    top_techniques = sorted(
        technique_counts.items(), key=lambda x: x[1], reverse=True
    )[:3]

    # Key findings
    key_findings = []

    if exploitable > 0:
        key_findings.append(
            f"{exploitable} exploitable privilege escalation paths detected "
            f"across {identities} scanned identities"
        )

    critical_count = summary.get("severity_counts", {}).get("critical", 0)
    if critical_count > 0:
        key_findings.append(
            f"{critical_count} CRITICAL paths allow direct escalation "
            f"to administrator access"
        )

    if cross_accounts:
        key_findings.append(
            f"Cross-account attack paths detected — "
            f"{len(cross_accounts)} member account(s) reachable: "
            f"{', '.join(cross_accounts)}"
        )

    if secrets_count > 0:
        key_findings.append(
            f"{secrets_count} secret(s) found in Secrets Manager "
            f"accessible to over-privileged identities"
        )

    if blocked > 0:
        key_findings.append(
            f"{blocked} paths are blocked by Service Control Policies — "
            f"SCPs are providing partial protection"
        )
    else:
        key_findings.append(
            "No Service Control Policies are blocking escalation paths — "
            "SCPs should be implemented immediately"
        )

    # Immediate actions
    immediate_actions = [
        "Conduct emergency IAM permission review for all identities with admin-level actions",
        "Implement Service Control Policies (SCPs) to deny high-risk IAM actions org-wide",
        "Enable MFA for all IAM users and require MFA for sensitive operations",
        "Enable AWS CloudTrail in all regions and set up alerting for privilege escalation indicators",
        "Rotate all credentials and access keys for over-privileged identities"
    ]

    if cross_accounts:
        immediate_actions.insert(
            1,
            "Restrict OrganizationAccountAccessRole — add MFA condition to trust policy"
        )

    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "account_id": results.account_id,
        "region": results.region,
        "overall_rating": rating,
        "overall_score": score,
        "risk_description": RISK_DESCRIPTIONS.get(rating, ""),
        "business_impacts": BUSINESS_IMPACTS.get(rating, []),
        "key_findings": key_findings,
        "immediate_actions": immediate_actions,
        "top_techniques": [
            {"technique": t, "count": c} for t, c in top_techniques
        ],
        "metrics": {
            "identities_scanned": identities,
            "total_paths": total_paths,
            "exploitable_paths": exploitable,
            "blocked_paths": blocked,
            "critical_paths": critical_count,
            "secrets_exposed": secrets_count,
            "accounts_at_risk": len(cross_accounts)
        }
    }
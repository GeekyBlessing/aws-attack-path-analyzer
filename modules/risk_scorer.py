"""
Risk Score Engine — scores each attack path 0-100.
Factors: severity, exploitability, asset value, control effectiveness.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class RiskScore:
    total: int                    # 0-100
    severity_score: int           # 0-40
    exploitability_score: int     # 0-30
    asset_value_score: int        # 0-20
    control_score: int            # 0-10 (deducted if controls present)
    rating: str                   # CRITICAL / HIGH / MEDIUM / LOW
    rationale: str                # Human-readable explanation


# Severity base scores
SEVERITY_SCORES = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10
}

# Exploitability — how easy is it to exploit?
# Fewer permissions = easier = higher score
EXPLOITABILITY_SCORES = {
    1: 30,   # Single permission needed — trivial
    2: 25,   # Two permissions — easy
    3: 18,   # Three permissions — moderate
    4: 12,   # Four permissions — harder
    5: 8,    # Five or more — complex
}

# Asset value — what does successful exploitation give you?
ASSET_VALUE_SCORES = {
    "admin": 20,           # Full admin access
    "cross_account": 18,   # Cross-account pivot
    "secrets": 15,         # Access to secrets/credentials
    "data": 12,            # Access to sensitive data (S3, SSM)
    "lateral": 10,         # Lateral movement capability
    "limited": 5           # Limited privilege gain
}

# Techniques and their asset value category
TECHNIQUE_ASSET_MAP = {
    "CreatePolicyVersion": "admin",
    "SetDefaultPolicyVersion": "admin",
    "AttachUserPolicy": "admin",
    "AttachGroupPolicy": "admin",
    "AttachRolePolicy": "admin",
    "CreateRole+PassRole": "admin",
    "AssumeRole": "lateral",
    "AssumeRole→Admin": "admin",
    "PassRole+EC2": "lateral",
    "PassRole+Lambda": "lateral",
    "PassRole+CloudFormation": "lateral",
    "UpdateAssumeRolePolicy": "admin",
    "PutUserPolicy": "admin",
    "PutRolePolicy": "admin",
    "CreateAccessKey": "lateral",
    "CreateLoginProfile": "lateral",
    "UpdateLoginProfile": "lateral",
    "SecretsManagerAccess": "secrets",
    "SSMParameterAccess": "secrets",
    "S3SensitiveRead": "data",
    "GlueDevEndpoint": "lateral",
    "CodeBuildPrivesc": "lateral",
    "CrossAccount": "cross_account"
}


class RiskScorer:
    def __init__(self):
        pass

    def score_path(self, path) -> RiskScore:
        """Score a single attack path."""

        # 1. Severity score (0-40)
        severity_score = SEVERITY_SCORES.get(path.severity, 10)

        # 2. Exploitability score (0-30)
        num_perms = len(path.permissions_used)
        exploitability_score = EXPLOITABILITY_SCORES.get(
            min(num_perms, 5), 8
        )

        # Bonus: if identity already has the permission directly (no chaining)
        if num_perms == 1:
            exploitability_score = 30

        # 3. Asset value score (0-20)
        technique = path.technique
        asset_category = TECHNIQUE_ASSET_MAP.get(technique, "limited")

        # Cross-account paths get highest asset value
        if hasattr(path, 'blocked_by_scp') and \
           "cross" in technique.lower():
            asset_category = "cross_account"

        asset_value_score = ASSET_VALUE_SCORES.get(asset_category, 5)

        # 4. Control effectiveness (0-10 deducted)
        control_score = 10  # Start at max (no controls = full score)

        if hasattr(path, 'blocked_by_scp') and path.blocked_by_scp:
            control_score = 0  # SCP blocks it entirely
        elif hasattr(path, 'condition_result'):
            if path.condition_result == "CONDITIONAL":
                control_score = 4  # Conditions reduce but don't eliminate risk
            else:
                control_score = 10  # No controls

        # Total score
        total = severity_score + exploitability_score + \
                asset_value_score + control_score

        # Cap at 100
        total = min(total, 100)

        # Rating
        if total >= 80:
            rating = "CRITICAL"
        elif total >= 60:
            rating = "HIGH"
        elif total >= 40:
            rating = "MEDIUM"
        else:
            rating = "LOW"

        # Rationale
        rationale = (
            f"Severity: {path.severity.upper()} (+{severity_score}) | "
            f"Exploitability: {num_perms} permission(s) needed (+{exploitability_score}) | "
            f"Asset value: {asset_category.upper()} (+{asset_value_score}) | "
            f"Controls: +{control_score}"
        )

        return RiskScore(
            total=total,
            severity_score=severity_score,
            exploitability_score=exploitability_score,
            asset_value_score=asset_value_score,
            control_score=control_score,
            rating=rating,
            rationale=rationale
        )

    def score_all_paths(self, attack_paths: list) -> list:
        """
        Score all paths and return them sorted by risk score descending.
        Attaches risk_score attribute to each path.
        """
        scored = []
        for path in attack_paths:
            score = self.score_path(path)
            path.risk_score = score
            scored.append(path)

        # Sort by total score descending
        scored.sort(key=lambda p: p.risk_score.total, reverse=True)
        return scored

    def get_overall_risk(self, attack_paths: list) -> dict:
        """
        Compute overall account risk based on all paths.
        """
        if not attack_paths:
            return {
                "overall_score": 0,
                "overall_rating": "LOW",
                "highest_path_score": 0,
                "average_score": 0
            }

        scores = [p.risk_score.total for p in attack_paths
                  if hasattr(p, 'risk_score')]

        if not scores:
            return {
                "overall_score": 0,
                "overall_rating": "LOW",
                "highest_path_score": 0,
                "average_score": 0
            }

        highest = max(scores)
        average = int(sum(scores) / len(scores))

        # Overall score weighted toward highest risk
        overall = int((highest * 0.6) + (average * 0.4))
        overall = min(overall, 100)

        if overall >= 80:
            rating = "CRITICAL"
        elif overall >= 60:
            rating = "HIGH"
        elif overall >= 40:
            rating = "MEDIUM"
        else:
            rating = "LOW"

        return {
            "overall_score": overall,
            "overall_rating": rating,
            "highest_path_score": highest,
            "average_score": average
        }
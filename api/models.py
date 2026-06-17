"""
Pydantic models for FastAPI request/response schemas.
"""

from pydantic import BaseModel
from typing import Optional


class ScanRequest(BaseModel):
    profile: str = "default"
    region: str = "eu-north-1"
    identity: Optional[str] = None
    severity: str = "low"


class RiskScoreModel(BaseModel):
    total: int
    rating: str
    rationale: str


class AttackPathModel(BaseModel):
    source: str
    target: str
    technique: str
    description: str
    severity: str
    permissions_used: list
    mitre_id: str
    path_steps: list
    blocked_by_scp: bool
    blocking_scp: str
    condition_result: str
    condition_explanation: str
    risk_score: Optional[RiskScoreModel] = None


class CrossAccountPathModel(BaseModel):
    source_account: str
    source_identity: str
    target_account: str
    target_role: str
    target_role_arn: str
    severity: str
    description: str
    path_steps: list
    target_is_admin: bool


class SensitiveResourceModel(BaseModel):
    secrets: list
    s3_buckets: list
    ssm_params: list


class OverallRiskModel(BaseModel):
    overall_score: int
    overall_rating: str
    highest_path_score: int
    average_score: int


class ScanResponse(BaseModel):
    account_id: str
    region: str
    start_identity: str
    summary: dict
    attack_paths: list
    cross_account_paths: list
    sensitive_resources: SensitiveResourceModel
    overall_risk: OverallRiskModel
    executive_summary: dict
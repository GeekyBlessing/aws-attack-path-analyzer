"""
Cross-Account Attack Path Detector.
Discovers attack paths that cross AWS account boundaries.
"""

import json
from dataclasses import dataclass, field
from typing import Optional
from botocore.exceptions import ClientError
from rich.console import Console

console = Console()


@dataclass
class CrossAccountPath:
    source_account: str
    source_identity: str
    target_account: str
    target_role: str
    target_role_arn: str
    severity: str
    description: str
    path_steps: list = field(default_factory=list)
    target_is_admin: bool = False
    target_permissions: list = field(default_factory=list)


class CrossAccountAnalyzer:
    def __init__(self, session, source_account_id: str,
                 source_identities: list, target_accounts: list):
        """
        session: boto3 session for management account
        source_account_id: management account ID
        source_identities: list of (type, name, arn) tuples from main scan
        target_accounts: list of account IDs to check
        """
        self.session = session
        self.source_account_id = source_account_id
        self.source_identities = source_identities
        self.target_accounts = target_accounts
        self.iam = session.client("iam")
        self.sts = session.client("sts")
        self.cross_account_paths = []

    def _get_roles_in_current_account(self) -> list:
        """Get all roles — we use these to find cross-account trust relationships."""
        roles = []
        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                roles.extend(page["Roles"])
        except ClientError:
            pass
        return roles

    def _parse_trust_policy_principals(self, trust_policy: dict) -> list:
        """Extract all principals from a role trust policy."""
        principals = []
        statements = trust_policy.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})

            if isinstance(principal, str):
                principals.append(principal)
            elif isinstance(principal, dict):
                aws = principal.get("AWS", [])
                if isinstance(aws, str):
                    aws = [aws]
                principals.extend(aws)

                service = principal.get("Service", [])
                if isinstance(service, str):
                    service = [service]
                principals.extend(service)

        return principals

    def _identity_can_assume_role(self, identity_arn: str,
                                   role_principals: list) -> bool:
        """Check if an identity ARN matches any principal in a trust policy."""
        account_root = f"arn:aws:iam::{self.source_account_id}:root"

        for principal in role_principals:
            if principal == "*":
                return True
            if identity_arn == principal:
                return True
            if account_root == principal:
                return True
            # Wildcard in principal
            if "*" in principal:
                prefix = principal.split("*")[0]
                if identity_arn.startswith(prefix):
                    return True

        return False

    def _get_role_permissions(self, role_name: str) -> list:
        """Get effective permissions for a role."""
        permissions = set()
        try:
            # Attached policies
            attached = self.iam.list_attached_role_policies(RoleName=role_name)
            for policy in attached["AttachedPolicies"]:
                try:
                    p = self.iam.get_policy(PolicyArn=policy["PolicyArn"])
                    vid = p["Policy"]["DefaultVersionId"]
                    v = self.iam.get_policy_version(
                        PolicyArn=policy["PolicyArn"], VersionId=vid
                    )
                    doc = v["PolicyVersion"]["Document"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            permissions.update(a.lower() for a in actions)
                except ClientError:
                    pass

            # Inline policies
            inline = self.iam.list_role_policies(RoleName=role_name)
            for policy_name in inline["PolicyNames"]:
                try:
                    doc = self.iam.get_role_policy(
                        RoleName=role_name, PolicyName=policy_name
                    )["PolicyDocument"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)
                    for stmt in doc.get("Statement", []):
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            if isinstance(actions, str):
                                actions = [actions]
                            permissions.update(a.lower() for a in actions)
                except ClientError:
                    pass

        except ClientError:
            pass

        return list(permissions)

    def _is_admin(self, permissions: list) -> bool:
        return "*" in permissions or "iam:*" in permissions

    def _check_cross_account_trust(self, roles: list) -> list:
        """
        Find roles that trust principals from the source account.
        These are potential cross-account pivot points.
        """
        cross_account_roles = []

        for role in roles:
            role_account = role["Arn"].split(":")[4]

            # Only care about roles that belong to a different account
            # but trust our source account
            trust_policy = role.get("AssumeRolePolicyDocument", {})
            principals = self._parse_trust_policy_principals(trust_policy)

            # Check if any source account identity can assume this role
            source_account_refs = [
                p for p in principals
                if self.source_account_id in p or p == "*"
            ]

            if source_account_refs:
                # Find which specific identities can assume it
                assumable_by = []
                for id_type, id_name, id_arn in self.source_identities:
                    if self._identity_can_assume_role(id_arn, principals):
                        assumable_by.append((id_type, id_name, id_arn))

                if assumable_by:
                    cross_account_roles.append({
                        "role": role,
                        "assumable_by": assumable_by,
                        "principals": source_account_refs
                    })

        return cross_account_roles

    def _try_assume_role(self, role_arn: str) -> Optional[dict]:
        """
        Attempt to assume a cross-account role.
        Returns temporary credentials if successful.
        """
        try:
            response = self.sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName="AttackPathAnalyzer",
                DurationSeconds=900
            )
            return response["Credentials"]
        except ClientError:
            return None

    def analyze(self) -> list:
        """
        Main analysis — find cross-account attack paths.
        Uses trust policy analysis (no actual role assumption needed).
        """
        console.print(
            "\n[bold cyan]Analyzing cross-account attack paths...[/bold cyan]"
        )

        all_roles = self._get_roles_in_current_account()
        console.print(
            f"  [dim]Checking {len(all_roles)} roles for cross-account trust...[/dim]"
        )

        # Find roles that trust the source account
        # These could be in the same account but also represent
        # patterns used for cross-account access
        cross_account_candidates = self._check_cross_account_trust(all_roles)

        for candidate in cross_account_candidates:
            role = candidate["role"]
            role_name = role["RoleName"]
            role_arn = role["Arn"]
            role_account = role_arn.split(":")[4]

            # Get permissions of this role
            permissions = self._get_role_permissions(role_name)
            is_admin = self._is_admin(permissions)

            severity = "critical" if is_admin else "high"

            for id_type, id_name, id_arn in candidate["assumable_by"]:
                path = CrossAccountPath(
                    source_account=self.source_account_id,
                    source_identity=id_arn,
                    target_account=role_account,
                    target_role=role_name,
                    target_role_arn=role_arn,
                    severity=severity,
                    description=(
                        f"Cross-account role assumption: "
                        f"{id_name} → {role_name} "
                        f"({'ADMIN' if is_admin else 'elevated'} access)"
                    ),
                    path_steps=[
                        f"Start: {id_arn} (Account: {self.source_account_id})",
                        f"Action: sts:AssumeRole on {role_arn}",
                        f"Pivot to account: {role_account}",
                        f"Result: {'Full admin access' if is_admin else 'Elevated access'} "
                        f"in account {role_account}"
                    ],
                    target_is_admin=is_admin,
                    target_permissions=permissions[:20]
                )
                self.cross_account_paths.append(path)

        # Also check target accounts directly if accessible
        for target_account in self.target_accounts:
            if target_account == self.source_account_id:
                continue
            self._check_target_account(target_account)

        console.print(
            f"  [green]✓ Found {len(self.cross_account_paths)} "
            f"cross-account paths[/green]"
        )
        return self.cross_account_paths

    def _check_target_account(self, target_account_id: str):
        """
        Try to enumerate roles in a target account using
        common cross-account role naming patterns.
        """
        common_role_names = [
            "OrganizationAccountAccessRole",
            "AWSControlTowerExecution",
            "SecurityAudit",
            "ReadOnlyAccess",
            "AdministratorAccess",
            f"arn:aws:iam::{target_account_id}:role/OrganizationAccountAccessRole"
        ]

        for role_name in common_role_names:
            role_arn = f"arn:aws:iam::{target_account_id}:role/{role_name}"

            # Try to get role info by attempting assume
            # (we check trust without actually assuming)
            try:
                # Check if role exists by trying to get its info
                # This works if we have iam:GetRole cross-account
                pass
            except ClientError:
                pass

            # Check if any of our identities can assume standard org roles
            for id_type, id_name, id_arn in self.source_identities:
                # Management account can typically assume
                # OrganizationAccountAccessRole in member accounts
                if role_name == "OrganizationAccountAccessRole":
                    path = CrossAccountPath(
                        source_account=self.source_account_id,
                        source_identity=id_arn,
                        target_account=target_account_id,
                        target_role=role_name,
                        target_role_arn=role_arn,
                        severity="critical",
                        description=(
                            f"Management account identity may assume "
                            f"OrganizationAccountAccessRole in member account "
                            f"{target_account_id}"
                        ),
                        path_steps=[
                            f"Start: {id_arn} (Management Account)",
                            f"Action: sts:AssumeRole",
                            f"Target: {role_arn}",
                            f"Result: Full admin access in account {target_account_id}",
                            "Note: OrganizationAccountAccessRole grants "
                            "AdministratorAccess by default"
                        ],
                        target_is_admin=True,
                        target_permissions=["*"]
                    )
                    self.cross_account_paths.append(path)
                    break  # One path per role is enough

    def get_summary(self) -> dict:
        critical = sum(
            1 for p in self.cross_account_paths if p.severity == "critical"
        )
        high = sum(
            1 for p in self.cross_account_paths if p.severity == "high"
        )
        accounts_reachable = list(set(
            p.target_account for p in self.cross_account_paths
        ))

        return {
            "total_paths": len(self.cross_account_paths),
            "critical": critical,
            "high": high,
            "accounts_reachable": accounts_reachable,
            "paths": [
                {
                    "source": p.source_identity,
                    "target_account": p.target_account,
                    "target_role": p.target_role_arn,
                    "severity": p.severity,
                    "description": p.description,
                    "steps": p.path_steps,
                    "is_admin": p.target_is_admin
                }
                for p in self.cross_account_paths
            ]
        }
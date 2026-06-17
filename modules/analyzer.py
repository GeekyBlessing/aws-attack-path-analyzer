"""
Core attack path analysis engine.
Enumerates AWS IAM, S3, Secrets Manager, and maps privilege escalation vectors.
"""

import json
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.table import Table
from dataclasses import dataclass, field
from typing import Optional
import networkx as nx

console = Console()

# Known privilege escalation techniques mapped to required permissions
PRIVESC_TECHNIQUES = {
    "CreatePolicyVersion": {
        "permissions": ["iam:CreatePolicyVersion"],
        "description": "Create new policy version with admin permissions",
        "severity": "critical",
        "mitre": "T1098.001"
    },
    "SetDefaultPolicyVersion": {
        "permissions": ["iam:SetDefaultPolicyVersion"],
        "description": "Revert to old policy version with higher privileges",
        "severity": "high",
        "mitre": "T1098.001"
    },
    "AttachUserPolicy": {
        "permissions": ["iam:AttachUserPolicy"],
        "description": "Attach AdministratorAccess policy to self",
        "severity": "critical",
        "mitre": "T1098.001"
    },
    "AttachGroupPolicy": {
        "permissions": ["iam:AttachGroupPolicy"],
        "description": "Attach admin policy to group you belong to",
        "severity": "critical",
        "mitre": "T1098.001"
    },
    "AttachRolePolicy": {
        "permissions": ["iam:AttachRolePolicy"],
        "description": "Attach admin policy to assumable role",
        "severity": "critical",
        "mitre": "T1098.001"
    },
    "CreateRole+PassRole": {
        "permissions": ["iam:CreateRole", "iam:PassRole"],
        "description": "Create privileged role and pass to service",
        "severity": "critical",
        "mitre": "T1098.001"
    },
    "AssumeRole": {
        "permissions": ["sts:AssumeRole"],
        "description": "Assume a higher-privileged role",
        "severity": "high",
        "mitre": "T1548"
    },
    "PassRole+EC2": {
        "permissions": ["iam:PassRole", "ec2:RunInstances"],
        "description": "Launch EC2 with privileged instance profile",
        "severity": "high",
        "mitre": "T1548"
    },
    "PassRole+Lambda": {
        "permissions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "description": "Create Lambda with admin role and invoke it",
        "severity": "high",
        "mitre": "T1648"
    },
    "PassRole+CloudFormation": {
        "permissions": ["iam:PassRole", "cloudformation:CreateStack"],
        "description": "Deploy CloudFormation stack with privileged role",
        "severity": "high",
        "mitre": "T1648"
    },
    "UpdateAssumeRolePolicy": {
        "permissions": ["iam:UpdateAssumeRolePolicy"],
        "description": "Modify role trust policy to allow self to assume it",
        "severity": "critical",
        "mitre": "T1098.001"
    },
    "PutUserPolicy": {
        "permissions": ["iam:PutUserPolicy"],
        "description": "Add inline policy with admin permissions to user",
        "severity": "critical",
        "mitre": "T1098.001"
    },
    "PutRolePolicy": {
        "permissions": ["iam:PutRolePolicy"],
        "description": "Add inline policy with admin permissions to role",
        "severity": "critical",
        "mitre": "T1098.001"
    },
    "CreateAccessKey": {
        "permissions": ["iam:CreateAccessKey"],
        "description": "Create access keys for another user with higher privileges",
        "severity": "high",
        "mitre": "T1098.001"
    },
    "CreateLoginProfile": {
        "permissions": ["iam:CreateLoginProfile"],
        "description": "Set console password for privileged user without one",
        "severity": "high",
        "mitre": "T1098"
    },
    "UpdateLoginProfile": {
        "permissions": ["iam:UpdateLoginProfile"],
        "description": "Change console password of privileged user",
        "severity": "high",
        "mitre": "T1098"
    },
    "SecretsManagerAccess": {
        "permissions": ["secretsmanager:GetSecretValue"],
        "description": "Read secrets from Secrets Manager",
        "severity": "high",
        "mitre": "T1552.001"
    },
    "SSMParameterAccess": {
        "permissions": ["ssm:GetParameter", "ssm:GetParameters"],
        "description": "Read sensitive SSM parameters",
        "severity": "medium",
        "mitre": "T1552.001"
    },
    "S3SensitiveRead": {
        "permissions": ["s3:GetObject"],
        "description": "Read potentially sensitive S3 bucket contents",
        "severity": "medium",
        "mitre": "T1530"
    },
    "GlueDevEndpoint": {
        "permissions": ["glue:CreateDevEndpoint"],
        "description": "Create Glue dev endpoint with privileged role",
        "severity": "high",
        "mitre": "T1648"
    },
    "CodeBuildPrivesc": {
        "permissions": ["codebuild:CreateProject", "iam:PassRole"],
        "description": "Create CodeBuild project with privileged service role",
        "severity": "high",
        "mitre": "T1648"
    }
}

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class AttackPath:
    source: str
    target: str
    technique: str
    description: str
    severity: str
    permissions_used: list
    mitre_id: str
    path_steps: list = field(default_factory=list)
    intermediate_nodes: list = field(default_factory=list)
    blocked_by_scp: bool = False
    blocking_scp: str = ""
    condition_result: str = "EXPOSED"
    condition_explanation: str = ""


@dataclass
class AnalysisResults:
    account_id: str
    region: str
    start_identity: str
    identities: list
    roles: list
    policies: dict
    attack_paths: list
    sensitive_resources: dict
    graph_data: dict
    summary: dict
    cross_account_paths: list = None


class AttackPathAnalyzer:
    def __init__(self, profile: str, region: str, start_identity: Optional[str] = None,
                 min_severity: str = "low"):
        self.profile = profile
        self.region = region
        self.start_identity = start_identity
        self.min_severity = min_severity
        self.session = None
        self.iam = None
        self.sts = None
        self.account_id = None
        self.graph = nx.DiGraph()

        # Collected data
        self.users = []
        self.roles = []
        self.groups = []
        self.policies = {}
        self.identity_permissions = {}
        self.attack_paths = []
        self.sensitive_resources = {"secrets": [], "s3_buckets": [], "ssm_params": []}
        self.scp_denied_permissions = set()
        self.condition_evaluator = None
        self.cross_account_paths = []
        self.target_accounts = []

    def _init_session(self):
        try:
            self.session = boto3.Session(profile_name=self.profile, region_name=self.region)
            self.iam = self.session.client("iam")
            self.sts = self.session.client("sts")
            caller = self.sts.get_caller_identity()
            self.account_id = caller["Account"]
            return True
        except NoCredentialsError:
            console.print(f"[red]✗ No credentials found for profile '{self.profile}'[/red]")
            return False
        except ClientError as e:
            console.print(f"[red]✗ AWS error: {e}[/red]")
            return False

    def _get_all_users(self):
        users = []
        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                users.extend(page["Users"])
        except ClientError as e:
            console.print(f"[yellow]  Warning: Could not list users: {e.response['Error']['Code']}[/yellow]")
        return users

    def _get_all_roles(self):
        roles = []
        try:
            paginator = self.iam.get_paginator("list_roles")
            for page in paginator.paginate():
                roles.extend(page["Roles"])
        except ClientError as e:
            console.print(f"[yellow]  Warning: Could not list roles: {e.response['Error']['Code']}[/yellow]")
        return roles

    def _get_all_groups(self):
        groups = []
        try:
            paginator = self.iam.get_paginator("list_groups")
            for page in paginator.paginate():
                groups.extend(page["Groups"])
        except ClientError as e:
            console.print(f"[yellow]  Warning: Could not list groups: {e.response['Error']['Code']}[/yellow]")
        return groups

    def _get_effective_permissions(self, identity_type: str, identity_name: str) -> list:
        permissions = set()

        try:
            if identity_type == "user":
                attached = self.iam.list_attached_user_policies(UserName=identity_name)
                for policy in attached["AttachedPolicies"]:
                    perms = self._extract_policy_permissions(policy["PolicyArn"])
                    permissions.update(perms)

                inline = self.iam.list_user_policies(UserName=identity_name)
                for policy_name in inline["PolicyNames"]:
                    policy_doc = self.iam.get_user_policy(UserName=identity_name, PolicyName=policy_name)
                    perms = self._parse_policy_document(policy_doc["PolicyDocument"])
                    permissions.update(perms)

                groups = self.iam.list_groups_for_user(UserName=identity_name)
                for group in groups["Groups"]:
                    group_attached = self.iam.list_attached_group_policies(GroupName=group["GroupName"])
                    for policy in group_attached["AttachedPolicies"]:
                        perms = self._extract_policy_permissions(policy["PolicyArn"])
                        permissions.update(perms)

                    group_inline = self.iam.list_group_policies(GroupName=group["GroupName"])
                    for policy_name in group_inline["PolicyNames"]:
                        policy_doc = self.iam.get_group_policy(
                            GroupName=group["GroupName"], PolicyName=policy_name
                        )
                        perms = self._parse_policy_document(policy_doc["PolicyDocument"])
                        permissions.update(perms)

            elif identity_type == "role":
                attached = self.iam.list_attached_role_policies(RoleName=identity_name)
                for policy in attached["AttachedPolicies"]:
                    perms = self._extract_policy_permissions(policy["PolicyArn"])
                    permissions.update(perms)

                inline = self.iam.list_role_policies(RoleName=identity_name)
                for policy_name in inline["PolicyNames"]:
                    policy_doc = self.iam.get_role_policy(RoleName=identity_name, PolicyName=policy_name)
                    perms = self._parse_policy_document(policy_doc["PolicyDocument"])
                    permissions.update(perms)

        except ClientError:
            pass

        return list(permissions)

    def _extract_policy_permissions(self, policy_arn: str) -> list:
        permissions = []
        try:
            policy = self.iam.get_policy(PolicyArn=policy_arn)
            version_id = policy["Policy"]["DefaultVersionId"]
            version = self.iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            permissions = self._parse_policy_document(version["PolicyVersion"]["Document"])
        except ClientError:
            pass
        return permissions

    def _parse_policy_document(self, doc) -> list:
        allowed = []
        if isinstance(doc, str):
            try:
                doc = json.loads(doc)
            except json.JSONDecodeError:
                return allowed

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action == "*":
                    allowed.append("*")
                else:
                    allowed.append(action.lower())
        return allowed

    def _has_permission(self, identity_permissions: list, required_permission: str) -> bool:
        req = required_permission.lower()
        for perm in identity_permissions:
            if perm == "*":
                return True
            if perm == req:
                return True
            if "*" in perm:
                prefix = perm.split("*")[0]
                if req.startswith(prefix):
                    return True
        return False

    def _has_all_permissions(self, identity_permissions: list, required_permissions: list) -> bool:
        return all(self._has_permission(identity_permissions, p) for p in required_permissions)

    def _get_assumable_roles(self, identity_arn: str, identity_permissions: list) -> list:
        assumable = []
        for role in self.roles:
            trust_policy = role.get("AssumeRolePolicyDocument", {})
            stmts = trust_policy.get("Statement", [])
            if isinstance(stmts, dict):
                stmts = [stmts]

            for stmt in stmts:
                if stmt.get("Effect") != "Allow":
                    continue
                principals = stmt.get("Principal", {})

                principal_list = []
                if isinstance(principals, str):
                    principal_list = [principals]
                elif isinstance(principals, dict):
                    aws = principals.get("AWS", [])
                    if isinstance(aws, str):
                        aws = [aws]
                    principal_list.extend(aws)
                    service = principals.get("Service", [])
                    if isinstance(service, str):
                        service = [service]
                    principal_list.extend(service)

                for principal in principal_list:
                    if (principal == "*" or
                        identity_arn in principal or
                        f"arn:aws:iam::{self.account_id}:root" in principal):

                        if self._has_permission(identity_permissions, "sts:AssumeRole"):
                            assumable.append(role)
                            break
        return assumable

    def _check_admin_access(self, permissions: list) -> bool:
        return "*" in permissions or self._has_permission(permissions, "iam:*")

    def _enumerate_sensitive_resources(self):
        try:
            sm = self.session.client("secretsmanager")
            paginator = sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page.get("SecretList", []):
                    self.sensitive_resources["secrets"].append({
                        "name": secret["Name"],
                        "arn": secret["ARN"],
                        "description": secret.get("Description", ""),
                        "last_accessed": str(secret.get("LastAccessedDate", "Never"))
                    })
        except ClientError:
            pass

        try:
            s3 = self.session.client("s3")
            response = s3.list_buckets()
            for bucket in response.get("Buckets", []):
                bucket_name = bucket["Name"]
                bucket_info = {"name": bucket_name, "flags": []}

                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl.get("Grants", []):
                        grantee = grant.get("Grantee", {})
                        if grantee.get("URI", "").endswith("AllUsers"):
                            bucket_info["flags"].append("PUBLIC_READ")
                except ClientError:
                    pass

                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError:
                    bucket_info["flags"].append("NO_ENCRYPTION")

                self.sensitive_resources["s3_buckets"].append(bucket_info)
        except ClientError:
            pass

        try:
            ssm = self.session.client("ssm")
            paginator = ssm.get_paginator("describe_parameters")
            for page in paginator.paginate():
                for param in page.get("Parameters", []):
                    if param.get("Type") == "SecureString" or any(
                        kw in param["Name"].lower()
                        for kw in ["password", "secret", "key", "token", "credential"]
                    ):
                        self.sensitive_resources["ssm_params"].append({
                            "name": param["Name"],
                            "type": param.get("Type", "String"),
                            "description": param.get("Description", "")
                        })
        except ClientError:
            pass

    def _find_attack_paths(self, identity_arn: str, identity_name: str,
                            identity_type: str, permissions: list):
        min_sev_order = SEVERITY_ORDER.get(self.min_severity, 1)

        for technique_name, technique in PRIVESC_TECHNIQUES.items():
            if SEVERITY_ORDER.get(technique["severity"], 0) < min_sev_order:
                continue

            required_perms = technique["permissions"]
            if self._has_all_permissions(permissions, required_perms):
                # Check if SCP blocks any of the required permissions
                blocked, blocking_scp = self._is_blocked_by_scp(required_perms)

                # Evaluate conditions
                cond_result = None
                if not blocked and self.condition_evaluator:
                    identity_name_short = identity_arn.split("/")[-1]
                    cond_result = self.condition_evaluator.evaluate_path(
                        identity_type, identity_name_short, required_perms
                    )

                path = AttackPath(
                    source=identity_arn,
                    target="Administrator / Sensitive Data",
                    technique=technique_name,
                    description=technique["description"],
                    severity=technique["severity"],
                    permissions_used=required_perms,
                    mitre_id=technique["mitre"],
                    path_steps=[
                        f"Start: {identity_arn}",
                        f"Use: {', '.join(required_perms)}",
                        f"Result: {technique['description']}"
                    ],
                    blocked_by_scp=blocked,
                    blocking_scp=blocking_scp,
                    condition_result=cond_result.restriction_type if cond_result else "EXPOSED",
                    condition_explanation=cond_result.explanation if cond_result else ""
                )
                self.attack_paths.append(path)

                self.graph.add_node(identity_arn, type=identity_type, label=identity_name)
                self.graph.add_node(f"PRIVESC:{technique_name}", type="technique",
                                     label=technique_name, severity=technique["severity"],
                                     blocked=blocked)
                self.graph.add_node("ADMIN_ACCESS", type="target", label="Admin Access")
                self.graph.add_edge(identity_arn, f"PRIVESC:{technique_name}",
                                     label=", ".join(required_perms))
                self.graph.add_edge(f"PRIVESC:{technique_name}", "ADMIN_ACCESS")

        # Role assumption chains
        assumable = self._get_assumable_roles(identity_arn, permissions)
        for role in assumable:
            role_arn = role["Arn"]
            role_name = role["RoleName"]
            role_perms = self._get_effective_permissions("role", role_name)

            if self._check_admin_access(role_perms):
                blocked, blocking_scp = self._is_blocked_by_scp(["sts:AssumeRole"])

                path = AttackPath(
                    source=identity_arn,
                    target=role_arn,
                    technique="AssumeRole→Admin",
                    description=f"Assume role {role_name} which has admin/elevated permissions",
                    severity="critical",
                    permissions_used=["sts:AssumeRole"],
                    mitre_id="T1548",
                    path_steps=[
                        f"Start: {identity_arn}",
                        f"Assume role: {role_arn}",
                        "Result: Full administrator access via assumed role"
                    ],
                    blocked_by_scp=blocked,
                    blocking_scp=blocking_scp,
                    condition_result=cond_result.restriction_type if cond_result else "EXPOSED",
                    condition_explanation=cond_result.explanation if cond_result else ""
                )
                self.attack_paths.append(path)

                self.graph.add_node(identity_arn, type=identity_type, label=identity_name)
                self.graph.add_node(role_arn, type="role", label=role_name, is_admin=True)
                self.graph.add_edge(identity_arn, role_arn, label="sts:AssumeRole → ADMIN")

    def _is_blocked_by_scp(self, permissions: list) -> tuple:
        """Check if any required permission is denied by SCPs."""
        for perm in permissions:
            perm_lower = perm.lower()
            for denied in self.scp_denied_permissions:
                denied_lower = denied.lower()
                if denied_lower == "*":
                    return True, "SCP: Deny *"
                if denied_lower == perm_lower:
                    return True, f"SCP denies: {denied}"
                if "*" in denied_lower:
                    prefix = denied_lower.split("*")[0]
                    if perm_lower.startswith(prefix):
                        return True, f"SCP denies: {denied}"
        return False, ""

    def _build_graph_data(self) -> dict:
        nodes = []
        edges = []

        node_id_map = {node: i for i, node in enumerate(self.graph.nodes())}

        for node, data in self.graph.nodes(data=True):
            node_type = data.get("type", "unknown")

            color_map = {
                "user": "#3b82f6",
                "role": "#8b5cf6",
                "technique": "#f59e0b",
                "target": "#ef4444",
                "unknown": "#6b7280"
            }

            # Grey out blocked nodes
            if data.get("blocked", False):
                color = "#374151"
            else:
                color = color_map.get(node_type, "#6b7280")

            nodes.append({
                "id": node_id_map[node],
                "arn": node,
                "label": data.get("label", node.split(":")[-1]),
                "type": node_type,
                "color": color,
                "severity": data.get("severity", ""),
                "is_admin": data.get("is_admin", False),
                "blocked": data.get("blocked", False)
            })

        for src, dst, data in self.graph.edges(data=True):
            edges.append({
                "source": node_id_map[src],
                "target": node_id_map[dst],
                "label": data.get("label", ""),
            })

        return {"nodes": nodes, "edges": edges}

    def run(self) -> Optional[AnalysisResults]:
        console.print("\n[bold cyan]Initializing AWS session...[/bold cyan]")

        if not self._init_session():
            return None

        console.print(f"[green]✓ Connected to account {self.account_id} ({self.region})[/green]")
        console.print(f"[green]✓ Using profile: {self.profile}[/green]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:

            # Load SCPs first
            task0 = progress.add_task("Loading SCPs from AWS Organizations...", total=None)
            from modules.condition_evaluator import ConditionEvaluator
            self.condition_evaluator = ConditionEvaluator(self.session, self.account_id)
            from modules.scp_analyzer import SCPAnalyzer
            scp = SCPAnalyzer(self.session, self.account_id)
            self.scp_denied_permissions = scp.get_denied_permissions()
            scp_summary = scp.get_summary()
            progress.update(task0, description=f"Loaded {scp_summary['total_scps']} SCPs — {len(self.scp_denied_permissions)} denied actions")

            task = progress.add_task("Enumerating IAM users...", total=None)
            self.users = self._get_all_users()
            progress.update(task, description=f"Found {len(self.users)} IAM users")

            task2 = progress.add_task("Enumerating IAM roles...", total=None)
            self.roles = self._get_all_roles()
            progress.update(task2, description=f"Found {len(self.roles)} IAM roles")

            task3 = progress.add_task("Scanning sensitive resources...", total=None)
            self._enumerate_sensitive_resources()
            n_secrets = len(self.sensitive_resources["secrets"])
            n_s3 = len(self.sensitive_resources["s3_buckets"])
            n_ssm = len(self.sensitive_resources["ssm_params"])
            progress.update(task3, description=f"Found {n_secrets} secrets, {n_s3} S3 buckets, {n_ssm} SSM params")

        console.print("\n[bold cyan]Analyzing attack paths...[/bold cyan]")

        identities_to_check = []

        if self.start_identity:
            if ":user/" in self.start_identity:
                identity_name = self.start_identity.split("/")[-1]
                identities_to_check = [("user", identity_name, self.start_identity)]
            elif ":role/" in self.start_identity:
                identity_name = self.start_identity.split("/")[-1]
                identities_to_check = [("role", identity_name, self.start_identity)]
        else:
            for user in self.users:
                identities_to_check.append(("user", user["UserName"], user["Arn"]))
            for role in self.roles:
                if "aws-service-role" not in role["Arn"] and \
                   "AWSServiceRole" not in role["RoleName"]:
                    identities_to_check.append(("role", role["RoleName"], role["Arn"]))

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            console=console
        ) as progress:
            task = progress.add_task("Checking permissions...", total=len(identities_to_check))

            for identity_type, identity_name, identity_arn in identities_to_check:
                progress.update(task, description=f"Analyzing: {identity_name}")
                permissions = self._get_effective_permissions(identity_type, identity_name)
                self.identity_permissions[identity_arn] = permissions
                self._find_attack_paths(identity_arn, identity_name, identity_type, permissions)
                progress.advance(task)

        # Cross-account analysis
        from modules.cross_account import CrossAccountAnalyzer
        target_accounts = ["256773974686"]  # Log Archive account
        cross_analyzer = CrossAccountAnalyzer(
            self.session, self.account_id,
            identities_to_check, target_accounts
        )
        self.cross_account_paths = cross_analyzer.analyze()
        cross_summary = cross_analyzer.get_summary()

        # Score all attack paths
        from modules.risk_scorer import RiskScorer
        scorer = RiskScorer()
        self.attack_paths = scorer.score_all_paths(self.attack_paths)
        overall_risk = scorer.get_overall_risk(self.attack_paths)

        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        blocked_count = 0
        for path in self.attack_paths:
            if path.blocked_by_scp:
                blocked_count += 1
            else:
                severity_counts[path.severity] = severity_counts.get(path.severity, 0) + 1

        summary = {
            "total_identities": len(identities_to_check),
            "total_attack_paths": len(self.attack_paths),
            "exploitable_paths": len(self.attack_paths) - blocked_count,
            "blocked_by_scp": blocked_count,
            "severity_counts": severity_counts,
            "sensitive_resources": {
                "secrets": len(self.sensitive_resources["secrets"]),
                "s3_buckets": len(self.sensitive_resources["s3_buckets"]),
                "ssm_params": len(self.sensitive_resources["ssm_params"])
            },
            "scp_summary": scp_summary,
            "cross_account_summary": cross_summary,
            "overall_risk": overall_risk
        }

        return AnalysisResults(
            account_id=self.account_id,
            region=self.region,
            start_identity=self.start_identity or "All Identities",
            identities=identities_to_check,
            roles=self.roles,
            policies=self.policies,
            attack_paths=self.attack_paths,
            sensitive_resources=self.sensitive_resources,
            graph_data=self._build_graph_data(),
            summary=summary,
            cross_account_paths=self.cross_account_paths
        )
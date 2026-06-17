"""
Condition Key Evaluator — checks if IAM policy conditions
restrict exploitation of discovered attack paths.
"""

import json
from dataclasses import dataclass
from typing import Optional
from botocore.exceptions import ClientError
from rich.console import Console

console = Console()

# Conditions that restrict exploitation
RESTRICTING_CONDITIONS = {
    "aws:multifactorauthpresent": {
        "description": "Requires MFA to be active",
        "blocks_external_attacker": True
    },
    "aws:sourceip": {
        "description": "Restricts to specific IP ranges",
        "blocks_external_attacker": True
    },
    "aws:sourcevpc": {
        "description": "Restricts to specific VPC",
        "blocks_external_attacker": True
    },
    "aws:sourcevpce": {
        "description": "Restricts to specific VPC endpoint",
        "blocks_external_attacker": True
    },
    "aws:requestedregion": {
        "description": "Restricts to specific AWS regions",
        "blocks_external_attacker": False
    },
    "aws:principalorgid": {
        "description": "Restricts to principals within the Org",
        "blocks_external_attacker": True
    },
    "aws:calledvia": {
        "description": "Restricts to calls made via specific services",
        "blocks_external_attacker": False
    },
    "aws:tokenisstale": {
        "description": "Blocks stale session tokens",
        "blocks_external_attacker": True
    }
}


@dataclass
class ConditionEvalResult:
    is_restricted: bool
    restriction_type: str  # "BLOCKED", "CONDITIONAL", "EXPOSED"
    conditions_found: list
    explanation: str


class ConditionEvaluator:
    def __init__(self, session, account_id: str):
        self.session = session
        self.account_id = account_id
        self.iam = session.client("iam")
        # Cache policy documents to avoid redundant API calls
        self._policy_cache = {}

    def _get_policy_document(self, policy_arn: str) -> dict:
        if policy_arn in self._policy_cache:
            return self._policy_cache[policy_arn]
        try:
            policy = self.iam.get_policy(PolicyArn=policy_arn)
            version_id = policy["Policy"]["DefaultVersionId"]
            version = self.iam.get_policy_version(
                PolicyArn=policy_arn, VersionId=version_id
            )
            doc = version["PolicyVersion"]["Document"]
            if isinstance(doc, str):
                doc = json.loads(doc)
            self._policy_cache[policy_arn] = doc
            return doc
        except ClientError:
            return {}

    def _get_inline_policy_document(self, identity_type: str,
                                     identity_name: str, policy_name: str) -> dict:
        try:
            if identity_type == "user":
                response = self.iam.get_user_policy(
                    UserName=identity_name, PolicyName=policy_name
                )
            else:
                response = self.iam.get_role_policy(
                    RoleName=identity_name, PolicyName=policy_name
                )
            doc = response["PolicyDocument"]
            if isinstance(doc, str):
                doc = json.loads(doc)
            return doc
        except ClientError:
            return {}

    def _extract_conditions_for_action(self, doc: dict, action: str) -> list:
        """
        Find all conditions on statements that Allow the given action.
        Returns list of condition dicts found.
        """
        conditions = []
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue

            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]

            # Check if this statement covers the action
            action_match = False
            for a in actions:
                a_lower = a.lower()
                action_lower = action.lower()
                if a_lower == "*" or a_lower == action_lower:
                    action_match = True
                    break
                if "*" in a_lower:
                    prefix = a_lower.split("*")[0]
                    if action_lower.startswith(prefix):
                        action_match = True
                        break

            if action_match and "Condition" in stmt:
                conditions.append(stmt["Condition"])

        return conditions

    def _evaluate_condition(self, condition: dict) -> tuple:
        """
        Evaluate a single condition block.
        Returns (is_restricting, description)
        """
        found_restrictions = []

        for operator, keys in condition.items():
            operator_lower = operator.lower()
            for key, value in keys.items():
                key_lower = key.lower()

                # MFA check
                if key_lower == "aws:multifactorauthpresent":
                    if str(value).lower() == "true":
                        found_restrictions.append(
                            f"MFA required (aws:MultiFactorAuthPresent = true)"
                        )

                # IP restriction
                elif key_lower == "aws:sourceip":
                    ips = value if isinstance(value, list) else [value]
                    # Check if it's a private/corporate range
                    private_prefixes = ["10.", "172.16.", "172.17.", "172.18.",
                                       "172.19.", "172.2", "172.3", "192.168."]
                    is_private = any(
                        any(ip.startswith(p) for p in private_prefixes)
                        for ip in ips
                    )
                    if is_private:
                        found_restrictions.append(
                            f"IP restricted to corporate/private range: {', '.join(ips)}"
                        )
                    else:
                        found_restrictions.append(
                            f"IP restricted to: {', '.join(ips)}"
                        )

                # VPC restriction
                elif key_lower == "aws:sourcevpc":
                    vpcs = value if isinstance(value, list) else [value]
                    found_restrictions.append(
                        f"Restricted to VPC: {', '.join(vpcs)}"
                    )

                # VPC Endpoint restriction
                elif key_lower == "aws:sourcevpce":
                    vpces = value if isinstance(value, list) else [value]
                    found_restrictions.append(
                        f"Restricted to VPC Endpoint: {', '.join(vpces)}"
                    )

                # Org restriction
                elif key_lower == "aws:principalorgid":
                    found_restrictions.append(
                        f"Restricted to Org principals: {value}"
                    )

                # Token freshness
                elif key_lower == "aws:tokenisstale":
                    if str(value).lower() == "false":
                        found_restrictions.append(
                            "Blocks stale/replayed session tokens"
                        )

        return len(found_restrictions) > 0, found_restrictions

    def evaluate_path(self, identity_type: str, identity_name: str,
                      required_permissions: list) -> ConditionEvalResult:
        """
        Evaluate whether conditions on policies restrict exploitation
        of the given permissions for an identity.
        """
        all_conditions = []

        try:
            # Get all policies for this identity
            if identity_type == "user":
                # Attached managed policies
                attached = self.iam.list_attached_user_policies(
                    UserName=identity_name
                )
                for policy in attached["AttachedPolicies"]:
                    doc = self._get_policy_document(policy["PolicyArn"])
                    for perm in required_permissions:
                        conds = self._extract_conditions_for_action(doc, perm)
                        all_conditions.extend(conds)

                # Inline policies
                inline = self.iam.list_user_policies(UserName=identity_name)
                for policy_name in inline["PolicyNames"]:
                    doc = self._get_inline_policy_document(
                        "user", identity_name, policy_name
                    )
                    for perm in required_permissions:
                        conds = self._extract_conditions_for_action(doc, perm)
                        all_conditions.extend(conds)

                # Group policies
                groups = self.iam.list_groups_for_user(UserName=identity_name)
                for group in groups["Groups"]:
                    group_attached = self.iam.list_attached_group_policies(
                        GroupName=group["GroupName"]
                    )
                    for policy in group_attached["AttachedPolicies"]:
                        doc = self._get_policy_document(policy["PolicyArn"])
                        for perm in required_permissions:
                            conds = self._extract_conditions_for_action(doc, perm)
                            all_conditions.extend(conds)

            elif identity_type == "role":
                attached = self.iam.list_attached_role_policies(
                    RoleName=identity_name
                )
                for policy in attached["AttachedPolicies"]:
                    doc = self._get_policy_document(policy["PolicyArn"])
                    for perm in required_permissions:
                        conds = self._extract_conditions_for_action(doc, perm)
                        all_conditions.extend(conds)

                inline = self.iam.list_role_policies(RoleName=identity_name)
                for policy_name in inline["PolicyNames"]:
                    doc = self._get_inline_policy_document(
                        "role", identity_name, policy_name
                    )
                    for perm in required_permissions:
                        conds = self._extract_conditions_for_action(doc, perm)
                        all_conditions.extend(conds)

        except ClientError:
            pass

        # Evaluate all found conditions
        all_restrictions = []
        for condition in all_conditions:
            is_restricting, restrictions = self._evaluate_condition(condition)
            if is_restricting:
                all_restrictions.extend(restrictions)

        if not all_restrictions:
            return ConditionEvalResult(
                is_restricted=False,
                restriction_type="EXPOSED",
                conditions_found=[],
                explanation="No restricting conditions found — fully exploitable"
            )

        # Check if restrictions are strong enough to block exploitation
        blocks_external = any(
            any(key in r.lower() for key in ["mfa", "ip restricted", "vpc", "org"])
            for r in all_restrictions
        )

        if blocks_external:
            return ConditionEvalResult(
                is_restricted=True,
                restriction_type="CONDITIONAL",
                conditions_found=all_restrictions,
                explanation="; ".join(all_restrictions)
            )

        return ConditionEvalResult(
            is_restricted=False,
            restriction_type="EXPOSED",
            conditions_found=all_restrictions,
            explanation="Conditions present but do not block external exploitation"
        )
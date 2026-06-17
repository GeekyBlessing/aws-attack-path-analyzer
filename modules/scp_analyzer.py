"""
SCP Analyzer — pulls all Service Control Policies from AWS Organizations
and determines which permissions are denied in the account's OU chain.
"""

import json
from botocore.exceptions import ClientError
from rich.console import Console

console = Console()


class SCPAnalyzer:
    def __init__(self, session, account_id: str):
        self.session = session
        self.account_id = account_id
        self.org_client = None
        self.scps = []
        self.denied_permissions = set()
        self.ou_chain = []
        self._enabled = False

    def _init_org_client(self) -> bool:
        try:
            self.org_client = self.session.client("organizations")
            self.org_client.describe_organization()
            self._enabled = True
            return True
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "AWSOrganizationsNotInUseException":
                console.print("[yellow]  ⚠ Account is not part of an AWS Organization — skipping SCP analysis[/yellow]")
            elif code == "AccessDeniedException":
                console.print("[yellow]  ⚠ No Organizations read access — skipping SCP analysis[/yellow]")
            else:
                console.print(f"[yellow]  ⚠ Could not connect to Organizations: {code}[/yellow]")
            return False

    def _get_ou_chain(self) -> list:
        """Walk from account up to root, collecting all parent OUs."""
        chain = []
        try:
            # Start from account
            parents = self.org_client.list_parents(ChildId=self.account_id)
            current = parents["Parents"][0]
            chain.append(current)

            # Walk up to root
            while current["Type"] != "ROOT":
                parents = self.org_client.list_parents(ChildId=current["Id"])
                current = parents["Parents"][0]
                chain.append(current)

        except ClientError as e:
            console.print(f"[yellow]  ⚠ Could not walk OU chain: {e.response['Error']['Code']}[/yellow]")

        return chain

    def _get_scps_for_target(self, target_id: str) -> list:
        """Get all SCPs attached to a specific OU or root."""
        scps = []
        try:
            paginator = self.org_client.get_paginator("list_policies_for_target")
            for page in paginator.paginate(TargetId=target_id, Filter="SERVICE_CONTROL_POLICY"):
                scps.extend(page.get("Policies", []))
        except ClientError:
            pass
        return scps

    def _get_scp_document(self, policy_id: str) -> dict:
        """Fetch the full SCP document."""
        try:
            response = self.org_client.describe_policy(PolicyId=policy_id)
            content = response["Policy"]["Content"]
            if isinstance(content, str):
                return json.loads(content)
            return content
        except (ClientError, json.JSONDecodeError):
            return {}

    def _parse_denied_actions(self, doc: dict) -> list:
        """Extract all Deny actions from an SCP document."""
        denied = []
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Deny":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                denied.append(action.lower())

        return denied

    def _parse_allowed_actions(self, doc: dict) -> list:
        """
        Extract all Allow actions from an SCP.
        In SCPs, an Allow statement means everything NOT listed is implicitly denied.
        We handle this by computing the inverse.
        """
        allowed = []
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
                allowed.append(action.lower())

        return allowed

    def _is_full_aws_access(self, doc: dict) -> bool:
        """Check if SCP is the default FullAWSAccess (allows everything)."""
        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]
        for stmt in statements:
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                resource = stmt.get("Resource", [])
                if actions == "*" or actions == ["*"]:
                    if resource == "*" or resource == ["*"]:
                        return True
        return False

    def analyze(self):
        """Main entry — walk OU chain and collect all effective denied permissions."""
        if not self._init_org_client():
            return

        self.ou_chain = self._get_ou_chain()

        # Also check SCPs directly on the account
        targets = [self.account_id] + [ou["Id"] for ou in self.ou_chain]

        seen_policy_ids = set()

        for target_id in targets:
            scps = self._get_scps_for_target(target_id)
            for scp_meta in scps:
                policy_id = scp_meta["Id"]
                if policy_id in seen_policy_ids:
                    continue
                seen_policy_ids.add(policy_id)

                doc = self._get_scp_document(policy_id)

                # Skip FullAWSAccess — it's the default permissive SCP
                if self._is_full_aws_access(doc):
                    self.scps.append({
                        "id": policy_id,
                        "name": scp_meta["Name"],
                        "type": "FullAWSAccess",
                        "denied_actions": [],
                        "target": target_id
                    })
                    continue

                denied = self._parse_denied_actions(doc)
                self.denied_permissions.update(denied)

                self.scps.append({
                    "id": policy_id,
                    "name": scp_meta["Name"],
                    "type": "Restrictive",
                    "denied_actions": denied,
                    "target": target_id
                })

    def get_denied_permissions(self) -> set:
        """Run analysis and return all denied permissions."""
        self.analyze()
        return self.denied_permissions

    def get_summary(self) -> dict:
        return {
            "total_scps": len(self.scps),
            "ou_chain_depth": len(self.ou_chain),
            "total_denied_actions": len(self.denied_permissions),
            "scps": self.scps,
            "ou_chain": self.ou_chain,
            "enabled": self._enabled
        }
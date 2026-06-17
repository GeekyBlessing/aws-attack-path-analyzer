"""
Remediation Guidance — specific fixes for each attack technique.
"""

REMEDIATION_GUIDE = {
    "CreatePolicyVersion": {
        "title": "Restrict iam:CreatePolicyVersion",
        "risk": "Attacker can create a new policy version granting themselves admin access.",
        "steps": [
            "Remove iam:CreatePolicyVersion from all non-admin identities",
            "If required, restrict with condition: aws:ResourceTag/Environment = production",
            "Enable IAM Access Analyzer to detect overly permissive policies",
            "Implement SCP: Deny iam:CreatePolicyVersion for all except break-glass roles"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:CreatePolicyVersion","Resource":"*","Condition":{"StringNotEquals":{"aws:PrincipalARN":"arn:aws:iam::ACCOUNT_ID:role/BreakGlassRole"}}}',
        "effort": "Low",
        "priority": 1
    },
    "SetDefaultPolicyVersion": {
        "title": "Restrict iam:SetDefaultPolicyVersion",
        "risk": "Attacker can revert to an older policy version with higher privileges.",
        "steps": [
            "Remove iam:SetDefaultPolicyVersion from non-admin identities",
            "Audit all policy versions — delete unused older versions",
            "Add SCP deny for non-admin roles",
            "Enable CloudTrail alerts on SetDefaultPolicyVersion calls"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:SetDefaultPolicyVersion","Resource":"*"}',
        "effort": "Low",
        "priority": 2
    },
    "AttachUserPolicy": {
        "title": "Restrict iam:AttachUserPolicy",
        "risk": "Attacker can attach AdministratorAccess policy directly to their own user.",
        "steps": [
            "Remove iam:AttachUserPolicy from all non-admin identities",
            "Use permission boundaries to limit what policies can be attached",
            "Implement SCP to deny attaching admin policies",
            "Require MFA for all IAM write operations"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:AttachUserPolicy","Resource":"*","Condition":{"ArnNotLike":{"aws:PrincipalARN":"arn:aws:iam::*:role/AdminRole"}}}',
        "effort": "Low",
        "priority": 1
    },
    "AttachGroupPolicy": {
        "title": "Restrict iam:AttachGroupPolicy",
        "risk": "Attacker can attach admin policy to any group they belong to.",
        "steps": [
            "Remove iam:AttachGroupPolicy from non-admin identities",
            "Audit group memberships — apply least privilege",
            "Add SCP deny for non-admin principals",
            "Enable CloudTrail alerting on group policy changes"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:AttachGroupPolicy","Resource":"*"}',
        "effort": "Low",
        "priority": 2
    },
    "AttachRolePolicy": {
        "title": "Restrict iam:AttachRolePolicy",
        "risk": "Attacker can attach admin policy to any assumable role.",
        "steps": [
            "Remove iam:AttachRolePolicy from non-admin identities",
            "Implement permission boundaries on all roles",
            "Restrict role assumption with trust policy conditions",
            "Add SCP to deny attaching AWS managed admin policies"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:AttachRolePolicy","Resource":"*","Condition":{"ArnEquals":{"iam:PolicyARN":"arn:aws:iam::aws:policy/AdministratorAccess"}}}',
        "effort": "Medium",
        "priority": 2
    },
    "CreateRole+PassRole": {
        "title": "Restrict iam:CreateRole and iam:PassRole",
        "risk": "Attacker can create a privileged role and pass it to an AWS service.",
        "steps": [
            "Remove iam:PassRole or scope it with iam:PassedToService condition",
            "Restrict iam:CreateRole with permission boundaries",
            "Limit which services can receive passed roles",
            "Require tag-based conditions on role creation"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:PassRole","Resource":"*","Condition":{"StringNotEquals":{"iam:PassedToService":["ec2.amazonaws.com","lambda.amazonaws.com"]}}}',
        "effort": "Medium",
        "priority": 2
    },
    "AssumeRole": {
        "title": "Restrict sts:AssumeRole",
        "risk": "Attacker can assume a higher-privileged role.",
        "steps": [
            "Add MFA condition to role trust policies: aws:MultiFactorAuthPresent = true",
            "Restrict trust policies to specific principal ARNs",
            "Add IP condition to limit assumption to corporate IPs",
            "Enable CloudTrail alerts on cross-account role assumptions"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}',
        "effort": "Medium",
        "priority": 2
    },
    "AssumeRole→Admin": {
        "title": "Restrict assumption of admin roles",
        "risk": "Attacker can assume a role with full administrator access.",
        "steps": [
            "Add MFA condition to admin role trust policies",
            "Limit trust policy to specific break-glass users only",
            "Implement just-in-time access for admin roles",
            "Alert on every assumption of admin roles via CloudWatch"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"arn:aws:iam::*:role/*Admin*","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}',
        "effort": "Medium",
        "priority": 1
    },
    "PassRole+EC2": {
        "title": "Restrict iam:PassRole to EC2",
        "risk": "Attacker can launch an EC2 instance with a privileged instance profile.",
        "steps": [
            "Scope PassRole with condition: iam:PassedToService = ec2.amazonaws.com",
            "Restrict which roles can be passed using resource ARN conditions",
            "Require instance profile tags for compliance",
            "Limit ec2:RunInstances with tag-based conditions"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:PassRole","Resource":"*","Condition":{"StringEquals":{"iam:PassedToService":"ec2.amazonaws.com"},"ArnNotLike":{"aws:PrincipalARN":"arn:aws:iam::*:role/EC2AdminRole"}}}',
        "effort": "Medium",
        "priority": 3
    },
    "PassRole+Lambda": {
        "title": "Restrict iam:PassRole to Lambda",
        "risk": "Attacker can create a Lambda function with an admin execution role.",
        "steps": [
            "Scope PassRole with condition: iam:PassedToService = lambda.amazonaws.com",
            "Restrict lambda:CreateFunction to specific roles only",
            "Require Lambda functions to use approved execution roles",
            "Monitor Lambda creation events in CloudTrail"
        ],
        "scp_fix": '{"Effect":"Deny","Action":["lambda:CreateFunction","lambda:UpdateFunctionConfiguration"],"Resource":"*","Condition":{"ArnNotLike":{"aws:PrincipalARN":"arn:aws:iam::*:role/LambdaAdminRole"}}}',
        "effort": "Medium",
        "priority": 3
    },
    "PassRole+CloudFormation": {
        "title": "Restrict iam:PassRole to CloudFormation",
        "risk": "Attacker can deploy a CloudFormation stack using a privileged role.",
        "steps": [
            "Scope PassRole with condition: iam:PassedToService = cloudformation.amazonaws.com",
            "Require CloudFormation stacks to use approved service roles only",
            "Restrict cloudformation:CreateStack to specific roles",
            "Enable CloudFormation drift detection"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"cloudformation:CreateStack","Resource":"*","Condition":{"ArnNotLike":{"aws:PrincipalARN":"arn:aws:iam::*:role/CFNAdminRole"}}}',
        "effort": "Medium",
        "priority": 3
    },
    "UpdateAssumeRolePolicy": {
        "title": "Restrict iam:UpdateAssumeRolePolicy",
        "risk": "Attacker can modify a role trust policy to allow themselves to assume it.",
        "steps": [
            "Remove iam:UpdateAssumeRolePolicy from all non-admin identities",
            "Add SCP deny for non-admin principals",
            "Enable CloudTrail alerting on trust policy modifications",
            "Implement AWS Config rule to detect trust policy changes"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:UpdateAssumeRolePolicy","Resource":"*"}',
        "effort": "Low",
        "priority": 1
    },
    "PutUserPolicy": {
        "title": "Restrict iam:PutUserPolicy",
        "risk": "Attacker can add an inline policy granting themselves admin access.",
        "steps": [
            "Remove iam:PutUserPolicy from all non-admin identities",
            "Use AWS managed policies instead of inline policies",
            "Add SCP to deny inline policy creation",
            "Enable AWS Config rule: iam-no-inline-policy-check"
        ],
        "scp_fix": '{"Effect":"Deny","Action":["iam:PutUserPolicy","iam:PutRolePolicy","iam:PutGroupPolicy"],"Resource":"*"}',
        "effort": "Low",
        "priority": 1
    },
    "PutRolePolicy": {
        "title": "Restrict iam:PutRolePolicy",
        "risk": "Attacker can add an inline policy to a role granting admin permissions.",
        "steps": [
            "Remove iam:PutRolePolicy from all non-admin identities",
            "Migrate all inline policies to managed policies",
            "Add SCP to deny inline policy creation on roles",
            "Alert on iam:PutRolePolicy calls via CloudWatch Events"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:PutRolePolicy","Resource":"*"}',
        "effort": "Low",
        "priority": 1
    },
    "CreateAccessKey": {
        "title": "Restrict iam:CreateAccessKey",
        "risk": "Attacker can create access keys for a privileged user.",
        "steps": [
            "Remove iam:CreateAccessKey except for self (add condition aws:username = ${aws:username})",
            "Enforce maximum of 1 access key per user via SCP",
            "Rotate access keys every 90 days — enforce via AWS Config",
            "Alert on access key creation via CloudTrail"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:CreateAccessKey","Resource":"*","Condition":{"StringNotEquals":{"aws:username":"${aws:username}"}}}',
        "effort": "Low",
        "priority": 2
    },
    "CreateLoginProfile": {
        "title": "Restrict iam:CreateLoginProfile",
        "risk": "Attacker can set a console password for a privileged user that has none.",
        "steps": [
            "Remove iam:CreateLoginProfile from non-admin identities",
            "Enforce MFA for all console users via SCP",
            "Use IAM Identity Center instead of IAM users for console access",
            "Alert on login profile creation via CloudTrail"
        ],
        "scp_fix": '{"Effect":"Deny","Action":["iam:CreateLoginProfile","iam:UpdateLoginProfile"],"Resource":"*","Condition":{"StringNotEquals":{"aws:username":"${aws:username}"}}}',
        "effort": "Medium",
        "priority": 2
    },
    "UpdateLoginProfile": {
        "title": "Restrict iam:UpdateLoginProfile",
        "risk": "Attacker can change the console password of a privileged user.",
        "steps": [
            "Remove iam:UpdateLoginProfile from non-admin identities",
            "Scope with condition to only allow updating own password",
            "Enforce strong password policy via IAM account settings",
            "Alert on login profile updates via CloudTrail"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"iam:UpdateLoginProfile","Resource":"*","Condition":{"StringNotEquals":{"aws:username":"${aws:username}"}}}',
        "effort": "Low",
        "priority": 2
    },
    "SecretsManagerAccess": {
        "title": "Restrict secretsmanager:GetSecretValue",
        "risk": "Attacker can read all secrets including database credentials and API keys.",
        "steps": [
            "Scope GetSecretValue to specific secret ARNs only",
            "Add resource-based policy on secrets to restrict access",
            "Enable Secrets Manager rotation for all secrets",
            "Enable CloudTrail + CloudWatch alert on GetSecretValue calls",
            "Tag secrets and use tag-based conditions for access control"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"secretsmanager:GetSecretValue","Resource":"*","Condition":{"StringNotEquals":{"aws:ResourceTag/AllowedAccess":"true"}}}',
        "effort": "Medium",
        "priority": 2
    },
    "SSMParameterAccess": {
        "title": "Restrict ssm:GetParameter on sensitive parameters",
        "risk": "Attacker can read sensitive SSM parameters including passwords and tokens.",
        "steps": [
            "Use SecureString type for all sensitive parameters",
            "Scope GetParameter to specific parameter paths only",
            "Add KMS key policy to restrict who can decrypt SecureString values",
            "Enable CloudTrail alerting on SecureString access"
        ],
        "scp_fix": '{"Effect":"Deny","Action":["ssm:GetParameter","ssm:GetParameters"],"Resource":"arn:aws:ssm:*:*:parameter/prod/*","Condition":{"ArnNotLike":{"aws:PrincipalARN":"arn:aws:iam::*:role/AppRole"}}}',
        "effort": "Medium",
        "priority": 3
    },
    "S3SensitiveRead": {
        "title": "Restrict s3:GetObject on sensitive buckets",
        "risk": "Attacker can read potentially sensitive data from S3 buckets.",
        "steps": [
            "Enable S3 Block Public Access at account level",
            "Add bucket policies to restrict GetObject to specific roles",
            "Enable S3 server-side encryption on all buckets",
            "Enable S3 access logging and CloudTrail data events",
            "Use S3 Object Lambda for sensitive data masking"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::sensitive-bucket/*","Condition":{"ArnNotLike":{"aws:PrincipalARN":"arn:aws:iam::*:role/DataAccessRole"}}}',
        "effort": "Medium",
        "priority": 3
    },
    "GlueDevEndpoint": {
        "title": "Restrict glue:CreateDevEndpoint",
        "risk": "Attacker can create a Glue dev endpoint with a privileged role to run arbitrary code.",
        "steps": [
            "Remove glue:CreateDevEndpoint from non-admin identities",
            "Add SCP to deny Glue dev endpoint creation in production",
            "Restrict iam:PassRole to Glue service only for approved roles",
            "Monitor Glue endpoint creation via CloudTrail"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"glue:CreateDevEndpoint","Resource":"*"}',
        "effort": "Low",
        "priority": 3
    },
    "CodeBuildPrivesc": {
        "title": "Restrict codebuild:CreateProject with privileged roles",
        "risk": "Attacker can create a CodeBuild project with an admin service role to execute arbitrary code.",
        "steps": [
            "Scope codebuild:CreateProject to specific service roles only",
            "Restrict iam:PassRole to CodeBuild with approved role ARNs",
            "Require CodeBuild projects to use approved environments",
            "Enable CodeBuild logging and alert on new project creation"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"codebuild:CreateProject","Resource":"*","Condition":{"ArnNotLike":{"aws:PrincipalARN":"arn:aws:iam::*:role/DevOpsRole"}}}',
        "effort": "Medium",
        "priority": 3
    },
    "CrossAccount": {
        "title": "Restrict cross-account role assumption",
        "risk": "Attacker can pivot from management account to member accounts via OrganizationAccountAccessRole.",
        "steps": [
            "Add MFA condition to OrganizationAccountAccessRole trust policy",
            "Restrict OrganizationAccountAccessRole to specific admin users only",
            "Consider deleting OrganizationAccountAccessRole and using IAM Identity Center",
            "Enable CloudTrail in all accounts and alert on cross-account assumptions",
            "Add SCP to deny cross-account role assumption without MFA"
        ],
        "scp_fix": '{"Effect":"Deny","Action":"sts:AssumeRole","Resource":"arn:aws:iam::*:role/OrganizationAccountAccessRole","Condition":{"BoolIfExists":{"aws:MultiFactorAuthPresent":"false"}}}',
        "effort": "High",
        "priority": 1
    }
}


def get_remediation(technique: str) -> dict:
    """Get remediation guidance for a specific technique."""
    # Handle variations
    if "AssumeRole" in technique and "Admin" in technique:
        return REMEDIATION_GUIDE.get("AssumeRole→Admin", {})
    if "Cross" in technique or "cross" in technique:
        return REMEDIATION_GUIDE.get("CrossAccount", {})
    return REMEDIATION_GUIDE.get(technique, {
        "title": f"Review permissions for {technique}",
        "risk": "This technique may allow privilege escalation.",
        "steps": [
            "Apply principle of least privilege",
            "Remove unnecessary permissions",
            "Add CloudTrail alerting for this action",
            "Review with AWS IAM Access Analyzer"
        ],
        "scp_fix": "",
        "effort": "Medium",
        "priority": 3
    })


def get_top_remediations(attack_paths: list, limit: int = 10) -> list:
    """
    Get prioritized remediations based on scored attack paths.
    Deduplicates by technique.
    """
    seen_techniques = set()
    remediations = []

    for path in attack_paths:
        technique = path.technique
        if technique in seen_techniques:
            continue
        seen_techniques.add(technique)

        guidance = get_remediation(technique)
        risk_score = getattr(path, 'risk_score', None)

        remediations.append({
            "technique": technique,
            "risk_score": risk_score.total if risk_score else 0,
            "severity": path.severity,
            "guidance": guidance
        })

    # Sort by risk score then priority
    remediations.sort(
        key=lambda r: (
            -r["risk_score"],
            r["guidance"].get("priority", 99)
        )
    )

    return remediations[:limit]
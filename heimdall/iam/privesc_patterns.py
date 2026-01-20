"""
IAM Privilege Escalation Pattern Library

Based on:
- Rhino Security Labs research: https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/
- Bishop Fox IAM Vulnerable test cases
- Real-world pentesting experience
"""

from dataclasses import dataclass
from typing import List, Optional, Set
from enum import Enum


class PrivescMethod(Enum):
    """Privilege escalation method categories"""
    POLICY_MANIPULATION = "policy_manipulation"
    ROLE_MANIPULATION = "role_manipulation"
    PASSROLE_ABUSE = "passrole_abuse"
    CREDENTIAL_ACCESS = "credential_access"
    LAMBDA_ABUSE = "lambda_abuse"
    REMOTE_EXECUTION = "remote_execution"  # v0.9.0
    SECRET_EXFILTRATION = "secret_exfiltration"  # v0.9.0
    DIRECT_ROLE_ASSUMPTION = "direct_role_assumption"  # v0.9.0
    COMPUTE_MANIPULATION = "compute_manipulation"  # v0.9.0
    EKS_ABUSE = "eks_abuse"  # v1.1.0


@dataclass
class PrivescPattern:
    """Single privilege escalation pattern"""
    id: str
    name: str
    description: str
    required_actions: List[str]
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    method: PrivescMethod
    service: Optional[str] = None
    requires_target_role: bool = False
    explanation: Optional[str] = None
    remediation: Optional[str] = None
    conditional_requirements: Optional[List[str]] = None  # Non-IAM prerequisites (e.g., "kubectl access", "console access")


# Phase 2A-1: First 5 Critical Patterns
PRIVESC_PATTERNS = {
    
    # Pattern 1: PassRole + Lambda
    'passrole_lambda': PrivescPattern(
        id='passrole_lambda',
        name='iam:PassRole + lambda:CreateFunction',
        description='Create Lambda function with privileged role, execute code with elevated permissions',
        required_actions=['iam:PassRole', 'lambda:CreateFunction'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='lambda',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and lambda:CreateFunction can create a new Lambda function "
            "and attach a privileged role to it. When the Lambda executes, it runs with the permissions "
            "of the attached role. If that role has admin access, the attacker can execute arbitrary "
            "code with admin privileges."
        ),
        remediation=(
            "1. Remove lambda:CreateFunction permission\n"
            "2. Restrict iam:PassRole to specific roles:\n"
            "   Resource: arn:aws:iam::*:role/SafeRoleName\n"
            "3. Add MFA condition to sensitive permissions\n"
            "4. Use Lambda execution roles with minimal required permissions"
        )
    ),
    
    # Pattern 2: PassRole + EC2
    'passrole_ec2': PrivescPattern(
        id='passrole_ec2',
        name='iam:PassRole + ec2:RunInstances',
        description='Launch EC2 instance with privileged role, SSH and execute commands with elevated permissions',
        required_actions=['iam:PassRole', 'ec2:RunInstances'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='ec2',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and ec2:RunInstances can launch an EC2 instance "
            "with a privileged IAM role attached. Once the instance is running, they can SSH "
            "into it and use the instance metadata service (IMDS) to retrieve temporary credentials "
            "for the attached role. If that role has admin access, the attacker gains full AWS access."
        ),
        remediation=(
            "1. Remove ec2:RunInstances permission if not needed\n"
            "2. Restrict iam:PassRole to specific roles:\n"
            "   Resource: arn:aws:iam::*:role/SafeEC2Role\n"
            "3. Add condition to iam:PassRole:\n"
            "   Condition: StringEquals: iam:PassedToService: ec2.amazonaws.com\n"
            "4. Use VPC endpoints and disable IMDS v1\n"
            "5. Monitor EC2 instance launches with high-privilege roles"
        )
    ),
    
    # Pattern 3: AttachUserPolicy
    'attach_user_policy': PrivescPattern(
        id='attach_user_policy',
        name='iam:AttachUserPolicy',
        description='Attach AdministratorAccess policy to self or other user',
        required_actions=['iam:AttachUserPolicy'],
        severity='CRITICAL',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "With iam:AttachUserPolicy, an attacker can attach any managed policy (including "
            "AdministratorAccess) to themselves or another user they control. This immediately "
            "grants full AWS account access."
        ),
        remediation=(
            "1. Remove iam:AttachUserPolicy permission\n"
            "2. Use iam:AttachUserPolicy with resource constraints:\n"
            "   Resource: arn:aws:iam::*:user/SpecificUser\n"
            "3. Add condition to prevent attaching admin policies:\n"
            "   Condition: StringNotEquals: iam:PolicyARN: arn:aws:iam::aws:policy/AdministratorAccess"
        )
    ),
    
    # Pattern 3: PutUserPolicy
    'put_user_policy': PrivescPattern(
        id='put_user_policy',
        name='iam:PutUserPolicy',
        description='Create/update inline policy with admin permissions on self or other user',
        required_actions=['iam:PutUserPolicy'],
        severity='CRITICAL',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "iam:PutUserPolicy allows creating or updating inline policies. An attacker can create "
            "a new inline policy granting themselves full permissions (Effect: Allow, Action: *, Resource: *)."
        ),
        remediation=(
            "1. Remove iam:PutUserPolicy permission\n"
            "2. Use resource constraints to limit which users can be modified\n"
            "3. Monitor CloudTrail for PutUserPolicy API calls\n"
            "4. Prefer managed policies over inline policies for better auditability"
        )
    ),
    
    # Pattern 4: CreatePolicyVersion
    'create_policy_version': PrivescPattern(
        id='create_policy_version',
        name='iam:CreatePolicyVersion',
        description='Modify existing policy to grant admin access',
        required_actions=['iam:CreatePolicyVersion'],
        severity='HIGH',
        method=PrivescMethod.POLICY_MANIPULATION,
        explanation=(
            "If a principal has iam:CreatePolicyVersion on a policy that is attached to them "
            "(or a role they can assume), they can create a new version of that policy with "
            "admin permissions. The new version becomes active immediately."
        ),
        remediation=(
            "1. Remove iam:CreatePolicyVersion permission\n"
            "2. Use resource constraints to limit which policies can be modified\n"
            "3. Set up alerts for policy version changes\n"
            "4. Use policy versioning limits (max 5 versions) as a partial mitigation"
        )
    ),
    
    # Pattern 5: UpdateAssumeRolePolicy
    'update_assume_role_policy': PrivescPattern(
        id='update_assume_role_policy',
        name='iam:UpdateAssumeRolePolicy',
        description='Modify role trust policy to assume privileged role',
        required_actions=['iam:UpdateAssumeRolePolicy'],
        severity='HIGH',
        method=PrivescMethod.ROLE_MANIPULATION,
        requires_target_role=True,
        explanation=(
            "With iam:UpdateAssumeRolePolicy, an attacker can modify the trust policy of a role "
            "to allow themselves (or a principal they control) to assume it. If the role has "
            "elevated permissions, this grants privilege escalation."
        ),
        remediation=(
            "1. Remove iam:UpdateAssumeRolePolicy permission\n"
            "2. Use resource constraints to protect critical roles\n"
            "3. Add MFA requirement in trust policies for sensitive roles\n"
            "4. Monitor AssumeRole API calls with CloudTrail"
        )
    ),
    
    # Pattern 6: PassRole + CloudFormation
    'passrole_cloudformation': PrivescPattern(
        id='passrole_cloudformation',
        name='iam:PassRole + cloudformation:CreateStack',
        description='Launch CloudFormation stack with privileged role, execute resources with elevated permissions',
        required_actions=['iam:PassRole', 'cloudformation:CreateStack'],
        severity='CRITICAL',
        method=PrivescMethod.PASSROLE_ABUSE,
        service='cloudformation',
        requires_target_role=True,
        explanation=(
            "An attacker with iam:PassRole and cloudformation:CreateStack can create a CloudFormation "
            "stack with a privileged IAM role. The stack's resources (Lambda functions, EC2 instances, "
            "etc.) execute with the passed role's permissions. If that role has admin access, the attacker "
            "can deploy malicious resources with full AWS privileges."
        ),
        remediation=(
            "1. Remove cloudformation:CreateStack permission if not needed\n"
            "2. Restrict iam:PassRole to specific roles:\n"
            "   Resource: arn:aws:iam::*:role/SafeCloudFormationRole\n"
            "3. Add condition to iam:PassRole:\n"
            "   Condition: StringEquals: iam:PassedToService: cloudformation.amazonaws.com\n"
            "4. Use CloudFormation StackSets with service-managed permissions\n"
            "5. Monitor CloudFormation stack creation with CloudTrail"
        )
    ),
    
    # Pattern 7: CreateAccessKey
    'create_access_key': PrivescPattern(
        id='create_access_key',
        name='iam:CreateAccessKey',
        description='Create programmatic access keys for other users, steal credentials',
        required_actions=['iam:CreateAccessKey'],
        severity='CRITICAL',
        method=PrivescMethod.CREDENTIAL_ACCESS,
        explanation=(
            "With iam:CreateAccessKey, an attacker can generate new programmatic access keys "
            "for other IAM users. If the target user has elevated permissions, the attacker can "
            "use these keys to authenticate as that user and inherit their privileges. This is "
            "especially dangerous if the permission applies to admin users or is not resource-constrained."
        ),
        remediation=(
            "1. Remove iam:CreateAccessKey permission if not needed\n"
            "2. Use resource constraints to limit key creation:\n"
            "   Resource: arn:aws:iam::*:user/${aws:username}\n"
            "   (Only allow users to create keys for themselves)\n"
            "3. Monitor CreateAccessKey API calls with CloudTrail\n"
            "4. Implement key rotation policies\n"
            "5. Use AWS IAM Access Analyzer to detect unused keys\n"
            "6. Require MFA for sensitive API operations"
        )
    ),
    
    # Pattern 8: UpdateLoginProfile
    'update_login_profile': PrivescPattern(
        id='update_login_profile',
        name='iam:UpdateLoginProfile',
        description='Reset console password for other users, gain console access',
        required_actions=['iam:UpdateLoginProfile'],
        severity='HIGH',
        method=PrivescMethod.CREDENTIAL_ACCESS,
        explanation=(
            "iam:UpdateLoginProfile allows resetting the console password for IAM users. An attacker "
            "with this permission can change the password of another user (including admin users) and "
            "log into the AWS Console as that user. Unlike CreateAccessKey, this provides console access "
            "which may bypass some programmatic access restrictions."  # Removed hardcoded password
        ),
        remediation=(
            "1. Remove iam:UpdateLoginProfile permission if not needed\n"
            "2. Use resource constraints to limit password resets:\n"
            "   Resource: arn:aws:iam::*:user/${aws:username}\n"
            "3. Monitor UpdateLoginProfile API calls with CloudTrail\n"
            "4. Require MFA for password changes\n"
            "5. Use AWS SSO instead of IAM users for console access"
        )
    ),
}
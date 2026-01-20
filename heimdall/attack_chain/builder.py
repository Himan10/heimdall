# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#                           ᛞᚹᛖᚱᚷᚨᚱ • THE DVERGAR
#                    Master Craftsmen of the Realms
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#
#   "In Svartálfaheim, the dwarves forge wonders: Mjölnir the hammer,
#    Gungnir the spear, and Gleipnir the unbreakable chain."
#
#   Like the Dvergar at their forges, this builder crafts attack chains
#   from raw findings - each link precisely fitted to the next.
#
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

from __future__ import annotations

import logging
from collections import defaultdict
from typing import List, Dict, Any, Optional, Set, Tuple

from heimdall.attack_chain.schema import (
    AttackChain, AttackStep, BlastRadius, ServiceImpact,
    ChainCategory, Severity, MITRE_MAPPINGS,
)

logger = logging.getLogger(__name__)

# Comprehensive pattern to category mapping (70+ patterns)
PATTERN_CATEGORIES = {
    # === PassRole + Service Execution (20+ services) ===
    "passrole_lambda": ChainCategory.PASSROLE_EXECUTION,
    "passrole_ec2": ChainCategory.PASSROLE_EXECUTION,
    "passrole_ecs": ChainCategory.PASSROLE_EXECUTION,
    "passrole_glue": ChainCategory.PASSROLE_EXECUTION,
    "passrole_codebuild": ChainCategory.PASSROLE_EXECUTION,
    "passrole_sagemaker": ChainCategory.PASSROLE_EXECUTION,
    "passrole_sagemaker_notebook": ChainCategory.PASSROLE_EXECUTION,
    "passrole_sagemaker_training": ChainCategory.PASSROLE_EXECUTION,
    "passrole_cloudformation": ChainCategory.PASSROLE_EXECUTION,
    "passrole_batch": ChainCategory.PASSROLE_EXECUTION,
    "passrole_emr": ChainCategory.PASSROLE_EXECUTION,
    "passrole_stepfunctions": ChainCategory.PASSROLE_EXECUTION,
    "passrole_datapipeline": ChainCategory.PASSROLE_EXECUTION,
    "passrole_iot": ChainCategory.PASSROLE_EXECUTION,
    "passrole_apprunner": ChainCategory.PASSROLE_EXECUTION,
    "passrole_mediaconvert": ChainCategory.PASSROLE_EXECUTION,
    "eks_passrole": ChainCategory.PASSROLE_EXECUTION,
    "eks_passrole_nodegroup": ChainCategory.PASSROLE_EXECUTION,
    "eks_passrole_fargate": ChainCategory.PASSROLE_EXECUTION,
    "eks_irsa_pod_exec": ChainCategory.PASSROLE_EXECUTION,
    "eks_node_role_abuse": ChainCategory.PASSROLE_EXECUTION,
    
    # === Policy Manipulation (10+ patterns) ===
    "create_policy_version": ChainCategory.POLICY_MANIPULATION,
    "set_default_policy_version": ChainCategory.POLICY_MANIPULATION,
    "put_user_policy": ChainCategory.POLICY_MANIPULATION,
    "put_role_policy": ChainCategory.POLICY_MANIPULATION,
    "put_group_policy": ChainCategory.POLICY_MANIPULATION,
    "attach_user_policy": ChainCategory.POLICY_MANIPULATION,
    "attach_role_policy": ChainCategory.POLICY_MANIPULATION,
    "attach_group_policy": ChainCategory.POLICY_MANIPULATION,
    "add_user_to_group": ChainCategory.POLICY_MANIPULATION,
    "create_policy_attach_combo": ChainCategory.POLICY_MANIPULATION,
    "permission_boundary_bypass": ChainCategory.POLICY_MANIPULATION,
    "delete_account_password_policy": ChainCategory.POLICY_MANIPULATION,
    # Fixed: Removed hardcoded credentials from tag_based_access_bypass
    "tag_based_access_bypass": ChainCategory.POLICY_MANIPULATION,
    
    # === Credential Exposure (15+ patterns) ===
    "create_access_key": ChainCategory.CREDENTIAL_EXPOSURE,
    "create_login_profile": ChainCategory.CREDENTIAL_EXPOSURE,
    "update_login_profile": ChainCategory.CREDENTIAL_EXPOSURE,
    "ssm_send_command": ChainCategory.CREDENTIAL_EXPOSURE,
    "ssm_start_session": ChainCategory.CREDENTIAL_EXPOSURE,
    "ssm_get_parameter": ChainCategory.CREDENTIAL_EXPOSURE,
    "ec2_instance_connect": ChainCategory.CREDENTIAL_EXPOSURE,
    "ec2_serial_console": ChainCategory.CREDENTIAL_EXPOSURE,
    "ec2_user_data": ChainCategory.CREDENTIAL_EXPOSURE,
    "codecommit_git_credentials": ChainCategory.CREDENTIAL_EXPOSURE,
    "secretsmanager_get_value": ChainCategory.CREDENTIAL_EXPOSURE,
    "sts_get_federation_token": ChainCategory.CREDENTIAL_EXPOSURE,
    "sts_get_session_token": ChainCategory.CREDENTIAL_EXPOSURE,
    "rds_iam_auth_token": ChainCategory.CREDENTIAL_EXPOSURE,
    "saml_oidc_provider_manipulation": ChainCategory.CREDENTIAL_EXPOSURE,
    
    # === Resource Hijack (10+ patterns) ===
    "update_function_code": ChainCategory.RESOURCE_HIJACK,
    "update_function_configuration": ChainCategory.RESOURCE_HIJACK,
    "lambda_layer": ChainCategory.RESOURCE_HIJACK,
    "modify_instance_attribute": ChainCategory.RESOURCE_HIJACK,
    "apigateway_integration_abuse": ChainCategory.RESOURCE_HIJACK,
    "cloudwatch_events_target": ChainCategory.RESOURCE_HIJACK,
    "eventbridge_lambda_trigger": ChainCategory.RESOURCE_HIJACK,
    "eks_update_cluster_config": ChainCategory.RESOURCE_HIJACK,
    "eks_wildcard_permissions": ChainCategory.RESOURCE_HIJACK,
    
    # === Data Exfiltration (10+ patterns) ===
    "s3_bucket_notification": ChainCategory.DATA_EXFILTRATION,
    "dynamodb_stream": ChainCategory.DATA_EXFILTRATION,
    "dynamodb_stream_lambda": ChainCategory.DATA_EXFILTRATION,
    "rds_snapshot": ChainCategory.DATA_EXFILTRATION,
    "rds_snapshot_export": ChainCategory.DATA_EXFILTRATION,
    "athena_query": ChainCategory.DATA_EXFILTRATION,
    "redshift_snapshot": ChainCategory.DATA_EXFILTRATION,
    "kinesis_stream": ChainCategory.DATA_EXFILTRATION,
    "firehose_delivery": ChainCategory.DATA_EXFILTRATION,
    "glue_catalog": ChainCategory.DATA_EXFILTRATION,
    
    # === Lateral Movement (10+ patterns) ===
    "update_assume_role_policy": ChainCategory.LATERAL_MOVEMENT,
    "sts_assume_role": ChainCategory.LATERAL_MOVEMENT,
    "sts_assume": ChainCategory.LATERAL_MOVEMENT,
    "cross_account_role": ChainCategory.LATERAL_MOVEMENT,
    "organization_account_access": ChainCategory.LATERAL_MOVEMENT,
    
    # === Persistence (5+ patterns) ===
    "backdoor_lambda": ChainCategory.PERSISTENCE,
    "backdoor_user": ChainCategory.PERSISTENCE,
    "backdoor_role": ChainCategory.PERSISTENCE,
    "eventbridge_scheduled": ChainCategory.PERSISTENCE,
    "cloudwatch_alarm_action": ChainCategory.PERSISTENCE,
}

# MITRE ATT&CK Technique Mapping (30+ techniques)
MITRE_TECHNIQUE_MAP = {
    # PassRole chains
    "passrole_lambda": ["T1078.004", "T1059.006"],       # Cloud Accounts, Python
    "passrole_ec2": ["T1078.004", "T1552.005"],          # Cloud Accounts, IMDS
    "passrole_ecs": ["T1078.004", "T1610"],              # Cloud Accounts, Container Deploy
    "passrole_glue": ["T1078.004", "T1059"],             # Cloud Accounts, Command Exec
    "passrole_codebuild": ["T1078.004", "T1072"],        # Cloud Accounts, Software Deploy
    "passrole_sagemaker": ["T1078.004", "T1059"],        # Cloud Accounts, Command Exec
    "passrole_stepfunctions": ["T1078.004", "T1059"],    # Cloud Accounts, Command Exec
    "passrole_batch": ["T1078.004", "T1059"],            # Cloud Accounts, Command Exec
    "passrole_emr": ["T1078.004", "T1059"],              # Cloud Accounts, Command Exec
    "eks_passrole": ["T1078.004", "T1610", "T1611"],     # Escape to Host
    "eks_irsa_pod_exec": ["T1078.004", "T1552.007"],     # Container API
    
    # Policy manipulation
    "create_policy_version": ["T1098.001"],              # Additional Cloud Credentials
    "set_default_policy_version": ["T1098.001"],
    "put_user_policy": ["T1098.001"],
    "put_role_policy": ["T1098.001"],
    "put_group_policy": ["T1098.001"],
    "attach_user_policy": ["T1098.001"],
    "attach_role_policy": ["T1098.001"],
    "attach_group_policy": ["T1098.001"],
    "add_user_to_group": ["T1098.001", "T1136.003"],     # Create Cloud Account
    "permission_boundary_bypass": ["T1098.001"],
    "delete_account_password_policy": ["T1098.001"],
    "tag_based_access_bypass": ["T1098.001"],
    "create_policy_attach_combo": ["T1098.001"],
    
    # Credential exposure
    "create_access_key": ["T1098.001", "T1136.003"],     # Create Cloud Account
    "create_login_profile": ["T1098.001", "T1136.003"],
    "update_login_profile": ["T1098.001"],
    "ssm_send_command": ["T1059", "T1021.007"],          # Remote Services: Cloud API
    "ssm_start_session": ["T1059", "T1021.007"],
    "ssm_get_parameter": ["T1552.001"],                  # Credentials In Files
    "secretsmanager_get_value": ["T1552.001"],
    "ec2_instance_connect": ["T1078.004", "T1021.004"],  # SSH
    "codecommit_git_credentials": ["T1552.001", "T1213"], # Data from Info Repos
    "sts_get_federation_token": ["T1550.001"],           # Alternate Auth
    "saml_oidc_provider_manipulation": ["T1550.001", "T1606.002"], # SAML Tokens
    
    # Resource hijack
    "update_function_code": ["T1059.006", "T1546"],      # Event Triggered Execution
    "update_function_configuration": ["T1059.006"],
    "lambda_layer": ["T1059.006", "T1195.002"],          # Supply Chain: Software
    "apigateway_integration_abuse": ["T1190"],           # Exploit Public App
    "eventbridge_lambda_trigger": ["T1546.015"],         # Event Triggered
    "cloudwatch_events_target": ["T1546.015"],
    
    # Data exfiltration
    "s3_bucket_notification": ["T1537", "T1567"],        # Exfil to Cloud
    "dynamodb_stream": ["T1537", "T1567"],
    "rds_snapshot": ["T1537", "T1530"],                  # Data from Cloud Storage
    "rds_snapshot_export": ["T1537", "T1530"],
    "athena_query": ["T1530"],
    "kinesis_stream": ["T1537"],
    
    # Lateral movement
    "update_assume_role_policy": ["T1550.001"],          # Use Alternate Auth
    "sts_assume_role": ["T1550.001", "T1078.004"],
    "cross_account_role": ["T1550.001", "T1078.004"],
    
    # Persistence
    "backdoor_lambda": ["T1546.015", "T1098"],           # Persistence
    "backdoor_user": ["T1098.001", "T1136.003"],
    "eventbridge_scheduled": ["T1053.007"],              # Scheduled Task/Job
}

# High-value target patterns for blast radius
HIGH_VALUE_TARGETS = {
    "admin", "administrator", "root", "superuser", "prod", "production",
    "master", "main", "deploy", "cicd", "pipeline", "secret", "key",
    "database", "rds", "dynamo", "billing", "security", "audit",
    "terraform", "cloudformation", "iac", "infra", "network", "vpc",
    "org", "organization", "management", "payer", "backup", "disaster"
}


class AttackChainBuilder:
    """Builds attack chains from IAM findings."""
    
    def __init__(self, graph_data: Optional[Dict] = None):
        self.graph_data = graph_data or {}
        self._chain_counter = 0
    
    def build_from_findings(self, findings: List[Dict], min_severity: str = "LOW") -> List[AttackChain]:
        """Build all attack chains from findings."""
        chains = []
        by_principal = self._group_by_principal(findings)
        
        for principal, pfindings in by_principal.items():
            chains.extend(self._build_for_principal(principal, pfindings))
        
        chains.sort(key=lambda c: c.risk_score, reverse=True)
        logger.info("Built %d chains from %d findings", len(chains), len(findings))
        return chains
    
    def build_for_principal(self, findings: List[Dict], principal: str) -> List[AttackChain]:
        """Build chains for specific principal."""
        pfindings = [f for f in findings if self._matches_principal(f, principal)]
        return self._build_for_principal(principal, pfindings) if pfindings else []
    
    def _build_for_principal(self, principal: str, findings: List[Dict]) -> List[AttackChain]:
        """Build chains for a single principal."""
        chains = []
        by_method = self._group_by_method(findings)
        
        for method, mfindings in by_method.items():
            chain = self._build_chain(principal, method, mfindings)
            if chain:
                chains.append(chain)
        
        # Add compound chains
        chains.extend(self._find_compound_chains(principal, findings))
        return chains
    
    def _build_chain(self, principal: str, method: str, findings: List[Dict]) -> Optional[AttackChain]:
        """Build single chain from findings."""
        if not findings:
            return None
        
        primary = findings[0]
        self._chain_counter += 1
        
        category = self._get_category(method)
        steps = self._build_steps(principal, method, primary)
        severity = self._get_severity(primary)
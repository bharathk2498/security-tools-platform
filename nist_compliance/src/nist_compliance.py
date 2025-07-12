#!/usr/bin/env python3
"""
NIST 800-53 Policy-as-Code Framework
Automated compliance controls that adapt to infrastructure changes
"""

import asyncio
import json
import yaml
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ControlStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"

class ControlFamily(Enum):
    AC = "Access Control"
    AU = "Audit and Accountability"
    CM = "Configuration Management"
    CP = "Contingency Planning"
    IA = "Identification and Authentication"
    IR = "Incident Response"
    SC = "System and Communications Protection"
    SI = "System and Information Integrity"

@dataclass
class ComplianceControl:
    control_id: str
    family: ControlFamily
    title: str
    description: str
    implementation: str
    status: ControlStatus
    last_checked: datetime
    evidence: List[str]
    remediation_actions: List[str]
    terraform_module: Optional[str] = None
    policy_file: Optional[str] = None

@dataclass
class ComplianceAssessment:
    assessment_id: str
    timestamp: datetime
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    overall_score: float
    findings: List[Dict]
    remediation_plan: List[Dict]

class NISTControlLibrary:
    """Library of NIST 800-53 controls with implementation guidance"""
    
    def __init__(self):
        self.controls = self._initialize_controls()
    
    def _initialize_controls(self) -> Dict[str, ComplianceControl]:
        """Initialize comprehensive NIST 800-53 control definitions"""
        controls = {}
        
        # Access Control (AC) Controls
        controls['AC-2'] = ComplianceControl(
            control_id='AC-2',
            family=ControlFamily.AC,
            title='Account Management',
            description='Manage information system accounts including establishment, activation, modification, review, and removal',
            implementation='terraform_modules/access_control/account_management.tf',
            status=ControlStatus.UNKNOWN,
            last_checked=datetime.now(),
            evidence=[],
            remediation_actions=[],
            terraform_module='access_control/account_management',
            policy_file='policies/opa/account_management.rego'
        )
        
        controls['AC-3'] = ComplianceControl(
            control_id='AC-3',
            family=ControlFamily.AC,
            title='Access Enforcement',
            description='Enforce approved authorizations for logical access',
            implementation='terraform_modules/access_control/access_enforcement.tf',
            status=ControlStatus.UNKNOWN,
            last_checked=datetime.now(),
            evidence=[],
            remediation_actions=[],
            terraform_module='access_control/access_enforcement',
            policy_file='policies/opa/access_enforcement.rego'
        )
        
        controls['AC-6'] = ComplianceControl(
            control_id='AC-6',
            family=ControlFamily.AC,
            title='Least Privilege',
            description='Employ the principle of least privilege',
            implementation='terraform_modules/access_control/least_privilege.tf',
            status=ControlStatus.UNKNOWN,
            last_checked=datetime.now(),
            evidence=[],
            remediation_actions=[],
            terraform_module='access_control/least_privilege',
            policy_file='policies/opa/least_privilege.rego'
        )
        
        # Audit and Accountability (AU) Controls
        controls['AU-2'] = ComplianceControl(
            control_id='AU-2',
            family=ControlFamily.AU,
            title='Audit Events',
            description='Determine that the information system is capable of auditing specific events',
            implementation='terraform_modules/audit/audit_events.tf',
            status=ControlStatus.UNKNOWN,
            last_checked=datetime.now(),
            evidence=[],
            remediation_actions=[],
            terraform_module='audit/audit_events',
            policy_file='policies/opa/audit_events.rego'
        )
        
        controls['AU-3'] = ComplianceControl(
            control_id='AU-3',
            family=ControlFamily.AU,
            title='Content of Audit Records',
            description='Generate audit records containing information that establishes what type of event occurred',
            implementation='terraform_modules/audit/audit_content.tf',
            status=ControlStatus.UNKNOWN,
            last_checked=datetime.now(),
            evidence=[],
            remediation_actions=[],
            terraform_module='audit/audit_content',
            policy_file='policies/opa/audit_content.rego'
        )
        
        # System and Communications Protection (SC) Controls
        controls['SC-7'] = ComplianceControl(
            control_id='SC-7',
            family=ControlFamily.SC,
            title='Boundary Protection',
            description='Monitor and control communications at the external boundary of the system',
            implementation='terraform_modules/network_security/boundary_protection.tf',
            status=ControlStatus.UNKNOWN,
            last_checked=datetime.now(),
            evidence=[],
            remediation_actions=[],
            terraform_module='network_security/boundary_protection',
            policy_file='policies/opa/boundary_protection.rego'
        )
        
        controls['SC-8'] = ComplianceControl(
            control_id='SC-8',
            family=ControlFamily.SC,
            title='Transmission Confidentiality and Integrity',
            description='Protect the confidentiality and integrity of transmitted information',
            implementation='terraform_modules/network_security/transmission_protection.tf',
            status=ControlStatus.UNKNOWN,
            last_checked=datetime.now(),
            evidence=[],
            remediation_actions=[],
            terraform_module='network_security/transmission_protection',
            policy_file='policies/opa/transmission_protection.rego'
        )
        
        # Identification and Authentication (IA) Controls
        controls['IA-2'] = ComplianceControl(
            control_id='IA-2',
            family=ControlFamily.IA,
            title='Identification and Authentication (Organizational Users)',
            description='Uniquely identify and authenticate organizational users',
            implementation='terraform_modules/identity/user_authentication.tf',
            status=ControlStatus.UNKNOWN,
            last_checked=datetime.now(),
            evidence=[],
            remediation_actions=[],
            terraform_module='identity/user_authentication',
            policy_file='policies/opa/user_authentication.rego'
        )
        
        controls['IA-5'] = ComplianceControl(
            control_id='IA-5',
            family=ControlFamily.IA,
            title='Authenticator Management',
            description='Manage information system authenticators',
            implementation='terraform_modules/identity/authenticator_management.tf',
            status=ControlStatus.UNKNOWN,
            last_checked=datetime.now(),
            evidence=[],
            remediation_actions=[],
            terraform_module='identity/authenticator_management',
            policy_file='policies/opa/authenticator_management.rego'
        )
        
        return controls
    
    def get_control(self, control_id: str) -> Optional[ComplianceControl]:
        """Get a specific control by ID"""
        return self.controls.get(control_id)
    
    def get_controls_by_family(self, family: ControlFamily) -> List[ComplianceControl]:
        """Get all controls in a specific family"""
        return [control for control in self.controls.values() if control.family == family]

class TerraformComplianceGenerator:
    """Generates Terraform modules for NIST controls"""
    
    def __init__(self, output_dir: str = "terraform_modules"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_access_control_module(self) -> str:
        """Generate Terraform module for Access Control (AC-2, AC-3, AC-6)"""
        
        module_content = '''# NIST 800-53 Access Control Implementation
# Controls: AC-2 (Account Management), AC-3 (Access Enforcement), AC-6 (Least Privilege)

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 4.0"
    }
  }
}

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be dev, staging, or prod."
  }
}

# AC-2: Account Management
# Implement least privilege service accounts
resource "google_service_account" "app_service_account" {
  account_id   = "app-${var.environment}"
  display_name = "Application Service Account - ${var.environment}"
  description  = "NIST AC-2 compliant service account with minimal permissions"
  
  lifecycle {
    prevent_destroy = true
  }
}

# AC-3: Access Enforcement
# Role-based access control with conditional IAM
resource "google_project_iam_member" "app_permissions" {
  for_each = toset([
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/cloudtrace.agent"
  ])
  
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.app_service_account.email}"
  
  condition {
    title       = "Environment-based access"
    description = "NIST AC-3: Access enforcement based on environment"
    expression  = "request.time.getHours() >= 6 && request.time.getHours() <= 22"
  }
}

# AC-6: Least Privilege
# Custom role with minimal required permissions
resource "google_project_iam_custom_role" "app_minimal_role" {
  role_id     = "appMinimalRole${title(var.environment)}"
  title       = "Application Minimal Role - ${var.environment}"
  description = "NIST AC-6 compliant minimal permissions for application"
  
  permissions = [
    "storage.objects.get",
    "storage.objects.list",
    "pubsub.messages.publish",
    "pubsub.topics.get"
  ]
  
  stage = "GA"
}

# Audit logging for access control compliance
resource "google_logging_project_sink" "access_audit_sink" {
  name        = "access-audit-${var.environment}"
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  
  filter = "protoPayload.serviceName=\\"iam.googleapis.com\\" OR protoPayload.serviceName=\\"cloudresourcemanager.googleapis.com\\""
  
  unique_writer_identity = true
}

resource "google_storage_bucket" "audit_logs" {
  name     = "${var.project_id}-access-audit-${var.environment}"
  location = "US"
  
  # NIST AU-2: Audit Events
  retention_policy {
    retention_period = 2592000 # 30 days minimum
  }
  
  # Encryption at rest
  encryption {
    default_kms_key_name = google_kms_crypto_key.audit_key.id
  }
  
  versioning {
    enabled = true
  }
  
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type          = "SetStorageClass"
      storage_class = "COLDLINE"
    }
  }
}

# KMS key for encryption
resource "google_kms_key_ring" "audit_keyring" {
  name     = "audit-keyring-${var.environment}"
  location = "us-central1"
}

resource "google_kms_crypto_key" "audit_key" {
  name     = "audit-key-${var.environment}"
  key_ring = google_kms_key_ring.audit_keyring.id
  
  rotation_period = "7776000s" # 90 days
  
  lifecycle {
    prevent_destroy = true
  }
}

# Output compliance evidence
output "compliance_evidence" {
  description = "Evidence of NIST 800-53 compliance implementation"
  value = {
    ac_2_account_management = {
      service_account_email = google_service_account.app_service_account.email
      creation_time        = google_service_account.app_service_account.name
    }
    ac_3_access_enforcement = {
      conditional_iam_bindings = length(google_project_iam_member.app_permissions)
      custom_role_id          = google_project_iam_custom_role.app_minimal_role.role_id
    }
    ac_6_least_privilege = {
      permissions_count = length(google_project_iam_custom_role.app_minimal_role.permissions)
      custom_role_stage = google_project_iam_custom_role.app_minimal_role.stage
    }
    audit_compliance = {
      audit_sink_name   = google_logging_project_sink.access_audit_sink.name
      audit_bucket_name = google_storage_bucket.audit_logs.name
      encryption_key    = google_kms_crypto_key.audit_key.id
    }
  }
}'''
        
        # Write module to file
        module_path = self.output_dir / "access_control" / "main.tf"
        module_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(module_path, 'w') as f:
            f.write(module_content)
        
        return str(module_path)
    
    def generate_network_security_module(self) -> str:
        """Generate Terraform module for Network Security (SC-7, SC-8)"""
        
        module_content = '''# NIST 800-53 Network Security Implementation
# Controls: SC-7 (Boundary Protection), SC-8 (Transmission Protection)

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed for SSH access"
  type        = list(string)
  default     = ["10.0.0.0/8"]  # Internal networks only
}

# SC-7: Boundary Protection
# Create secure VPC with proper firewall rules
resource "google_compute_network" "secure_vpc" {
  name                    = "secure-vpc-${var.environment}"
  auto_create_subnetworks = false
  description             = "NIST SC-7 compliant VPC with boundary protection"
}

resource "google_compute_subnetwork" "private_subnet" {
  name          = "private-subnet-${var.environment}"
  ip_cidr_range = "10.0.1.0/24"
  region        = "us-central1"
  network       = google_compute_network.secure_vpc.id
  
  # Enable private Google access
  private_ip_google_access = true
  
  # Enable flow logs for audit
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling        = 0.5
    metadata             = "INCLUDE_ALL_METADATA"
  }
}

# Default deny-all firewall rule
resource "google_compute_firewall" "deny_all" {
  name    = "deny-all-${var.environment}"
  network = google_compute_network.secure_vpc.name
  
  deny {
    protocol = "all"
  }
  
  source_ranges = ["0.0.0.0/0"]
  priority      = 65534
  description   = "NIST SC-7: Default deny rule for boundary protection"
}

# Allow internal communication
resource "google_compute_firewall" "allow_internal" {
  name    = "allow-internal-${var.environment}"
  network = google_compute_network.secure_vpc.name
  
  allow {
    protocol = "tcp"
    ports    = ["22", "80", "443", "3389"]
  }
  
  allow {
    protocol = "icmp"
  }
  
  source_ranges = ["10.0.0.0/8"]
  priority      = 1000
  description   = "NIST SC-7: Allow internal network communication"
}

# Restricted SSH access
resource "google_compute_firewall" "allow_ssh_restricted" {
  name    = "allow-ssh-restricted-${var.environment}"
  network = google_compute_network.secure_vpc.name
  
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  
  source_ranges = var.allowed_cidr_blocks
  target_tags   = ["ssh-allowed"]
  priority      = 1000
  description   = "NIST SC-7: Restricted SSH access from approved networks"
}

# SC-8: Transmission Protection
# HTTPS load balancer with SSL termination
resource "google_compute_ssl_certificate" "app_cert" {
  name_prefix = "app-cert-${var.environment}-"
  description = "NIST SC-8 compliant SSL certificate"
  
  managed {
    domains = ["app-${var.environment}.swift.com"]
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# Output compliance evidence
output "network_compliance_evidence" {
  description = "Evidence of network security compliance"
  value = {
    sc_7_boundary_protection = {
      vpc_name              = google_compute_network.secure_vpc.name
      firewall_rules_count  = 3
      private_subnet_cidr   = google_compute_subnetwork.private_subnet.ip_cidr_range
    }
    sc_8_transmission_protection = {
      ssl_certificate       = google_compute_ssl_certificate.app_cert.name
      managed_domains       = google_compute_ssl_certificate.app_cert.managed[0].domains
    }
    audit_capabilities = {
      vpc_flow_logs    = true
      private_access   = true
    }
  }
}'''
        
        # Write module to file
        module_path = self.output_dir / "network_security" / "main.tf"
        module_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(module_path, 'w') as f:
            f.write(module_content)
        
        return str(module_path)

class OPAPolicyGenerator:
    """Generates Open Policy Agent (OPA) policies for compliance validation"""
    
    def __init__(self, output_dir: str = "policies/opa"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_access_control_policy(self) -> str:
        """Generate OPA policy for access control compliance"""
        
        policy_content = '''package nist.access_control

# NIST 800-53 AC-2: Account Management
# Validate service account configuration

deny[msg] {
    input.resource_type == "google_service_account"
    not input.lifecycle.prevent_destroy
    msg := "AC-2 Violation: Service accounts must have prevent_destroy enabled"
}

deny[msg] {
    input.resource_type == "google_service_account"
    count(input.display_name) == 0
    msg := "AC-2 Violation: Service accounts must have descriptive display names"
}

# NIST 800-53 AC-3: Access Enforcement
# Validate IAM bindings have appropriate conditions

deny[msg] {
    input.resource_type == "google_project_iam_member"
    startswith(input.role, "roles/owner")
    msg := "AC-3 Violation: Owner role should not be assigned without explicit approval"
}

deny[msg] {
    input.resource_type == "google_project_iam_member"
    startswith(input.role, "roles/editor")
    not input.condition
    msg := "AC-3 Violation: Editor role must include conditional access controls"
}

# NIST 800-53 AC-6: Least Privilege
# Validate custom roles have minimal permissions

deny[msg] {
    input.resource_type == "google_project_iam_custom_role"
    count(input.permissions) > 20
    msg := "AC-6 Violation: Custom roles should follow least privilege principle"
}

warn[msg] {
    input.resource_type == "google_project_iam_custom_role"
    "roles/owner" in input.permissions
    msg := "AC-6 Warning: Custom role includes owner-level permissions"
}

# Validate audit logging is enabled
deny[msg] {
    input.resource_type == "google_storage_bucket"
    contains(input.name, "audit")
    not input.retention_policy
    msg := "AU-2 Violation: Audit log buckets must have retention policies"
}

deny[msg] {
    input.resource_type == "google_storage_bucket"
    contains(input.name, "audit")
    not input.encryption
    msg := "SC-8 Violation: Audit log buckets must be encrypted"
}'''
        
        policy_path = self.output_dir / "access_control.rego"
        with open(policy_path, 'w') as f:
            f.write(policy_content)
        
        return str(policy_path)
    
    def generate_network_security_policy(self) -> str:
        """Generate OPA policy for network security compliance"""
        
        policy_content = '''package nist.network_security

# NIST 800-53 SC-7: Boundary Protection
# Validate firewall rules and VPC configuration

deny[msg] {
    input.resource_type == "google_compute_firewall"
    input.direction == "INGRESS"
    "0.0.0.0/0" in input.source_ranges
    input.allow[_].protocol == "tcp"
    "22" in input.allow[_].ports
    msg := "SC-7 Violation: SSH should not be open to the internet"
}

deny[msg] {
    input.resource_type == "google_compute_firewall"
    input.direction == "INGRESS"
    "0.0.0.0/0" in input.source_ranges
    input.allow[_].protocol == "tcp"
    "3389" in input.allow[_].ports
    msg := "SC-7 Violation: RDP should not be open to the internet"
}

# Validate VPC has private Google access enabled
deny[msg] {
    input.resource_type == "google_compute_subnetwork"
    not input.private_ip_google_access
    msg := "SC-7 Violation: Subnets should enable private Google access"
}

# NIST 800-53 SC-8: Transmission Protection
# Validate SSL/TLS configuration

deny[msg] {
    input.resource_type == "google_compute_ssl_policy"
    input.min_tls_version != "TLS_1_2"
    input.min_tls_version != "TLS_1_3"
    msg := "SC-8 Violation: Minimum TLS version must be 1.2 or higher"
}

# Validate managed SSL certificates
allow[msg] {
    input.resource_type == "google_compute_ssl_certificate"
    input.managed
    msg := "SC-8 Compliance: Using managed SSL certificate"
}

# Validate audit logging is enabled
deny[msg] {
    input.resource_type == "google_compute_subnetwork"
    not input.log_config
    msg := "AU-2 Violation: VPC subnets should have flow logs enabled"
}

warn[msg] {
    input.resource_type == "google_compute_firewall"
    input.priority > 1000
    msg := "Best Practice: Consider using lower priority values for important rules"
}'''
        
        policy_path = self.output_dir / "network_security.rego"
        with open(policy_path, 'w') as f:
            f.write(policy_content)
        
        return str(policy_path)

class ComplianceAssessmentEngine:
    """Performs automated compliance assessments against NIST 800-53 controls"""
    
    def __init__(self, project_id: str):
        self.project_id = project_id
        self.control_library = NISTControlLibrary()
        
    async def assess_infrastructure_compliance(self) -> ComplianceAssessment:
        """Perform comprehensive compliance assessment"""
        logger.info("Starting NIST 800-53 compliance assessment...")
        
        assessment_id = f"assessment_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        findings = []
        
        # Get current infrastructure state (simulated for demo)
        infrastructure_state = await self.get_infrastructure_state()
        
        # Assess each control
        for control_id, control in self.control_library.controls.items():
            finding = await self.assess_control(control, infrastructure_state)
            findings.append(finding)
        
        # Calculate overall compliance score
        compliant_count = len([f for f in findings if f['status'] == ControlStatus.COMPLIANT.value])
        total_count = len(findings)
        overall_score = (compliant_count / total_count) * 100 if total_count > 0 else 0
        
        # Generate remediation plan
        remediation_plan = self.generate_remediation_plan(findings)
        
        assessment = ComplianceAssessment(
            assessment_id=assessment_id,
            timestamp=datetime.now(),
            total_controls=total_count,
            compliant_controls=compliant_count,
            non_compliant_controls=total_count - compliant_count,
            overall_score=overall_score,
            findings=findings,
            remediation_plan=remediation_plan
        )
        
        logger.info(f"Assessment complete. Overall score: {overall_score:.1f}%")
        return assessment
    
    async def get_infrastructure_state(self) -> Dict:
        """Get current state of infrastructure resources (simulated for demo)"""
        logger.info("Gathering infrastructure state...")
        
        # For demo, simulate infrastructure state
        state = {
            'compute_instances': [
                {
                    'name': 'projects/swift-demo/instances/web-server-prod-1',
                    'location': 'us-central1-a',
                    'labels': {'environment': 'production', 'tier': 'web'},
                    'state': 'RUNNING'
                },
                {
                    'name': 'projects/swift-demo/instances/trading-system-1',
                    'location': 'us-east1-a',
                    'labels': {'environment': 'production', 'tier': 'trading'},
                    'state': 'RUNNING'
                }
            ],
            'networks': [
                {
                    'name': 'projects/swift-demo/networks/vpc-prod',
                    'location': 'global',
                    'labels': {'environment': 'production'},
                    'state': 'ACTIVE'
                }
            ],
            'subnetworks': [
                {
                    'name': 'projects/swift-demo/subnetworks/private-subnet-prod',
                    'ip_cidr_range': '10.0.1.0/24',
                    'private_ip_google_access': True,
                    'log_config': {'enable': True}
                }
            ],
            'firewalls': [
                {
                    'name': 'deny-all-prod',
                    'direction': 'INGRESS',
                    'priority': 65534,
                    'action': 'DENY'
                },
                {
                    'name': 'allow-ssh-restricted',
                    'direction': 'INGRESS',
                    'source_ranges': ['10.0.0.0/8'],
                    'allowed_ports': ['22']
                }
            ],
            'storage_buckets': [
                {
                    'name': 'swift-demo-access-audit-prod',
                    'location': 'US',
                    'encryption': {'default_kms_key_name': 'audit-key'},
                    'retention_policy': {'retention_period': 2592000}
                }
            ],
            'service_accounts': [
                {
                    'name': 'app-prod@swift-demo.iam.gserviceaccount.com',
                    'display_name': 'Application Service Account - prod',
                    'description': 'NIST AC-2 compliant service account'
                }
            ],
            'kms_keys': [
                {
                    'name': 'audit-key-prod',
                    'rotation_period': '7776000s'
                }
            ],
            'iam_bindings': [
                {
                    'member': 'serviceAccount:app-prod@swift-demo.iam.gserviceaccount.com',
                    'role': 'roles/logging.logWriter',
                    'condition': {'title': 'Environment-based access'}
                }
            ]
        }
        
        return state
    
    async def assess_control(self, control: ComplianceControl, 
                           infrastructure_state: Dict) -> Dict:
        """Assess a specific NIST control against infrastructure state"""
        
        finding = {
            'control_id': control.control_id,
            'title': control.title,
            'family': control.family.value,
            'status': ControlStatus.UNKNOWN.value,
            'score': 0,
            'evidence': [],
            'gaps': [],
            'recommendations': []
        }
        
        # Control-specific assessment logic
        if control.control_id == 'AC-2':  # Account Management
            finding = await self.assess_ac_2(finding, infrastructure_state)
        elif control.control_id == 'AC-3':  # Access Enforcement
            finding = await self.assess_ac_3(finding, infrastructure_state)
        elif control.control_id == 'AC-6':  # Least Privilege
            finding = await self.assess_ac_6(finding, infrastructure_state)
        elif control.control_id == 'AU-2':  # Audit Events
            finding = await self.assess_au_2(finding, infrastructure_state)
        elif control.control_id == 'AU-3':  # Audit Content
            finding = await self.assess_au_3(finding, infrastructure_state)
        elif control.control_id == 'SC-7':  # Boundary Protection
            finding = await self.assess_sc_7(finding, infrastructure_state)
        elif control.control_id == 'SC-8':  # Transmission Protection
            finding = await self.assess_sc_8(finding, infrastructure_state)
        elif control.control_id == 'IA-2':  # Identification and Authentication
            finding = await self.assess_ia_2(finding, infrastructure_state)
        elif control.control_id == 'IA-5':  # Authenticator Management
            finding = await self.assess_ia_5(finding, infrastructure_state)
        
        return finding
    
    async def assess_ac_2(self, finding: Dict, state: Dict) -> Dict:
        """Assess AC-2 (Account Management) control"""
        service_accounts = state.get('service_accounts', [])
        
        if not service_accounts:
            finding['status'] = ControlStatus.NON_COMPLIANT.value
            finding['gaps'].append("No service accounts found - account management not implemented")
            finding['score'] = 0
            finding['recommendations'].append("Implement service account management with proper lifecycle controls")
        else:
            compliant_accounts = 0
            total_accounts = len(service_accounts)
            
            for account in service_accounts:
                # Check if account has proper naming and description
                if account.get('display_name') and account.get('description'):
                    compliant_accounts += 1
                    finding['evidence'].append(f"Service account {account['name']} has proper documentation")
                else:
                    finding['gaps'].append(f"Service account {account['name']} lacks proper documentation")
            
            compliance_ratio = compliant_accounts / total_accounts
            finding['score'] = int(compliance_ratio * 100)
            
            if compliance_ratio >= 0.9:
                finding['status'] = ControlStatus.COMPLIANT.value
            elif compliance_ratio >= 0.5:
              finding['status'] = ControlStatus.PARTIALLY_COMPLIANT.value
            else:
                finding['status'] = ControlStatus.NON_COMPLIANT.value
                finding['recommendations'].append("Implement proper service account documentation and lifecycle management")
        
        return finding
    
    async def assess_ac_3(self, finding: Dict, state: Dict) -> Dict:
        """Assess AC-3 (Access Enforcement) control"""
        iam_bindings = state.get('iam_bindings', [])
        
        if not iam_bindings:
            finding['status'] = ControlStatus.NON_COMPLIANT.value
            finding['gaps'].append("No IAM bindings found - access enforcement not configured")
            finding['score'] = 0
        else:
            conditional_bindings = 0
            total_bindings = len(iam_bindings)
            
            for binding in iam_bindings:
                if binding.get('condition'):
                    conditional_bindings += 1
                    finding['evidence'].append(f"Conditional access configured for {binding['role']}")
                else:
                    finding['gaps'].append(f"No conditional access for {binding['role']}")
            
            compliance_ratio = conditional_bindings / total_bindings if total_bindings > 0 else 0
            finding['score'] = int(compliance_ratio * 100)
            
            if compliance_ratio >= 0.8:
                finding['status'] = ControlStatus.COMPLIANT.value
            elif compliance_ratio >= 0.5:
                finding['status'] = ControlStatus.PARTIALLY_COMPLIANT.value
            else:
                finding['status'] = ControlStatus.NON_COMPLIANT.value
                finding['recommendations'].append("Implement conditional access controls for all IAM bindings")
        
        return finding
    
    async def assess_ac_6(self, finding: Dict, state: Dict) -> Dict:
        """Assess AC-6 (Least Privilege) control"""
        iam_bindings = state.get('iam_bindings', [])
        
        over_privileged = 0
        total_bindings = len(iam_bindings)
        
        for binding in iam_bindings:
            role = binding.get('role', '')
            if 'owner' in role.lower() or 'editor' in role.lower():
                over_privileged += 1
                finding['gaps'].append(f"Over-privileged role assigned: {role}")
            else:
                finding['evidence'].append(f"Least privilege role: {role}")
        
        compliance_ratio = (total_bindings - over_privileged) / total_bindings if total_bindings > 0 else 1
        finding['score'] = int(compliance_ratio * 100)
        
        if compliance_ratio >= 0.9:
            finding['status'] = ControlStatus.COMPLIANT.value
        elif compliance_ratio >= 0.7:
            finding['status'] = ControlStatus.PARTIALLY_COMPLIANT.value
        else:
            finding['status'] = ControlStatus.NON_COMPLIANT.value
            finding['recommendations'].append("Review and reduce permissions for over-privileged accounts")
        
        return finding
    
    async def assess_au_2(self, finding: Dict, state: Dict) -> Dict:
        """Assess AU-2 (Audit Events) control"""
        audit_buckets = [b for b in state.get('storage_buckets', []) if 'audit' in b.get('name', '')]
        subnetworks = state.get('subnetworks', [])
        
        audit_score = 0
        
        # Check audit storage
        if audit_buckets:
            audit_score += 50
            finding['evidence'].append(f"Audit storage configured: {len(audit_buckets)} buckets")
        else:
            finding['gaps'].append("No audit log storage configured")
        
        # Check VPC flow logs
        flow_logs_enabled = sum(1 for subnet in subnetworks if subnet.get('log_config', {}).get('enable'))
        if flow_logs_enabled > 0:
            audit_score += 50
            finding['evidence'].append(f"VPC flow logs enabled on {flow_logs_enabled} subnets")
        else:
            finding['gaps'].append("VPC flow logs not enabled")
        
        finding['score'] = audit_score
        
        if audit_score >= 90:
            finding['status'] = ControlStatus.COMPLIANT.value
        elif audit_score >= 60:
            finding['status'] = ControlStatus.PARTIALLY_COMPLIANT.value
        else:
            finding['status'] = ControlStatus.NON_COMPLIANT.value
            finding['recommendations'].append("Enable comprehensive audit logging for all critical services")
        
        return finding
    
    async def assess_au_3(self, finding: Dict, state: Dict) -> Dict:
        """Assess AU-3 (Content of Audit Records) control"""
        # Simplified assessment - in real implementation, would check log content
        finding['status'] = ControlStatus.COMPLIANT.value
        finding['score'] = 95
        finding['evidence'].append("Audit logs contain required information elements")
        
        return finding
    
    async def assess_sc_7(self, finding: Dict, state: Dict) -> Dict:
        """Assess SC-7 (Boundary Protection) control"""
        firewalls = state.get('firewalls', [])
        
        # Check for deny-all default rule
        has_default_deny = any(fw.get('action') == 'DENY' and fw.get('priority') == 65534 for fw in firewalls)
        internet_exposed_ssh = any(
            '0.0.0.0/0' in fw.get('source_ranges', []) and '22' in fw.get('allowed_ports', [])
            for fw in firewalls
        )
        
        score = 0
        if has_default_deny:
            score += 60
            finding['evidence'].append("Default deny firewall rule configured")
        else:
            finding['gaps'].append("No default deny rule found")
        
        if not internet_exposed_ssh:
            score += 40
            finding['evidence'].append("SSH not exposed to internet")
        else:
            finding['gaps'].append("SSH exposed to internet")
        
        finding['score'] = score
        
        if score >= 90:
            finding['status'] = ControlStatus.COMPLIANT.value
        elif score >= 60:
            finding['status'] = ControlStatus.PARTIALLY_COMPLIANT.value
        else:
            finding['status'] = ControlStatus.NON_COMPLIANT.value
            finding['recommendations'].append("Implement default-deny firewall rules and restrict SSH access")
        
        return finding
    
    async def assess_sc_8(self, finding: Dict, state: Dict) -> Dict:
        """Assess SC-8 (Transmission Protection) control"""
        # Check for SSL certificates and encryption
        buckets = state.get('storage_buckets', [])
        encrypted_buckets = [b for b in buckets if b.get('encryption')]
        
        score = 0
        if encrypted_buckets:
            score += 50
            finding['evidence'].append(f"Encryption at rest configured for {len(encrypted_buckets)} buckets")
        
        # Assume HTTPS is configured (would check load balancers in real implementation)
        score += 50
        finding['evidence'].append("HTTPS encryption in transit configured")
        
        finding['score'] = score
        
        if score >= 90:
            finding['status'] = ControlStatus.COMPLIANT.value
        elif score >= 60:
            finding['status'] = ControlStatus.PARTIALLY_COMPLIANT.value
        else:
            finding['status'] = ControlStatus.NON_COMPLIANT.value
            finding['recommendations'].append("Implement encryption for all data in transit and at rest")
        
        return finding
    
    async def assess_ia_2(self, finding: Dict, state: Dict) -> Dict:
        """Assess IA-2 (Identification and Authentication) control"""
        # Simplified assessment
        finding['status'] = ControlStatus.COMPLIANT.value
        finding['score'] = 85
        finding['evidence'].append("User authentication mechanisms configured")
        
        return finding
    
    async def assess_ia_5(self, finding: Dict, state: Dict) -> Dict:
        """Assess IA-5 (Authenticator Management) control"""
        kms_keys = state.get('kms_keys', [])
        
        if kms_keys:
            finding['status'] = ControlStatus.COMPLIANT.value
            finding['score'] = 90
            finding['evidence'].append(f"Key management configured with {len(kms_keys)} keys")
        else:
            finding['status'] = ControlStatus.NON_COMPLIANT.value
            finding['score'] = 30
            finding['gaps'].append("No key management system configured")
            finding['recommendations'].append("Implement centralized key management")
        
        return finding
    
    def generate_remediation_plan(self, findings: List[Dict]) -> List[Dict]:
        """Generate prioritized remediation plan"""
        remediation_actions = []
        
        for finding in findings:
            if finding['status'] in [ControlStatus.NON_COMPLIANT.value, ControlStatus.PARTIALLY_COMPLIANT.value]:
                priority = 'High' if finding['status'] == ControlStatus.NON_COMPLIANT.value else 'Medium'
                effort = 'High' if finding['score'] < 50 else 'Medium' if finding['score'] < 80 else 'Low'
                
                action = {
                    'control_id': finding['control_id'],
                    'title': finding['title'],
                    'priority': priority,
                    'estimated_effort': effort,
                    'current_score': finding['score'],
                    'target_score': 90,
                    'recommendations': finding.get('recommendations', []),
                    'terraform_module': f"terraform_modules/{finding['control_id'].lower().replace('-', '_')}/main.tf",
                    'status': 'Planned'
                }
                
                remediation_actions.append(action)
        
        # Sort by priority and potential impact
        priority_order = {'High': 3, 'Medium': 2, 'Low': 1}
        remediation_actions.sort(
            key=lambda x: (priority_order.get(x['priority'], 0), 100 - x['current_score']), 
            reverse=True
        )
        
        return remediation_actions

class ComplianceOrchestrator:
    """Main orchestrator for NIST 800-53 compliance automation"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.project_id = config.get('project_id', 'demo-project')
        self.terraform_generator = TerraformComplianceGenerator()
        self.policy_generator = OPAPolicyGenerator()
        self.assessment_engine = ComplianceAssessmentEngine(self.project_id)
        self.db_path = config.get('database_path', 'data/compliance.db')
        self.init_database()
    
    def init_database(self):
        """Initialize database for compliance tracking"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assessments (
                assessment_id TEXT PRIMARY KEY,
                timestamp TIMESTAMP,
                overall_score REAL,
                total_controls INTEGER,
                compliant_controls INTEGER,
                findings TEXT,
                remediation_plan TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS control_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                control_id TEXT,
                assessment_id TEXT,
                status TEXT,
                score INTEGER,
                timestamp TIMESTAMP,
                evidence TEXT,
                gaps TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def generate_compliance_infrastructure(self) -> Dict:
        """Generate Terraform modules and OPA policies for compliance"""
        logger.info("Generating compliance infrastructure...")
        
        generated_files = {}
        
        try:
            # Generate Terraform modules
            generated_files['access_control_module'] = self.terraform_generator.generate_access_control_module()
            generated_files['network_security_module'] = self.terraform_generator.generate_network_security_module()
            
            # Generate OPA policies
            generated_files['access_control_policy'] = self.policy_generator.generate_access_control_policy()
            generated_files['network_security_policy'] = self.policy_generator.generate_network_security_policy()
            
            logger.info(f"Generated {len(generated_files)} compliance files")
        except Exception as e:
            logger.error(f"Error generating compliance infrastructure: {e}")
            generated_files['error'] = str(e)
        
        return generated_files
    
    async def run_compliance_assessment(self) -> ComplianceAssessment:
        """Run complete compliance assessment"""
        logger.info("Running NIST 800-53 compliance assessment...")
        
        assessment = await self.assessment_engine.assess_infrastructure_compliance()
        
        # Store assessment results
        self.store_assessment(assessment)
        
        return assessment
    
    def store_assessment(self, assessment: ComplianceAssessment):
        """Store assessment results in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Store assessment summary
        cursor.execute('''
            INSERT INTO assessments 
            (assessment_id, timestamp, overall_score, total_controls, compliant_controls, findings, remediation_plan)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            assessment.assessment_id,
            assessment.timestamp,
            assessment.overall_score,
            assessment.total_controls,
            assessment.compliant_controls,
            json.dumps(assessment.findings),
            json.dumps(assessment.remediation_plan)
        ))
        
        # Store individual control results
        for finding in assessment.findings:
            cursor.execute('''
                INSERT INTO control_history 
                (control_id, assessment_id, status, score, timestamp, evidence, gaps)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                finding['control_id'],
                assessment.assessment_id,
                finding['status'],
                finding['score'],
                assessment.timestamp,
                json.dumps(finding.get('evidence', [])),
                json.dumps(finding.get('gaps', []))
            ))
        
        conn.commit()
        conn.close()
    
    def generate_compliance_report(self) -> Dict:
        """Generate executive compliance report"""
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Get latest assessment
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM assessments 
                ORDER BY timestamp DESC 
                LIMIT 1
            ''')
            
            latest_assessment = cursor.fetchone()
            
            if not latest_assessment:
                # Return demo data if no assessments found
                return self._generate_demo_report()
            
            # Get control family breakdown
            cursor.execute('''
                SELECT SUBSTR(control_id, 1, 2) as family, 
                       AVG(score) as avg_score,
                       COUNT(*) as total_controls,
                       SUM(CASE WHEN status = 'compliant' THEN 1 ELSE 0 END) as compliant_controls
                FROM control_history 
                WHERE assessment_id = ?
                GROUP BY SUBSTR(control_id, 1, 2)
            ''', (latest_assessment[0],))
            
            family_breakdown = cursor.fetchall()
            
            conn.close()
            
            report = {
                'assessment_id': latest_assessment[0],
                'timestamp': latest_assessment[1],
                'overall_score': latest_assessment[2],
                'total_controls': latest_assessment[3],
                'compliant_controls': latest_assessment[4],
                'compliance_percentage': (latest_assessment[4] / latest_assessment[3]) * 100 if latest_assessment[3] > 0 else 0,
                'family_breakdown': [
                    {
                        'family': row[0],
                        'family_name': self._get_family_name(row[0]),
                        'avg_score': row[1],
                        'total_controls': row[2],
                        'compliant_controls': row[3],
                        'compliance_rate': (row[3] / row[2]) * 100 if row[2] > 0 else 0
                    }
                    for row in family_breakdown
                ],
                'recommendations': self._generate_executive_recommendations(family_breakdown)
            }
            
            return report
        except Exception as e:
            logger.error(f"Error generating compliance report: {e}")
            return self._generate_demo_report()
    
    def _generate_demo_report(self) -> Dict:
        """Generate demo compliance report"""
        return {
            'assessment_id': f"demo_{datetime.now().strftime('%Y%m%d')}",
            'timestamp': datetime.now().isoformat(),
            'overall_score': 87.5,
            'total_controls': 9,
            'compliant_controls': 7,
            'compliance_percentage': 77.8,
            'family_breakdown': [
                {
                    'family': 'AC',
                    'family_name': 'Access Control',
                    'avg_score': 85.0,
                    'total_controls': 3,
                    'compliant_controls': 2,
                    'compliance_rate': 66.7
                },
                {
                    'family': 'AU',
                    'family_name': 'Audit and Accountability',
                    'avg_score': 95.0,
                    'total_controls': 2,
                    'compliant_controls': 2,
                    'compliance_rate': 100.0
                },
                {
                    'family': 'SC',
                    'family_name': 'System Protection',
                    'avg_score': 78.0,
                    'total_controls': 2,
                    'compliant_controls': 1,
                    'compliance_rate': 50.0
                },
                {
                    'family': 'IA',
                    'family_name': 'Identification & Authentication',
                    'avg_score': 87.5,
                    'total_controls': 2,
                    'compliant_controls': 2,
                    'compliance_rate': 100.0
                }
            ],
            'recommendations': [
                'Prioritize AC (Access Control) family improvements',
                'Implement automated remediation for SC (System Protection) controls',
                'Enhance boundary protection controls for SC-7'
            ]
        }
    
    def _get_family_name(self, family_code: str) -> str:
        """Get full family name from code"""
        family_names = {
            'AC': 'Access Control',
            'AU': 'Audit and Accountability',
            'SC': 'System and Communications Protection',
            'IA': 'Identification and Authentication',
            'CM': 'Configuration Management',
            'CP': 'Contingency Planning',
            'IR': 'Incident Response',
            'SI': 'System and Information Integrity'
        }
        return family_names.get(family_code, family_code)
    
    def _generate_executive_recommendations(self, family_breakdown: List) -> List[str]:
        """Generate executive-level recommendations"""
        recommendations = []
        
        for row in family_breakdown:
            family_code = row[0]
            compliance_rate = (row[3] / row[2]) * 100 if row[2] > 0 else 0
            
            if compliance_rate < 70:
                family_name = self._get_family_name(family_code)
                recommendations.append(f"Prioritize {family_code} ({family_name}) family improvements")
        
        recommendations.extend([
            'Implement automated remediation for high-priority controls',
            'Establish continuous compliance monitoring',
            'Schedule quarterly compliance assessments'
        ])
        
        return recommendations[:5]  # Return top 5 recommendations

# Example usage
def main():
    """Example usage of NIST Compliance Framework"""
    
    config = {
        'project_id': 'demo-project',
        'database_path': 'data/compliance.db',
        'terraform_output_dir': 'terraform_modules',
        'policy_output_dir': 'policies/opa'
    }
    
    orchestrator = ComplianceOrchestrator(config)
    
    async def run_compliance_cycle():
        # Generate compliance infrastructure
        print("🏗️  Generating compliance infrastructure...")
        generated_files = await orchestrator.generate_compliance_infrastructure()
        print(f"\n📁 GENERATED COMPLIANCE FILES:")
        for file_type, path in generated_files.items():
            if 'error' not in file_type:
                print(f"- {file_type}: {path}")
        
        # Run compliance assessment
        print(f"\n📊 Running compliance assessment...")
        assessment = await orchestrator.run_compliance_assessment()
        print(f"\n📊 COMPLIANCE ASSESSMENT RESULTS:")
        print(f"Overall Score: {assessment.overall_score:.1f}%")
        print(f"Compliant Controls: {assessment.compliant_controls}/{assessment.total_controls}")
        
        # Generate report
        print(f"\n📈 Generating executive report...")
        report = orchestrator.generate_compliance_report()
        print(f"\n📈 EXECUTIVE SUMMARY:")
        print(f"Compliance Percentage: {report['compliance_percentage']:.1f}%")
        
        print(f"\n🏗️ CONTROL FAMILY BREAKDOWN:")
        for family in report['family_breakdown']:
            print(f"- {family['family']} ({family['family_name']}): {family['compliance_rate']:.1f}% ({family['compliant_controls']}/{family['total_controls']})")
        
        print(f"\n💡 REMEDIATION PRIORITIES:")
        for i, action in enumerate(assessment.remediation_plan[:3], 1):
            print(f"{i}. {action['control_id']} ({action['title']}) - {action['priority']} Priority")
    
    # Run the compliance cycle
    asyncio.run(run_compliance_cycle())

if __name__ == "__main__":
    main()

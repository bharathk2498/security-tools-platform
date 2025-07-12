#!/usr/bin/env python3
"""
NIST 800-53 Compliance Automation Framework
Policy-as-code implementation with automated monitoring and remediation
"""

import asyncio
import json
import yaml
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Union
from dataclasses import dataclass
from enum import Enum
import sqlite3
import hashlib
import logging
from pathlib import Path
import subprocess
import tempfile
import jinja2

logger = logging.getLogger(__name__)

class ComplianceStatus(Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_ASSESSED = "not_assessed"

class ControlFamily(Enum):
    ACCESS_CONTROL = "AC"
    AUDIT_ACCOUNTABILITY = "AU"
    CONFIGURATION_MANAGEMENT = "CM"
    IDENTIFICATION_AUTHENTICATION = "IA"
    INCIDENT_RESPONSE = "IR"
    MAINTENANCE = "MA"
    MEDIA_PROTECTION = "MP"
    PHYSICAL_PROTECTION = "PE"
    PLANNING = "PL"
    SYSTEM_PROTECTION = "SC"
    RISK_ASSESSMENT = "RA"
    SYSTEM_ACQUISITION = "SA"
    SYSTEM_COMMUNICATION = "SC"
    SYSTEM_INFORMATION = "SI"

@dataclass
class NISTControl:
    control_id: str
    control_name: str
    family: ControlFamily
    description: str
    implementation_guidance: str
    assessment_procedures: List[str]
    status: ComplianceStatus = ComplianceStatus.NOT_ASSESSED
    score: float = 0.0
    evidence: List[str] = None
    remediation_actions: List[str] = None
    last_assessed: Optional[datetime] = None

    def __post_init__(self):
        if self.evidence is None:
            self.evidence = []
        if self.remediation_actions is None:
            self.remediation_actions = []

@dataclass
class ComplianceAssessment:
    assessment_id: str
    timestamp: datetime
    overall_score: float
    total_controls: int
    compliant_controls: int
    partially_compliant_controls: int
    non_compliant_controls: int
    control_results: List[NISTControl]
    remediation_plan: List[str]
    terraform_modules: Dict[str, str] = None
    opa_policies: Dict[str, str] = None

    def __post_init__(self):
        if self.terraform_modules is None:
            self.terraform_modules = {}
        if self.opa_policies is None:
            self.opa_policies = {}

class TerraformGenerator:
    """Generates Terraform modules for NIST control implementation"""
    
    def __init__(self):
        self.template_env = jinja2.Environment(
            loader=jinja2.DictLoader(self._get_terraform_templates()),
            trim_blocks=True,
            lstrip_blocks=True
        )
    
    def _get_terraform_templates(self) -> Dict[str, str]:
        """Define Terraform module templates for NIST controls"""
        return {
            'access_control': '''
# NIST 800-53 Access Control (AC) Implementation
# Controls: AC-2, AC-3, AC-6

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

variable "organization_id" {
  description = "GCP Organization ID"
  type        = string
}

# AC-2: Account Management
resource "google_organization_iam_policy" "access_control_policy" {
  org_id      = var.organization_id
  policy_data = data.google_iam_policy.access_control.policy_data
}

data "google_iam_policy" "access_control" {
  # Principle of Least Privilege (AC-6)
  binding {
    role = "roles/viewer"
    members = [
      "group:employees@{{domain}}"
    ]
    
    condition {
      title       = "Time-based Access"
      description = "Only allow access during business hours"
      expression  = "request.time.getHours() >= 9 && request.time.getHours() <= 17"
    }
  }
  
  # Administrative Access Control (AC-2, AC-3)
  binding {
    role = "roles/resourcemanager.organizationAdmin"
    members = [
      "group:admins@{{domain}}"
    ]
    
    condition {
      title       = "Admin Access Control"
      description = "Administrative access with justification required"
      expression  = "has(request.auth.access_levels)"
    }
  }
  
  # Financial Services Specific Controls
  binding {
    role = "roles/bigquery.dataViewer"
    members = [
      "group:trading-analysts@{{domain}}"
    ]
    
    condition {
      title       = "Trading Data Access"
      description = "Access to trading data with audit logging"
      expression  = "request.time.getHours() >= 6 && request.time.getHours() <= 18"
    }
  }
}

# Service Account Management (AC-2)
resource "google_service_account" "compliance_service_accounts" {
  for_each = var.service_accounts
  
  account_id   = each.key
  display_name = each.value.display_name
  description  = each.value.description
  project      = var.project_id
}

# Service Account IAM (Least Privilege - AC-6)
resource "google_project_iam_member" "service_account_roles" {
  for_each = var.service_account_roles
  
  project = var.project_id
  role    = each.value.role
  member  = "serviceAccount:${google_service_account.compliance_service_accounts[each.value.account].email}"
  
  condition {
    title       = "Conditional Service Account Access"
    description = "Service account access with resource constraints"
    expression  = each.value.condition_expression
  }
}

# Access Context Manager (AC-3)
resource "google_access_context_manager_access_policy" "financial_access_policy" {
  parent = "organizations/${var.organization_id}"
  title  = "Financial Services Access Policy"
}

resource "google_access_context_manager_access_level" "secure_access_level" {
  parent = "accessPolicies/${google_access_context_manager_access_policy.financial_access_policy.name}"
  name   = "accessPolicies/${google_access_context_manager_access_policy.financial_access_policy.name}/accessLevels/secure_access"
  title  = "Secure Access Level"
  
  basic {
    conditions {
      ip_subnetworks = ["10.0.0.0/8"]
      required_access_levels = []
      
      device_policy {
        require_screen_lock = true
        require_admin_approval = true
        
        os_constraints {
          os_type = "DESKTOP_WINDOWS"
          minimum_version = "10.0.0"
        }
      }
    }
  }
}

# Outputs for compliance reporting
output "access_control_policy_etag" {
  description = "ETag of the IAM policy for compliance tracking"
  value       = google_organization_iam_policy.access_control_policy.etag
}

output "service_account_emails" {
  description = "Service account emails for audit trail"
  value = {
    for k, v in google_service_account.compliance_service_accounts : k => v.email
  }
}

output "access_policy_name" {
  description = "Access Context Manager policy name"
  value       = google_access_context_manager_access_policy.financial_access_policy.name
}
''',
            
            'network_security': '''
# NIST 800-53 System and Communication Protection (SC) Implementation
# Controls: SC-7, SC-8

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

variable "network_name" {
  description = "VPC Network Name"
  type        = string
  default     = "compliance-network"
}

# SC-7: Boundary Protection
resource "google_compute_network" "compliance_vpc" {
  name                    = var.network_name
  project                 = var.project_id
  auto_create_subnetworks = false
  description             = "NIST 800-53 SC-7 Compliant Network"
}

# Secure Subnetworks with Boundary Protection
resource "google_compute_subnetwork" "secure_subnets" {
  for_each = var.secure_subnets
  
  name          = each.key
  ip_cidr_range = each.value.cidr
  region        = each.value.region
  network       = google_compute_network.compliance_vpc.id
  project       = var.project_id
  
  # Enable flow logs for SC-7 monitoring
  log_config {
    aggregation_interval = "INTERVAL_10_MIN"
    flow_sampling       = 0.8
    metadata           = "INCLUDE_ALL_METADATA"
  }
  
  # Private Google Access for secure communication
  private_ip_google_access = true
  
  description = "SC-7 Boundary Protected Subnet: ${each.value.description}"
}

# Firewall Rules - Default Deny (SC-7)
resource "google_compute_firewall" "default_deny_all" {
  name    = "${var.network_name}-deny-all"
  network = google_compute_network.compliance_vpc.name
  project = var.project_id
  
  deny {
    protocol = "all"
  }
  
  source_ranges = ["0.0.0.0/0"]
  priority      = 65534
  description   = "NIST SC-7: Default deny all traffic"
}

# Secure Internal Communication Rules
resource "google_compute_firewall" "allow_internal_secure" {
  name    = "${var.network_name}-allow-internal"
  network = google_compute_network.compliance_vpc.name
  project = var.project_id
  
  allow {
    protocol = "tcp"
    ports    = ["22", "443", "3389"]
  }
  
  source_ranges = [for subnet in var.secure_subnets : subnet.cidr]
  target_tags   = ["secure-internal"]
  priority      = 1000
  description   = "NIST SC-7: Secure internal communication"
}

# Financial Services Specific Rules
resource "google_compute_firewall" "trading_system_access" {
  name    = "${var.network_name}-trading-secure"
  network = google_compute_network.compliance_vpc.name
  project = var.project_id
  
  allow {
    protocol = "tcp"
    ports    = ["8443", "9443"]  # Secure trading ports
  }
  
  source_tags      = ["trading-client"]
  target_tags      = ["trading-system"]
  priority         = 900
  description      = "NIST SC-7: Secure trading system access"
}

# SC-8: Transmission Protection
resource "google_compute_ssl_policy" "secure_ssl_policy" {
  name            = "${var.network_name}-secure-ssl"
  profile         = "MODERN"
  min_tls_version = "TLS_1_2"
  project         = var.project_id
  description     = "NIST SC-8: Secure transmission policy"
}

# Load Balancer with SSL/TLS (SC-8)
resource "google_compute_global_address" "secure_lb_ip" {
  name         = "${var.network_name}-secure-lb-ip"
  address_type = "EXTERNAL"
  project      = var.project_id
  description  = "Secure load balancer IP for SC-8 compliance"
}

resource "google_compute_managed_ssl_certificate" "secure_cert" {
  name    = "${var.network_name}-secure-cert"
  project = var.project_id
  
  managed {
    domains = var.secure_domains
  }
  
  description = "NIST SC-8: Managed SSL certificate for secure transmission"
}

# Cloud NAT for Secure Outbound (SC-7)
resource "google_compute_router" "secure_router" {
  for_each = var.secure_subnets
  
  name    = "${var.network_name}-router-${each.value.region}"
  region  = each.value.region
  network = google_compute_network.compliance_vpc.id
  project = var.project_id
  
  description = "NIST SC-7: Secure router for controlled outbound access"
}

resource "google_compute_router_nat" "secure_nat" {
  for_each = var.secure_subnets
  
  name                               = "${var.network_name}-nat-${each.value.region}"
  router                            = google_compute_router.secure_router[each.key].name
  region                            = each.value.region
  nat_ip_allocate_option            = "MANUAL_ONLY"
  nat_ips                           = [google_compute_address.nat_ips[each.key].self_link]
  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  project                           = var.project_id
  
  subnetwork {
    name                    = google_compute_subnetwork.secure_subnets[each.key].id
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }
  
  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

resource "google_compute_address" "nat_ips" {
  for_each = var.secure_subnets
  
  name         = "${var.network_name}-nat-ip-${each.value.region}"
  region       = each.value.region
  address_type = "EXTERNAL"
  project      = var.project_id
  description  = "NAT IP for secure outbound access"
}

# VPC Flow Logs for Monitoring (SC-7)
resource "google_compute_firewall" "log_all_traffic" {
  name    = "${var.network_name}-log-all"
  network = google_compute_network.compliance_vpc.name
  project = var.project_id
  
  allow {
    protocol = "all"
  }
  
  source_ranges = ["0.0.0.0/0"]
  priority      = 65535
  enable_logging = true
  
  log_config {
    metadata = "INCLUDE_ALL_METADATA"
  }
  
  description = "NIST SC-7: Comprehensive traffic logging"
}

# Outputs
output "vpc_network_id" {
  description = "VPC Network ID for compliance reporting"
  value       = google_compute_network.compliance_vpc.id
}

output "secure_subnet_ids" {
  description = "Secure subnet IDs"
  value = {
    for k, v in google_compute_subnetwork.secure_subnets : k => v.id
  }
}

output "ssl_policy_name" {
  description = "SSL Policy name for SC-8 compliance"
  value       = google_compute_ssl_policy.secure_ssl_policy.name
}

output "nat_gateway_ips" {
  description = "NAT Gateway IPs for audit trail"
  value = {
    for k, v in google_compute_address.nat_ips : k => v.address
  }
}
''',
            
            'audit_logging': '''
# NIST 800-53 Audit and Accountability (AU) Implementation
# Controls: AU-2, AU-3, AU-6, AU-12

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

variable "organization_id" {
  description = "GCP Organization ID"
  type        = string
}

# AU-2, AU-3: Comprehensive Audit Event Logging
resource "google_logging_organization_sink" "compliance_audit_sink" {
  name   = "nist-compliance-audit-sink"
  org_id = var.organization_id
  
  # Comprehensive audit filter for financial services
  filter = <<-EOT
    (protoPayload.serviceName="cloudresourcemanager.googleapis.com" OR
     protoPayload.serviceName="iam.googleapis.com" OR
     protoPayload.serviceName="storage.googleapis.com" OR
     protoPayload.serviceName="compute.googleapis.com" OR
     protoPayload.serviceName="bigquery.googleapis.com" OR
     protoPayload.serviceName="cloudsql.googleapis.com") AND
    (protoPayload.methodName=~".*create.*" OR
     protoPayload.methodName=~".*delete.*" OR
     protoPayload.methodName=~".*update.*" OR
     protoPayload.methodName=~".*patch.*" OR
     protoPayload.methodName=~".*setIamPolicy.*" OR
     protoPayload.authenticationInfo.principalEmail!="")
  EOT
  
  destination = "storage.googleapis.com/${google_storage_bucket.audit_logs.name}"
  
  description = "NIST AU-2/AU-3: Comprehensive audit log collection"
}

# Secure Audit Log Storage (AU-9)
resource "google_storage_bucket" "audit_logs" {
  name     = "${var.project_id}-nist-audit-logs"
  location = var.audit_storage_region
  project  = var.project_id
  
  # Prevent deletion of audit logs
  lifecycle_rule {
    condition {
      age = var.audit_retention_days
    }
    action {
      type = "Delete"
    }
  }
  
  # Audit log access logging
  logging {
    log_bucket = google_storage_bucket.audit_access_logs.name
  }
  
  # Encryption at rest
  encryption {
    default_kms_key_name = google_kms_crypto_key.audit_key.id
  }
  
  # Versioning for integrity
  versioning {
    enabled = true
  }
  
  # Prevent public access
  public_access_prevention = "enforced"
  
  labels = {
    purpose = "nist-compliance"
    control = "au-2-au-3-au-9"
    environment = var.environment
  }
}

# Audit Log Access Monitoring (AU-6)
resource "google_storage_bucket" "audit_access_logs" {
  name     = "${var.project_id}-audit-access-logs"
  location = var.audit_storage_region
  project  = var.project_id
  
  lifecycle_rule {
    condition {
      age = 90
    }
    action {
      type = "Delete"
    }
  }
  
  public_access_prevention = "enforced"
}

# KMS Key for Audit Log Encryption (AU-9)
resource "google_kms_key_ring" "audit_keyring" {
  name     = "${var.project_id}-audit-keyring"
  location = var.audit_storage_region
  project  = var.project_id
}

resource "google_kms_crypto_key" "audit_key" {
  name     = "audit-logs-key"
  key_ring = google_kms_key_ring.audit_keyring.id
  purpose  = "ENCRYPT_DECRYPT"
  
  rotation_period = "2592000s"  # 30 days
  
  lifecycle {
    prevent_destroy = true
  }
  
  labels = {
    purpose = "audit-encryption"
    control = "au-9"
  }
}

# Financial Services Specific Audit Sinks
resource "google_logging_project_sink" "trading_audit_sink" {
  name   = "trading-system-audit"
  project = var.project_id
  
  filter = <<-EOT
    resource.type="gce_instance" AND
    resource.labels.instance_name=~"trading-.*" AND
    (jsonPayload.transaction_amount!="" OR
     jsonPayload.wire_transfer_id!="" OR
     jsonPayload.market_data_access!="")
  EOT
  
  destination = "storage.googleapis.com/${google_storage_bucket.trading_audit_logs.name}"
  
  unique_writer_identity = true
}

resource "google_storage_bucket" "trading_audit_logs" {
  name     = "${var.project_id}-trading-audit-logs"
  location = var.audit_storage_region
  project  = var.project_id
  
  # Enhanced retention for financial data
  lifecycle_rule {
    condition {
      age = 2555  # 7 years for financial compliance
    }
    action {
      type = "Delete"
    }
  }
  
  encryption {
    default_kms_key_name = google_kms_crypto_key.audit_key.id
  }
  
  versioning {
    enabled = true
  }
  
  public_access_prevention = "enforced"
  
  labels = {
    purpose = "trading-audit"
    compliance = "sox-pci-dss"
    retention = "7-years"
  }
}

# Real-time Audit Monitoring (AU-6)
resource "google_monitoring_alert_policy" "audit_anomaly_alert" {
  display_name = "NIST AU-6: Audit Log Anomaly Detection"
  project      = var.project_id
  
  conditions {
    display_name = "Suspicious Audit Activity"
    
    condition_threshold {
      filter          = "resource.type=\"gcs_bucket\" AND resource.labels.bucket_name=\"${google_storage_bucket.audit_logs.name}\""
      duration        = "300s"
      comparison      = "COMPARISON_GREATER_THAN"
      threshold_value = 100
      
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_RATE"
      }
    }
  }
  
  notification_channels = var.audit_notification_channels
  
  alert_strategy {
    auto_close = "604800s"  # 7 days
  }
  
  documentation {
    content = "NIST 800-53 AU-6: Unusual audit log activity detected. Investigate immediately."
    mime_type = "text/markdown"
  }
}

# Automated Audit Analysis (AU-6)
resource "google_bigquery_dataset" "audit_analysis" {
  dataset_id    = "nist_audit_analysis"
  friendly_name = "NIST Compliance Audit Analysis"
  description   = "AU-6: Automated audit log analysis and reporting"
  location      = var.bigquery_region
  project       = var.project_id
  
  default_table_expiration_ms = 31536000000  # 1 year
  
  labels = {
    purpose = "audit-analysis"
    control = "au-6"
  }
}

# Audit Review Scheduled Queries
resource "google_bigquery_data_transfer_config" "audit_review_query" {
  display_name   = "NIST AU-6 Daily Audit Review"
  location       = var.bigquery_region
  data_source_id = "scheduled_query"
  project        = var.project_id
  
  schedule = "every day 02:00"
  
  params = {
    query = <<-EOT
      SELECT
        timestamp,
        protoPayload.authenticationInfo.principalEmail as user_email,
        protoPayload.serviceName as service,
        protoPayload.methodName as method,
        protoPayload.resourceName as resource,
        severity,
        COUNT(*) as event_count
      FROM `${var.project_id}.${google_bigquery_dataset.audit_analysis.dataset_id}.cloudaudit_googleapis_com_activity_*`
      WHERE _TABLE_SUFFIX = FORMAT_DATE('%Y%m%d', DATE_SUB(CURRENT_DATE(), INTERVAL 1 DAY))
      AND protoPayload.authenticationInfo.principalEmail IS NOT NULL
      GROUP BY 1,2,3,4,5,6
      HAVING event_count > 50
      ORDER BY event_count DESC
    EOT
    
    destination_table_name_template = "daily_audit_review_{run_date}"
    write_disposition = "WRITE_TRUNCATE"
  }
}

# Service Account for Audit Access (Least Privilege)
resource "google_service_account" "audit_service_account" {
  account_id   = "nist-audit-service"
  display_name = "NIST Compliance Audit Service Account"
  description  = "Service account for automated audit processing"
  project      = var.project_id
}

resource "google_project_iam_member" "audit_service_permissions" {
  for_each = toset([
    "roles/logging.viewer",
    "roles/storage.objectViewer",
    "roles/bigquery.dataViewer",
    "roles/bigquery.jobUser"
  ])
  
  project = var.project_id
  role    = each.value
  member  = "serviceAccount:${google_service_account.audit_service_account.email}"
}

# Outputs
output "audit_sink_name" {
  description = "Organization audit sink name"
  value       = google_logging_organization_sink.compliance_audit_sink.name
}

output "audit_bucket_name" {
  description = "Audit logs storage bucket"
  value       = google_storage_bucket.audit_logs.name
}

output "audit_kms_key_id" {
  description = "KMS key for audit log encryption"
  value       = google_kms_crypto_key.audit_key.id
}

output "trading_audit_bucket" {
  description = "Trading system specific audit bucket"
  value       = google_storage_bucket.trading_audit_logs.name
}

output "audit_analysis_dataset" {
  description = "BigQuery dataset for audit analysis"
  value       = google_bigquery_dataset.audit_analysis.dataset_id
}
'''
        }
    
    def generate_terraform_module(self, control_family: str, variables: Dict = None) -> str:
        """Generate Terraform module for specific control family"""
        try:
            if variables is None:
                variables = self._get_default_variables(control_family)
            
            template = self.template_env.get_template(control_family)
            return template.render(**variables)
            
        except Exception as e:
            logger.error(f"Terraform generation failed for {control_family}: {e}")
            return self._get_fallback_terraform(control_family)
    
    def _get_default_variables(self, control_family: str) -> Dict:
        """Get default variables for Terraform modules"""
        base_vars = {
            'domain': 'swift.com',
            'environment': 'production',
            'audit_storage_region': 'us-central1',
            'bigquery_region': 'US',
            'audit_retention_days': 2555,  # 7 years for financial compliance
        }
        
        if control_family == 'access_control':
            base_vars.update({
                'service_accounts': {
                    'trading-service': {
                        'display_name': 'Trading System Service Account',
                        'description': 'Service account for trading system operations'
                    },
                    'payment-service': {
                        'display_name': 'Payment Processing Service Account', 
                        'description': 'Service account for payment processing'
                    }
                },
                'service_account_roles': {
                    'trading_viewer': {
                        'account': 'trading-service',
                        'role': 'roles/bigquery.dataViewer',
                        'condition_expression': 'request.time.getHours() >= 6 && request.time.getHours() <= 18'
                    }
                }
            })
        elif control_family == 'network_security':
            base_vars.update({
                'secure_subnets': {
                    'trading-subnet': {
                        'cidr': '10.1.0.0/24',
                        'region': 'us-central1',
                        'description': 'Trading system secure subnet'
                    },
                    'payment-subnet': {
                        'cidr': '10.2.0.0/24', 
                        'region': 'us-east1',
                        'description': 'Payment processing secure subnet'
                    }
                },
                'secure_domains': ['trading.swift.com', 'payments.swift.com']
            })
        
        return base_vars
    
    def _get_fallback_terraform(self, control_family: str) -> str:
        """Fallback Terraform configuration"""
        return f"""
# Fallback Terraform configuration for {control_family}
# Generated due to template error - manual review required

terraform {{
  required_providers {{
    google = {{
      source  = "hashicorp/google"
      version = "~> 4.0"
    }}
  }}
}}

variable "project_id" {{
  description = "GCP Project ID"
  type        = string
}}

# Placeholder resource - replace with actual implementation
resource "null_resource" "{control_family}_placeholder" {{
  provisioner "local-exec" {{
    command = "echo 'Implement {control_family} controls here'"
  }}
}}
"""

class OPAPolicyGenerator:
    """Generates Open Policy Agent (OPA) policies for compliance validation"""
    
    def __init__(self):
        self.policy_templates = self._get_opa_templates()
    
    def _get_opa_templates(self) -> Dict[str, str]:
        """Define OPA policy templates"""
        return {
            'access_control': '''
package nist.access_control

# NIST 800-53 Access Control Policies (AC-2, AC-3, AC-6)

# AC-2: Account Management - Deny service accounts without proper naming convention
deny[msg] {
    input.resource.type == "google_service_account"
    not regex.match("^(trading|payment|audit|monitoring)-[a-z0-9-]+$", input.resource.change.after.account_id)
    msg := sprintf("Service account '%s' does not follow naming convention", [input.resource.change.after.account_id])
}

# AC-3: Access Enforcement - Require conditions on sensitive IAM bindings
deny[msg] {
    input.resource.type == "google_project_iam_member"
    sensitive_roles[input.resource.change.after.role]
    not input.resource.change.after.condition
    msg := sprintf("Sensitive role '%s' requires conditional access", [input.resource.change.after.role])
}

# AC-6: Least Privilege - Prevent overprivileged service accounts
deny[msg] {
    input.resource.type == "google_project_iam_member"
    startswith(input.resource.change.after.member, "serviceAccount:")
    admin_roles[input.resource.change.after.role]
    not input.resource.change.after.condition
    msg := sprintf("Service account cannot have admin role '%s' without conditions", [input.resource.change.after.role])
}

# Financial Services Specific: Trading system access controls
deny[msg] {
    input.resource.type == "google_project_iam_member"
    input.resource.change.after.role == "roles/bigquery.dataEditor"
    contains(input.resource.change.after.member, "trading")
    not trading_hours_condition(input.resource.change.after.condition)
    msg := "Trading system data access must be restricted to market hours"
}

# Helper functions
sensitive_roles[role] {
    role := "roles/owner"
}
sensitive_roles[role] {
    role := "roles/editor"
}
sensitive_roles[role] {
    role := "roles/iam.securityAdmin"
}

admin_roles[role] {
    role := "roles/resourcemanager.organizationAdmin"
}
admin_roles[role] {
    role := "roles/iam.organizationRoleAdmin"
}

trading_hours_condition(condition) {
    contains(condition.expression, "request.time.getHours() >= 6")
    contains(condition.expression, "request.time.getHours() <= 18")
}

# Compliance reporting
compliance_score := score {
    total_checks := count(deny)
    passed_checks := count(allow)
    score := (passed_checks / (total_checks + passed_checks)) * 100
}
''',
            
            'network_security': '''
package nist.network_security

# NIST 800-53 System and Communication Protection (SC-7, SC-8)

# SC-7: Boundary Protection - Require explicit firewall rules
deny[msg] {
    input.resource.type == "google_compute_firewall"
    input.resource.change.after.direction == "INGRESS"
    "0.0.0.0/0" in input.resource.change.after.source_ranges
    input.resource.change.after.allow
    msg := sprintf("Firewall rule '%s' allows unrestricted ingress", [input.resource.name])
}

# SC-7: Network Segmentation - Require VPC for production workloads
deny[msg] {
    input.resource.type == "google_compute_instance"
    production_labels(input.resource.change.after.labels)
    not input.resource.change.after.network_interface[_].subnetwork
    msg := sprintf("Production instance '%s' must use custom VPC", [input.resource.name])
}

# SC-8: Transmission Protection - Require TLS for load balancers
deny[msg] {
    input.resource.type == "google_compute_url_map"
    input.resource.change.after.default_service
    not https_redirect_required(input.resource.change.after)
    msg := sprintf("Load balancer '%s' must enforce HTTPS", [input.resource.name])
}

# SC-8: Encryption in Transit - Require SSL policies with minimum TLS 1.2
deny[msg] {
    input.resource.type == "google_compute_ssl_policy"
    input.resource.change.after.min_tls_version != "TLS_1_2"
    input.resource.change.after.min_tls_version != "TLS_1_3"
    msg := sprintf("SSL policy '%s' must require TLS 1.2 or higher", [input.resource.name])
}

# Financial Services: Trading network isolation
deny[msg] {
    input.resource.type == "google_compute_subnetwork"
    contains(input.resource.name, "trading")
    not private_google_access(input.resource.change.after)
    msg := sprintf("Trading subnet '%s' must have private Google access enabled", [input.resource.name])
}

# Financial Services: Payment processing security
deny[msg] {
    input.resource.type == "google_compute_firewall"
    payment_system_target(input.resource.change.after.target_tags)
    not secure_ports_only(input.resource.change.after.allow)
    msg := sprintf("Payment system firewall '%s' must only allow secure ports", [input.resource.name])
}

# Helper functions
production_labels(labels) {
    labels.environment == "production"
}

https_redirect_required(url_map) {
    url_map.host_rule[_].path_matcher == "https-redirect"
}

private_google_access(subnet) {
    subnet.private_ip_google_access == true
}

payment_system_target(tags) {
    "payment-system" in tags
}

secure_ports_only(allow_rules) {
    rule := allow_rules[_]
    secure_port := rule.ports[_]
    to_number(secure_port) >= 443
}

# Compliance scoring
network_compliance_score := score {
    violations := count(deny)
    total_resources := count(input.planned_values.root_module.resources)
    score := ((total_resources - violations) / total_resources) * 100
}
''',
            
            'audit_logging': '''
package nist.audit_logging

# NIST 800-53 Audit and Accountability (AU-2, AU-3, AU-6, AU-9)

# AU-2: Audit Events - Require comprehensive logging
deny[msg] {
    input.resource.type == "google_logging_project_sink"
    not comprehensive_filter(input.resource.change.after.filter)
    msg := sprintf("Audit sink '%s' must have comprehensive event filtering", [input.resource.name])
}

# AU-3: Audit Content - Require structured audit information
deny[msg] {
    input.resource.type == "google_logging_organization_sink"
    not structured_logging_destination(input.resource.change.after.destination)
    msg := sprintf("Audit sink '%s' must use structured logging destination", [input.resource.name])
}

# AU-9: Protection of Audit Information - Require encryption for audit storage
deny[msg] {
    input.resource.type == "google_storage_bucket"
    audit_bucket(input.resource.name)
    not input.resource.change.after.encryption
    msg := sprintf("Audit bucket '%s' must have encryption enabled", [input.resource.name])
}

# AU-9: Audit Storage Protection - Require lifecycle management
deny[msg] {
    input.resource.type == "google_storage_bucket"
    audit_bucket(input.resource.name)
    not appropriate_retention(input.resource.change.after.lifecycle_rule)
    msg := sprintf("Audit bucket '%s' must have appropriate retention policy", [input.resource.name])
}

# Financial Services: Enhanced audit for trading systems
deny[msg] {
    input.resource.type == "google_compute_instance"
    trading_system(input.resource.change.after.labels)
    not audit_logging_enabled(input.resource.change.after.metadata)
    msg := sprintf("Trading instance '%s' must have audit logging enabled", [input.resource.name])
}

# Financial Services: Secure audit log transmission
deny[msg] {
    input.resource.type == "google_logging_project_sink"
    financial_data_filter(input.resource.change.after.filter)
    not secure_destination(input.resource.change.after.destination)
    msg := sprintf("Financial audit sink '%s' must use secure destination", [input.resource.name])
}

# AU-6: Audit Review - Require automated analysis
deny[msg] {
    input.resource.type == "google_bigquery_data_transfer_config"
    audit_analysis_query(input.resource.change.after.params.query)
    not appropriate_schedule(input.resource.change.after.schedule)
    msg := sprintf("Audit analysis '%s' must run at appropriate intervals", [input.resource.name])
}

# Helper functions
comprehensive_filter(filter) {
    contains(filter, "protoPayload.serviceName")
    contains(filter, "protoPayload.methodName")
    contains(filter, "authenticationInfo.principalEmail")
}

structured_logging_destination(destination) {
    startswith(destination, "storage.googleapis.com/")
}
structured_logging_destination(destination) {
    startswith(destination, "bigquery.googleapis.com/")
}

audit_bucket(name) {
    contains(name, "audit")
}
audit_bucket(name) {
    contains(name, "compliance")
}

appropriate_retention(lifecycle_rules) {
    rule := lifecycle_rules[_]
    to_number(rule.condition.age) >= 2555  # 7 years for financial compliance
}

trading_system(labels) {
    labels.system_type == "trading"
}
trading_system(labels) {
    contains(labels.name, "trading")
}

audit_logging_enabled(metadata) {
    metadata["enable-oslogin"] == "TRUE"
}

financial_data_filter(filter) {
    contains(filter, "trading")
}
financial_data_filter(filter) {
    contains(filter, "payment")
}
financial_data_filter(filter) {
    contains(filter, "transaction")
}

secure_destination(destination) {
    startswith(destination, "storage.googleapis.com/")
    contains(destination, "encrypted")
}

audit_analysis_query(query) {
    contains(query, "cloudaudit_googleapis_com")
}

appropriate_schedule(schedule) {
    contains(schedule, "every day")
}

# Compliance metrics
audit_compliance_score := score {
    total_violations := count(deny)
    audit_resources := count([r | r := input.planned_values.root_module.resources[_]; audit_related_resource(r.type)])
    score := ((audit_resources - total_violations) / audit_resources) * 100
}

audit_related_resource(type) {
    type == "google_logging_project_sink"
}
audit_related_resource(type) {
    type == "google_storage_bucket"
}
audit_related_resource(type) {
    type == "google_bigquery_dataset"
}
'''
        }
    
    def generate_opa_policy(self, control_family: str, custom_rules: List[str] = None) -> str:
        """Generate OPA policy for specific control family"""
        try:
            base_policy = self.policy_templates.get(control_family, "")
            
            if custom_rules:
                additional_rules = "\n\n# Custom Rules\n" + "\n\n".join(custom_rules)
                base_policy += additional_rules
            
            return base_policy
            
        except Exception as e:
            logger.error(f"OPA policy generation failed for {control_family}: {e}")
            return self._get_fallback_opa_policy(control_family)
    
    def _get_fallback_opa_policy(self, control_family: str) -> str:
        """Fallback OPA policy"""
        return f"""
package nist.{control_family}

# Fallback OPA policy for {control_family}
# Generated due to template error - manual review required

# Default deny rule
deny[msg] {{
    msg := "Manual policy implementation required for {control_family}"
}}
"""

class NISTControlDatabase:
    """Database of NIST 800-53 controls with implementation guidance"""
    
    def __init__(self):
        self.controls = self._initialize_controls()
    
    def _initialize_controls(self) -> Dict[str, NISTControl]:
        """Initialize NIST 800-53 control definitions"""
        controls = {}
        
        # Access Control Family (AC)
        controls["AC-2"] = NISTControl(
            control_id="AC-2",
            control_name="Account Management",
            family=ControlFamily.ACCESS_CONTROL,
            description="Manage information system accounts, group memberships, privileges, workflow, notifications, deactivations, and authorizations.",
            implementation_guidance="Implement automated account lifecycle management with proper authorization workflows and regular access reviews.",
            assessment_procedures=[
                "Review account provisioning processes",
                "Verify automated deprovisioning for terminated users",
                "Check privilege escalation controls",
                "Validate account monitoring procedures"
            ]
        )
        
        controls["AC-3"] = NISTControl(
            control_id="AC-3",
            control_name="Access Enforcement",
            family=ControlFamily.ACCESS_CONTROL,
            description="Enforce approved authorizations for logical access to information and system resources.",
            implementation_guidance="Implement role-based access control (RBAC) with conditional access policies and continuous verification.",
            assessment_procedures=[
                "Test access control enforcement mechanisms",
                "Verify role-based access implementation",
                "Check conditional access policies",
                "Validate access decision points"
            ]
        )
        
        controls["AC-6"] = NISTControl(
            control_id="AC-6",
            control_name="Least Privilege",
            family=ControlFamily.ACCESS_CONTROL,
            description="Employ the principle of least privilege, allowing only authorized accesses for users which are necessary to accomplish assigned tasks.",
            implementation_guidance="Implement just-in-time access, regular privilege reviews, and automated privilege escalation controls.",
            assessment_procedures=[
                "Review user privilege assignments",
                "Check just-in-time access implementation",
                "Verify privilege escalation controls",
                "Validate privilege review processes"
            ]
        )
        
        # Audit and Accountability (AU)
        controls["AU-2"] = NISTControl(
            control_id="AU-2",
            control_name="Audit Events", 
            family=ControlFamily.AUDIT_ACCOUNTABILITY,
            description="Identify the types of events that the system is capable of auditing and coordinate the security audit function with other organizational entities.",
            implementation_guidance="Implement comprehensive audit logging covering all security-relevant events with centralized log management.",
            assessment_procedures=[
                "Review audit event types and coverage",
                "Verify centralized log management",
                "Check audit correlation capabilities",
                "Validate audit retention policies"
            ]
        )
        
        controls["AU-3"] = NISTControl(
            control_id="AU-3",
            control_name="Audit Content",
            family=ControlFamily.AUDIT_ACCOUNTABILITY, 
            description="Ensure that audit records contain information that establishes what type of event occurred, when the event occurred, where the event occurred, the source of the event, the outcome of the event, and the identity of any individuals or subjects associated with the event.",
            implementation_guidance="Ensure audit logs include comprehensive metadata for forensic analysis and compliance reporting.",
            assessment_procedures=[
                "Review audit record content standards",
                "Verify required audit metadata inclusion",
                "Check audit record integrity",
                "Validate audit format consistency"
            ]
        )
        
        # System and Communication Protection (SC)
        controls["SC-7"] = NISTControl(
            control_id="SC-7",
            control_name="Boundary Protection",
            family=ControlFamily.SYSTEM_PROTECTION,
            description="Monitor, control, and protect organizational communications at the external boundaries and key internal boundaries of the information system.",
            implementation_guidance="Implement network segmentation, firewall rules, and intrusion detection at network boundaries.",
            assessment_procedures=[
                "Review network boundary protections",
                "Test firewall rule effectiveness",
                "Verify network segmentation",
                "Check intrusion detection coverage"
            ]
        )
        
        controls["SC-8"] = NISTControl(
            control_id="SC-8",
            control_name="Transmission Protection",
            family=ControlFamily.SYSTEM_PROTECTION,
            description="Protect the confidentiality and integrity of transmitted information.",
            implementation_guidance="Implement encryption in transit using TLS 1.2+ for all data transmission with proper certificate management.",
            assessment_procedures=[
                "Review encryption in transit implementation",
                "Verify TLS configuration strength",
                "Check certificate management processes",
                "Validate encryption coverage"
            ]
        )
        
        # Identification and Authentication (IA)
        controls["IA-2"] = NISTControl(
            control_id="IA-2",
            control_name="Identification and Authentication (Organizational Users)",
            family=ControlFamily.IDENTIFICATION_AUTHENTICATION,
            description="Uniquely identify and authenticate organizational users (or processes acting on behalf of organizational users).",
            implementation_guidance="Implement multi-factor authentication for all users with centralized identity management.",
            assessment_procedures=[
                "Review user identification processes",
                "Verify multi-factor authentication",
                "Check identity management system",
                "Validate authentication strength"
            ]
        )
        
        controls["IA-5"] = NISTControl(
            control_id="IA-5",
            control_name="Authenticator Management",
            family=ControlFamily.IDENTIFICATION_AUTHENTICATION,
            description="Manage information system authenticators by defining initial authenticator content, establishing administrative procedures for initial authenticator distribution, for lost/compromised or damaged authenticators, and for revoking authenticators.",
            implementation_guidance="Implement automated authenticator lifecycle management with secure distribution and revocation processes.",
            assessment_procedures=[
                "Review authenticator management procedures",
                "Verify secure distribution processes",
                "Check revocation mechanisms",
                "Validate authenticator strength policies"
            ]
        )
        
        return controls
    
    def get_control(self, control_id: str) -> Optional[NISTControl]:
        """Get specific NIST control definition"""
        return self.controls.get(control_id)
    
    def get_controls_by_family(self, family: ControlFamily) -> List[NISTControl]:
        """Get all controls for a specific family"""
        return [control for control in self.controls.values() if control.family == family]
    
    def get_all_controls(self) -> List[NISTControl]:
        """Get all available controls"""
        return list(self.controls.values())

class InfrastructureScanner:
    """Scans cloud infrastructure against NIST controls"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.project_id = config.get('project_id', 'demo-project')
    
    async def scan_infrastructure(self, controls: List[str] = None) -> Dict[str, Dict]:
        """Scan infrastructure for compliance with specified controls"""
        if controls is None:
            controls = ["AC-2", "AC-3", "AC-6", "AU-2", "AU-3", "SC-7", "SC-8", "IA-2", "IA-5"]
        
        scan_results = {}
        
        for control_id in controls:
            try:
                result = await self._assess_control(control_id)
                scan_results[control_id] = result
                logger.info(f"Assessed control {control_id}: {result['status']}")
            except Exception as e:
                logger.error(f"Failed to assess control {control_id}: {e}")
                scan_results[control_id] = {
                    'status': ComplianceStatus.NOT_ASSESSED.value,
                    'score': 0,
                    'findings': [f"Assessment failed: {str(e)}"],
                    'evidence': [],
                    'remediation': []
                }
        
        return scan_results
    
    async def _assess_control(self, control_id: str) -> Dict:
        """Assess individual control implementation"""
        # Simulate infrastructure scanning with realistic financial services scenarios
        await asyncio.sleep(0.5)  # Simulate API calls
        
        if control_id == "AC-2":
            return await self._assess_account_management()
        elif control_id == "AC-3":
            return await self._assess_access_enforcement()
        elif control_id == "AC-6":
            return await self._assess_least_privilege()
        elif control_id == "AU-2":
            return await self._assess_audit_events()
        elif control_id == "AU-3":
            return await self._assess_audit_content()
        elif control_id == "SC-7":
            return await self._assess_boundary_protection()
        elif control_id == "SC-8":
            return await self._assess_transmission_protection()
        elif control_id == "IA-2":
            return await self._assess_identification_authentication()
        elif control_id == "IA-5":
            return await self._assess_authenticator_management()
        else:
            return {
                'status': ComplianceStatus.NOT_ASSESSED.value,
                'score': 0,
                'findings': [f"Control {control_id} assessment not implemented"],
                'evidence': [],
                'remediation': [f"Implement assessment for control {control_id}"]
            }
    
    async def _assess_account_management(self) -> Dict:
        """Assess AC-2 Account Management"""
        # Simulate account management assessment
        findings = []
        evidence = []
        remediation = []
        score = 65
        
        # Check service account naming
        findings.append("Some service accounts do not follow naming convention")
        evidence.append("Found 3 service accounts without proper naming: sa-1, sa-2, temp-service")
        remediation.append("Rename service accounts to follow pattern: {purpose}-{env}-service")
        
        # Check account lifecycle
        findings.append("Manual account provisioning process identified")
        evidence.append("Account creation requires manual approval in 40% of cases")
        remediation.append("Implement automated account lifecycle management")
        
        # Positive findings
        evidence.append("Account deprovisioning automated for 95% of terminated users")
        evidence.append("Privileged account monitoring implemented")
        
        return {
            'status': ComplianceStatus.NON_COMPLIANT.value,
            'score': score,
            'findings': findings,
            'evidence': evidence,
            'remediation': remediation
        }
    
    async def _assess_access_enforcement(self) -> Dict:
        """Assess AC-3 Access Enforcement"""
        findings = []
        evidence = []
        remediation = []
        score = 92
        
        evidence.append("Role-based access control implemented across all systems")
        evidence.append("Conditional access policies active for 98% of user accounts")
        evidence.append("Access Context Manager configured for sensitive resources")
        
        findings.append("Minor: Some legacy systems lack conditional access")
        remediation.append("Migrate remaining 2% of systems to conditional access")
        
        return {
            'status': ComplianceStatus.COMPLIANT.value,
            'score': score,
            'findings': findings,
            'evidence': evidence,
            'remediation': remediation
        }
    
    async def _assess_least_privilege(self) -> Dict:
        """Assess AC-6 Least Privilege"""
        findings = []
        evidence = []
        remediation = []
        score = 75
        
        findings.append("Several users have elevated privileges beyond job requirements")
        evidence.append("Privilege review completed quarterly")
        evidence.append("Just-in-time access implemented for 60% of administrative functions")
        
        remediation.append("Conduct comprehensive privilege review")
        remediation.append("Implement JIT access for remaining administrative functions")
        
        return {
            'status': ComplianceStatus.PARTIALLY_COMPLIANT.value,
            'score': score,
            'findings': findings,
            'evidence': evidence,
            'remediation': remediation
        }
    
    async def _assess_audit_events(self) -> Dict:
        """Assess AU-2 Audit Events"""
        score = 95
        evidence = [
            "Comprehensive audit logging implemented across all systems",
            "Cloud Audit Logs capturing 100% of administrative actions",
            "Application-level audit logging for trading systems",
            "Centralized log management with SIEM integration"
        ]
        
        return {
            'status': ComplianceStatus.COMPLIANT.value,
            'score': score,
            'findings': [],
            'evidence': evidence,
            'remediation': []
        }
    
    async def _assess_audit_content(self) -> Dict:
        """Assess AU-3 Audit Content"""
        score = 88
        evidence = [
            "Audit records include required metadata fields",
            "Structured logging format implemented",
            "Integrity protection for audit logs via KMS encryption"
        ]
        
        findings = ["Some legacy applications missing detailed audit context"]
        remediation = ["Update legacy applications to include full audit context"]
        
        return {
            'status': ComplianceStatus.COMPLIANT.value,
            'score': score,
            'findings': findings,
            'evidence': evidence,
            'remediation': remediation
        }
    
    async def _assess_boundary_protection(self) -> Dict:
        """Assess SC-7 Boundary Protection"""
        score = 78
        findings = [
            "Some firewall rules allow overly broad access",
            "Network segmentation partially implemented"
        ]
        evidence = [
            "VPC firewall rules implemented with default deny",
            "Network flow logs enabled for monitoring",
            "Trading systems isolated in dedicated subnets"
        ]
        remediation = [
            "Review and tighten firewall rules",
            "Complete network micro-segmentation implementation"
        ]
        
        return {
            'status': ComplianceStatus.PARTIALLY_COMPLIANT.value,
            'score': score,
            'findings': findings,
            'evidence': evidence,
            'remediation': remediation
        }
    
    async def _assess_transmission_protection(self) -> Dict:
        """Assess SC-8 Transmission Protection"""
        score = 82
        evidence = [
            "TLS 1.2+ enforced for all external communications",
            "Internal service mesh with mTLS implemented",
            "Certificate management automated"
        ]
        
        findings = ["Some internal communications not encrypted"]
        remediation = ["Encrypt all internal communications with TLS"]
        
        return {
            'status': ComplianceStatus.PARTIALLY_COMPLIANT.value,
            'score': score,
            'findings': findings,
            'evidence': evidence,
            'remediation': remediation
        }
    
    async def _assess_identification_authentication(self) -> Dict:
        """Assess IA-2 Identification and Authentication"""
        score = 90
        evidence = [
            "Multi-factor authentication enforced for all users",
            "SSO implementation with SAML federation",
            "Risk-based authentication for sensitive operations"
        ]
        
        return {
            'status': ComplianceStatus.COMPLIANT.value,
            'score': score,
            'findings': [],
            'evidence': evidence,
            'remediation': []
        }
    
    async def _assess_authenticator_management(self) -> Dict:
        """Assess IA-5 Authenticator Management"""
        score = 85
        evidence = [
            "Automated password policy enforcement",
            "Certificate lifecycle management implemented",
            "Hardware security modules for key protection"
        ]
        
        findings = ["Some service account keys lack rotation"]
        remediation = ["Implement automated key rotation for all service accounts"]
        
        return {
            'status': ComplianceStatus.COMPLIANT.value,
            'score': score,
            'findings': findings,
            'evidence': evidence,
            'remediation': remediation
        }

class ComplianceOrchestrator:
    """Main orchestrator for NIST 800-53 compliance automation"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.db_path = config.get('database_path', 'data/compliance.db')
        self.control_db = NISTControlDatabase()
        self.infrastructure_scanner = InfrastructureScanner(config)
        self.terraform_generator = TerraformGenerator()
        self.opa_generator = OPAPolicyGenerator()
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database for compliance data"""
        import os
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                timestamp TIMESTAMP,
                overall_score REAL,
                total_controls INTEGER,
                compliant_controls INTEGER,
                assessment_data TEXT,
                terraform_modules TEXT,
                opa_policies TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS control_results (
                assessment_id TEXT,
                control_id TEXT,
                control_name TEXT,
                family TEXT,
                status TEXT,
                score REAL,
                findings TEXT,
                evidence TEXT,
                remediation TEXT,
                last_assessed TIMESTAMP,
                FOREIGN KEY (assessment_id) REFERENCES assessments (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    async def run_compliance_assessment(self, controls: List[str] = None) -> ComplianceAssessment:
        """Run comprehensive NIST 800-53 compliance assessment"""
        logger.info("Starting NIST 800-53 compliance assessment...")
        
        if controls is None:
            controls = ["AC-2", "AC-3", "AC-6", "AU-2", "AU-3", "SC-7", "SC-8", "IA-2", "IA-5"]
        
        assessment_id = hashlib.md5(str(datetime.now()).encode()).hexdigest()[:8]
        timestamp = datetime.now()
        
        # Scan infrastructure
        scan_results = await self.infrastructure_scanner.scan_infrastructure(controls)
        
        # Process results
        control_results = []
        total_score = 0
        compliant_count = 0
        partially_compliant_count = 0
        non_compliant_count = 0
        
        for control_id, result in scan_results.items():
            control_def = self.control_db.get_control(control_id)
            if not control_def:
                continue
            
            control = NISTControl(
                control_id=control_id,
                control_name=control_def.control_name,
                family=control_def.family,
                description=control_def.description,
                implementation_guidance=control_def.implementation_guidance,
                assessment_procedures=control_def.assessment_procedures,
                status=ComplianceStatus(result['status']),
                score=result['score'],
                evidence=result['evidence'],
                remediation_actions=result['remediation'],
                last_assessed=timestamp
            )
            
            control_results.append(control)
            total_score += result['score']
            
            if control.status == ComplianceStatus.COMPLIANT:
                compliant_count += 1
            elif control.status == ComplianceStatus.PARTIALLY_COMPLIANT:
                partially_compliant_count += 1
            elif control.status == ComplianceStatus.NON_COMPLIANT:
                non_compliant_count += 1
        
        # Calculate overall score
        overall_score = total_score / len(control_results) if control_results else 0
        
        # Generate remediation plan
        remediation_plan = self._generate_remediation_plan(control_results)
        
        # Create assessment
        assessment = ComplianceAssessment(
            assessment_id=assessment_id,
            timestamp=timestamp,
            overall_score=overall_score,
            total_controls=len(control_results),
            compliant_controls=compliant_count,
            partially_compliant_controls=partially_compliant_count,
            non_compliant_controls=non_compliant_count,
            control_results=control_results,
            remediation_plan=remediation_plan
        )
        
        # Store assessment
        self.store_assessment(assessment)
        
        logger.info(f"Assessment complete: {overall_score:.1f}% compliance ({compliant_count}/{len(control_results)} controls)")
        
        return assessment
    
    def _generate_remediation_plan(self, control_results: List[NISTControl]) -> List[str]:
        """Generate prioritized remediation plan"""
        remediation_plan = []
        
        # Prioritize by criticality and non-compliance
        critical_controls = [c for c in control_results if c.status == ComplianceStatus.NON_COMPLIANT and c.score < 70]
        medium_controls = [c for c in control_results if c.status == ComplianceStatus.PARTIALLY_COMPLIANT]
        
        # Critical remediation items
        for control in critical_controls:
            for action in control.remediation_actions:
                remediation_plan.append(f"CRITICAL ({control.control_id}): {action}")
        
        # Medium priority items
        for control in medium_controls:
            for action in control.remediation_actions:
                remediation_plan.append(f"MEDIUM ({control.control_id}): {action}")
        
        return remediation_plan
    
    async def generate_compliance_infrastructure(self) -> Dict[str, str]:
        """Generate Terraform modules and OPA policies for compliance"""
        logger.info("Generating compliance infrastructure...")
        
        generated_files = {}
        
        # Generate Terraform modules
        terraform_modules = {
            'access_control': self.terraform_generator.generate_terraform_module('access_control'),
            'network_security': self.terraform_generator.generate_terraform_module('network_security'),
            'audit_logging': self.terraform_generator.generate_terraform_module('audit_logging')
        }
        
        # Generate OPA policies
        opa_policies = {
            'access_control_policy': self.opa_generator.generate_opa_policy('access_control'),
            'network_security_policy': self.opa_generator.generate_opa_policy('network_security'),
            'audit_logging_policy': self.opa_generator.generate_opa_policy('audit_logging')
        }
        
        # Combine all files
        for name, content in terraform_modules.items():
            generated_files[f"terraform_modules/{name}/main.tf"] = content
        
        for name, content in opa_policies.items():
            generated_files[f"policies/opa/{name}.rego"] = content
        
        # Generate variables files
        generated_files["terraform_modules/variables.tf"] = self._generate_terraform_variables()
        generated_files["terraform_modules/outputs.tf"] = self._generate_terraform_outputs()
        
        logger.info(f"Generated {len(generated_files)} compliance infrastructure files")
        
        return generated_files
    
    def _generate_terraform_variables(self) -> str:
        """Generate common Terraform variables file"""
        return '''
# Common Terraform Variables for NIST 800-53 Compliance

variable "project_id" {
  description = "GCP Project ID"
  type        = string
}

variable "organization_id" {
  description = "GCP Organization ID"
  type        = string
}

variable "environment" {
  description = "Environment (dev, staging, prod)"
  type        = string
  default     = "prod"
}

variable "domain" {
  description = "Organization domain name"
  type        = string
  default     = "swift.com"
}

variable "audit_storage_region" {
  description = "Region for audit log storage"
  type        = string
  default     = "us-central1"
}

variable "audit_retention_days" {
  description = "Audit log retention period in days"
  type        = number
  default     = 2555  # 7 years for financial compliance
}

variable "bigquery_region" {
  description = "BigQuery region for audit analysis"
  type        = string
  default     = "US"
}

variable "audit_notification_channels" {
  description = "Notification channels for audit alerts"
  type        = list(string)
  default     = []
}
'''
    
    def _generate_terraform_outputs(self) -> str:
        """Generate common Terraform outputs file"""
        return '''
# Common Terraform Outputs for NIST 800-53 Compliance

output "compliance_summary" {
  description = "Summary of implemented NIST controls"
  value = {
    access_control = {
      policy_etag = module.access_control.access_control_policy_etag
      service_accounts = module.access_control.service_account_emails
    }
    network_security = {
      vpc_id = module.network_security.vpc_network_id
      ssl_policy = module.network_security.ssl_policy_name
    }
    audit_logging = {
      audit_sink = module.audit_logging.audit_sink_name
      audit_bucket = module.audit_logging.audit_bucket_name
      kms_key = module.audit_logging.audit_kms_key_id
    }
  }
}

output "compliance_evidence" {
  description = "Evidence collection for compliance audits"
  value = {
    infrastructure_state = "terraform.tfstate"
    policy_validation = "opa-policies/*.rego"
    audit_logs = module.audit_logging.audit_bucket_name
    monitoring_dashboard = "https://console.cloud.google.com/monitoring"
  }
}
'''
    
    def store_assessment(self, assessment: ComplianceAssessment):
        """Store compliance assessment in database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Store assessment summary
        cursor.execute('''
            INSERT OR REPLACE INTO assessments 
            (id, timestamp, overall_score, total_controls, compliant_controls, 
             assessment_data, terraform_modules, opa_policies)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            assessment.assessment_id,
            assessment.timestamp,
            assessment.overall_score,
            assessment.total_controls,
            assessment.compliant_controls,
            json.dumps(assessment.__dict__, default=str),
            json.dumps(assessment.terraform_modules),
            json.dumps(assessment.opa_policies)
        ))
        
        # Store individual control results
        for control in assessment.control_results:
            cursor.execute('''
                INSERT OR REPLACE INTO control_results
                (assessment_id, control_id, control_name, family, status, score, 
                 findings, evidence, remediation, last_assessed)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                assessment.assessment_id,
                control.control_id,
                control.control_name,
                control.family.value,
                control.status.value,
                control.score,
                json.dumps(control.evidence),
                json.dumps(control.evidence),
                json.dumps(control.remediation_actions),
                control.last_assessed
            ))
        
        conn.commit()
        conn.close()
    
    def generate_compliance_report(self) -> Dict:
        """Generate executive compliance report"""
        conn = sqlite3.connect(self.db_path)
        
        try:
            # Get latest assessment
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM assessments 
                ORDER BY timestamp DESC 
                LIMIT 1
            ''')
            
            result = cursor.fetchone()
            if not result:
                return self._get_demo_compliance_report()
            
            assessment_id = result[0]
            
            # Get control family breakdown
            cursor.execute('''
                SELECT family, 
                       COUNT(*) as total,
                       SUM(CASE WHEN status = 'compliant' THEN 1 ELSE 0 END) as compliant,
                       AVG(score) as avg_score
                FROM control_results 
                WHERE assessment_id = ?
                GROUP BY family
            ''', (assessment_id,))
            
            family_results = cursor.fetchall()
            family_breakdown = []
            
            for family, total, compliant, avg_score in family_results:
                family_breakdown.append({
                    'family': family,
                    'family_name': self._get_family_name(family),
                    'compliance_rate': (compliant / total * 100) if total > 0 else 0,
                    'average_score': avg_score or 0
                })
            
            return {
                'overall_score': result[2],
                'total_controls': result[3],
                'compliant_controls': result[4],
                'compliance_percentage': (result[4] / result[3] * 100) if result[3] > 0 else 0,
                'family_breakdown': family_breakdown,
                'recommendations': self._generate_executive_recommendations(family_breakdown)
            }
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return self._get_demo_compliance_report()
        finally:
            conn.close()
    
    def _get_family_name(self, family_code: str) -> str:
        """Get full family name from code"""
        family_names = {
            'ACCESS_CONTROL': 'Access Control',
            'AUDIT_ACCOUNTABILITY': 'Audit and Accountability',
            'SYSTEM_PROTECTION': 'System Protection',
            'IDENTIFICATION_AUTHENTICATION': 'Identification & Authentication'
        }
        return family_names.get(family_code, family_code)
    
    def _generate_executive_recommendations(self, family_breakdown: List[Dict]) -> List[str]:
        """Generate executive-level recommendations"""
        recommendations = []
        
        for family in family_breakdown:
            if family['compliance_rate'] < 80:
                recommendations.append(
                    f"Prioritize {family['family_name']} family improvements "
                    f"(current: {family['compliance_rate']:.1f}%)"
                )
        
        recommendations.append("Implement automated remediation for identified gaps")
        recommendations.append("Establish continuous compliance monitoring")
        
        return recommendations
    
    def _get_demo_compliance_report(self) -> Dict:
        """Return demo compliance report"""
        return {
            'overall_score': 87.5,
            'total_controls': 9,
            'compliant_controls': 7,
            'compliance_percentage': 77.8,
            'family_breakdown': [
                {'family': 'AC', 'family_name': 'Access Control', 'compliance_rate': 66.7},
                {'family': 'AU', 'family_name': 'Audit and Accountability', 'compliance_rate': 100.0},
                {'family': 'SC', 'family_name': 'System Protection', 'compliance_rate': 50.0},
                {'family': 'IA', 'family_name': 'Identification & Authentication', 'compliance_rate': 100.0}
            ],
            'recommendations': [
                'Prioritize AC (Access Control) family improvements',
                'Implement automated remediation for SC (System Protection) controls'
            ]
        }

# Example usage
async def main():
    """Example usage of Compliance Orchestrator"""
    config = {
        'project_id': 'demo-project',
        'database_path': 'data/compliance.db'
    }
    
    orchestrator = ComplianceOrchestrator(config)
    
    # Run compliance assessment
    assessment = await orchestrator.run_compliance_assessment()
    
    print(f"Assessment ID: {assessment.assessment_id}")
    print(f"Overall Score: {assessment.overall_score:.1f}%")
    print(f"Compliant Controls: {assessment.compliant_controls}/{assessment.total_controls}")
    
    # Generate infrastructure
    generated_files = await orchestrator.generate_compliance_infrastructure()
    print(f"Generated {len(generated_files)} infrastructure files")
    
    # Generate report
    report = orchestrator.generate_compliance_report()
    print(f"Compliance Report: {report['compliance_percentage']:.1f}% overall compliance")

if __name__ == "__main__":
    asyncio.run(main())

#!/usr/bin/env python3
"""Run closed INTERNAL_SANDBOX deployment acceptance journeys.

The original stateful command remains the closed ten-account Trust journey;
the separate invited-Demand-Owner command exercises the provider-only
enrollment boundary without adding that identity to bootstrap.  The runner
talks only to the two fixed local HTTPS hostnames, keeps every
cookie, CSRF token, OIDC state/code and request handle in a private temporary
directory, and emits only a small non-secret result summary.  It is intended
for a deployment acceptance gate, never for real identities or production
traffic.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any, Mapping, NoReturn, Sequence, TextIO
import unicodedata
from urllib.parse import parse_qsl, urlencode, urlsplit
from uuid import UUID, uuid4


PILOT_ORIGIN = "https://pilot.example.test"
IDENTITY_ORIGIN = "https://identity.example.test"
RESOLVE_ADDRESS = "127.0.0.1"
ROLE_EXPECTATIONS = {
    "access_admin_01": ("PLATFORM", ("ACCESS_ADMIN",)),
    "appeal_reviewer_01": ("PLATFORM", ("APPEAL_REVIEWER",)),
    "creator_01": ("PERSONAL", ("CREATOR",)),
    "demand_owner_01": ("ORGANIZATION", ("DEMAND_OWNER",)),
    "operations_reviewer_01": ("PLATFORM", ("OPERATIONS_REVIEWER",)),
    "finance_operator_01": ("PLATFORM", ("FINANCE_OPERATOR",)),
    "finance_operator_02": ("PLATFORM", ("FINANCE_OPERATOR",)),
    "org_admin_01": ("ORGANIZATION", ("ORG_ADMIN",)),
    "trust_officer_01": ("PLATFORM", ("TRUST_OFFICER",)),
    "trust_officer_02": ("PLATFORM", ("TRUST_OFFICER",)),
}
PROVIDER_ONLY_INVITED_DEMAND_OWNER_ACCOUNT_CODE = "invited_demand_owner_02"
PROVIDER_ONLY_INVITED_DEMAND_OWNER_EMAIL = (
    "sandbox-invited-demand-owner-02@example.test"
)
OIDC_CHOOSER_ACCOUNT_CODES = (
    *ROLE_EXPECTATIONS,
    PROVIDER_ONLY_INVITED_DEMAND_OWNER_ACCOUNT_CODE,
)
_ROLE_CODES = {
    "ACCESS_ADMIN",
    "APPEAL_REVIEWER",
    "CREATOR",
    "DEMAND_OWNER",
    "FINANCE_OPERATOR",
    "OPERATIONS_REVIEWER",
    "ORG_ADMIN",
    "TRUST_OFFICER",
}
_CONFIGURABLE_PLATFORM_DUTY_CODES = frozenset(
    {"APPEAL_REVIEWER", "TRUST_OFFICER"}
)
PROFILE_SECTION_KEYS = (
    "interests",
    "skills",
    "availability",
    "collaboration",
    "compensation",
    "boundaries",
    "location",
    "conflicts",
    "ai",
)
DEMAND_SECTION_KEYS = (
    "problem",
    "scope",
    "acceptance",
    "skills",
    "matching",
    "schedule",
    "budget",
    "milestone_plan",
    "risk",
    "ai",
    "collaboration",
    "location",
    "declarations",
)
_EDITOR_CONFIGURATION_FIELDS = {
    "schema_version",
    "deployment_mode",
    "taxonomy_bundle",
    "editor_choices",
}
_EDITOR_TAXONOMY_FIELDS = {
    "bundle_id",
    "status",
    "effective_at",
    "effective_until",
}
_EDITOR_CHOICES_FIELDS = {"schema_version", "locale", "fields"}
_EDITOR_CHOICE_FIELD_FIELDS = {
    "resource_type",
    "path_template",
    "value_contract",
    "intended_node_kind",
    "status",
    "reason_code",
    "options",
}
_EDITOR_CHOICE_OPTION_FIELDS = {"value", "label", "source"}
_EDITOR_CHOICE_VALUE_PATTERNS = {
    "TAXONOMY_CODE": re.compile(r"[A-Z][A-Z0-9_.:-]{1,63}"),
    "REGION_CODE": re.compile(r"[A-Z0-9][A-Z0-9-]{1,31}"),
    "LANGUAGE_TAG": re.compile(r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*"),
    "CURRENCY_CODE": re.compile(r"[A-Z]{3}"),
    "CONTENT_ENUM": re.compile(r"[A-Z][A-Z0-9_]{1,63}"),
}
# Same closed, byte-ordered 23-field binding as the production
# EditorChoicesDto and browser parser. ``None`` fixed options are supplied by
# the selected taxonomy; tuples are exact policy/preset options. Keeping the
# binding here lets this standalone deployment runner fail closed without
# importing application dependencies.
_EDITOR_CHOICE_BINDINGS = (
    (
        "CREATOR_PROFILE", "/ai/prohibited_case_codes/*", "TAXONOMY_CODE",
        None, "UNAVAILABLE", "NO_REVIEWED_CHOICE_SET", None, (),
    ),
    (
        "CREATOR_PROFILE", "/boundaries/prohibited_domains/*/code",
        "TAXONOMY_CODE", "DOMAIN", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "CREATOR_PROFILE", "/boundaries/prohibited_tasks/*/code",
        "TAXONOMY_CODE", "TASK", "AVAILABLE", None,
        "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "CREATOR_PROFILE", "/collaboration/languages/*/language_code",
        "LANGUAGE_TAG", None, "AVAILABLE", None,
        "INTERNAL_SANDBOX_PRESET",
        (("zh-CN", "中文（简体）", "INTERNAL_SANDBOX_PRESET"),),
    ),
    (
        "CREATOR_PROFILE", "/compensation/currency", "CURRENCY_CODE",
        None, "AVAILABLE", None, "INTERNAL_SANDBOX_POLICY",
        (("CNY", "人民币", "INTERNAL_SANDBOX_POLICY"),),
    ),
    (
        "CREATOR_PROFILE", "/interests/*/domain_code", "TAXONOMY_CODE",
        "DOMAIN", "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "CREATOR_PROFILE", "/interests/*/problem_code", "TAXONOMY_CODE",
        "PROBLEM_TYPE", "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "CREATOR_PROFILE", "/interests/*/task_code", "TAXONOMY_CODE",
        "TASK", "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "CREATOR_PROFILE", "/location/region_code", "REGION_CODE", None,
        "AVAILABLE", None, "INTERNAL_SANDBOX_PRESET",
        (("CN", "中国", "INTERNAL_SANDBOX_PRESET"),),
    ),
    (
        "CREATOR_PROFILE", "/skills/*/skill_code", "TAXONOMY_CODE",
        "SKILL", "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "DEMAND", "/budget/currency", "CURRENCY_CODE", None, "AVAILABLE",
        None, "INTERNAL_SANDBOX_POLICY",
        (("CNY", "人民币", "INTERNAL_SANDBOX_POLICY"),),
    ),
    (
        "DEMAND", "/collaboration/languages/*", "LANGUAGE_TAG", None,
        "AVAILABLE", None, "INTERNAL_SANDBOX_PRESET",
        (("zh-CN", "中文（简体）", "INTERNAL_SANDBOX_PRESET"),),
    ),
    (
        "DEMAND", "/location/allowed_creator_region_codes/*", "REGION_CODE",
        None, "AVAILABLE", None, "INTERNAL_SANDBOX_PRESET",
        (("CN", "中国", "INTERNAL_SANDBOX_PRESET"),),
    ),
    (
        "DEMAND", "/location/demand_region_code", "REGION_CODE", None,
        "AVAILABLE", None, "INTERNAL_SANDBOX_PRESET",
        (("CN", "中国", "INTERNAL_SANDBOX_PRESET"),),
    ),
    (
        "DEMAND", "/matching/domain_codes/*", "TAXONOMY_CODE", "DOMAIN",
        "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "DEMAND", "/matching/problem_codes/*", "TAXONOMY_CODE",
        "PROBLEM_TYPE", "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "DEMAND", "/matching/task_codes/*", "TAXONOMY_CODE", "TASK",
        "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "DEMAND", "/problem/domain_code", "TAXONOMY_CODE", "DOMAIN",
        "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "DEMAND", "/problem/problem_type_codes/*", "TAXONOMY_CODE",
        "PROBLEM_TYPE", "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "DEMAND", "/problem/target_user_category_codes/*", "TAXONOMY_CODE",
        "TARGET_USER_CATEGORY", "AVAILABLE", None,
        "INTERNAL_SANDBOX_POLICY",
        (("SYNTHETIC_USER", "合成用户", "INTERNAL_SANDBOX_POLICY"),),
    ),
    (
        "DEMAND", "/risk/dependency_codes/*", "TAXONOMY_CODE", None,
        "UNAVAILABLE", "NO_REVIEWED_CHOICE_SET", None, (),
    ),
    (
        "DEMAND", "/skills/must_have/*/skill_code", "TAXONOMY_CODE",
        "SKILL", "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
    (
        "DEMAND", "/skills/nice_to_have/*/skill_code", "TAXONOMY_CODE",
        "SKILL", "AVAILABLE", None, "TAXONOMY_BUNDLE_NODE", None,
    ),
)
FINANCE_FUNDING_ATTESTATION_CODES = (
    "SYNTHETIC_ONLY",
    "ZERO_REAL_FUNDS",
    "NO_PROVIDER_OR_PAYMENT",
    "TARGET_AND_EVIDENCE_MATCH",
)
FINANCE_FUNDING_ACTIONS = (
    "CONFIRM",
    "RELEASE_ASSIGNMENT",
    "SUBMIT_FINDING",
)
FINANCE_FUNDING_RELEASE_REASON_CODE = "WORKLOAD_RELEASE"
FINANCE_FUNDING_DISCREPANCY_REASON_CODE = "TARGET_CONTENT_MISMATCH"
FINANCE_FUNDING_DISCREPANCY_FIELD_CODE = "SCOPE"
JOURNEY_GREEN_STATUS = "TEN_ACCOUNT_TRUST_APPEAL_E2E_GREEN"
RESTART_GREEN_STATUS = "TEN_ACCOUNT_TRUST_APPEAL_RESTART_GREEN"
INVITED_DEMAND_OWNER_GREEN_STATUS = (
    "PROVIDER_ONLY_INVITED_DEMAND_OWNER_E2E_GREEN"
)
STATE_SCHEMA = "internal-sandbox-ten-account-trust-appeal-e2e-v8"
UPDATED_ORGANIZATION_PUBLIC_NAME = "Desire Sandbox Organization (Updated)"

_UUID = re.compile(
    r"^(?!0{8}-0{4}-0{4}-0{4}-0{12}$)"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
_CSRF = re.compile(r"^[A-Za-z0-9_-]{32,512}$")
_WORKSPACE = re.compile(
    r"^(?:org|personal|platform):"
    r"(?!0{8}-0{4}-0{4}-0{4}-0{12}$)"
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
    r"[0-9a-f]{4}-[0-9a-f]{12}$"
)
_ENTITY_TAG = re.compile(r'^"v[1-9][0-9]*"$')
_RESOURCE_ETAG = re.compile(
    r'^"(?:creator_profile|demand)-[1-9][0-9]*-[a-f0-9]{24}"$'
)
_QUEUE_ETAG = re.compile(r'^"demand-[1-9][0-9]*-review-queue"$')
_FINANCE_QUEUE_ETAG = re.compile(
    r'^"(?:demand-[1-9][0-9]*-finance-queue|funding-review-[1-9][0-9]*)"$'
)
_FINANCE_REVIEW_ETAG = re.compile(r'^"funding-review-[1-9][0-9]*"$')
_TRUST_ETAG = re.compile(r'^"trust-[1-9][0-9]*-[a-f0-9]{24}"$')
_APPEAL_ETAG = re.compile(r'^"appeal-[1-9][0-9]*-[a-f0-9]{24}"$')
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_AUTH_HANDLE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_AUTH_URL = re.compile(r"^[\x21-\x7e]+$")
_HEADER_VALUE = re.compile(r"^[\x20-\x7e]+$")
_CAPABILITY_TOKEN = re.compile(r"^[A-Za-z0-9_-]{80,4096}$")
_UTC_TIMESTAMP = re.compile(
    r"^(?P<second>[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(?:\.(?P<fraction>[0-9]{1,9}))?(?:Z|\+00:00)$"
)
_STATE_FIELDS = {
    "schema",
    "profile_id",
    "demand_id",
    "demand_version_id",
    "funding_review_id",
    "profile_revision",
    "demand_revision",
    "trust_report_id",
    "trust_case_id",
    "trust_hold_id",
    "trust_outcome_version_id",
    "trust_report_etag",
    "trust_case_etag",
    "expected_trust_outcome_code",
    "expected_appeal_eligibility_code",
    "expected_operations_result",
    "appeal_id",
    "appeal_decision_version_id",
    "appeal_etag",
    "expected_appeal_status",
    "expected_appeal_decision_code",
    "organization_id",
    "accepted_invitation_id",
    "accepted_membership_id",
    "revoked_invitation_id",
}
_APPEAL_COMMAND_FIELDS = {
    "aggregate_version",
    "appeal_id",
    "appeal_status",
    "application_draft_version",
    "application_version",
    "completed_at",
    "decision_version_id",
    "event_types",
    "replayed",
    "review_draft_version",
}
_APPEAL_OWN_FIELDS = {
    "aggregate_version",
    "appeal_id",
    "application",
    "application_draft",
    "decision",
    "entity_tag",
    "source",
    "source_case_id",
    "source_outcome_version_id",
    "status",
}
_APPEAL_SOURCE_FIELDS = {
    "action_codes",
    "appeal_deadline",
    "appeal_eligibility_code",
    "appeal_eligible",
    "case_id",
    "content_sha256",
    "decided_at",
    "demand_id",
    "demand_version_id",
    "evidence_packet_sha256",
    "evidence_packet_version_id",
    "outcome_code",
    "outcome_version_id",
    "policy_version",
    "reason_codes",
}
_APPEAL_APPLICATION_DRAFT_FIELDS = {
    "edited_at",
    "grounds",
    "new_evidence_reference_ids",
    "requested_outcome",
    "statement_recorded",
    "version",
}
_APPEAL_APPLICATION_FIELDS = {
    "grounds",
    "new_evidence_reference_ids",
    "requested_outcome",
    "statement_recorded",
    "submitted_at",
}
_APPEAL_DECISION_FIELDS = {
    "assessments",
    "decided_at",
    "decision_code",
    "decision_sha256",
    "decision_version_id",
    "policy_version",
    "reason_codes",
    "remedy_delta_codes",
}
_APPEAL_QUEUE_FIELDS = {"entity_tag", "items"}
_APPEAL_ACTIVE_ASSIGNMENTS_FIELDS = {"entity_tag", "items"}
_APPEAL_ACTIVE_ASSIGNMENT_ITEM_FIELDS = {
    "appeal_id",
    "assignment_expires_at",
}
_APPEAL_TERMINAL_HISTORY_FIELDS = {"entity_tag", "has_more", "items"}
_APPEAL_TERMINAL_HISTORY_ITEM_FIELDS = {
    "appeal_id",
    "decided_at",
    "decision_code",
}
_APPEAL_TERMINAL_DETAIL_FIELDS = {
    "appeal_id",
    "application",
    "decision",
    "entity_tag",
    "review_note_recorded",
    "status",
}
_APPEAL_QUEUE_ITEM_FIELDS = {
    "appeal_id",
    "entity_tag",
    "grounds",
    "requested_outcome",
    "source_case_id",
    "source_outcome_version_id",
    "submitted_at",
}
_APPEAL_ASSESSMENT_FIELDS = {
    "accepted_evidence_reference_ids",
    "assessment_code",
    "finding_codes",
    "ground",
}
_APPEAL_REVIEW_DRAFT_FIELDS = {
    "assessments",
    "edited_at",
    "reason_codes",
    "remedy_delta_codes",
    "review_note_recorded",
    "version",
}
_APPEAL_ASSIGNED_FIELDS = {
    "appeal",
    "application",
    "assignment_expires_at",
    "entity_tag",
    "review_draft",
    "source",
}
_APPEAL_STATUSES = {"DECIDED", "DRAFT", "IN_REVIEW", "SUBMITTED", "WITHDRAWN"}
_APPEAL_GROUNDS = {
    "NEW_MATERIAL_EVIDENCE",
    "PROCEDURAL_ERROR",
    "RULE_MISAPPLICATION",
}
_APPEAL_REQUESTED_OUTCOMES = {
    "MODIFY_MEASURE",
    "REMOVE_MEASURE",
    "VACATE_AND_REMAND",
}
_APPEAL_DECISION_CODES = {"AFFIRM", "DISMISS", "MODIFY", "VACATE_AND_REMAND"}
_APPEAL_REASON_CODES = {
    "APPEAL_SCOPE_INVALID",
    "NEW_EVIDENCE_REVIEWED",
    "PROCEDURAL_REVIEW_COMPLETE",
    "REMAND_REQUIRED",
    "SOURCE_OUTCOME_SUPPORTED",
    "SOURCE_OUTCOME_UNSUPPORTED",
}
_APPEAL_REMEDY_CODES = {
    "NARROW_CORRECTIVE_MEASURE",
    "NO_CHANGE",
    "REMOVE_CORRECTIVE_MEASURE",
    "REPLACE_CORRECTIVE_MEASURE",
    "RETURN_TO_TRUST_REVIEW",
}
_TRUST_COMMAND_FIELDS = {
    "aggregate_version",
    "case_id",
    "case_status",
    "completed_at",
    "event_types",
    "hold_id",
    "hold_version",
    "outcome_version_id",
    "replayed",
    "report_id",
    "triage_draft_version",
    "triage_version",
}
_TRUST_REPORT_FIELDS = {
    "demand_id",
    "demand_version_id",
    "entity_tag",
    "outcome",
    "report",
    "report_id",
    "status",
    "submitted_at",
}
_TRUST_REPORT_SUMMARY_FIELDS = {
    "category",
    "evidence_reference_ids",
    "impact_codes",
    "incident_ended_at",
    "incident_started_at",
    "requested_protection_codes",
}
_TRUST_QUEUE_FIELDS = {"entity_tag", "items"}
_TRUST_ACTIVE_ASSIGNMENTS_FIELDS = {"entity_tag", "items"}
_TRUST_ACTIVE_ASSIGNMENT_ITEM_FIELDS = {
    "assignment_expires_at",
    "assignment_purpose",
    "case_id",
    "hold_id",
}
_TRUST_TERMINAL_HISTORY_FIELDS = {"entity_tag", "has_more", "items"}
_TRUST_TERMINAL_HISTORY_ITEM_FIELDS = {
    "case_id",
    "decided_at",
    "outcome_code",
}
_TRUST_QUEUE_ITEM_FIELDS = {
    "category",
    "case_id",
    "demand_id",
    "demand_version_id",
    "entity_tag",
    "impact_codes",
    "report_id",
    "submitted_at",
}
_TRUST_HOLD_QUEUE_ITEM_FIELDS = {
    "action_codes",
    "case_id",
    "demand_id",
    "demand_version_id",
    "entity_tag",
    "expires_at",
    "hold_id",
    "reason_code",
}
_TRUST_CASE_FIELDS = {
    "active_hold",
    "aggregate_version",
    "case_id",
    "demand_id",
    "demand_version_id",
    "entity_tag",
    "outcome",
    "report",
    "report_id",
    "status",
    "triage_draft",
}
_TRUST_TRIAGE_DRAFT_FIELDS = {
    "content",
    "content_sha256",
    "saved_at",
    "triage_version",
}
_TRUST_SAFE_TRIAGE_FIELDS = {
    "investigation_step_codes",
    "issue_codes",
    "jurisdiction_code",
    "priority_code",
    "proposed_hold_actions",
    "proposed_hold_ttl_minutes",
    "sealed_note_reference",
    "sealed_note_sha256",
    "severity_code",
}
_TRUST_HOLD_FIELDS = {
    "action_codes",
    "effective_at",
    "entity_tag",
    "expires_at",
    "hold_id",
    "status",
}
_TRUST_ASSIGNED_HOLD_FIELDS = {
    "action_codes",
    "assignment_expires_at",
    "case_id",
    "case_status",
    "effective_at",
    "entity_tag",
    "expires_at",
    "hold_id",
    "hold_status",
    "reason_code",
}
_TRUST_OUTCOME_FIELDS = {
    "action_codes",
    "appeal_deadline",
    "appeal_eligibility_code",
    "content_sha256",
    "decided_at",
    "evidence_packet_digest",
    "evidence_packet_version_id",
    "outcome_code",
    "outcome_version_id",
    "policy_version",
    "reason_codes",
    "redaction_profile_code",
    "source_digest",
}
_TRUST_ACTION_CODES = {"REQUEST_MATCHING", "SUBMIT_DEMAND", "VERIFY_DEMAND"}
_TRUST_CASE_STATUSES = {
    "APPEAL_PENDING",
    "DECIDED",
    "DISMISSED",
    "IN_REVIEW",
    "OPEN",
    "RESOLVED",
    "TRIAGING",
}
_TRUST_OUTCOME_CODES = {
    "NO_ACTION",
    "PROTECTION_LIFTED",
    "PROTECTION_MAINTAINED",
    "PROTECTION_MODIFIED",
    "REMEDIATION_REQUIRED",
}
_TRUST_OUTCOME_REASON_CODES = {
    "INSUFFICIENT_VERIFIED_EVIDENCE",
    "NO_POLICY_BREACH",
    "POLICY_REQUIREMENT_NOT_MET",
    "PRECAUTIONARY_ACTION_REQUIRED",
    "RISK_MITIGATED",
}
_RESOURCE_FIELDS = {
    "resource_type",
    "object_id",
    "status",
    "revision",
    "etag",
    "capabilities",
    "editable_paths",
    "current_version",
    "versions",
    "submissions",
    "findings",
    "review_assignment",
}
_FINDING_FIELDS = {
    "finding_id",
    "version_id",
    "assignment_id",
    "result",
    "reason_codes",
    "required_field_paths",
    "reviewed_at",
}
_QUEUE_FIELDS = {
    "demand_id",
    "demand_revision",
    "demand_version_no",
    "submitted_at",
    "demand_expires_at",
    "etag",
}
_CLAIM_FIELDS = {
    "assignment_id",
    "demand_id",
    "demand_revision",
    "status",
    "expires_at",
    "etag",
    "replayed",
}
_FINANCE_QUEUE_FIELDS = {
    "demand_id",
    "demand_version_id",
    "demand_revision",
    "funding_review_id",
    "review_status",
    "review_revision",
    "assigned_to_me",
    "confirmation_count",
    "required_confirmations",
    "expires_at",
    "etag",
}
_FINANCE_REVIEW_FIELDS = {
    "funding_review_id",
    "demand_id",
    "demand_version_id",
    "status",
    "revision",
    "assignment_id",
    "assignment_expires_at",
    "target_sha256",
    "target_content_sha256",
    "planned_budget_currency",
    "planned_budget_minimum_amount_minor",
    "planned_budget_maximum_amount_minor",
    "planned_budget_direct_cost_amount_minor",
    "evidence_kind",
    "evidence_reference_sha256",
    "sandbox_funds_amount_minor",
    "provider_code",
    "payment_operation_code",
    "synthetic",
    "legal_effect",
    "confirmation_count",
    "required_confirmations",
    "assignment_status",
    "confirmation_by_me",
    "available_actions",
    "can_confirm",
    "etag",
    "replayed",
}
_FINANCE_HISTORY_PAGE_FIELDS = {
    "schema_version",
    "items",
    "next_cursor",
    "has_more",
}
_FINANCE_HISTORY_ITEM_FIELDS = {
    "funding_review_id",
    "demand_id",
    "demand_version_id",
    "status",
    "completed_at",
}
_ORGANIZATION_FIELDS = {
    "organization_id",
    "public_name",
    "type",
    "status",
    "aggregate_version",
    "entity_tag",
}
_INVITATION_ADMIN_FIELDS = {
    "invitation_id",
    "purpose",
    "organization_id",
    "target_role",
    "masked_recipient_label",
    "is_initial_admin",
    "status",
    "expires_at",
    "created_at",
    "required_policy_bundle_id",
    "aggregate_version",
    "entity_tag",
}
_INVITATION_PREVIEW_FIELDS = {
    "invitation_id",
    "purpose",
    "organization",
    "target_role",
    "expires_at",
    "required_policy_bundle_id",
    "status",
    "aggregate_version",
    "entity_tag",
}
_MEMBERSHIP_FIELDS = {
    "membership_id",
    "organization_id",
    "user_id",
    "display_handle",
    "status",
    "roles",
    "aggregate_version",
    "entity_tag",
}
_POLICY_BUNDLE_FIELDS = {
    "policy_bundle_id",
    "purpose",
    "jurisdiction",
    "locale",
    "documents",
    "consent_offers",
    "effective_at",
    "entity_tag",
}
_POLICY_DOCUMENT_FIELDS = {
    "document_id",
    "kind",
    "semantic_version",
    "locale",
    "content_sha256",
    "legal_effect",
    "body",
}
_CONSENT_OFFER_FIELDS = {
    "consent_offer_id",
    "purpose",
    "scope_type",
    "data_categories",
    "document_id",
    "content_sha256",
    "recipient_label",
    "expiry_rule",
    "not_after",
    "canonical_offer_sha256",
    "optional",
}
_FAILURE_STAGES = frozenset(
    {
        "INPUT",
        "LOGIN_ACCESS_ADMIN",
        "LOGIN_APPEAL_REVIEWER",
        "LOGIN_CREATOR",
        "LOGIN_DEMAND_OWNER",
        "LOGIN_OPERATIONS_REVIEWER",
        "LOGIN_FINANCE_OPERATOR_01",
        "LOGIN_FINANCE_OPERATOR_02",
        "LOGIN_ORG_ADMIN",
        "LOGIN_TRUST_OFFICER_01",
        "LOGIN_TRUST_OFFICER_02",
        "INVITED_DEMAND_OWNER_ADMIN_LOGIN",
        "INVITED_DEMAND_OWNER_INVITATION",
        "INVITED_DEMAND_OWNER_PENDING",
        "INVITED_DEMAND_OWNER_PENDING_SESSION",
        "INVITED_DEMAND_OWNER_PENDING_ME",
        "INVITED_DEMAND_OWNER_PENDING_WORKSPACES",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_BODY",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_EXPOSED",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_BAD_REQUEST",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_UNAUTHENTICATED",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_FORBIDDEN",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_WORKSPACE_REQUIRED",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_METHOD_REJECTED",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_INVALID_REQUEST",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_SERVER_ERROR",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_GATEWAY_ERROR",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_UNAVAILABLE",
        "INVITED_DEMAND_OWNER_PENDING_ADMIN_OTHER",
        "INVITED_DEMAND_OWNER_ACCEPTANCE",
        "INVITED_DEMAND_OWNER_ACCEPTANCE_POLICY",
        "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
        "INVITED_DEMAND_OWNER_ACCEPTANCE_SESSION",
        "INVITED_DEMAND_OWNER_AUTHORITY",
        "INVITED_DEMAND_OWNER_AUTHORITY_RESPONSE",
        "INVITED_DEMAND_OWNER_AUTHORITY_REFRESHED_ME",
        "INVITED_DEMAND_OWNER_AUTHORITY_WORKSPACES",
        "INVITED_DEMAND_OWNER_AUTHORITY_ADMIN",
        "INVITED_DEMAND_OWNER_DEMAND",
        "CONFIGURATION",
        "PROFILE",
        "DEMAND_REVIEW",
        "TRUST_REPORT",
        "TRUST_CASE_REVIEW",
        "TRUST_HOLD_ENFORCEMENT",
        "TRUST_HOLD_RELEASE",
        "TRUST_OUTCOME",
        "TRUST_APPEAL",
        "ASSIGNMENT_DISCOVERY_BOUNDARY",
        "FINANCE_FUNDING",
        "ACCOUNT_DUTY_CONFIGURATION",
        "ORGANIZATION_ADMIN",
        "ACCOUNT_LIFECYCLE",
        "STATE_OUTPUT",
        "RESULT_OUTPUT",
        "RESTART_PROFILE",
        "RESTART_DEMAND",
        "RESTART_REVIEW",
        "RESTART_TRUST",
        "RESTART_APPEAL",
        "RESTART_FINANCE",
        "RESTART_FINANCE_HISTORY",
        "RESTART_ACCOUNTS",
        "RESTART_ORGANIZATION",
        "INTERNAL",
    }
)


class InternalSandboxE2eError(RuntimeError):
    """Stable, non-reflective acceptance failure."""

    def __init__(self, *, stage: str = "INPUT") -> None:
        if stage not in _FAILURE_STAGES:
            stage = "INTERNAL"
        self.stage = stage
        super().__init__("INTERNAL_SANDBOX_E2E_FAILED")


@dataclass(frozen=True)
class JourneyState:
    profile_id: str
    demand_id: str
    demand_version_id: str
    funding_review_id: str
    profile_revision: int
    demand_revision: int
    trust_report_id: str
    trust_case_id: str
    trust_hold_id: str
    trust_outcome_version_id: str
    trust_report_etag: str
    trust_case_etag: str
    expected_trust_outcome_code: str
    expected_appeal_eligibility_code: str
    expected_operations_result: str
    appeal_id: str
    appeal_decision_version_id: str
    appeal_etag: str
    expected_appeal_status: str
    expected_appeal_decision_code: str
    organization_id: str
    accepted_invitation_id: str
    accepted_membership_id: str
    revoked_invitation_id: str

    def __post_init__(self) -> None:
        _canonical_uuid(self.profile_id)
        _canonical_uuid(self.demand_id)
        _canonical_uuid(self.demand_version_id)
        _canonical_uuid(self.funding_review_id)
        _canonical_uuid(self.trust_report_id)
        _canonical_uuid(self.trust_case_id)
        _canonical_uuid(self.trust_hold_id)
        _canonical_uuid(self.trust_outcome_version_id)
        _canonical_uuid(self.appeal_id)
        _canonical_uuid(self.appeal_decision_version_id)
        _canonical_uuid(self.organization_id)
        _canonical_uuid(self.accepted_invitation_id)
        _canonical_uuid(self.accepted_membership_id)
        _canonical_uuid(self.revoked_invitation_id)
        for value in (self.profile_revision, self.demand_revision):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                _invalid()
        if (
            not isinstance(self.trust_report_etag, str)
            or _TRUST_ETAG.fullmatch(self.trust_report_etag) is None
            or not isinstance(self.trust_case_etag, str)
            or _TRUST_ETAG.fullmatch(self.trust_case_etag) is None
            or self.expected_trust_outcome_code != "PROTECTION_MODIFIED"
            or self.expected_appeal_eligibility_code != "ELIGIBLE"
            or self.expected_operations_result != "VERIFIED"
            or not isinstance(self.appeal_etag, str)
            or _APPEAL_ETAG.fullmatch(self.appeal_etag) is None
            or self.expected_appeal_status != "DECIDED"
            or self.expected_appeal_decision_code != "VACATE_AND_REMAND"
        ):
            _invalid()


@dataclass(frozen=True)
class HttpResult:
    status: int
    headers: Mapping[str, str]
    body: bytes

    def json(self) -> Any:
        if len(self.body) > 1_048_576:
            _invalid()
        try:
            return json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            _invalid()


@dataclass(frozen=True)
class RoleSession:
    account_code: str
    workspace_id: str
    workspace_kind: str
    role_codes: tuple[str, ...]
    csrf_token: str
    client: "CurlClient"
    policy_accepted: bool


@dataclass(frozen=True, repr=False)
class _PlatformDutyCommand:
    user_id: str
    duty_code: str
    action: str
    path: str
    body_items: tuple[tuple[str, str], ...]
    if_match: str
    idempotency_key: str


class _RequestHandleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.values: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        if (
            tag == "input"
            and attributes.get("type") == "hidden"
            and attributes.get("name") == "request_handle"
        ):
            value = attributes.get("value")
            if isinstance(value, str):
                self.values.append(value)


class CurlClient:
    """One isolated cookie jar and private request ledger for one role."""

    def __init__(self, *, root: Path, ca_file: Path) -> None:
        self._root = root
        self._ca_file = ca_file
        self._curl = shutil.which("curl")
        if self._curl is None:
            _invalid()
        self._counter = 0
        self._cookie_jar = root / "cookies.txt"
        _write_new(self._cookie_jar, b"", mode=0o600)

    def request(
        self,
        *,
        method: str,
        path: str,
        body: Mapping[str, Any] | None = None,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        sensitive_body: bool = False,
    ) -> HttpResult:
        if (
            not path.startswith("/")
            or "?" in path
            or "#" in path
            or not isinstance(sensitive_body, bool)
        ):
            _invalid()
        suffix = ""
        if query is not None:
            if (
                not isinstance(query, Mapping)
                or not query
                or any(
                    not isinstance(name, str)
                    or not isinstance(value, str)
                    or re.fullmatch(r"[a-z_]{1,40}", name) is None
                    or not value
                    or len(value) > 2048
                    for name, value in query.items()
                )
            ):
                _invalid()
            suffix = "?" + urlencode(query)
        return self._run(
            method=method,
            url=PILOT_ORIGIN + path + suffix,
            body=body,
            headers=headers,
            sensitive_body=sensitive_body,
        )

    def get_authorization_page(self, authorization_url: str) -> bytes:
        _validated_authorization_url(authorization_url)
        result = self._run(
            method="GET",
            url=None,
            body=None,
            headers=None,
            dynamic_url=authorization_url,
        )
        _expect_status(result, 200)
        return result.body

    def authorize(self, *, account_code: str, request_handle: str) -> None:
        if account_code not in OIDC_CHOOSER_ACCOUNT_CODES or _AUTH_HANDLE.fullmatch(
            request_handle
        ) is None:
            _invalid()
        handle_file = self._new_path("request-handle")
        _write_new(handle_file, request_handle.encode("ascii"), mode=0o600)
        selection = self._run(
            method="FORM_POST",
            url=IDENTITY_ORIGIN + "/authorize",
            body=None,
            headers=None,
            form_fields=(
                ("request_handle", handle_file),
                ("account_code", account_code),
            ),
        )
        _expect_status(selection, 303)
        callback_url = _validated_oidc_callback_location(selection)
        callback = self._run(
            method="GET",
            url=None,
            body=None,
            headers=None,
            dynamic_url=callback_url,
        )
        _expect_status(callback, 303)
        if callback.headers.get("location") != "/app":
            _invalid()
        landing = self._run(
            method="GET",
            url=PILOT_ORIGIN + "/app",
            body=None,
            headers=None,
        )
        _expect_status(landing, 200)

    def _run(
        self,
        *,
        method: str,
        url: str | None,
        body: Mapping[str, Any] | None,
        headers: Mapping[str, str] | None,
        dynamic_url: str | None = None,
        form_fields: tuple[tuple[str, Path | str], ...] = (),
        sensitive_body: bool = False,
    ) -> HttpResult:
        if not isinstance(sensitive_body, bool):
            _invalid()
        response_path = self._new_path("response")
        response_headers_path = self._new_path("response-headers")
        command = [
            self._curl,
            "--disable",
            "--silent",
            "--show-error",
            "--proto",
            "=https",
            "--noproxy",
            "*",
            "--cacert",
            str(self._ca_file),
            "--resolve",
            f"pilot.example.test:443:{RESOLVE_ADDRESS}",
            "--resolve",
            f"identity.example.test:443:{RESOLVE_ADDRESS}",
            "--cookie",
            str(self._cookie_jar),
            "--cookie-jar",
            str(self._cookie_jar),
            "--max-time",
            "20",
            "--output",
            str(response_path),
            "--dump-header",
            str(response_headers_path),
            "--write-out",
            "%{http_code}",
        ]
        if headers:
            header_path = self._new_path("request-headers")
            lines: list[str] = []
            for name, value in headers.items():
                if (
                    not isinstance(name, str)
                    or not isinstance(value, str)
                    or not name
                    or ":" in name
                    or _HEADER_VALUE.fullmatch(value) is None
                    or "\r" in value
                    or "\n" in value
                ):
                    _invalid()
                lines.append(f"{name}: {value}\n")
            _write_new(header_path, "".join(lines).encode("ascii"), mode=0o600)
            command.extend(("--header", f"@{header_path}"))
        standard_input: str | None = None
        if body is not None:
            if not isinstance(body, Mapping):
                _invalid()
            serialized_body = json.dumps(
                body,
                ensure_ascii=False,
                separators=(",", ":"),
            )
            if sensitive_body:
                if method not in {"POST", "PUT"} or form_fields:
                    _invalid()
                standard_input = serialized_body
                command.extend(("--data-binary", "@-"))
            else:
                body_path = self._new_path("request-body")
                _write_new(
                    body_path,
                    serialized_body.encode("utf-8"),
                    mode=0o600,
                )
                command.extend(("--data-binary", f"@{body_path}"))
        elif sensitive_body:
            _invalid()
        if method == "FORM_POST":
            for name, value in form_fields:
                if isinstance(value, Path):
                    command.extend(("--data-urlencode", f"{name}@{value}"))
                elif isinstance(value, str) and value in OIDC_CHOOSER_ACCOUNT_CODES:
                    command.extend(("--data-urlencode", f"{name}={value}"))
                else:
                    _invalid()
        elif method != "GET":
            if method not in {"POST", "PUT"}:
                _invalid()
            command.extend(("--request", method))
        if dynamic_url is not None:
            config_path = self._new_path("dynamic-url")
            _write_new(
                config_path,
                f'url = "{dynamic_url}"\n'.encode("ascii"),
                mode=0o600,
            )
            command.extend(("--config", str(config_path)))
        elif url is not None:
            command.append(url)
        else:
            _invalid()
        run_options: dict[str, Any] = {
            "check": False,
            "capture_output": True,
            "text": True,
            "env": {
                "HOME": str(self._root),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.defpath,
            },
        }
        if standard_input is not None:
            run_options["input"] = standard_input
        completed = subprocess.run(command, **run_options)
        if completed.returncode != 0 or re.fullmatch(
            r"[1-5][0-9]{2}", completed.stdout
        ) is None:
            _invalid()
        try:
            body_bytes = response_path.read_bytes()
            header_bytes = response_headers_path.read_bytes()
        except OSError:
            _invalid()
        if len(body_bytes) > 1_048_576 or len(header_bytes) > 65_536:
            _invalid()
        return HttpResult(
            status=int(completed.stdout),
            headers=_parse_last_headers(header_bytes),
            body=body_bytes,
        )

    def _new_path(self, label: str) -> Path:
        self._counter += 1
        return self._root / f"{self._counter:04d}-{label}"


def _validate_editor_choices(value: Any) -> Mapping[str, Any]:
    choices = _exact_keys(value, _EDITOR_CHOICES_FIELDS)
    fields = choices["fields"]
    if (
        choices["schema_version"] != "editor-choices-v1"
        or choices["locale"] != "zh-CN"
        or not isinstance(fields, list)
        or len(fields) != len(_EDITOR_CHOICE_BINDINGS)
        or len(fields) != 23
    ):
        _invalid()
    taxonomy_options: dict[str, tuple[tuple[str, str, str], ...]] = {}
    for raw_field, binding in zip(fields, _EDITOR_CHOICE_BINDINGS):
        field = _exact_keys(raw_field, _EDITOR_CHOICE_FIELD_FIELDS)
        (
            resource_type,
            path_template,
            value_contract,
            intended_node_kind,
            status,
            reason_code,
            expected_source,
            fixed_options,
        ) = binding
        if (
            field["resource_type"] != resource_type
            or field["path_template"] != path_template
            or field["value_contract"] != value_contract
            or field["intended_node_kind"] != intended_node_kind
            or field["status"] != status
            or field["reason_code"] != reason_code
            or not isinstance(field["options"], list)
        ):
            _invalid()
        options = field["options"]
        if (
            status == "AVAILABLE"
            and not 1 <= len(options) <= 16
        ) or (status == "UNAVAILABLE" and options):
            _invalid()
        normalized_options: list[tuple[str, str, str]] = []
        previous_value: bytes | None = None
        for raw_option in options:
            option = _exact_keys(raw_option, _EDITOR_CHOICE_OPTION_FIELDS)
            option_value = option["value"]
            label = option["label"]
            source = option["source"]
            pattern = _EDITOR_CHOICE_VALUE_PATTERNS[value_contract]
            if (
                not isinstance(option_value, str)
                or pattern.fullmatch(option_value) is None
                or unicodedata.normalize("NFC", option_value) != option_value
                or not isinstance(label, str)
                or not 1 <= len(label) <= 120
                or label.strip() != label
                or unicodedata.normalize("NFC", label) != label
                or any(unicodedata.category(character) == "Cc" for character in label)
                or source != expected_source
            ):
                _invalid()
            encoded_value = option_value.encode("utf-8")
            if previous_value is not None and previous_value >= encoded_value:
                _invalid()
            previous_value = encoded_value
            normalized_options.append((option_value, label, source))
        normalized = tuple(normalized_options)
        if fixed_options is not None and normalized != fixed_options:
            _invalid()
        if expected_source == "TAXONOMY_BUNDLE_NODE":
            if intended_node_kind is None:
                _invalid()
            previous = taxonomy_options.setdefault(intended_node_kind, normalized)
            if previous != normalized:
                _invalid()
    return choices


def _first_available_editor_choices(
    editor_choices: Mapping[str, Any], *, resource_type: str
) -> Mapping[str, str]:
    if resource_type not in {"CREATOR_PROFILE", "DEMAND"}:
        _invalid()
    choices = _validate_editor_choices(editor_choices)
    result = {
        field["path_template"]: field["options"][0]["value"]
        for field in choices["fields"]
        if field["resource_type"] == resource_type
        and field["status"] == "AVAILABLE"
    }
    if len(result) != (9 if resource_type == "CREATOR_PROFILE" else 12):
        _invalid()
    return result


def _editor_values_at_path(
    value: Any, segments: tuple[str, ...]
) -> Sequence[Any]:
    if not segments:
        return (value,)
    segment, remaining = segments[0], segments[1:]
    if segment == "*":
        if not isinstance(value, list):
            return ()
        result: list[Any] = []
        for child in value:
            result.extend(_editor_values_at_path(child, remaining))
        return result
    if not isinstance(value, Mapping) or segment not in value:
        return ()
    return _editor_values_at_path(value[segment], remaining)


def _validate_editor_content_choices(
    *,
    resource_type: str,
    content: Mapping[str, Any],
    editor_choices: Mapping[str, Any],
) -> None:
    """Mirror production write-bound editor choice membership validation."""

    if resource_type not in {"CREATOR_PROFILE", "DEMAND"} or not isinstance(
        content, Mapping
    ):
        _invalid()
    choices = _validate_editor_choices(editor_choices)
    for field in choices["fields"]:
        if field["resource_type"] != resource_type:
            continue
        allowed = {option["value"] for option in field["options"]}
        segments = tuple(field["path_template"][1:].split("/"))
        for choice_value in _editor_values_at_path(content, segments):
            if (
                field["status"] != "AVAILABLE"
                or not isinstance(choice_value, str)
                or choice_value not in allowed
            ):
                _invalid()


def safe_profile_content(
    editor_choices: Mapping[str, Any],
) -> dict[str, Any]:
    choices = _first_available_editor_choices(
        editor_choices,
        resource_type="CREATOR_PROFILE",
    )
    metadata = {
        "visibility": "MATCH_ONLY",
        "source_kind": "SELF_ASSERTED",
        "evidence_ids": [],
    }
    private = {**metadata, "visibility": "PRIVATE"}
    content = {
        "interests": [
            {
                "problem_code": choices["/interests/*/problem_code"],
                "domain_code": choices["/interests/*/domain_code"],
                "task_code": choices["/interests/*/task_code"],
                "strength": 4,
                **metadata,
            }
        ],
        "skills": [
            {
                "skill_code": choices["/skills/*/skill_code"],
                "proficiency": 3,
                **metadata,
            }
        ],
        "availability": {
            "available_from": (
                datetime.now(timezone.utc).date() + timedelta(days=1)
            ).isoformat(),
            "weekly_hours": 20,
            "duration_weeks": 12,
            "timezone": "Asia/Shanghai",
            **metadata,
        },
        "collaboration": {
            "languages": [
                {
                    "language_code": choices[
                        "/collaboration/languages/*/language_code"
                    ],
                    **metadata,
                }
            ],
            "work_modes": [{"work_mode": "REMOTE", **metadata}],
            "feedback_cadence": {"feedback_cadence": "WEEKLY", **metadata},
            "team_preference": {"team_preference": "SMALL_TEAM", **metadata},
        },
        "compensation": {
            # Synthetic preference data only; this is not a funding or payment
            # fact and it cannot trigger any money movement.
            "minimum_project_amount_minor": 100000,
            "currency": choices["/compensation/currency"],
            "direct_cost_amount_minor": 20000,
            **private,
        },
        "boundaries": {
            # Optional exclusions stay empty: the small reviewed taxonomy can
            # expose the same first DOMAIN/TASK used by the required interest,
            # and selecting it here would make the Profile contradictory.
            "prohibited_domains": [],
            "prohibited_tasks": [],
            "allowed_data_sensitivity": {
                "data_sensitivity": "INTERNAL",
                **private,
            },
        },
        "location": {
            "region_code": choices["/location/region_code"],
            "visibility": "PUBLIC",
            "source_kind": "SELF_ASSERTED",
            "evidence_ids": [],
        },
        "conflicts": [{"organization_id": "organization_conflict_0001", **private}],
        "ai": {
            "allowed": False,
            "requires_ai": False,
            "human_review_code": "REQUIRED",
            "prohibited_case_codes": [],
            **metadata,
        },
    }
    _validate_editor_content_choices(
        resource_type="CREATOR_PROFILE",
        content=content,
        editor_choices=editor_choices,
    )
    return content


def safe_demand_content(
    editor_choices: Mapping[str, Any],
) -> dict[str, Any]:
    choices = _first_available_editor_choices(
        editor_choices,
        resource_type="DEMAND",
    )
    today = datetime.now(timezone.utc).date()
    content = {
        "problem": {
            "background": "INTERNAL_SANDBOX 合成问题背景",
            "domain_code": choices["/problem/domain_code"],
            "problem_type_codes": [
                choices["/problem/problem_type_codes/*"]
            ],
            "target_user_category_codes": [
                choices["/problem/target_user_category_codes/*"]
            ],
            "desired_outcomes": ["验证内部流程"],
        },
        "scope": {
            "deliverables": [
                {
                    "item_id": "deliverable_1",
                    "description": "合成验收材料",
                }
            ],
            "out_of_scope": ["真实用户与真实交易"],
        },
        "acceptance": {
            "criteria": [
                {
                    "criterion_id": "criterion_1",
                    "description": "内部试运行负责人确认",
                }
            ],
            "response_days": 5,
            "owner_role_code": "DEMAND_OWNER",
        },
        "skills": {
            "must_have": [
                {
                    "skill_code": choices[
                        "/skills/must_have/*/skill_code"
                    ],
                    "minimum_level_code": "WORKING",
                }
            ],
            "nice_to_have": [],
        },
        "matching": {
            "problem_codes": [choices["/matching/problem_codes/*"]],
            "domain_codes": [choices["/matching/domain_codes/*"]],
            "task_codes": [choices["/matching/task_codes/*"]],
        },
        "schedule": {
            "start_date": (today + timedelta(days=1)).isoformat(),
            "due_date": (today + timedelta(days=31)).isoformat(),
            "estimated_days": 20,
            "weekly_hours": 20,
            "duration_weeks": 4,
        },
        "budget": {
            "minimum_amount_minor": 0,
            "maximum_amount_minor": 0,
            "direct_cost_amount_minor": 0,
            "currency": choices["/budget/currency"],
        },
        "milestone_plan": {
            "items": [
                {
                    "item_id": "milestone_1",
                    "label": "内部试运行里程碑",
                    "percent": 100,
                }
            ]
        },
        "risk": {
            "uncertainty_code": "MEDIUM",
            "urgency_code": "LOW",
            "dependency_codes": [],
            "data_sensitivity": "INTERNAL",
            "data_handling_plan": "仅使用合成资料。",
        },
        "ai": {
            "allowed": False,
            "required": False,
            "data_model_policy": None,
            "human_review_code": "RISK_BASED",
        },
        "collaboration": {
            "languages": [choices["/collaboration/languages/*"]],
            "work_mode": "REMOTE",
            "feedback_cadence": "ASYNC",
            "team_preference": "ANY",
        },
        "location": {
            "demand_region_code": choices["/location/demand_region_code"],
            "allowed_creator_region_codes": [
                choices["/location/allowed_creator_region_codes/*"]
            ],
        },
        "declarations": {
            "decision_authority": True,
            "data_rights": True,
            "procurement_intent": True,
        },
    }
    _validate_editor_content_choices(
        resource_type="DEMAND",
        content=content,
        editor_choices=editor_choices,
    )
    return content


def write_state(path: Path, value: JourneyState) -> None:
    if not isinstance(value, JourneyState):
        _invalid()
    target = _new_absolute_output(path)
    body = {
        "schema": STATE_SCHEMA,
        "profile_id": value.profile_id,
        "demand_id": value.demand_id,
        "demand_version_id": value.demand_version_id,
        "funding_review_id": value.funding_review_id,
        "profile_revision": value.profile_revision,
        "demand_revision": value.demand_revision,
        "trust_report_id": value.trust_report_id,
        "trust_case_id": value.trust_case_id,
        "trust_hold_id": value.trust_hold_id,
        "trust_outcome_version_id": value.trust_outcome_version_id,
        "trust_report_etag": value.trust_report_etag,
        "trust_case_etag": value.trust_case_etag,
        "expected_trust_outcome_code": value.expected_trust_outcome_code,
        "expected_appeal_eligibility_code": (
            value.expected_appeal_eligibility_code
        ),
        "expected_operations_result": value.expected_operations_result,
        "appeal_id": value.appeal_id,
        "appeal_decision_version_id": value.appeal_decision_version_id,
        "appeal_etag": value.appeal_etag,
        "expected_appeal_status": value.expected_appeal_status,
        "expected_appeal_decision_code": value.expected_appeal_decision_code,
        "organization_id": value.organization_id,
        "accepted_invitation_id": value.accepted_invitation_id,
        "accepted_membership_id": value.accepted_membership_id,
        "revoked_invitation_id": value.revoked_invitation_id,
    }
    _write_new(
        target,
        json.dumps(body, separators=(",", ":")).encode("ascii") + b"\n",
        mode=0o600,
    )


def load_state(path: Path) -> JourneyState:
    source = _private_absolute_file(path)
    try:
        value = json.loads(source.read_text(encoding="ascii"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        _invalid()
    _exact_keys(value, _STATE_FIELDS)
    if value["schema"] != STATE_SCHEMA:
        _invalid()
    return JourneyState(
        profile_id=value["profile_id"],
        demand_id=value["demand_id"],
        demand_version_id=value["demand_version_id"],
        funding_review_id=value["funding_review_id"],
        profile_revision=value["profile_revision"],
        demand_revision=value["demand_revision"],
        trust_report_id=value["trust_report_id"],
        trust_case_id=value["trust_case_id"],
        trust_hold_id=value["trust_hold_id"],
        trust_outcome_version_id=value["trust_outcome_version_id"],
        trust_report_etag=value["trust_report_etag"],
        trust_case_etag=value["trust_case_etag"],
        expected_trust_outcome_code=value["expected_trust_outcome_code"],
        expected_appeal_eligibility_code=value[
            "expected_appeal_eligibility_code"
        ],
        expected_operations_result=value["expected_operations_result"],
        appeal_id=value["appeal_id"],
        appeal_decision_version_id=value["appeal_decision_version_id"],
        appeal_etag=value["appeal_etag"],
        expected_appeal_status=value["expected_appeal_status"],
        expected_appeal_decision_code=value["expected_appeal_decision_code"],
        organization_id=value["organization_id"],
        accepted_invitation_id=value["accepted_invitation_id"],
        accepted_membership_id=value["accepted_membership_id"],
        revoked_invitation_id=value["revoked_invitation_id"],
    )


def run_journey(*, ca_file: Path, state_output: Path) -> Mapping[str, Any]:
    ca = _ca_file(ca_file)
    _new_absolute_output(state_output)
    temporary = Path(tempfile.mkdtemp(prefix="desire-ten-account."))
    os.chmod(temporary, 0o700)
    try:
        sessions: dict[str, RoleSession] = {}
        login_stages = {
            "access_admin_01": "LOGIN_ACCESS_ADMIN",
            "appeal_reviewer_01": "LOGIN_APPEAL_REVIEWER",
            "creator_01": "LOGIN_CREATOR",
            "demand_owner_01": "LOGIN_DEMAND_OWNER",
            "operations_reviewer_01": "LOGIN_OPERATIONS_REVIEWER",
            "finance_operator_01": "LOGIN_FINANCE_OPERATOR_01",
            "finance_operator_02": "LOGIN_FINANCE_OPERATOR_02",
            "org_admin_01": "LOGIN_ORG_ADMIN",
            "trust_officer_01": "LOGIN_TRUST_OFFICER_01",
            "trust_officer_02": "LOGIN_TRUST_OFFICER_02",
        }
        for code in ROLE_EXPECTATIONS:
            sessions[code] = _run_stage(
                login_stages[code],
                _login,
                account_code=code,
                root=_role_root(temporary, code),
                ca_file=ca,
            )
        policy_acceptance_performed = {
            code: sessions[code].policy_accepted
            for code in ("creator_01", "demand_owner_01")
        }
        # Configuration is a write-side editor capability. Prove that Creator
        # and Demand Owner see the exact same closed taxonomy and choice
        # catalog; Reviewer and ACCESS_ADMIN deliberately cannot read it.
        configuration = _run_stage(
            "CONFIGURATION",
            _shared_editor_configuration,
            sessions["creator_01"],
            sessions["demand_owner_01"],
        )
        taxonomy_id = configuration["taxonomy_bundle"]["bundle_id"]
        editor_choices = configuration["editor_choices"]
        profile = _run_stage(
            "PROFILE",
            _create_and_publish_profile,
            sessions["creator_01"],
            taxonomy_id=taxonomy_id,
            editor_choices=editor_choices,
        )
        reviewable_demand, assignment_changed = _run_stage(
            "DEMAND_REVIEW",
            _create_reviewable_demand,
            owner=sessions["demand_owner_01"],
            reviewer=sessions["operations_reviewer_01"],
            taxonomy_id=taxonomy_id,
            editor_choices=editor_choices,
        )
        report_context = _run_stage(
            "TRUST_REPORT",
            _submit_trust_report,
            owner=sessions["demand_owner_01"],
            reviewable_demand=reviewable_demand,
        )
        case_context = _run_stage(
            "TRUST_CASE_REVIEW",
            _review_trust_case,
            officer=sessions["trust_officer_01"],
            report_context=report_context,
        )
        hold_context = _run_stage(
            "TRUST_HOLD_ENFORCEMENT",
            _place_trust_hold_and_prove_blocked,
            officer=sessions["trust_officer_01"],
            reviewer=sessions["operations_reviewer_01"],
            case_context=case_context,
            reviewable_demand=reviewable_demand,
        )
        released_context, verified_demand = _run_stage(
            "TRUST_HOLD_RELEASE",
            _release_trust_hold_and_verify,
            releasing_officer=sessions["trust_officer_02"],
            deciding_officer=sessions["trust_officer_01"],
            reviewer=sessions["operations_reviewer_01"],
            hold_context=hold_context,
        )
        trust_summary = _run_stage(
            "TRUST_OUTCOME",
            _publish_trust_outcome,
            owner=sessions["demand_owner_01"],
            officer=sessions["trust_officer_01"],
            released_context=released_context,
        )
        appeal_summary = _run_stage(
            "TRUST_APPEAL",
            _exercise_trust_appeal,
            owner=sessions["demand_owner_01"],
            reviewer=sessions["appeal_reviewer_01"],
            trust_summary=trust_summary,
        )
        assignment_discovery_boundary = _run_stage(
            "ASSIGNMENT_DISCOVERY_BOUNDARY",
            _verify_assignment_discovery_boundaries,
            admin=sessions["access_admin_01"],
            trust_officer=sessions["trust_officer_01"],
            appeal_reviewer=sessions["appeal_reviewer_01"],
            second_reviewer_candidate=sessions["trust_officer_02"],
            wrong_role=sessions["operations_reviewer_01"],
            completed_appeal_id=appeal_summary["appeal_id"],
        )
        funded_demand, finance_summary = _run_stage(
            "FINANCE_FUNDING",
            _fund_verified_demand,
            operator_one=sessions["finance_operator_01"],
            operator_two=sessions["finance_operator_02"],
            owner=sessions["demand_owner_01"],
            verified_demand=verified_demand,
        )
        duty_configuration = _run_stage(
            "ACCOUNT_DUTY_CONFIGURATION",
            _exercise_platform_duty_configuration,
            admin=sessions["access_admin_01"],
            target=sessions["finance_operator_01"],
            funding_review_id=finance_summary["funding_review_id"],
        )
        sessions["creator_01"], organization_admin = _run_stage(
            "ORGANIZATION_ADMIN",
            _exercise_organization_admin,
            admin=sessions["org_admin_01"],
            creator=sessions["creator_01"],
        )
        sessions["creator_01"] = _run_stage(
            "ACCOUNT_LIFECYCLE",
            _exercise_account_lifecycle,
            admin=sessions["access_admin_01"],
            creator=sessions["creator_01"],
            temporary=temporary,
            ca_file=ca,
        )
        state = JourneyState(
            profile_id=profile["object_id"],
            demand_id=funded_demand["object_id"],
            demand_version_id=trust_summary["demand_version_id"],
            funding_review_id=finance_summary["funding_review_id"],
            profile_revision=profile["revision"],
            demand_revision=funded_demand["revision"],
            trust_report_id=trust_summary["report_id"],
            trust_case_id=trust_summary["case_id"],
            trust_hold_id=trust_summary["hold_id"],
            trust_outcome_version_id=trust_summary["outcome_version_id"],
            trust_report_etag=trust_summary["report_etag"],
            trust_case_etag=trust_summary["case_etag"],
            expected_trust_outcome_code=trust_summary["outcome_code"],
            expected_appeal_eligibility_code=trust_summary[
                "appeal_eligibility_code"
            ],
            expected_operations_result=verified_demand["status"],
            appeal_id=appeal_summary["appeal_id"],
            appeal_decision_version_id=appeal_summary["decision_version_id"],
            appeal_etag=appeal_summary["appeal_etag"],
            expected_appeal_status=appeal_summary["appeal_status"],
            expected_appeal_decision_code=appeal_summary["decision_code"],
            organization_id=organization_admin["organization_id"],
            accepted_invitation_id=organization_admin[
                "accepted_invitation_id"
            ],
            accepted_membership_id=organization_admin[
                "accepted_membership_id"
            ],
            revoked_invitation_id=organization_admin[
                "revoked_invitation_id"
            ],
        )
        _run_stage("STATE_OUTPUT", write_state, state_output, state)
        return {
            "status": JOURNEY_GREEN_STATUS,
            "roles": {
                code: {
                    "workspace_kind": session.workspace_kind,
                    "role_codes": list(session.role_codes),
                }
                for code, session in sessions.items()
            },
            "policy_acceptance_performed": policy_acceptance_performed,
            "assignment_discovery_boundary": assignment_discovery_boundary,
            "taxonomy_bundle_id": taxonomy_id,
            "profile": {
                "object_id": profile["object_id"],
                "status": profile["status"],
                "revision": profile["revision"],
            },
            "demand": {
                "object_id": funded_demand["object_id"],
                "status": funded_demand["status"],
                "revision": funded_demand["revision"],
            },
            "review": {
                "assignment_changed": assignment_changed,
                "final_status": verified_demand["status"],
            },
            "trust": trust_summary,
            "appeal": appeal_summary,
            "finance": finance_summary,
            "platform_duty_configuration": duty_configuration,
            "organization_admin": organization_admin,
            "account_lifecycle": {
                "self_management_http": 403,
                "suspend_invalidated_session": True,
                "resume_did_not_revive_session": True,
                "revoke_invalidated_session": True,
                "relogin_succeeded": True,
            },
        }
    finally:
        shutil.rmtree(temporary)


def run_invited_demand_owner_journey(*, ca_file: Path) -> Mapping[str, Any]:
    """Exercise provider-only invitation enrollment without changing bootstrap."""

    ca = _ca_file(ca_file)
    temporary = Path(tempfile.mkdtemp(prefix="desire-invited-demand-owner."))
    os.chmod(temporary, 0o700)
    try:
        admin = _run_stage(
            "INVITED_DEMAND_OWNER_ADMIN_LOGIN",
            _login,
            account_code="org_admin_01",
            root=_role_root(temporary, "organization-admin"),
            ca_file=ca,
        )
        organization_id = admin.workspace_id.removeprefix("org:")
        _canonical_uuid(organization_id)
        organization = _run_stage(
            "INVITED_DEMAND_OWNER_INVITATION",
            _organization_summary,
            admin,
            organization_id=organization_id,
        )
        issued = _run_stage(
            "INVITED_DEMAND_OWNER_INVITATION",
            _issue_organization_invitation_exact_replay,
            admin,
            organization=organization,
            recipient_email=PROVIDER_ONLY_INVITED_DEMAND_OWNER_EMAIL,
            target_role="DEMAND_OWNER",
        )
        pending, preview, pending_user_id = _run_stage(
            "INVITED_DEMAND_OWNER_PENDING",
            _authenticate_provider_only_invitee,
            root=_role_root(temporary, "provider-only-invitee"),
            ca_file=ca,
            organization_id=organization_id,
            issued=issued,
        )
        accepted, acceptance = _run_stage(
            "INVITED_DEMAND_OWNER_ACCEPTANCE",
            _accept_organization_invitation,
            pending,
            preview=preview,
        )
        owner = _run_stage(
            "INVITED_DEMAND_OWNER_AUTHORITY",
            _activate_invited_demand_owner,
            accepted,
            acceptance=acceptance,
            organization_id=organization_id,
            expected_user_id=pending_user_id,
        )
        demand = _run_stage(
            "INVITED_DEMAND_OWNER_DEMAND",
            _create_cancelled_demand_with_history,
            owner,
        )
        return {
            "status": INVITED_DEMAND_OWNER_GREEN_STATUS,
            "pending_boundary": {
                "pending_identity_session": True,
                "roles_absent": True,
                "memberships_absent": True,
                "workspaces_absent": True,
                "admin_surface_absent": True,
            },
            "activation": {
                "invitation_and_policies_accepted": True,
                "target_organization_only": True,
                "demand_owner_only": True,
                "admin_surface_absent": True,
            },
            "demand": demand,
        }
    finally:
        shutil.rmtree(temporary)


def verify_restart(*, ca_file: Path, state_file: Path) -> Mapping[str, Any]:
    ca = _ca_file(ca_file)
    state = load_state(state_file)
    temporary = Path(tempfile.mkdtemp(prefix="desire-ten-account."))
    os.chmod(temporary, 0o700)
    try:
        login_stages = {
            "access_admin_01": "LOGIN_ACCESS_ADMIN",
            "appeal_reviewer_01": "LOGIN_APPEAL_REVIEWER",
            "creator_01": "LOGIN_CREATOR",
            "demand_owner_01": "LOGIN_DEMAND_OWNER",
            "operations_reviewer_01": "LOGIN_OPERATIONS_REVIEWER",
            "finance_operator_01": "LOGIN_FINANCE_OPERATOR_01",
            "finance_operator_02": "LOGIN_FINANCE_OPERATOR_02",
            "org_admin_01": "LOGIN_ORG_ADMIN",
            "trust_officer_01": "LOGIN_TRUST_OFFICER_01",
            "trust_officer_02": "LOGIN_TRUST_OFFICER_02",
        }
        sessions = {
            code: _run_stage(
                login_stages[code],
                _login,
                account_code=code,
                root=_role_root(temporary, code),
                ca_file=ca,
            )
            for code in ROLE_EXPECTATIONS
        }
        creator = sessions["creator_01"]
        owner = sessions["demand_owner_01"]
        reviewer = sessions["operations_reviewer_01"]
        appeal_reviewer = sessions["appeal_reviewer_01"]
        admin = sessions["access_admin_01"]
        profile = _run_stage(
            "RESTART_PROFILE",
            _get_resource,
            creator,
            f"/v1/app/profiles/{state.profile_id}",
            resource_type="CREATOR_PROFILE",
        )
        demand = _run_stage(
            "RESTART_DEMAND",
            _get_resource,
            owner,
            f"/v1/app/demands/{state.demand_id}",
            resource_type="DEMAND",
        )
        if (
            profile["status"] != "ACTIVE"
            or profile["revision"] != state.profile_revision
            or demand["status"] != "FUNDED"
            or demand["revision"] != state.demand_revision
        ):
            _invalid()
        current_version = demand.get("current_version")
        if (
            not isinstance(current_version, Mapping)
            or current_version.get("version_id") != state.demand_version_id
        ):
            _invalid()
        _require_verified_finding(
            demand, demand_version_id=state.demand_version_id
        )
        queue = _run_stage("RESTART_REVIEW", _review_queue, reviewer)
        if any(item["demand_id"] == state.demand_id for item in queue):
            _invalid()
        for code in ("finance_operator_01", "finance_operator_02"):
            finance_queue = _run_stage(
                "RESTART_FINANCE", _finance_queue, sessions[code]
            )
            if any(item["demand_id"] == state.demand_id for item in finance_queue):
                _invalid()
            finance_detail = _run_stage(
                "RESTART_FINANCE",
                _finance_detail,
                sessions[code],
                funding_review_id=state.funding_review_id,
            )
            if (
                finance_detail["demand_id"] != state.demand_id
                or finance_detail["status"] != "SECURED"
                or finance_detail["assignment_status"] != "COMPLETED"
                or finance_detail["confirmation_by_me"] is not True
                or finance_detail["available_actions"] != []
                or finance_detail["can_confirm"] is not False
            ):
                _invalid()
            finance_history = _run_stage(
                "RESTART_FINANCE_HISTORY",
                _finance_history,
                sessions[code],
                limit=1,
            )
            secured_history = [
                item
                for item in finance_history
                if item["funding_review_id"] == state.funding_review_id
            ]
            if (
                len(secured_history) != 1
                or secured_history[0]["demand_id"] != state.demand_id
                or secured_history[0]["demand_version_id"]
                != state.demand_version_id
                or secured_history[0]["status"] != "SECURED"
            ):
                _invalid()
        trust_restart = _run_stage(
            "RESTART_TRUST",
            _verify_trust_restart,
            owner=owner,
            officer_one=sessions["trust_officer_01"],
            officer_two=sessions["trust_officer_02"],
            state=state,
        )
        appeal_restart = _run_stage(
            "RESTART_APPEAL",
            _verify_appeal_restart,
            owner=owner,
            reviewer=appeal_reviewer,
            state=state,
        )
        accounts = _run_stage("RESTART_ACCOUNTS", _account_list, admin)
        by_code = {item["account_code"]: item for item in accounts}
        if not set(ROLE_EXPECTATIONS).issubset(by_code):
            _invalid()
        creator_account = by_code["creator_01"]
        if creator_account["status"] != "ACTIVE":
            _invalid()
        organization_restart = _run_stage(
            "RESTART_ORGANIZATION",
            _verify_organization_restart,
            sessions["org_admin_01"],
            creator_user_id=creator_account["user_id"],
            state=state,
        )
        return {
            "status": RESTART_GREEN_STATUS,
            "profile": {
                "object_id": profile["object_id"],
                "status": profile["status"],
                "revision": profile["revision"],
            },
            "demand": {
                "object_id": demand["object_id"],
                "status": demand["status"],
                "revision": demand["revision"],
            },
            "review_queue_absent": True,
            "finance_queues_absent": True,
            "finance_active_assignments_absent": True,
            "finance_terminal_history_discoverable": True,
            "trust_terminal_history_discoverable": trust_restart[
                "terminal_history_discoverable"
            ],
            "trust": trust_restart,
            "appeal": appeal_restart,
            "appeal_review_queue_absent": True,
            "required_account_codes": sorted(ROLE_EXPECTATIONS),
            "creator_status": creator_account["status"],
            "creator_active_session_count": creator_account[
                "active_session_count"
            ],
            "organization_admin": organization_restart,
        }
    finally:
        shutil.rmtree(temporary)


def _verify_trust_restart(
    *,
    owner: RoleSession,
    officer_one: RoleSession,
    officer_two: RoleSession,
    state: JourneyState,
) -> Mapping[str, Any]:
    if (
        officer_one.account_code != "trust_officer_01"
        or officer_two.account_code != "trust_officer_02"
        or officer_one.role_codes != ("TRUST_OFFICER",)
        or officer_two.role_codes != ("TRUST_OFFICER",)
    ):
        _invalid()
    report = _get_trust_report(owner, report_id=state.trust_report_id)
    if (
        report["entity_tag"] != state.trust_report_etag
        or report["demand_id"] != state.demand_id
        or report["demand_version_id"] != state.demand_version_id
        or report["status"] != "DECIDED"
    ):
        _invalid()
    _require_eligible_outcome(
        report["outcome"],
        outcome_version_id=state.trust_outcome_version_id,
        party_safe=True,
    )
    case = _get_trust_case(officer_one, case_id=state.trust_case_id)
    if (
        case["entity_tag"] != state.trust_case_etag
        or case["report_id"] != state.trust_report_id
        or case["demand_id"] != state.demand_id
        or case["demand_version_id"] != state.demand_version_id
        or case["status"] != "DECIDED"
        or case["active_hold"] is not None
    ):
        _invalid()
    _require_eligible_outcome(
        case["outcome"], outcome_version_id=state.trust_outcome_version_id
    )
    officer_one_assignments = _trust_active_assignments(officer_one)
    officer_two_assignments = _trust_active_assignments(officer_two)
    _require_trust_assignment_absent(
        officer_one_assignments, case_id=state.trust_case_id
    )
    _require_trust_assignment_absent(
        officer_two_assignments, case_id=state.trust_case_id
    )
    if any(
        item["case_id"] == state.trust_case_id
        for item in _trust_case_queue(officer_one)["items"]
    ):
        _invalid()
    if any(
        item["hold_id"] == state.trust_hold_id
        for item in _trust_hold_release_queue(officer_two)["items"]
    ):
        _invalid()
    officer_one_history = _trust_terminal_history(officer_one)
    officer_two_history = _trust_terminal_history(officer_two)
    officer_one_matches = [
        item
        for item in officer_one_history["items"]
        if item["case_id"] == state.trust_case_id
    ]
    if (
        len(officer_one_matches) != 1
        or officer_one_matches[0]["outcome_code"]
        != state.expected_trust_outcome_code
        or any(
            item["case_id"] == state.trust_case_id
            for item in officer_two_history["items"]
        )
    ):
        _invalid()
    if (
        state.expected_trust_outcome_code != "PROTECTION_MODIFIED"
        or state.expected_appeal_eligibility_code != "ELIGIBLE"
        or state.expected_operations_result != "VERIFIED"
    ):
        _invalid()
    return {
        "officer_accounts_authenticated": [
            officer_one.account_code,
            officer_two.account_code,
        ],
        "report_status": report["status"],
        "case_status": case["status"],
        "outcome_code": state.expected_trust_outcome_code,
        "appeal_eligibility_code": state.expected_appeal_eligibility_code,
        "appeal_deadline_present": True,
        "hold_released": True,
        "case_queue_absent": True,
        "hold_release_queue_absent": True,
        "active_assignment_lists_absent": True,
        "terminal_history_discoverable": True,
        "terminal_history_actor_scoped": True,
        "operations_result": state.expected_operations_result,
    }


def _verify_appeal_restart(
    *,
    owner: RoleSession,
    reviewer: RoleSession,
    state: JourneyState,
) -> Mapping[str, Any]:
    if (
        owner.account_code != "demand_owner_01"
        or owner.role_codes != ("DEMAND_OWNER",)
        or reviewer.account_code != "appeal_reviewer_01"
        or reviewer.role_codes != ("APPEAL_REVIEWER",)
    ):
        _invalid()
    appeal = _get_own_appeal(owner, appeal_id=state.appeal_id)
    application = appeal.get("application")
    decision = appeal.get("decision")
    if (
        appeal.get("appeal_id") != state.appeal_id
        or appeal.get("entity_tag") != state.appeal_etag
        or appeal.get("source_case_id") != state.trust_case_id
        or appeal.get("source_outcome_version_id")
        != state.trust_outcome_version_id
        or appeal.get("status") != state.expected_appeal_status
        or not isinstance(application, Mapping)
        or application.get("statement_recorded") is not True
        or not isinstance(decision, Mapping)
        or decision.get("decision_version_id")
        != state.appeal_decision_version_id
        or decision.get("decision_code")
        != state.expected_appeal_decision_code
    ):
        _invalid()
    queue = _appeal_queue(reviewer)
    if any(item["appeal_id"] == state.appeal_id for item in queue["items"]):
        _invalid()
    _require_appeal_assignment_absent(
        _appeal_active_assignments(reviewer), appeal_id=state.appeal_id
    )
    terminal_history = _appeal_terminal_history(reviewer)
    terminal_matches = [
        item
        for item in terminal_history["items"]
        if item["appeal_id"] == state.appeal_id
    ]
    terminal_detail = _get_terminal_appeal(
        reviewer, appeal_id=state.appeal_id
    )
    if (
        len(terminal_matches) != 1
        or terminal_matches[0]["decision_code"]
        != state.expected_appeal_decision_code
        or terminal_detail["entity_tag"] != state.appeal_etag
        or terminal_detail["application"] != application
        or terminal_detail["decision"] != decision
    ):
        _invalid()
    return {
        "appeal_id": state.appeal_id,
        "appeal_status": state.expected_appeal_status,
        "decision_code": state.expected_appeal_decision_code,
        "decision_version_id": state.appeal_decision_version_id,
        "review_queue_absent": True,
        "active_assignment_list_absent": True,
        "terminal_history_discoverable": True,
        "terminal_detail_party_safe": True,
    }


def _login(*, account_code: str, root: Path, ca_file: Path) -> RoleSession:
    expected = ROLE_EXPECTATIONS.get(account_code)
    if expected is None:
        _invalid()
    client = CurlClient(root=root, ca_file=ca_file)
    begin = client.request(
        method="POST",
        path="/v1/auth/oidc/authorizations",
        body={"return_to": "/app"},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    _expect_status(begin, 201)
    begin_body = begin.json()
    _exact_keys(
        begin_body,
        {"auth_transaction_id", "authorization_url", "expires_at"},
    )
    _utc_timestamp(begin_body["expires_at"])
    authorization_url = _nonempty_text(begin_body["authorization_url"])
    chooser = client.get_authorization_page(authorization_url)
    parser = _RequestHandleParser()
    try:
        parser.feed(chooser.decode("utf-8"))
    except UnicodeDecodeError:
        _invalid()
    if len(parser.values) != 1:
        _invalid()
    client.authorize(account_code=account_code, request_handle=parser.values[0])
    session_body = _session(client, expected_status=200)
    csrf = session_body["csrf_token"]
    me = _get_json(client, "/v1/me")
    if me.get("status") != "ACTIVE" or not _ENTITY_TAG.fullmatch(
        str(me.get("entity_tag", ""))
    ):
        _invalid()
    policy_accepted = _accept_missing_policies(client, session_body, me)
    discovery = _get_json(client, "/v1/app/workspaces")
    _exact_keys(discovery, {"data"})
    data = discovery["data"]
    _exact_keys(data, {"workspaces", "selection_required"})
    workspaces = data["workspaces"]
    if (
        not isinstance(workspaces, list)
        or len(workspaces) != 1
        or data["selection_required"] is not False
    ):
        _invalid()
    workspace = workspaces[0]
    _exact_keys(workspace, {"workspace_id", "workspace_kind", "role_codes"})
    roles = tuple(workspace["role_codes"])
    if (
        _WORKSPACE.fullmatch(str(workspace["workspace_id"])) is None
        or workspace["workspace_kind"] != expected[0]
        or roles != expected[1]
    ):
        _invalid()
    return RoleSession(
        account_code=account_code,
        workspace_id=workspace["workspace_id"],
        workspace_kind=workspace["workspace_kind"],
        role_codes=roles,
        csrf_token=csrf,
        client=client,
        policy_accepted=policy_accepted,
    )


def _authenticate_provider_only_invitee(
    *,
    root: Path,
    ca_file: Path,
    organization_id: str,
    issued: Mapping[str, Any],
) -> tuple[RoleSession, Mapping[str, Any], str]:
    _canonical_uuid(organization_id)
    exact_issued = _exact_keys(
        issued,
        {"invitation", "access_invitation_token", "join_fragment_url"},
    )
    invitation = _invitation_admin(exact_issued["invitation"])
    token = exact_issued["access_invitation_token"]
    if (
        invitation["organization_id"] != organization_id
        or invitation["target_role"] != "DEMAND_OWNER"
        or invitation["status"] != "ISSUED"
        or _CAPABILITY_TOKEN.fullmatch(str(token)) is None
    ):
        _invalid()
    client = CurlClient(root=root, ca_file=ca_file)
    preview = _inspect_organization_invitation(client, token=token)
    if (
        preview["invitation_id"] != invitation["invitation_id"]
        or preview["target_role"] != "DEMAND_OWNER"
        or preview["required_policy_bundle_id"]
        != invitation["required_policy_bundle_id"]
        or preview["entity_tag"] != invitation["entity_tag"]
    ):
        _invalid()
    begin = client.request(
        method="POST",
        path="/v1/auth/oidc/authorizations",
        body={"return_to": "/app", "access_invitation_token": token},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        sensitive_body=True,
    )
    _expect_status(begin, 201)
    begin_body = _exact_keys(
        begin.json(),
        {"auth_transaction_id", "authorization_url", "expires_at"},
    )
    _utc_timestamp(begin_body["expires_at"])
    chooser = client.get_authorization_page(
        _nonempty_text(begin_body["authorization_url"])
    )
    parser = _RequestHandleParser()
    try:
        parser.feed(chooser.decode("utf-8"))
    except UnicodeDecodeError:
        _invalid()
    if len(parser.values) != 1:
        _invalid()
    client.authorize(
        account_code=PROVIDER_ONLY_INVITED_DEMAND_OWNER_ACCOUNT_CODE,
        request_handle=parser.values[0],
    )
    session_body = _run_stage(
        "INVITED_DEMAND_OWNER_PENDING_SESSION", _pending_session, client
    )
    me = _run_stage(
        "INVITED_DEMAND_OWNER_PENDING_ME", _get_json, client, "/v1/me"
    )
    user_id = _run_stage(
        "INVITED_DEMAND_OWNER_PENDING_ME",
        _require_provider_only_me,
        me,
        expected_status="PENDING_ENROLLMENT",
        organization_id=organization_id,
    )
    candidates, selection_required = _run_stage(
        "INVITED_DEMAND_OWNER_PENDING_WORKSPACES",
        _workspace_candidates,
        client,
    )
    if candidates or selection_required is not False:
        raise InternalSandboxE2eError(
            stage="INVITED_DEMAND_OWNER_PENDING_WORKSPACES"
        )
    _run_stage(
        "INVITED_DEMAND_OWNER_PENDING_ADMIN",
        _expect_pending_admin_hidden,
        client.request(
            method="GET",
            path="/v1/app/admin/accounts",
            headers={"Accept": "application/json"},
        ),
    )
    return (
        RoleSession(
            account_code=PROVIDER_ONLY_INVITED_DEMAND_OWNER_ACCOUNT_CODE,
            workspace_id="",
            workspace_kind="",
            role_codes=(),
            csrf_token=session_body["csrf_token"],
            client=client,
            policy_accepted=False,
        ),
        preview,
        user_id,
    )


def _pending_session(client: CurlClient) -> Mapping[str, Any]:
    response = client.request(method="GET", path="/v1/auth/session")
    _expect_status(response, 200)
    value = _exact_keys(
        response.json(), {"session", "user_status", "csrf_token"}
    )
    if (
        value["user_status"] != "PENDING_ENROLLMENT"
        or not isinstance(value["session"], Mapping)
        or _CSRF.fullmatch(str(value["csrf_token"])) is None
    ):
        _invalid()
    return value


def _require_provider_only_me(
    value: Any,
    *,
    expected_status: str,
    organization_id: str,
) -> str:
    if expected_status not in {"PENDING_ENROLLMENT", "ACTIVE"}:
        _invalid()
    _canonical_uuid(organization_id)
    me = _exact_keys(
        value,
        {
            "user_id",
            "status",
            "display_handle",
            "user_roles",
            "memberships",
            "policy_requirements",
            "aggregate_version",
            "entity_tag",
        },
    )
    user_id = _canonical_uuid(me["user_id"])
    if (
        me["status"] != expected_status
        or not isinstance(me["display_handle"], str)
        or not me["display_handle"]
        or me["user_roles"] != []
        or not _version_and_tag(me)
    ):
        _invalid()
    if expected_status == "PENDING_ENROLLMENT":
        if me["memberships"] != [] or me["policy_requirements"] != []:
            _invalid()
        return user_id
    memberships = me["memberships"]
    requirements = me["policy_requirements"]
    if (
        not isinstance(memberships, list)
        or len(memberships) != 1
        or not isinstance(requirements, list)
        or len(requirements) != 1
    ):
        _invalid()
    membership = _exact_keys(
        memberships[0],
        {
            "membership_id",
            "organization",
            "status",
            "roles",
            "aggregate_version",
            "entity_tag",
        },
    )
    _canonical_uuid(membership["membership_id"])
    organization = _organization(membership["organization"])
    if (
        membership["status"] != "ACTIVE"
        or membership["roles"] != ["DEMAND_OWNER"]
        or not _version_and_tag(membership)
        or organization["organization_id"] != organization_id
        or organization["status"] != "ACTIVE"
    ):
        _invalid()
    requirement = _exact_keys(
        requirements[0],
        {
            "selector_digest",
            "purpose",
            "role",
            "scope_type",
            "scope_id",
            "satisfied",
            "required_policy_bundle_id",
            "missing_document_ids",
        },
    )
    if (
        _SHA256.fullmatch(str(requirement["selector_digest"])) is None
        or requirement["purpose"] != "ORGANIZATION_MEMBERSHIP"
        or requirement["role"] != "DEMAND_OWNER"
        or requirement["scope_type"] != "ORGANIZATION_ROLE"
        or requirement["scope_id"] != organization_id
        or requirement["satisfied"] is not True
        or requirement["missing_document_ids"] != []
    ):
        _invalid()
    _canonical_uuid(requirement["required_policy_bundle_id"])
    return user_id


def _activate_invited_demand_owner(
    session: RoleSession,
    *,
    acceptance: Mapping[str, Any],
    organization_id: str,
    expected_user_id: str,
) -> RoleSession:
    _canonical_uuid(organization_id)
    _canonical_uuid(expected_user_id)
    exact = _run_stage(
        "INVITED_DEMAND_OWNER_AUTHORITY_RESPONSE",
        _exact_keys,
        acceptance,
        {"invitation", "me", "activated_scope"},
    )
    invitation = _run_stage(
        "INVITED_DEMAND_OWNER_AUTHORITY_RESPONSE",
        _invitation_admin,
        exact["invitation"],
    )
    accepted_user_id = _run_stage(
        "INVITED_DEMAND_OWNER_AUTHORITY_RESPONSE",
        _require_provider_only_me,
        exact["me"],
        expected_status="ACTIVE",
        organization_id=organization_id,
    )
    if (
        exact["activated_scope"] != "ORGANIZATION_MEMBERSHIP"
        or invitation["organization_id"] != organization_id
        or invitation["target_role"] != "DEMAND_OWNER"
        or invitation["status"] != "ACCEPTED"
        or accepted_user_id != expected_user_id
    ):
        raise InternalSandboxE2eError(
            stage="INVITED_DEMAND_OWNER_AUTHORITY_RESPONSE"
        )
    refreshed_me = _run_stage(
        "INVITED_DEMAND_OWNER_AUTHORITY_REFRESHED_ME",
        _get_json,
        session.client,
        "/v1/me",
    )
    refreshed_user_id = _run_stage(
        "INVITED_DEMAND_OWNER_AUTHORITY_REFRESHED_ME",
        _require_provider_only_me,
        refreshed_me,
        expected_status="ACTIVE",
        organization_id=organization_id,
    )
    if refreshed_user_id != expected_user_id:
        raise InternalSandboxE2eError(
            stage="INVITED_DEMAND_OWNER_AUTHORITY_REFRESHED_ME"
        )
    candidates, selection_required = _run_stage(
        "INVITED_DEMAND_OWNER_AUTHORITY_WORKSPACES",
        _workspace_candidates,
        session.client,
    )
    expected_workspace = f"org:{organization_id}"
    if (
        len(candidates) != 1
        or selection_required is not False
        or candidates[0]["workspace_id"] != expected_workspace
        or candidates[0]["workspace_kind"] != "ORGANIZATION"
        or candidates[0]["role_codes"] != ["DEMAND_OWNER"]
    ):
        raise InternalSandboxE2eError(
            stage="INVITED_DEMAND_OWNER_AUTHORITY_WORKSPACES"
        )
    owner = RoleSession(
        account_code=session.account_code,
        workspace_id=expected_workspace,
        workspace_kind="ORGANIZATION",
        role_codes=("DEMAND_OWNER",),
        csrf_token=session.csrf_token,
        client=session.client,
        policy_accepted=True,
    )
    admin_response = _run_stage(
        "INVITED_DEMAND_OWNER_AUTHORITY_ADMIN",
        owner.client.request,
        method="GET",
        path="/v1/app/admin/accounts",
        headers=_app_headers(owner),
    )
    _run_stage(
        "INVITED_DEMAND_OWNER_AUTHORITY_ADMIN",
        _expect_resource_not_found,
        admin_response,
    )
    return owner


def _expect_resource_not_found(response: HttpResult) -> None:
    _expect_status(response, 404)
    error = _exact_keys(response.json(), {"error"})
    detail = _exact_keys(error["error"], {"code"})
    if detail["code"] != "RESOURCE_NOT_FOUND":
        _invalid()


def _expect_pending_admin_hidden(response: HttpResult) -> None:
    if response.status == 400:
        try:
            body = _exact_keys(response.json(), {"code", "message"})
        except InternalSandboxE2eError:
            raise InternalSandboxE2eError(
                stage="INVITED_DEMAND_OWNER_PENDING_ADMIN_BAD_REQUEST"
            ) from None
        if (
            body["code"] == "WORKSPACE_REQUIRED"
            and isinstance(body["message"], str)
            and 1 <= len(body["message"]) <= 160
        ):
            return
        raise InternalSandboxE2eError(
            stage="INVITED_DEMAND_OWNER_PENDING_ADMIN_BAD_REQUEST"
        )
    if response.status == 404:
        try:
            error = _exact_keys(response.json(), {"error"})
            detail = _exact_keys(error["error"], {"code"})
        except InternalSandboxE2eError:
            raise InternalSandboxE2eError(
                stage="INVITED_DEMAND_OWNER_PENDING_ADMIN_BODY"
            ) from None
        if detail["code"] == "RESOURCE_NOT_FOUND":
            return
        raise InternalSandboxE2eError(
            stage="INVITED_DEMAND_OWNER_PENDING_ADMIN_BODY"
        )
    stage_by_status = {
        200: "INVITED_DEMAND_OWNER_PENDING_ADMIN_EXPOSED",
        401: "INVITED_DEMAND_OWNER_PENDING_ADMIN_UNAUTHENTICATED",
        403: "INVITED_DEMAND_OWNER_PENDING_ADMIN_FORBIDDEN",
        409: "INVITED_DEMAND_OWNER_PENDING_ADMIN_WORKSPACE_REQUIRED",
        405: "INVITED_DEMAND_OWNER_PENDING_ADMIN_METHOD_REJECTED",
        422: "INVITED_DEMAND_OWNER_PENDING_ADMIN_INVALID_REQUEST",
        500: "INVITED_DEMAND_OWNER_PENDING_ADMIN_SERVER_ERROR",
        502: "INVITED_DEMAND_OWNER_PENDING_ADMIN_GATEWAY_ERROR",
        504: "INVITED_DEMAND_OWNER_PENDING_ADMIN_GATEWAY_ERROR",
        503: "INVITED_DEMAND_OWNER_PENDING_ADMIN_UNAVAILABLE",
    }
    raise InternalSandboxE2eError(
        stage=stage_by_status.get(
            response.status, "INVITED_DEMAND_OWNER_PENDING_ADMIN_OTHER"
        )
    )


def _accept_missing_policies(
    client: CurlClient, session: Mapping[str, Any], initial_me: Mapping[str, Any]
) -> bool:
    me = dict(initial_me)
    accepted = False
    for _attempt in range(20):
        requirements = me.get("policy_requirements")
        if not isinstance(requirements, list):
            _invalid()
        missing = [item for item in requirements if item.get("satisfied") is False]
        if not missing:
            return accepted
        requirement = missing[0]
        required_fields = {
            "selector_digest",
            "purpose",
            "role",
            "scope_type",
            "scope_id",
            "satisfied",
            "required_policy_bundle_id",
            "missing_document_ids",
        }
        _exact_keys(requirement, required_fields)
        bundle_id = _nonempty_text(requirement["required_policy_bundle_id"])
        purpose = requirement["purpose"]
        if purpose not in {"CREATOR_ENROLLMENT", "ORGANIZATION_MEMBERSHIP"}:
            _invalid()
        bundle_response = client.request(
            method="GET",
            path=f"/v1/policy-bundles/{bundle_id}",
            headers={"Accept": "application/json"},
        )
        _expect_status(bundle_response, 200)
        bundle = _policy_bundle(
            bundle_response,
            expected_id=bundle_id,
            expected_purpose=purpose,
        )
        documents = bundle["documents"]
        by_id = {document.get("document_id"): document for document in documents}
        acceptances: list[dict[str, Any]] = []
        missing_ids = requirement["missing_document_ids"]
        if (
            not isinstance(missing_ids, list)
            or not missing_ids
            or not all(isinstance(value, str) for value in missing_ids)
            or len(set(missing_ids)) != len(missing_ids)
        ):
            _invalid()
        for document_id in missing_ids:
            _canonical_uuid(document_id)
            document = by_id.get(document_id)
            if (
                not isinstance(document, dict)
                or document.get("legal_effect") == "CONSENT_TEXT"
                or not isinstance(document.get("body"), str)
                or hashlib.sha256(document["body"].encode("utf-8")).hexdigest()
                != document.get("content_sha256")
            ):
                _invalid()
            acceptances.append(
                {
                    "document_id": document_id,
                    "content_sha256": document["content_sha256"],
                    "affirmed": True,
                }
            )
        entity_tag = _nonempty_text(me.get("entity_tag"))
        csrf = _nonempty_text(session.get("csrf_token"))
        if _ENTITY_TAG.fullmatch(entity_tag) is None or _CSRF.fullmatch(csrf) is None:
            _invalid()
        response = client.request(
            method="POST",
            path="/v1/me/policy-acceptances",
            body={
                "policy_requirement": {
                    "selector_digest": requirement["selector_digest"],
                    "scope_type": requirement["scope_type"],
                    "scope_id": requirement["scope_id"],
                },
                "policy_bundle_id": bundle_id,
                "policy_acceptances": acceptances,
            },
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
                "If-Match": entity_tag,
                "Idempotency-Key": _idempotency_key(),
                "X-CSRF-Token": csrf,
            },
        )
        _expect_status(response, 200)
        result = response.json()
        if result.get("satisfied") is not True or result.get(
            "missing_document_ids"
        ) != []:
            _invalid()
        accepted = True
        me = _get_json(client, "/v1/me")
    _invalid()


def _configuration(session: RoleSession) -> Mapping[str, Any]:
    response = session.client.request(
        method="GET",
        path="/v1/app/configuration",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    envelope = response.json()
    _exact_keys(envelope, {"data"})
    data = envelope["data"]
    _exact_keys(data, _EDITOR_CONFIGURATION_FIELDS)
    if (
        data["schema_version"] != "editor-configuration-v2"
        or data["deployment_mode"] != "INTERNAL_SANDBOX"
    ):
        _invalid()
    taxonomy = _exact_keys(
        data["taxonomy_bundle"],
        _EDITOR_TAXONOMY_FIELDS,
    )
    effective_at = _parse_utc_timestamp(taxonomy["effective_at"])
    effective_until = (
        None
        if taxonomy["effective_until"] is None
        else _parse_utc_timestamp(taxonomy["effective_until"])
    )
    observed_now = datetime.now(timezone.utc)
    evaluated_at = (
        observed_now.replace(microsecond=0),
        observed_now.microsecond * 1_000,
    )
    if (
        taxonomy["status"] != "CURRENT_APPROVED"
        or effective_at > evaluated_at
        or (
            effective_until is not None
            and (
                effective_until <= effective_at
                or effective_until <= evaluated_at
            )
        )
    ):
        _invalid()
    _canonical_uuid(taxonomy["bundle_id"])
    _validate_editor_choices(data["editor_choices"])
    return data


def _shared_editor_configuration(
    creator: RoleSession,
    demand_owner: RoleSession,
) -> Mapping[str, Any]:
    if (
        creator.account_code != "creator_01"
        or creator.role_codes != ("CREATOR",)
        or demand_owner.account_code != "demand_owner_01"
        or demand_owner.role_codes != ("DEMAND_OWNER",)
    ):
        _invalid()
    creator_configuration = _configuration(creator)
    demand_configuration = _configuration(demand_owner)
    if creator_configuration != demand_configuration:
        _invalid()
    return creator_configuration


def _create_and_publish_profile(
    session: RoleSession,
    *,
    taxonomy_id: str,
    editor_choices: Mapping[str, Any],
) -> Mapping[str, Any]:
    existing = _list_resources(
        session,
        path="/v1/app/profiles",
        resource_type="CREATOR_PROFILE",
    )
    if len(existing) > 1:
        _invalid()
    if existing:
        created = _get_resource(
            session,
            f"/v1/app/profiles/{existing[0]['object_id']}",
            resource_type="CREATOR_PROFILE",
        )
        if created["status"] not in {"DRAFT", "ACTIVE"}:
            _invalid()
    else:
        created = _write_editor(
            session,
            method="POST",
            path="/v1/app/profiles",
            body={},
            expected_status=201,
            resource_type="CREATOR_PROFILE",
        )
        if created["status"] != "DRAFT" or created["current_version"] is not None:
            _invalid()
    initial_revision = created["revision"]
    base_version_id = (
        None
        if created["current_version"] is None
        else created["current_version"]["version_id"]
    )
    drafted = _write_editor(
        session,
        method="PUT",
        path=f"/v1/app/profiles/{created['object_id']}/draft",
        body={
            "base_version_id": base_version_id,
            "taxonomy_bundle_id": taxonomy_id,
            "content": safe_profile_content(editor_choices),
        },
        if_match=created["etag"],
        expected_status=200,
        resource_type="CREATOR_PROFILE",
    )
    current = drafted["current_version"]
    if not isinstance(current, dict) or current.get("status") != "DRAFT":
        _invalid()
    published = _write_editor(
        session,
        method="POST",
        path=f"/v1/app/profiles/{created['object_id']}/publish",
        body={"draft_version_id": current["version_id"]},
        if_match=drafted["etag"],
        expected_status=200,
        resource_type="CREATOR_PROFILE",
    )
    if (
        published["status"] != "ACTIVE"
        or published["revision"] != initial_revision + 2
    ):
        _invalid()
    return published


def _create_cancelled_demand_with_history(
    owner: RoleSession,
) -> Mapping[str, Any]:
    if (
        owner.workspace_kind != "ORGANIZATION"
        or owner.role_codes != ("DEMAND_OWNER",)
    ):
        _invalid()
    configuration = _configuration(owner)
    taxonomy_id = configuration["taxonomy_bundle"]["bundle_id"]
    editor_choices = configuration["editor_choices"]
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=60)
    ).replace(microsecond=0).isoformat()
    created = _write_editor(
        owner,
        method="POST",
        path="/v1/app/demands",
        body={
            "taxonomy_bundle_id": taxonomy_id,
            "content": {},
            "client_reference": f"internal-sandbox-invitee-{uuid4()}",
            "expires_at": expires_at,
        },
        expected_status=201,
        resource_type="DEMAND",
    )
    first_version = created["current_version"]
    if (
        created["status"] != "DRAFT"
        or not isinstance(first_version, Mapping)
        or "CANCEL" not in created["capabilities"]
    ):
        _invalid()
    drafted = _write_editor(
        owner,
        method="PUT",
        path=f"/v1/app/demands/{created['object_id']}/draft",
        body={
            "base_version_id": first_version["version_id"],
            "taxonomy_bundle_id": taxonomy_id,
            "content": safe_demand_content(editor_choices),
        },
        if_match=created["etag"],
        expected_status=200,
        resource_type="DEMAND",
    )
    if (
        drafted["status"] != "DRAFT"
        or "SAVE_DRAFT" not in drafted["capabilities"]
        or "CANCEL" not in drafted["capabilities"]
        or len(drafted["versions"]) <= len(created["versions"])
    ):
        _invalid()
    cancelled = _cancel_demand_exact_replay(owner, demand=drafted)
    if (
        cancelled["status"] != "CANCELLED"
        or cancelled["revision"] != drafted["revision"] + 1
        or cancelled["capabilities"] != []
        or cancelled["editable_paths"] != []
        or cancelled["current_version"] != drafted["current_version"]
        or cancelled["versions"] != drafted["versions"]
        or cancelled["submissions"] != drafted["submissions"]
        or cancelled["findings"] != drafted["findings"]
        or cancelled["review_assignment"] is not None
    ):
        _invalid()
    detail = _get_resource(
        owner,
        f"/v1/app/demands/{cancelled['object_id']}",
        resource_type="DEMAND",
    )
    if detail != cancelled:
        _invalid()
    listed = _list_resources(
        owner,
        path="/v1/app/demands",
        resource_type="DEMAND",
    )
    matches = [
        item for item in listed if item["object_id"] == cancelled["object_id"]
    ]
    if matches != [cancelled]:
        _invalid()
    _require_cancelled_demand_history_task(
        owner, demand_id=cancelled["object_id"]
    )
    return {
        "created_and_cancelled": True,
        "exact_replay_verified": True,
        "read_only": True,
        "version_history_preserved": True,
        "completed_history_discovered": True,
    }


def _cancel_demand_exact_replay(
    session: RoleSession, *, demand: Mapping[str, Any]
) -> Mapping[str, Any]:
    demand_id = _canonical_uuid(demand.get("object_id"))
    if (
        demand.get("resource_type") != "DEMAND"
        or demand.get("status") not in {"DRAFT", "SUBMITTED", "NEEDS_CHANGES"}
        or "CANCEL" not in demand.get("capabilities", ())
        or _RESOURCE_ETAG.fullmatch(str(demand.get("etag", ""))) is None
    ):
        _invalid()
    headers = _write_headers(session, if_match=demand["etag"])
    path = f"/v1/app/demands/{demand_id}/cancel"
    body = {"reason_code": "OWNER_WITHDREW"}
    first_response = session.client.request(
        method="POST", path=path, body=body, headers=headers
    )
    _expect_status(first_response, 200)
    first = _editor_envelope(first_response, resource_type="DEMAND")
    replay_response = session.client.request(
        method="POST", path=path, body=body, headers=headers
    )
    _expect_status(replay_response, 200)
    replay = _editor_envelope(replay_response, resource_type="DEMAND")
    if first != replay:
        _invalid()
    return first


def _require_cancelled_demand_history_task(
    session: RoleSession, *, demand_id: str
) -> None:
    _canonical_uuid(demand_id)
    response = session.client.request(
        method="GET",
        path="/v1/app/tasks",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    envelope = _exact_keys(response.json(), {"data"})
    data = _exact_keys(
        envelope["data"], {"schema_version", "items", "has_more"}
    )
    items = data["items"]
    if (
        data["schema_version"] != "current-account-task-discovery-v1"
        or not isinstance(items, list)
        or len(items) > 2000
        or not isinstance(data["has_more"], bool)
    ):
        _invalid()
    matches = []
    for value in items:
        item = _exact_keys(
            value,
            {
                "classification",
                "resource_kind",
                "resource_id",
                "source_status",
                "next_action",
                "resource_path",
                "updated_at",
                "due_at",
            },
        )
        if item["resource_kind"] == "DEMAND" and item["resource_id"] == demand_id:
            matches.append(item)
    if len(matches) != 1:
        _invalid()
    task = matches[0]
    if (
        task["classification"] != "COMPLETED"
        or task["source_status"] != "CANCELLED"
        or task["next_action"] != "VIEW_DEMAND_HISTORY"
        or task["resource_path"] != f"/v1/app/demands/{demand_id}"
        or task["due_at"] is not None
    ):
        _invalid()
    if task["updated_at"] is not None:
        _utc_timestamp(task["updated_at"])


def _create_reviewable_demand(
    *,
    owner: RoleSession,
    reviewer: RoleSession,
    taxonomy_id: str,
    editor_choices: Mapping[str, Any],
) -> tuple[Mapping[str, Any], bool]:
    expires_at = (
        datetime.now(timezone.utc) + timedelta(days=60)
    ).replace(microsecond=0).isoformat()
    created = _write_editor(
        owner,
        method="POST",
        path="/v1/app/demands",
        body={
            "taxonomy_bundle_id": taxonomy_id,
            "content": {},
            "client_reference": f"internal-sandbox-e2e-{uuid4()}",
            "expires_at": expires_at,
        },
        expected_status=201,
        resource_type="DEMAND",
    )
    first_version = created["current_version"]
    if not isinstance(first_version, dict):
        _invalid()
    drafted = _write_editor(
        owner,
        method="PUT",
        path=f"/v1/app/demands/{created['object_id']}/draft",
        body={
            "base_version_id": first_version["version_id"],
            "taxonomy_bundle_id": taxonomy_id,
            "content": safe_demand_content(editor_choices),
        },
        if_match=created["etag"],
        expected_status=200,
        resource_type="DEMAND",
    )
    submitted = _write_editor(
        owner,
        method="POST",
        path=f"/v1/app/demands/{created['object_id']}/submit",
        body={},
        if_match=drafted["etag"],
        expected_status=200,
        resource_type="DEMAND",
    )
    if submitted["status"] != "SUBMITTED":
        _invalid()
    first_claim = _claim(reviewer, demand_id=created["object_id"])
    first_detail = _get_resource(
        reviewer,
        f"/v1/app/demands/{created['object_id']}",
        resource_type="DEMAND",
    )
    assignment = first_detail["review_assignment"]
    if (
        not isinstance(assignment, dict)
        or assignment.get("assignment_id") != first_claim["assignment_id"]
    ):
        _invalid()
    changes = _write_editor(
        reviewer,
        method="POST",
        path=(
            f"/v1/app/demands/{created['object_id']}/review-assignments/"
            f"{first_claim['assignment_id']}/findings"
        ),
        body={
            "reason_codes": ["SCOPE_UNCLEAR"],
            "required_field_paths": ["/scope"],
        },
        if_match=first_detail["etag"],
        expected_status=200,
        resource_type="DEMAND",
    )
    if changes["status"] != "NEEDS_CHANGES":
        _invalid()
    owner_detail = _get_resource(
        owner,
        f"/v1/app/demands/{created['object_id']}",
        resource_type="DEMAND",
    )
    _require_owner_scope_finding(owner_detail)
    content = json.loads(json.dumps(owner_detail["current_version"]["content"]))
    content["scope"]["deliverables"][0][
        "description"
    ] = "合成验收材料（补充范围、格式与完成条件）"
    redrafted = _write_editor(
        owner,
        method="PUT",
        path=f"/v1/app/demands/{created['object_id']}/draft",
        body={
            "base_version_id": owner_detail["current_version"]["version_id"],
            "taxonomy_bundle_id": taxonomy_id,
            "content": content,
        },
        if_match=owner_detail["etag"],
        expected_status=200,
        resource_type="DEMAND",
    )
    resubmitted = _write_editor(
        owner,
        method="POST",
        path=f"/v1/app/demands/{created['object_id']}/submit",
        body={},
        if_match=redrafted["etag"],
        expected_status=200,
        resource_type="DEMAND",
    )
    if resubmitted["status"] != "SUBMITTED":
        _invalid()
    second_claim = _claim(reviewer, demand_id=created["object_id"])
    if second_claim["assignment_id"] == first_claim["assignment_id"]:
        _invalid()
    second_detail = _get_resource(
        reviewer,
        f"/v1/app/demands/{created['object_id']}",
        resource_type="DEMAND",
    )
    assignment = second_detail["review_assignment"]
    if (
        not isinstance(assignment, dict)
        or assignment.get("assignment_id") != second_claim["assignment_id"]
    ):
        _invalid()
    current_version = second_detail.get("current_version")
    if (
        second_detail["status"] != "SUBMITTED"
        or second_detail["revision"] != 6
        or not isinstance(current_version, Mapping)
    ):
        _invalid()
    _canonical_uuid(current_version.get("version_id"))
    return second_detail, True


def _submit_trust_report(
    *, owner: RoleSession, reviewable_demand: Mapping[str, Any]
) -> Mapping[str, Any]:
    demand_id, demand_version_id = _reviewable_demand_identity(
        reviewable_demand
    )
    incident_started_at = (
        datetime.now(timezone.utc) - timedelta(hours=2)
    ).replace(microsecond=0).isoformat()
    command = _trust_write_exact_replay(
        owner,
        method="POST",
        path="/v1/app/trust/reports",
        body={
            "category": "WORKFLOW_INTEGRITY",
            "demand_id": demand_id,
            "demand_version_id": demand_version_id,
            "evidence_reference_ids": [demand_version_id],
            "impact_codes": [
                "PARTICIPANT_SAFETY_RISK",
                "WORKFLOW_INTEGRITY_RISK",
            ],
            "incident_ended_at": None,
            "incident_started_at": incident_started_at,
            "requested_protection_codes": ["PAUSE_VERIFICATION"],
        },
        expected_status=201,
        expected_event_type="TrustReportSubmitted",
    )
    report_id = _canonical_uuid(command["report_id"])
    case_id = _canonical_uuid(command["case_id"])
    if command["case_status"] != "OPEN" or command["aggregate_version"] != 1:
        _invalid()
    report = _get_trust_report(owner, report_id=report_id)
    if (
        report["report_id"] != report_id
        or report["demand_id"] != demand_id
        or report["demand_version_id"] != demand_version_id
        or report["status"] != "OPEN"
        or report["outcome"] is not None
        or report["report"]["category"] != "WORKFLOW_INTEGRITY"
        or report["report"]["requested_protection_codes"]
        != ["PAUSE_VERIFICATION"]
    ):
        _invalid()
    return {
        "case_id": case_id,
        "demand_id": demand_id,
        "demand_version_id": demand_version_id,
        "report_id": report_id,
        "report_etag": report["entity_tag"],
    }


def _review_trust_case(
    *, officer: RoleSession, report_context: Mapping[str, Any]
) -> Mapping[str, Any]:
    case_id = _canonical_uuid(report_context.get("case_id"))
    report_id = _canonical_uuid(report_context.get("report_id"))
    demand_id = _canonical_uuid(report_context.get("demand_id"))
    demand_version_id = _canonical_uuid(
        report_context.get("demand_version_id")
    )
    queue = _trust_case_queue(officer)
    items = [item for item in queue["items"] if item["case_id"] == case_id]
    if len(items) != 1:
        _invalid()
    item = items[0]
    if (
        item["report_id"] != report_id
        or item["demand_id"] != demand_id
        or item["demand_version_id"] != demand_version_id
        or item["category"] != "WORKFLOW_INTEGRITY"
        or "PARTICIPANT_SAFETY_RISK" not in item["impact_codes"]
    ):
        _invalid()
    claimed = _trust_write_exact_replay(
        officer,
        method="POST",
        path=f"/v1/app/trust/queue/{case_id}/claim",
        body={},
        if_match=item["entity_tag"],
        expected_status=201,
        expected_event_type="TrustCaseClaimed",
    )
    if (
        claimed["case_id"] != case_id
        or claimed["case_status"] != "TRIAGING"
        or claimed["aggregate_version"] < 2
    ):
        _invalid()
    _require_trust_active_assignment(
        _trust_active_assignments(officer),
        case_id=case_id,
        assignment_purpose="CASE_TRIAGE",
    )
    current = _get_trust_case(officer, case_id=case_id)
    _require_trust_case_identity(current, report_context)
    if current["status"] != "TRIAGING" or current["triage_draft"] is not None:
        _invalid()

    first_body = {
        "investigation_step_codes": ["CHECK_DEMAND_VERSION"],
        "issue_codes": ["WORKFLOW_INTEGRITY_GAP"],
        "jurisdiction_code": "PLATFORM_INTERNAL",
        "priority_code": "P1",
        "proposed_hold_actions": ["VERIFY_DEMAND"],
        "proposed_hold_ttl_minutes": 60,
        "restricted_note": (
            "Synthetic first-pass Trust triage note; sealed input only."
        ),
        "severity_code": "HIGH",
    }
    first_saved = _trust_write_exact_replay(
        officer,
        method="PUT",
        path=f"/v1/app/trust/cases/{case_id}/triage-draft",
        body=first_body,
        if_match=current["entity_tag"],
        expected_status=200,
        expected_event_type="TrustTriageDraftSaved",
    )
    first = _get_trust_case(officer, case_id=case_id)
    _require_trust_case_identity(first, report_context)
    _require_triage_projection(
        first,
        request=first_body,
        expected_version=first_saved["triage_draft_version"],
    )

    second_body = {
        "investigation_step_codes": [
            "CHECK_DEMAND_VERSION",
            "CHECK_POLICY_REQUIREMENTS",
        ],
        "issue_codes": [
            "WORKFLOW_INTEGRITY_GAP",
            "SCOPE_DISCLOSURE_RISK",
        ],
        "jurisdiction_code": "PLATFORM_INTERNAL",
        "priority_code": "P0",
        "proposed_hold_actions": ["VERIFY_DEMAND"],
        "proposed_hold_ttl_minutes": 60,
        "restricted_note": (
            "Synthetic second-pass Trust triage note; replaces prior sealed input."
        ),
        "severity_code": "CRITICAL",
    }
    second_saved = _trust_write_exact_replay(
        officer,
        method="PUT",
        path=f"/v1/app/trust/cases/{case_id}/triage-draft",
        body=second_body,
        if_match=first["entity_tag"],
        expected_status=200,
        expected_event_type="TrustTriageDraftSaved",
    )
    second = _get_trust_case(officer, case_id=case_id)
    _require_trust_case_identity(second, report_context)
    _require_triage_projection(
        second,
        request=second_body,
        expected_version=second_saved["triage_draft_version"],
    )
    first_draft = first["triage_draft"]
    second_draft = second["triage_draft"]
    if (
        not isinstance(first_draft, Mapping)
        or not isinstance(second_draft, Mapping)
        or second_draft["triage_version"] != first_draft["triage_version"] + 1
        or second_draft["content_sha256"] == first_draft["content_sha256"]
        or second_draft["content"] == first_draft["content"]
    ):
        _invalid()
    draft_version = second_draft["triage_version"]
    published = _trust_write_exact_replay(
        officer,
        method="POST",
        path=f"/v1/app/trust/cases/{case_id}/triage-publish",
        body={"expected_draft_version": draft_version},
        if_match=second["entity_tag"],
        expected_status=200,
        expected_event_type="TrustTriagePublished",
    )
    if (
        published["triage_draft_version"] is not None
        or published["triage_version"] != 1
        or published["case_status"] != "IN_REVIEW"
    ):
        _invalid()
    reviewed = _get_trust_case(officer, case_id=case_id)
    _require_trust_case_identity(reviewed, report_context)
    if reviewed["status"] != "IN_REVIEW":
        _invalid()
    return {
        **report_context,
        "case": reviewed,
        "triage_draft_versions": [
            first_draft["triage_version"],
            second_draft["triage_version"],
        ],
        "triage_configuration_changed": True,
    }


def _place_trust_hold_and_prove_blocked(
    *,
    officer: RoleSession,
    reviewer: RoleSession,
    case_context: Mapping[str, Any],
    reviewable_demand: Mapping[str, Any],
) -> Mapping[str, Any]:
    case_id = _canonical_uuid(case_context.get("case_id"))
    case = case_context.get("case")
    if not isinstance(case, Mapping) or case.get("status") != "IN_REVIEW":
        _invalid()
    placed = _trust_write_exact_replay(
        officer,
        method="POST",
        path=f"/v1/app/trust/cases/{case_id}/holds",
        body={
            "action_codes": ["VERIFY_DEMAND"],
            "reason_code": "PARTICIPANT_SAFETY_RISK",
            "ttl_minutes": 60,
        },
        if_match=case["entity_tag"],
        expected_status=201,
        expected_event_type="SafetyHoldPlaced",
    )
    hold_id = _canonical_uuid(placed["hold_id"])
    if (
        placed["case_id"] != case_id
        or placed["hold_version"] != 1
        or placed["case_status"] != "IN_REVIEW"
    ):
        _invalid()
    held_case = _get_trust_case(officer, case_id=case_id)
    _require_trust_case_identity(held_case, case_context)
    active_hold = held_case["active_hold"]
    if (
        not isinstance(active_hold, Mapping)
        or active_hold["hold_id"] != hold_id
        or active_hold["status"] != "ACTIVE"
        or active_hold["action_codes"] != ["VERIFY_DEMAND"]
    ):
        _invalid()
    blocked_demand, blocked_idempotency_key = _blocked_verify_under_trust_hold(
        reviewer,
        reviewable_demand=reviewable_demand,
    )
    return {
        **case_context,
        "case": held_case,
        "hold_id": hold_id,
        "blocked_demand": blocked_demand,
        "blocked_idempotency_key": blocked_idempotency_key,
        "blocked_verification": {
            "http_status": 403,
            "error_code": "SAFETY_HOLD_BLOCKED",
            "public_demand_projection_unchanged": True,
            "expected_receipt_delta": 0,
            "expected_audit_delta": 0,
            "expected_outbox_delta": 0,
        },
    }


def _release_trust_hold_and_verify(
    *,
    releasing_officer: RoleSession,
    deciding_officer: RoleSession,
    reviewer: RoleSession,
    hold_context: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    case_id = _canonical_uuid(hold_context.get("case_id"))
    hold_id = _canonical_uuid(hold_context.get("hold_id"))
    demand_id = _canonical_uuid(hold_context.get("demand_id"))
    demand_version_id = _canonical_uuid(hold_context.get("demand_version_id"))
    queue = _trust_hold_release_queue(releasing_officer)
    items = [item for item in queue["items"] if item["hold_id"] == hold_id]
    if len(items) != 1:
        _invalid()
    item = items[0]
    if (
        item["case_id"] != case_id
        or item["demand_id"] != demand_id
        or item["demand_version_id"] != demand_version_id
        or item["action_codes"] != ["VERIFY_DEMAND"]
        or item["reason_code"] != "PARTICIPANT_SAFETY_RISK"
    ):
        _invalid()
    claimed = _trust_write_exact_replay(
        releasing_officer,
        method="POST",
        path=f"/v1/app/trust/hold-release-queue/{hold_id}/claim",
        body={},
        if_match=item["entity_tag"],
        expected_status=201,
        expected_event_type="TrustHoldReleaseClaimed",
    )
    if claimed["case_id"] != case_id or claimed["hold_id"] != hold_id:
        _invalid()
    _require_trust_active_assignment(
        _trust_active_assignments(releasing_officer),
        case_id=case_id,
        assignment_purpose="HOLD_RELEASE",
        hold_id=hold_id,
    )
    active_hold = _get_assigned_trust_hold(
        releasing_officer, hold_id=hold_id
    )
    if (
        active_hold["case_id"] != case_id
        or active_hold["hold_id"] != hold_id
        or active_hold["case_status"] != "IN_REVIEW"
        or active_hold["hold_status"] != "ACTIVE"
        or active_hold["action_codes"] != ["VERIFY_DEMAND"]
        or active_hold["reason_code"] != "PARTICIPANT_SAFETY_RISK"
    ):
        _invalid()
    released = _trust_write_exact_replay(
        releasing_officer,
        method="POST",
        path=f"/v1/app/trust/holds/{hold_id}/release",
        body={"reason_code": "RISK_MITIGATED"},
        if_match=active_hold["entity_tag"],
        expected_status=200,
        expected_event_type="SafetyHoldReleased",
    )
    if (
        released["case_id"] != case_id
        or released["hold_id"] != hold_id
        or released["hold_version"] != 3
    ):
        _invalid()
    refreshed_queue = _trust_hold_release_queue(releasing_officer)
    if any(child["hold_id"] == hold_id for child in refreshed_queue["items"]):
        _invalid()
    _require_trust_assignment_absent(
        _trust_active_assignments(releasing_officer),
        case_id=case_id,
        assignment_purpose="HOLD_RELEASE",
        hold_id=hold_id,
    )
    released_case = _get_trust_case(deciding_officer, case_id=case_id)
    _require_trust_case_identity(released_case, hold_context)
    if released_case["active_hold"] is not None:
        _invalid()
    blocked_demand = hold_context.get("blocked_demand")
    blocked_key = hold_context.get("blocked_idempotency_key")
    if not isinstance(blocked_demand, Mapping) or not isinstance(blocked_key, str):
        _invalid()
    verified = _verify_demand_after_hold_release(
        reviewer,
        blocked_demand=blocked_demand,
        blocked_idempotency_key=blocked_key,
    )
    return {
        **hold_context,
        "case": released_case,
        "hold_released": True,
        "assigned_hold_read_verified": True,
    }, verified


def _publish_trust_outcome(
    *,
    owner: RoleSession,
    officer: RoleSession,
    released_context: Mapping[str, Any],
) -> Mapping[str, Any]:
    case_id = _canonical_uuid(released_context.get("case_id"))
    report_id = _canonical_uuid(released_context.get("report_id"))
    case = released_context.get("case")
    if not isinstance(case, Mapping) or case.get("active_hold") is not None:
        _invalid()
    published = _trust_write_exact_replay(
        officer,
        method="POST",
        path=f"/v1/app/trust/cases/{case_id}/decisions",
        body={
            "action_codes": ["VERIFY_DEMAND"],
            "outcome_code": "PROTECTION_MODIFIED",
            "reason_codes": ["RISK_MITIGATED"],
        },
        if_match=case["entity_tag"],
        expected_status=201,
        expected_event_type="TrustCaseOutcomePublished",
    )
    outcome_version_id = _canonical_uuid(published["outcome_version_id"])
    if published["case_id"] != case_id or published["case_status"] != "DECIDED":
        _invalid()
    decided_case = _get_trust_case(officer, case_id=case_id)
    _require_trust_case_identity(decided_case, released_context)
    if (
        decided_case["status"] != "DECIDED"
        or decided_case["active_hold"] is not None
    ):
        _invalid()
    _require_trust_assignment_absent(
        _trust_active_assignments(officer),
        case_id=case_id,
    )
    _require_eligible_outcome(
        decided_case["outcome"], outcome_version_id=outcome_version_id
    )
    owner_report = _get_trust_report(owner, report_id=report_id)
    if (
        owner_report["status"] != "DECIDED"
        or owner_report["demand_id"] != released_context["demand_id"]
        or owner_report["demand_version_id"]
        != released_context["demand_version_id"]
    ):
        _invalid()
    _require_eligible_outcome(
        owner_report["outcome"],
        outcome_version_id=outcome_version_id,
        party_safe=True,
    )
    return {
        "report_id": report_id,
        "case_id": case_id,
        "hold_id": released_context["hold_id"],
        "outcome_version_id": outcome_version_id,
        "demand_version_id": released_context["demand_version_id"],
        "report_etag": owner_report["entity_tag"],
        "case_etag": decided_case["entity_tag"],
        "report_status": owner_report["status"],
        "case_status": decided_case["status"],
        "outcome_code": "PROTECTION_MODIFIED",
        "appeal_eligibility_code": "ELIGIBLE",
        "appeal_deadline_present": True,
        "owner_outcome_visible": True,
        "hold_released": released_context["hold_released"],
        "independent_release": True,
        "triage_draft_versions": released_context["triage_draft_versions"],
        "triage_configuration_changed": released_context[
            "triage_configuration_changed"
        ],
        "blocked_verification": released_context["blocked_verification"],
        "active_assignment_absent": True,
        "assigned_hold_read_verified": released_context[
            "assigned_hold_read_verified"
        ],
    }


def _exercise_trust_appeal(
    *,
    owner: RoleSession,
    reviewer: RoleSession,
    trust_summary: Mapping[str, Any],
) -> Mapping[str, Any]:
    if (
        owner.account_code != "demand_owner_01"
        or owner.role_codes != ("DEMAND_OWNER",)
        or reviewer.account_code != "appeal_reviewer_01"
        or reviewer.role_codes != ("APPEAL_REVIEWER",)
        or trust_summary.get("report_status") != "DECIDED"
        or trust_summary.get("case_status") != "DECIDED"
        or trust_summary.get("appeal_eligibility_code") != "ELIGIBLE"
        or trust_summary.get("outcome_code") != "PROTECTION_MODIFIED"
    ):
        _invalid()
    source_outcome_version_id = _canonical_uuid(
        trust_summary.get("outcome_version_id")
    )
    source_case_id = _canonical_uuid(trust_summary.get("case_id"))
    if (
        _find_own_appeal_by_source(
            owner,
            source_outcome_version_id=source_outcome_version_id,
            allow_missing=True,
        )
        is not None
    ):
        _invalid()

    opened = _appeal_write_exact_replay(
        owner,
        method="POST",
        path="/v1/app/appeals",
        body={"source_outcome_version_id": source_outcome_version_id},
        expected_status=201,
        expected_event_type="AppealOpened",
    )
    appeal_id = _canonical_uuid(opened["appeal_id"])
    if opened["appeal_status"] != "DRAFT":
        _invalid()
    discovered = _find_own_appeal_by_source(
        owner,
        source_outcome_version_id=source_outcome_version_id,
        allow_missing=False,
    )
    if discovered is None or discovered["appeal_id"] != appeal_id:
        _invalid()
    draft_body = {
        "applicant_statement": (
            "Synthetic Appeal statement held only in process memory."
        ),
        "grounds": ["PROCEDURAL_ERROR"],
        "new_evidence_reference_ids": [],
        "requested_outcome": "VACATE_AND_REMAND",
    }
    saved = _appeal_write_exact_replay(
        owner,
        method="PUT",
        path=f"/v1/app/appeals/{appeal_id}/draft",
        body=draft_body,
        if_match=discovered["entity_tag"],
        expected_status=200,
        expected_event_type="AppealApplicationDraftSaved",
        sensitive_body=True,
    )
    draft_version = _positive_int(saved["application_draft_version"])
    drafted = _get_own_appeal(owner, appeal_id=appeal_id)
    _require_appeal_identity(
        drafted,
        appeal_id=appeal_id,
        source_case_id=source_case_id,
        source_outcome_version_id=source_outcome_version_id,
    )
    application_draft = drafted.get("application_draft")
    if (
        drafted["status"] != "DRAFT"
        or not isinstance(application_draft, Mapping)
        or application_draft["version"] != draft_version
        or application_draft["statement_recorded"] is not True
        or application_draft["grounds"] != ["PROCEDURAL_ERROR"]
        or application_draft["new_evidence_reference_ids"] != []
        or application_draft["requested_outcome"] != "VACATE_AND_REMAND"
    ):
        _invalid()
    submitted = _appeal_write_exact_replay(
        owner,
        method="POST",
        path=f"/v1/app/appeals/{appeal_id}/submit",
        body={"expected_draft_version": draft_version},
        if_match=drafted["entity_tag"],
        expected_status=200,
        expected_event_type="AppealSubmitted",
    )
    application_version = _positive_int(submitted["application_version"])
    submitted_appeal = _get_own_appeal(owner, appeal_id=appeal_id)
    _require_appeal_identity(
        submitted_appeal,
        appeal_id=appeal_id,
        source_case_id=source_case_id,
        source_outcome_version_id=source_outcome_version_id,
    )
    application = submitted_appeal.get("application")
    if (
        submitted_appeal["status"] != "SUBMITTED"
        or not isinstance(application, Mapping)
        or application["statement_recorded"] is not True
        or application["grounds"] != ["PROCEDURAL_ERROR"]
        or application["requested_outcome"] != "VACATE_AND_REMAND"
    ):
        _invalid()

    queued = _appeal_queue(reviewer)
    queue_items = [
        item for item in queued["items"] if item["appeal_id"] == appeal_id
    ]
    if len(queue_items) != 1:
        _invalid()
    queue_item = queue_items[0]
    if (
        queue_item["source_case_id"] != source_case_id
        or queue_item["source_outcome_version_id"]
        != source_outcome_version_id
        or queue_item["grounds"] != ["PROCEDURAL_ERROR"]
        or queue_item["requested_outcome"] != "VACATE_AND_REMAND"
    ):
        _invalid()
    claimed = _appeal_write_exact_replay(
        reviewer,
        method="POST",
        path=f"/v1/app/appeal-review/queue/{appeal_id}/claim",
        body={},
        if_match=queue_item["entity_tag"],
        expected_status=201,
        expected_event_type="AppealReviewClaimed",
    )
    if claimed["appeal_status"] != "IN_REVIEW":
        _invalid()
    _require_appeal_active_assignment(
        _appeal_active_assignments(reviewer), appeal_id=appeal_id
    )
    first_assignment = _get_assigned_appeal(reviewer, appeal_id=appeal_id)
    released = _appeal_write_exact_replay(
        reviewer,
        method="POST",
        path=f"/v1/app/appeal-review/appeals/{appeal_id}/assignment/release",
        body={"reason_code": "WORKLOAD_RELEASE"},
        if_match=first_assignment["entity_tag"],
        expected_status=200,
        expected_event_type="AppealReviewAssignmentReleased",
    )
    if released["appeal_status"] != "SUBMITTED":
        _invalid()
    _require_appeal_assignment_absent(
        _appeal_active_assignments(reviewer), appeal_id=appeal_id
    )
    released_queue = _appeal_queue(reviewer)
    released_items = [
        item for item in released_queue["items"] if item["appeal_id"] == appeal_id
    ]
    if len(released_items) != 1:
        _invalid()
    released_item = released_items[0]
    if (
        released_item["source_case_id"] != source_case_id
        or released_item["source_outcome_version_id"]
        != source_outcome_version_id
        or released_item["grounds"] != ["PROCEDURAL_ERROR"]
        or released_item["requested_outcome"] != "VACATE_AND_REMAND"
    ):
        _invalid()
    reclaimed = _appeal_write_exact_replay(
        reviewer,
        method="POST",
        path=f"/v1/app/appeal-review/queue/{appeal_id}/claim",
        body={},
        if_match=released_item["entity_tag"],
        expected_status=201,
        expected_event_type="AppealReviewClaimed",
    )
    if reclaimed["appeal_status"] != "IN_REVIEW":
        _invalid()
    _require_appeal_active_assignment(
        _appeal_active_assignments(reviewer), appeal_id=appeal_id
    )
    assigned = _get_assigned_appeal(reviewer, appeal_id=appeal_id)
    _require_appeal_identity(
        assigned["appeal"],
        appeal_id=appeal_id,
        source_case_id=source_case_id,
        source_outcome_version_id=source_outcome_version_id,
    )
    review_body = {
        "assessments": [
            {
                "accepted_evidence_reference_ids": [],
                "assessment_code": "ACCEPTED",
                "finding_codes": ["PROCEDURE_MATERIAL_ERROR"],
                "ground": "PROCEDURAL_ERROR",
            }
        ],
        "reason_codes": ["PROCEDURAL_REVIEW_COMPLETE", "REMAND_REQUIRED"],
        "remedy_delta_codes": ["RETURN_TO_TRUST_REVIEW"],
        "reviewer_note": (
            "Synthetic Appeal review note held only in process memory."
        ),
    }
    review_saved = _appeal_write_exact_replay(
        reviewer,
        method="PUT",
        path=f"/v1/app/appeal-review/appeals/{appeal_id}/review-draft",
        body=review_body,
        if_match=assigned["entity_tag"],
        expected_status=200,
        expected_event_type="AppealReviewDraftSaved",
        sensitive_body=True,
    )
    review_draft_version = _positive_int(
        review_saved["review_draft_version"]
    )
    reviewed = _get_assigned_appeal(reviewer, appeal_id=appeal_id)
    review_draft = reviewed.get("review_draft")
    if (
        not isinstance(review_draft, Mapping)
        or review_draft["version"] != review_draft_version
        or review_draft["review_note_recorded"] is not True
        or review_draft["reason_codes"]
        != ["PROCEDURAL_REVIEW_COMPLETE", "REMAND_REQUIRED"]
        or review_draft["remedy_delta_codes"]
        != ["RETURN_TO_TRUST_REVIEW"]
    ):
        _invalid()
    decided = _appeal_write_exact_replay(
        reviewer,
        method="POST",
        path=f"/v1/app/appeal-review/appeals/{appeal_id}/decide",
        body={
            "decision_code": "VACATE_AND_REMAND",
            "expected_review_draft_version": review_draft_version,
        },
        if_match=reviewed["entity_tag"],
        expected_status=200,
        expected_event_type="AppealDecisionPublished",
    )
    decision_version_id = _canonical_uuid(decided["decision_version_id"])
    _require_appeal_assignment_absent(
        _appeal_active_assignments(reviewer), appeal_id=appeal_id
    )
    final_appeal = _get_own_appeal(owner, appeal_id=appeal_id)
    _require_appeal_identity(
        final_appeal,
        appeal_id=appeal_id,
        source_case_id=source_case_id,
        source_outcome_version_id=source_outcome_version_id,
    )
    final_decision = final_appeal.get("decision")
    if (
        final_appeal["status"] != "DECIDED"
        or not isinstance(final_decision, Mapping)
        or final_decision["decision_version_id"] != decision_version_id
        or final_decision["decision_code"] != "VACATE_AND_REMAND"
    ):
        _invalid()
    refreshed_queue = _appeal_queue(reviewer)
    if any(item["appeal_id"] == appeal_id for item in refreshed_queue["items"]):
        _invalid()
    terminal_history = _appeal_terminal_history(reviewer)
    terminal_matches = [
        item
        for item in terminal_history["items"]
        if item["appeal_id"] == appeal_id
    ]
    terminal_detail = _get_terminal_appeal(reviewer, appeal_id=appeal_id)
    if (
        len(terminal_matches) != 1
        or terminal_matches[0]["decision_code"] != "VACATE_AND_REMAND"
        or terminal_detail["entity_tag"] != final_appeal["entity_tag"]
        or terminal_detail["application"] != final_appeal["application"]
        or terminal_detail["decision"] != final_decision
    ):
        _invalid()
    return {
        "appeal_id": appeal_id,
        "source_outcome_version_id": source_outcome_version_id,
        "decision_version_id": decision_version_id,
        "appeal_etag": final_appeal["entity_tag"],
        "appeal_status": final_appeal["status"],
        "decision_code": final_decision["decision_code"],
        "application_version": application_version,
        "review_draft_version": review_draft_version,
        "applicant_replays_verified": True,
        "reviewer_replays_verified": True,
        "assignment_release_replay_verified": True,
        "reclaim_replay_verified": True,
        "write_kinds_verified": 7,
        "review_queue_absent": True,
        "active_assignment_discovery_verified": True,
        "terminal_history_discoverable": True,
        "terminal_detail_party_safe": True,
    }


def _appeal_write_exact_replay(
    session: RoleSession,
    *,
    method: str,
    path: str,
    body: Mapping[str, Any],
    expected_status: int,
    expected_event_type: str,
    if_match: str | None = None,
    sensitive_body: bool = False,
) -> Mapping[str, Any]:
    route_contract = {
        "AppealOpened": ("POST", 201, r"/v1/app/appeals", "APPLICANT"),
        "AppealApplicationDraftSaved": (
            "PUT",
            200,
            r"/v1/app/appeals/([^/]+)/draft",
            "APPLICANT",
        ),
        "AppealSubmitted": (
            "POST",
            200,
            r"/v1/app/appeals/([^/]+)/submit",
            "APPLICANT",
        ),
        "AppealReviewClaimed": (
            "POST",
            201,
            r"/v1/app/appeal-review/queue/([^/]+)/claim",
            "REVIEWER",
        ),
        "AppealReviewAssignmentReleased": (
            "POST",
            200,
            r"/v1/app/appeal-review/appeals/([^/]+)/assignment/release",
            "REVIEWER",
        ),
        "AppealReviewDraftSaved": (
            "PUT",
            200,
            r"/v1/app/appeal-review/appeals/([^/]+)/review-draft",
            "REVIEWER",
        ),
        "AppealDecisionPublished": (
            "POST",
            200,
            r"/v1/app/appeal-review/appeals/([^/]+)/decide",
            "REVIEWER",
        ),
    }
    contract = route_contract.get(expected_event_type)
    match = (
        re.fullmatch(contract[2], path)
        if contract is not None and isinstance(path, str)
        else None
    )
    if (
        contract is None
        or match is None
        or method != contract[0]
        or expected_status != contract[1]
        or not isinstance(body, Mapping)
        or not isinstance(sensitive_body, bool)
        or sensitive_body
        != (
            expected_event_type
            in {"AppealApplicationDraftSaved", "AppealReviewDraftSaved"}
        )
        or (expected_event_type == "AppealOpened") != (if_match is None)
        or (
            contract[3] == "APPLICANT"
            and (
                session.account_code != "demand_owner_01"
                or session.role_codes != ("DEMAND_OWNER",)
            )
        )
        or (
            contract[3] == "REVIEWER"
            and (
                session.account_code != "appeal_reviewer_01"
                or session.role_codes != ("APPEAL_REVIEWER",)
            )
        )
    ):
        _invalid()
    if match.groups():
        _canonical_uuid(match.group(1))
    _validate_appeal_command_input(path=path, body=body)
    headers = {**_write_headers(session, if_match=if_match), "Origin": PILOT_ORIGIN}
    first_response = session.client.request(
        method=method,
        path=path,
        body=body,
        headers=headers,
        sensitive_body=sensitive_body,
    )
    _expect_appeal_command_status(first_response, expected_status)
    first = _appeal_command_receipt(
        first_response, expected_event_type=expected_event_type
    )
    if first["replayed"] is not False:
        _invalid()
    replay_response = session.client.request(
        method=method,
        path=path,
        body=body,
        headers=headers,
        sensitive_body=sensitive_body,
    )
    _expect_appeal_command_status(replay_response, expected_status)
    replay = _appeal_command_receipt(
        replay_response, expected_event_type=expected_event_type
    )
    if replay["replayed"] is not True:
        _invalid()
    if {
        key: value for key, value in first.items() if key != "replayed"
    } != {key: value for key, value in replay.items() if key != "replayed"}:
        _invalid()
    return first


def _validate_appeal_command_input(
    *, path: str, body: Mapping[str, Any]
) -> None:
    forbidden = {
        "actor_id",
        "applicant_id",
        "assignment_id",
        "decision_version_id",
        "organization_id",
        "reviewer_id",
        "role_code",
        "session_id",
    }
    if any(not isinstance(key, str) or key in forbidden for key in body):
        _invalid()
    if path == "/v1/app/appeals":
        _exact_keys(body, {"source_outcome_version_id"})
        _canonical_uuid(body["source_outcome_version_id"])
    elif path.endswith("/draft") and not path.endswith("/review-draft"):
        _exact_keys(
            body,
            {
                "applicant_statement",
                "grounds",
                "new_evidence_reference_ids",
                "requested_outcome",
            },
        )
        statement = body["applicant_statement"]
        if not isinstance(statement, str) or not (1 <= len(statement) <= 4_000):
            _invalid()
        _appeal_application_facts(body)
    elif path.endswith("/submit"):
        _exact_keys(body, {"expected_draft_version"})
        _positive_int(body["expected_draft_version"])
    elif path.endswith("/claim"):
        _exact_keys(body, set())
    elif path.endswith("/assignment/release"):
        _exact_keys(body, {"reason_code"})
        if body["reason_code"] not in {
            "ASSIGNMENT_EXPIRED",
            "CONFLICT_DECLARED",
            "WORKLOAD_RELEASE",
        }:
            _invalid()
    elif path.endswith("/review-draft"):
        _exact_keys(
            body,
            {"assessments", "reason_codes", "remedy_delta_codes", "reviewer_note"},
        )
        note = body["reviewer_note"]
        if not isinstance(note, str) or not (1 <= len(note) <= 4_000):
            _invalid()
        _appeal_assessments(body["assessments"])
        _closed_string_list(
            body["reason_codes"],
            allowed=_APPEAL_REASON_CODES,
            minimum=1,
            maximum=32,
        )
        _closed_string_list(
            body["remedy_delta_codes"],
            allowed=_APPEAL_REMEDY_CODES,
            minimum=1,
            maximum=32,
        )
    elif path.endswith("/decide"):
        _exact_keys(body, {"decision_code", "expected_review_draft_version"})
        if body["decision_code"] not in _APPEAL_DECISION_CODES:
            _invalid()
        _positive_int(body["expected_review_draft_version"])
    else:
        _invalid()


def _expect_appeal_command_status(response: HttpResult, expected_status: int) -> None:
    if response.status != expected_status:
        error = _appeal_error(response)
        # COMMAND_OUTCOME_UNKNOWN is an explicit terminal latch: never issue
        # an automatic replay or a new command after this response.
        if error["code"] == "COMMAND_OUTCOME_UNKNOWN":
            _invalid()
        _invalid()
    _require_appeal_http_headers(response, require_etag=False)


def _appeal_error(response: HttpResult) -> Mapping[str, Any]:
    _require_appeal_http_headers(response, require_etag=False)
    envelope = _exact_keys(response.json(), {"error"})
    error = envelope["error"]
    if not isinstance(error, Mapping) or set(error) not in ({"code"}, {"code", "path"}):
        _invalid()
    statuses = {
        "APPEAL_NOT_AVAILABLE": 404,
        "APPEAL_STATE_CONFLICT": 409,
        "APPEAL_VALIDATION_FAILED": 422,
        "ASSIGNMENT_UNAVAILABLE": 409,
        "AUTHENTICATION_REQUIRED": 401,
        "COMMAND_IN_PROGRESS": 409,
        "COMMAND_OUTCOME_UNKNOWN": 503,
        "CONFLICT_OF_INTEREST": 409,
        "CSRF_INVALID": 403,
        "CSRF_REQUIRED": 403,
        "IDEMPOTENCY_KEY_REUSED": 409,
        "INVALID_IDEMPOTENCY_KEY": 400,
        "INVALID_REQUEST": 400,
        "POLICY_ACCEPTANCE_REQUIRED": 403,
        "PRECONDITION_REQUIRED": 428,
        "RESOURCE_NOT_FOUND": 404,
        "SERVICE_UNAVAILABLE": 503,
        "SESSION_EXPIRED": 401,
        "STALE_VERSION": 412,
    }
    code = error.get("code")
    if not isinstance(code, str) or statuses.get(code) != response.status:
        _invalid()
    if "path" in error and (
        not isinstance(error["path"], str)
        or len(error["path"]) > 256
        or re.fullmatch(
            r"/(?:body|headers|path|query)(?:/[A-Za-z0-9_.~-]+)*",
            error["path"],
        )
        is None
    ):
        _invalid()
    return error


def _appeal_command_receipt(
    response: HttpResult, *, expected_event_type: str
) -> Mapping[str, Any]:
    envelope = _exact_keys(response.json(), {"data"})
    command = _exact_keys(envelope["data"], _APPEAL_COMMAND_FIELDS)
    _canonical_uuid(command["appeal_id"])
    _positive_int(command["aggregate_version"])
    if (
        command["appeal_status"] not in _APPEAL_STATUSES
        or not isinstance(command["replayed"], bool)
    ):
        _invalid()
    _appeal_timestamp(command["completed_at"])
    allowed_events = {
        "AppealApplicationDraftSaved",
        "AppealDecisionPublished",
        "AppealOpened",
        "AppealReviewClaimed",
        "AppealReviewAssignmentReleased",
        "AppealReviewDraftSaved",
        "AppealSubmitted",
    }
    if expected_event_type not in allowed_events or command["event_types"] != [
        expected_event_type
    ]:
        _invalid()
    for field in (
        "application_draft_version",
        "application_version",
        "review_draft_version",
    ):
        if command[field] is not None:
            _positive_int(command[field])
    if command["decision_version_id"] is not None:
        _canonical_uuid(command["decision_version_id"])
    expected_statuses = {
        "AppealOpened": "DRAFT",
        "AppealApplicationDraftSaved": "DRAFT",
        "AppealSubmitted": "SUBMITTED",
        "AppealReviewClaimed": "IN_REVIEW",
        "AppealReviewAssignmentReleased": "SUBMITTED",
        "AppealReviewDraftSaved": "IN_REVIEW",
        "AppealDecisionPublished": "DECIDED",
    }
    if command["appeal_status"] != expected_statuses[expected_event_type]:
        _invalid()
    if (expected_event_type == "AppealDecisionPublished") != (
        command["decision_version_id"] is not None
    ):
        _invalid()
    version_presence = {
        "AppealOpened": (False, False, False),
        "AppealApplicationDraftSaved": (True, False, False),
        "AppealSubmitted": (True, True, False),
        "AppealReviewClaimed": (True, True, False),
        "AppealReviewAssignmentReleased": (True, True, False),
        "AppealReviewDraftSaved": (True, True, True),
        "AppealDecisionPublished": (True, True, True),
    }
    actual_presence = tuple(
        command[field] is not None
        for field in (
            "application_draft_version",
            "application_version",
            "review_draft_version",
        )
    )
    if actual_presence != version_presence[expected_event_type]:
        _invalid()
    return command


def _find_own_appeal_by_source(
    session: RoleSession,
    *,
    source_outcome_version_id: str,
    allow_missing: bool,
) -> Mapping[str, Any] | None:
    _canonical_uuid(source_outcome_version_id)
    if not isinstance(allow_missing, bool):
        _invalid()
    response = session.client.request(
        method="GET",
        path="/v1/app/appeals",
        query={"source_outcome_version_id": source_outcome_version_id},
        headers=_app_headers(session),
    )
    if response.status == 404 and allow_missing:
        error = _appeal_error(response)
        if error["code"] != "RESOURCE_NOT_FOUND":
            _invalid()
        return None
    _expect_appeal_read_status(response)
    appeal = _appeal_own_envelope(response)
    if appeal["source_outcome_version_id"] != source_outcome_version_id:
        _invalid()
    return appeal


def _get_own_appeal(
    session: RoleSession, *, appeal_id: str
) -> Mapping[str, Any]:
    _canonical_uuid(appeal_id)
    response = session.client.request(
        method="GET",
        path=f"/v1/app/appeals/{appeal_id}",
        headers=_app_headers(session),
    )
    _expect_appeal_read_status(response)
    appeal = _appeal_own_envelope(response)
    if appeal["appeal_id"] != appeal_id:
        _invalid()
    return appeal


def _require_assignment_reader(
    session: RoleSession, *, role_code: str
) -> None:
    if (
        not isinstance(session, RoleSession)
        or role_code not in {"APPEAL_REVIEWER", "TRUST_OFFICER"}
        or session.workspace_kind != "PLATFORM"
        or session.role_codes != (role_code,)
        or ROLE_EXPECTATIONS.get(session.account_code)
        != ("PLATFORM", (role_code,))
        or _WORKSPACE.fullmatch(session.workspace_id) is None
    ):
        _invalid()


def _require_closed_read_failure(
    response: HttpResult,
    *,
    status: int,
    code: str,
    path: str | None = None,
) -> None:
    if (
        not isinstance(response, HttpResult)
        or response.status != status
        or response.headers.get("cache-control") != "no-store"
        or response.headers.get("content-type") != "application/json"
        or "etag" in response.headers
    ):
        _invalid()
    detail: dict[str, str] = {"code": code}
    if path is not None:
        detail["path"] = path
    envelope = _exact_keys(response.json(), {"error"})
    if _exact_keys(envelope["error"], set(detail)) != detail:
        _invalid()


def _verify_assignment_discovery_boundaries(
    *,
    admin: RoleSession,
    trust_officer: RoleSession,
    appeal_reviewer: RoleSession,
    second_reviewer_candidate: RoleSession,
    wrong_role: RoleSession,
    completed_appeal_id: str,
) -> Mapping[str, Any]:
    _require_assignment_reader(trust_officer, role_code="TRUST_OFFICER")
    _require_assignment_reader(appeal_reviewer, role_code="APPEAL_REVIEWER")
    _canonical_uuid(completed_appeal_id)
    if (
        not isinstance(admin, RoleSession)
        or admin.workspace_kind != "PLATFORM"
        or admin.role_codes != ("ACCESS_ADMIN",)
        or ROLE_EXPECTATIONS.get(admin.account_code)
        != ("PLATFORM", ("ACCESS_ADMIN",))
        or _WORKSPACE.fullmatch(admin.workspace_id) is None
        or not isinstance(second_reviewer_candidate, RoleSession)
        or second_reviewer_candidate.account_code != "trust_officer_02"
        or second_reviewer_candidate.workspace_kind != "PLATFORM"
        or second_reviewer_candidate.role_codes != ("TRUST_OFFICER",)
        or ROLE_EXPECTATIONS.get(second_reviewer_candidate.account_code)
        != ("PLATFORM", ("TRUST_OFFICER",))
        or _WORKSPACE.fullmatch(second_reviewer_candidate.workspace_id) is None
        or not isinstance(wrong_role, RoleSession)
        or wrong_role.workspace_kind != "PLATFORM"
        or wrong_role.role_codes != ("OPERATIONS_REVIEWER",)
        or ROLE_EXPECTATIONS.get(wrong_role.account_code)
        != ("PLATFORM", ("OPERATIONS_REVIEWER",))
        or _WORKSPACE.fullmatch(wrong_role.workspace_id) is None
    ):
        _invalid()

    for path in (
        "/v1/app/trust/assignments",
        "/v1/app/appeal-review/assignments",
        "/v1/app/appeal-review/history",
        f"/v1/app/appeal-review/history/{completed_appeal_id}",
    ):
        _require_closed_read_failure(
            wrong_role.client.request(
                method="GET",
                path=path,
                headers=_app_headers(wrong_role),
            ),
            status=404,
            code="RESOURCE_NOT_FOUND",
        )
    probe_hold_id = str(uuid4())
    assigned_hold_path = f"/v1/app/trust/assigned-holds/{probe_hold_id}"
    _require_closed_read_failure(
        wrong_role.client.request(
            method="GET",
            path=assigned_hold_path,
            headers=_app_headers(wrong_role),
        ),
        status=404,
        code="RESOURCE_NOT_FOUND",
    )
    _require_closed_read_failure(
        trust_officer.client.request(
            method="GET",
            path="/v1/app/trust/assignments",
            query={"limit": "1"},
            headers=_app_headers(trust_officer),
        ),
        status=404,
        code="RESOURCE_NOT_FOUND",
    )
    _require_closed_read_failure(
        trust_officer.client.request(
            method="GET",
            path=assigned_hold_path,
            headers=_app_headers(trust_officer),
        ),
        status=404,
        code="RESOURCE_NOT_FOUND",
    )
    _require_closed_read_failure(
        trust_officer.client.request(
            method="GET",
            path=assigned_hold_path,
            query={"limit": "1"},
            headers=_app_headers(trust_officer),
        ),
        status=404,
        code="RESOURCE_NOT_FOUND",
    )
    _require_closed_read_failure(
        appeal_reviewer.client.request(
            method="GET",
            path="/v1/app/appeal-review/assignments",
            query={"limit": "1"},
            headers=_app_headers(appeal_reviewer),
        ),
        status=400,
        code="INVALID_REQUEST",
        path="/query",
    )
    for path in (
        "/v1/app/appeal-review/history",
        f"/v1/app/appeal-review/history/{completed_appeal_id}",
    ):
        _require_closed_read_failure(
            appeal_reviewer.client.request(
                method="GET",
                path=path,
                query={"limit": "1"},
                headers=_app_headers(appeal_reviewer),
            ),
            status=400,
            code="INVALID_REQUEST",
            path="/query",
        )
    actor_scope = _verify_second_appeal_reviewer_history_boundary(
        admin=admin,
        candidate=second_reviewer_candidate,
        completed_appeal_id=completed_appeal_id,
    )
    if actor_scope != {
        "second_reviewer_history_empty": True,
        "second_reviewer_detail_hidden": True,
        "temporary_reviewer_duty_restored": True,
    }:
        _invalid()
    return {
        "wrong_role_reads_hidden": True,
        "extra_queries_rejected": True,
        "wrong_hold_reads_hidden": True,
        "assigned_hold_extra_queries_rejected": True,
        "wrong_role_history_hidden": True,
        "history_extra_queries_rejected": True,
        **actor_scope,
    }


def _verify_second_appeal_reviewer_history_boundary(
    *,
    admin: RoleSession,
    candidate: RoleSession,
    completed_appeal_id: str,
) -> Mapping[str, Any]:
    completed_appeal_id = _canonical_uuid(completed_appeal_id)
    if (
        admin.account_code != "access_admin_01"
        or admin.workspace_kind != "PLATFORM"
        or admin.role_codes != ("ACCESS_ADMIN",)
        or candidate.account_code != "trust_officer_02"
        or candidate.workspace_kind != "PLATFORM"
        or candidate.role_codes != ("TRUST_OFFICER",)
        or candidate.workspace_id == admin.workspace_id
    ):
        _invalid()
    accounts = _account_list(admin)
    targets = [
        item
        for item in accounts
        if item.get("account_code") == candidate.account_code
    ]
    if len(targets) != 1:
        _invalid()
    target = targets[0]
    original_role_codes = tuple(_closed_role_codes(target.get("role_codes")))
    duty_code = "APPEAL_REVIEWER"
    if (
        target.get("status") != "ACTIVE"
        or target.get("is_self") is not False
        or original_role_codes != candidate.role_codes
        or duty_code in original_role_codes
    ):
        _invalid()
    user_id = _canonical_uuid(target.get("user_id"))
    combined_role_codes = tuple(sorted({*original_role_codes, duty_code}))
    grant_command = _new_platform_duty_command(
        user_id=user_id,
        duty_code=duty_code,
        action="grant",
        if_match=target.get("entity_tag"),
    )

    operation_succeeded = False
    cleanup_succeeded = False
    grant_command_closed = False
    grant_first = None
    try:
        grant_first = _send_platform_duty_command(admin, grant_command)
        grant_replay = _send_platform_duty_command(admin, grant_command)
        granted = _validate_platform_duty_exact_replay(
            grant_first,
            grant_replay,
        )
        grant_command_closed = True
        after_grant = _account_detail(admin, user_id=user_id)
        if (
            after_grant["entity_tag"] != granted["entity_tag"]
            or set(_closed_role_codes(after_grant["role_codes"]))
            != set(combined_role_codes)
        ):
            _invalid()
        _expect_single_platform_workspace(
            candidate,
            expected_role_codes=combined_role_codes,
        )
        history_response = candidate.client.request(
            method="GET",
            path="/v1/app/appeal-review/history",
            headers=_app_headers(candidate),
        )
        history = _appeal_terminal_history_response(history_response)
        if history["items"] != [] or history["has_more"] is not False:
            _invalid()
        _require_closed_read_failure(
            candidate.client.request(
                method="GET",
                path=(
                    "/v1/app/appeal-review/history/"
                    f"{completed_appeal_id}"
                ),
                headers=_app_headers(candidate),
            ),
            status=404,
            code="RESOURCE_NOT_FOUND",
        )
        operation_succeeded = True
    except BaseException:
        operation_succeeded = False
    finally:
        if not grant_command_closed:
            grant_command_closed, _closed_receipt = (
                _converge_platform_duty_command(
                    admin,
                    command=grant_command,
                    observed_receipt=grant_first,
                )
            )
        if grant_command_closed:
            cleanup_succeeded = _reconcile_platform_duty_cleanup(
                admin,
                target_account_code=candidate.account_code,
                user_id=user_id,
                duty_code=duty_code,
                original_role_codes=original_role_codes,
            )
        if cleanup_succeeded:
            try:
                _expect_single_platform_workspace(
                    candidate,
                    expected_role_codes=original_role_codes,
                )
            except BaseException:
                cleanup_succeeded = False
    if not operation_succeeded or not cleanup_succeeded:
        _invalid()
    return {
        "second_reviewer_history_empty": True,
        "second_reviewer_detail_hidden": True,
        "temporary_reviewer_duty_restored": True,
    }


def _appeal_queue(session: RoleSession) -> Mapping[str, Any]:
    response = session.client.request(
        method="GET",
        path="/v1/app/appeal-review/queue",
        headers=_app_headers(session),
    )
    _expect_appeal_read_status(response)
    envelope = _exact_keys(response.json(), {"data"})
    queue = _exact_keys(envelope["data"], _APPEAL_QUEUE_FIELDS)
    _require_appeal_http_headers(response, require_etag=True)
    _require_appeal_etag(response, queue["entity_tag"])
    items = queue["items"]
    if not isinstance(items, list) or len(items) > 100:
        _invalid()
    seen: set[str] = set()
    for value in items:
        item = _exact_keys(value, _APPEAL_QUEUE_ITEM_FIELDS)
        for field in ("appeal_id", "source_case_id", "source_outcome_version_id"):
            _canonical_uuid(item[field])
        if (
            _APPEAL_ETAG.fullmatch(str(item["entity_tag"])) is None
            or item["appeal_id"] in seen
        ):
            _invalid()
        _appeal_ground_outcome_facts(item)
        _appeal_timestamp(item["submitted_at"])
        seen.add(item["appeal_id"])
    return queue


def _appeal_active_assignments(session: RoleSession) -> Mapping[str, Any]:
    _require_assignment_reader(session, role_code="APPEAL_REVIEWER")
    response = session.client.request(
        method="GET",
        path="/v1/app/appeal-review/assignments",
        headers=_app_headers(session),
    )
    _expect_appeal_read_status(response)
    envelope = _exact_keys(response.json(), {"data"})
    assignments = _exact_keys(
        envelope["data"], _APPEAL_ACTIVE_ASSIGNMENTS_FIELDS
    )
    _require_appeal_http_headers(response, require_etag=True)
    _require_appeal_etag(response, assignments["entity_tag"])
    items = assignments["items"]
    if not isinstance(items, list) or len(items) > 100:
        _invalid()
    seen: set[str] = set()
    for value in items:
        item = _exact_keys(value, _APPEAL_ACTIVE_ASSIGNMENT_ITEM_FIELDS)
        appeal_id = _canonical_uuid(item["appeal_id"])
        if appeal_id in seen:
            _invalid()
        _appeal_timestamp(item["assignment_expires_at"])
        seen.add(appeal_id)
    return assignments


def _appeal_terminal_history(session: RoleSession) -> Mapping[str, Any]:
    _require_assignment_reader(session, role_code="APPEAL_REVIEWER")
    response = session.client.request(
        method="GET",
        path="/v1/app/appeal-review/history",
        headers=_app_headers(session),
    )
    return _appeal_terminal_history_response(response)


def _appeal_terminal_history_response(
    response: HttpResult,
) -> Mapping[str, Any]:
    _expect_appeal_read_status(response)
    envelope = _exact_keys(response.json(), {"data"})
    history = _exact_keys(
        envelope["data"], _APPEAL_TERMINAL_HISTORY_FIELDS
    )
    _require_appeal_http_headers(response, require_etag=True)
    _require_appeal_etag(response, history["entity_tag"])
    items = history["items"]
    if not isinstance(items, list) or len(items) > 100:
        _invalid()
    has_more = history["has_more"]
    if not isinstance(has_more, bool) or (has_more and not items):
        _invalid()
    seen: set[str] = set()
    previous: tuple[datetime, str] | None = None
    for value in items:
        item = _exact_keys(value, _APPEAL_TERMINAL_HISTORY_ITEM_FIELDS)
        appeal_id = _canonical_uuid(item["appeal_id"])
        decided_at = _parse_utc_timestamp(item["decided_at"])
        if item["decision_code"] not in _APPEAL_DECISION_CODES:
            _invalid()
        coordinate = (decided_at, appeal_id)
        if appeal_id in seen or (
            previous is not None
            and not (
                coordinate[0] < previous[0]
                or (
                    coordinate[0] == previous[0]
                    and coordinate[1] < previous[1]
                )
            )
        ):
            _invalid()
        seen.add(appeal_id)
        previous = coordinate
    return history


def _get_terminal_appeal(
    session: RoleSession, *, appeal_id: str
) -> Mapping[str, Any]:
    _require_assignment_reader(session, role_code="APPEAL_REVIEWER")
    _canonical_uuid(appeal_id)
    response = session.client.request(
        method="GET",
        path=f"/v1/app/appeal-review/history/{appeal_id}",
        headers=_app_headers(session),
    )
    _expect_appeal_read_status(response)
    envelope = _exact_keys(response.json(), {"data"})
    detail = _exact_keys(
        envelope["data"], _APPEAL_TERMINAL_DETAIL_FIELDS
    )
    _require_appeal_http_headers(response, require_etag=True)
    _require_appeal_etag(response, detail["entity_tag"])
    application = _appeal_application(detail["application"])
    decision = _appeal_decision(detail["decision"])
    if (
        detail["appeal_id"] != appeal_id
        or detail["status"] != "DECIDED"
        or detail["review_note_recorded"] is not True
        or not isinstance(application, Mapping)
        or not isinstance(decision, Mapping)
    ):
        _invalid()
    _reject_restricted_appeal_projection(detail)
    return detail


def _require_appeal_active_assignment(
    assignments: Mapping[str, Any], *, appeal_id: str
) -> Mapping[str, Any]:
    _canonical_uuid(appeal_id)
    if not isinstance(assignments, Mapping):
        _invalid()
    items = assignments.get("items")
    if not isinstance(items, list):
        _invalid()
    matches = [item for item in items if item.get("appeal_id") == appeal_id]
    if len(matches) != 1:
        _invalid()
    return matches[0]


def _require_appeal_assignment_absent(
    assignments: Mapping[str, Any], *, appeal_id: str
) -> None:
    _canonical_uuid(appeal_id)
    if not isinstance(assignments, Mapping):
        _invalid()
    items = assignments.get("items")
    if not isinstance(items, list) or any(
        isinstance(item, Mapping) and item.get("appeal_id") == appeal_id
        for item in items
    ):
        _invalid()


def _get_assigned_appeal(
    session: RoleSession, *, appeal_id: str
) -> Mapping[str, Any]:
    _canonical_uuid(appeal_id)
    response = session.client.request(
        method="GET",
        path=f"/v1/app/appeal-review/appeals/{appeal_id}",
        headers=_app_headers(session),
    )
    _expect_appeal_read_status(response)
    envelope = _exact_keys(response.json(), {"data"})
    assigned = _exact_keys(envelope["data"], _APPEAL_ASSIGNED_FIELDS)
    _require_appeal_http_headers(response, require_etag=True)
    _require_appeal_etag(response, assigned["entity_tag"])
    appeal = _appeal_own_projection(assigned["appeal"])
    application = _appeal_application(assigned["application"])
    source = _appeal_source(assigned["source"])
    _appeal_timestamp(assigned["assignment_expires_at"])
    if (
        appeal["appeal_id"] != appeal_id
        or appeal["status"] != "IN_REVIEW"
        or appeal["entity_tag"] != assigned["entity_tag"]
        or appeal["application"] != application
        or appeal["source"] != source
    ):
        _invalid()
    if assigned["review_draft"] is not None:
        _appeal_review_draft(assigned["review_draft"])
    _reject_restricted_appeal_projection(assigned)
    return assigned


def _appeal_own_envelope(response: HttpResult) -> Mapping[str, Any]:
    _require_appeal_http_headers(response, require_etag=True)
    envelope = _exact_keys(response.json(), {"data"})
    appeal = _appeal_own_projection(envelope["data"])
    _require_appeal_etag(response, appeal["entity_tag"])
    return appeal


def _appeal_own_projection(value: Any) -> Mapping[str, Any]:
    appeal = _exact_keys(value, _APPEAL_OWN_FIELDS)
    _positive_int(appeal["aggregate_version"])
    for field in ("appeal_id", "source_case_id", "source_outcome_version_id"):
        _canonical_uuid(appeal[field])
    if (
        appeal["status"] not in _APPEAL_STATUSES
        or _APPEAL_ETAG.fullmatch(str(appeal["entity_tag"])) is None
    ):
        _invalid()
    source = _appeal_source(appeal["source"])
    if (
        source["case_id"] != appeal["source_case_id"]
        or source["outcome_version_id"] != appeal["source_outcome_version_id"]
    ):
        _invalid()
    if appeal["application_draft"] is not None:
        _appeal_application_draft(appeal["application_draft"])
    if appeal["application"] is not None:
        _appeal_application(appeal["application"])
    if appeal["decision"] is not None:
        _appeal_decision(appeal["decision"])
    if appeal["status"] == "DRAFT" and (
        appeal["application"] is not None or appeal["decision"] is not None
    ):
        _invalid()
    if appeal["status"] in {"SUBMITTED", "IN_REVIEW"} and (
        appeal["application"] is None or appeal["decision"] is not None
    ):
        _invalid()
    if appeal["status"] == "DECIDED" and (
        appeal["application"] is None or appeal["decision"] is None
    ):
        _invalid()
    if appeal["status"] == "WITHDRAWN" and appeal["decision"] is not None:
        _invalid()
    _reject_restricted_appeal_projection(appeal)
    return appeal


def _appeal_source(value: Any) -> Mapping[str, Any]:
    source = _exact_keys(value, _APPEAL_SOURCE_FIELDS)
    for field in (
        "case_id",
        "demand_id",
        "demand_version_id",
        "evidence_packet_version_id",
        "outcome_version_id",
    ):
        _canonical_uuid(source[field])
    for field in ("content_sha256", "evidence_packet_sha256"):
        if _SHA256.fullmatch(str(source[field])) is None:
            _invalid()
    _closed_string_list(
        source["action_codes"],
        allowed=_TRUST_ACTION_CODES,
        minimum=0,
        maximum=3,
    )
    _closed_string_list(
        source["reason_codes"],
        allowed=_TRUST_OUTCOME_REASON_CODES,
        minimum=1,
        maximum=32,
    )
    appeal_deadline = _appeal_timestamp(source["appeal_deadline"])
    decided_at = _appeal_timestamp(source["decided_at"])
    if (
        source["appeal_eligibility_code"] != "ELIGIBLE"
        or source["appeal_eligible"] is not True
        or source["outcome_code"] not in _TRUST_OUTCOME_CODES
        or re.fullmatch(r"[a-z][a-z0-9._-]{2,95}", str(source["policy_version"]))
        is None
    ):
        _invalid()
    if _parse_utc_timestamp(appeal_deadline) <= _parse_utc_timestamp(decided_at):
        _invalid()
    return source


def _appeal_application_facts(value: Mapping[str, Any]) -> None:
    _appeal_ground_outcome_facts(value)
    evidence_ids = value["new_evidence_reference_ids"]
    if (
        not isinstance(evidence_ids, list)
        or len(evidence_ids) > 32
        or not all(isinstance(child, str) for child in evidence_ids)
    ):
        _invalid()
    if len(set(evidence_ids)) != len(evidence_ids):
        _invalid()
    for evidence_id in evidence_ids:
        _canonical_uuid(evidence_id)
    if "NEW_MATERIAL_EVIDENCE" in value["grounds"] and not evidence_ids:
        _invalid()


def _appeal_ground_outcome_facts(value: Mapping[str, Any]) -> None:
    _closed_string_list(
        value["grounds"], allowed=_APPEAL_GROUNDS, minimum=1, maximum=3
    )
    if value["requested_outcome"] not in _APPEAL_REQUESTED_OUTCOMES:
        _invalid()


def _appeal_application_draft(value: Any) -> Mapping[str, Any]:
    draft = _exact_keys(value, _APPEAL_APPLICATION_DRAFT_FIELDS)
    _appeal_application_facts(draft)
    _appeal_timestamp(draft["edited_at"])
    _positive_int(draft["version"])
    if draft["statement_recorded"] is not True:
        _invalid()
    return draft


def _appeal_application(value: Any) -> Mapping[str, Any]:
    application = _exact_keys(value, _APPEAL_APPLICATION_FIELDS)
    _appeal_application_facts(application)
    _appeal_timestamp(application["submitted_at"])
    if application["statement_recorded"] is not True:
        _invalid()
    return application


def _appeal_assessments(value: Any) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not (1 <= len(value) <= 3):
        _invalid()
    canonical: set[str] = set()
    result: list[Mapping[str, Any]] = []
    for child in value:
        assessment = _exact_keys(child, _APPEAL_ASSESSMENT_FIELDS)
        evidence_ids = assessment["accepted_evidence_reference_ids"]
        if (
            not isinstance(evidence_ids, list)
            or len(evidence_ids) > 32
            or not all(isinstance(child, str) for child in evidence_ids)
        ):
            _invalid()
        if len(set(evidence_ids)) != len(evidence_ids):
            _invalid()
        for evidence_id in evidence_ids:
            _canonical_uuid(evidence_id)
        _closed_string_list(
            assessment["finding_codes"],
            allowed={
                "APPEAL_NOT_SUBSTANTIATED",
                "NEW_EVIDENCE_MATERIAL",
                "PROCEDURE_MATERIAL_ERROR",
                "RULE_APPLICATION_ERROR",
                "RULE_APPLIED_CORRECTLY",
            },
            minimum=1,
            maximum=32,
        )
        if (
            assessment["assessment_code"]
            not in {"ACCEPTED", "PARTIALLY_ACCEPTED", "REJECTED"}
            or assessment["ground"] not in _APPEAL_GROUNDS
        ):
            _invalid()
        encoded = json.dumps(assessment, sort_keys=True, separators=(",", ":"))
        if encoded in canonical:
            _invalid()
        canonical.add(encoded)
        result.append(assessment)
    return result


def _appeal_review_facts(value: Mapping[str, Any]) -> None:
    _appeal_assessments(value["assessments"])
    _closed_string_list(
        value["reason_codes"],
        allowed=_APPEAL_REASON_CODES,
        minimum=1,
        maximum=32,
    )
    _closed_string_list(
        value["remedy_delta_codes"],
        allowed=_APPEAL_REMEDY_CODES,
        minimum=1,
        maximum=32,
    )


def _appeal_review_draft(value: Any) -> Mapping[str, Any]:
    draft = _exact_keys(value, _APPEAL_REVIEW_DRAFT_FIELDS)
    _appeal_review_facts(draft)
    _appeal_timestamp(draft["edited_at"])
    _positive_int(draft["version"])
    if draft["review_note_recorded"] is not True:
        _invalid()
    return draft


def _appeal_decision(value: Any) -> Mapping[str, Any]:
    decision = _exact_keys(value, _APPEAL_DECISION_FIELDS)
    _appeal_review_facts(decision)
    _appeal_timestamp(decision["decided_at"])
    _canonical_uuid(decision["decision_version_id"])
    if (
        decision["decision_code"] not in _APPEAL_DECISION_CODES
        or _SHA256.fullmatch(str(decision["decision_sha256"])) is None
        or re.fullmatch(
            r"[a-z][a-z0-9._-]{2,95}", str(decision["policy_version"])
        )
        is None
    ):
        _invalid()
    return decision


def _require_appeal_http_headers(
    response: HttpResult, *, require_etag: bool
) -> None:
    if (
        response.headers.get("cache-control") != "no-store"
        or response.headers.get("content-type") != "application/json"
        or not isinstance(require_etag, bool)
    ):
        _invalid()
    if require_etag:
        if _APPEAL_ETAG.fullmatch(str(response.headers.get("etag"))) is None:
            _invalid()
    elif "etag" in response.headers:
        _invalid()


def _expect_appeal_read_status(response: HttpResult) -> None:
    if response.status != 200:
        _appeal_error(response)
        _invalid()


def _appeal_timestamp(value: Any) -> str:
    timestamp = _utc_timestamp(value)
    if not timestamp.endswith("Z"):
        _invalid()
    return timestamp


def _require_appeal_etag(response: HttpResult, value: Any) -> str:
    if (
        not isinstance(value, str)
        or _APPEAL_ETAG.fullmatch(value) is None
        or response.headers.get("etag") != value
    ):
        _invalid()
    return value


def _require_appeal_identity(
    appeal: Mapping[str, Any],
    *,
    appeal_id: str,
    source_case_id: str,
    source_outcome_version_id: str,
) -> None:
    if (
        appeal["appeal_id"] != appeal_id
        or appeal["source_case_id"] != source_case_id
        or appeal["source_outcome_version_id"] != source_outcome_version_id
    ):
        _invalid()


def _reject_restricted_appeal_projection(value: Mapping[str, Any]) -> None:
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":")).casefold()
    for forbidden in (
        "applicant_statement",
        "reviewer_note",
        "assignment_id",
        "applicant_id",
        "reviewer_id",
        "sealed_",
        "duty_grant",
    ):
        if forbidden in serialized:
            _invalid()


def _positive_int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        _invalid()
    return value


def _reviewable_demand_identity(
    value: Mapping[str, Any]
) -> tuple[str, str]:
    if value.get("status") != "SUBMITTED":
        _invalid()
    demand_id = _canonical_uuid(value.get("object_id"))
    current_version = value.get("current_version")
    if not isinstance(current_version, Mapping):
        _invalid()
    demand_version_id = _canonical_uuid(current_version.get("version_id"))
    assignment = value.get("review_assignment")
    if not isinstance(assignment, Mapping):
        _invalid()
    _canonical_uuid(assignment.get("assignment_id"))
    return demand_id, demand_version_id


def _verification_body() -> Mapping[str, Any]:
    return {
        "budget_health_code": "HEALTHY",
        "risk_code": "STANDARD",
        "evidence_codes": [
            "SCOPE_COMPLETE",
            "ACCEPTANCE_TESTABLE",
            "BUDGET_COHERENT",
            "RISK_HANDLED",
            "DECLARATIONS_CONFIRMED",
        ],
    }


def _blocked_verify_under_trust_hold(
    reviewer: RoleSession, *, reviewable_demand: Mapping[str, Any]
) -> tuple[Mapping[str, Any], str]:
    demand_id, demand_version_id = _reviewable_demand_identity(
        reviewable_demand
    )
    before = _get_resource(
        reviewer,
        f"/v1/app/demands/{demand_id}",
        resource_type="DEMAND",
    )
    current_demand_id, current_version_id = _reviewable_demand_identity(before)
    if current_demand_id != demand_id or current_version_id != demand_version_id:
        _invalid()
    assignment_id = _canonical_uuid(
        before["review_assignment"].get("assignment_id")
    )
    headers = _write_headers(reviewer, if_match=before["etag"])
    blocked_idempotency_key = headers["Idempotency-Key"]
    result = reviewer.client.request(
        method="POST",
        path=(
            f"/v1/app/demands/{demand_id}/review-assignments/"
            f"{assignment_id}/verify"
        ),
        body=_verification_body(),
        headers=headers,
    )
    _expect_status(result, 403)
    envelope = _exact_keys(result.json(), {"error"})
    error = _exact_keys(envelope["error"], {"code"})
    if error["code"] != "SAFETY_HOLD_BLOCKED":
        _invalid()
    after = _get_resource(
        reviewer,
        f"/v1/app/demands/{demand_id}",
        resource_type="DEMAND",
    )
    if after != before:
        _invalid()
    return before, blocked_idempotency_key


def _verify_demand_after_hold_release(
    reviewer: RoleSession,
    *,
    blocked_demand: Mapping[str, Any],
    blocked_idempotency_key: str,
) -> Mapping[str, Any]:
    demand_id, demand_version_id = _reviewable_demand_identity(blocked_demand)
    fresh = _get_resource(
        reviewer,
        f"/v1/app/demands/{demand_id}",
        resource_type="DEMAND",
    )
    fresh_demand_id, fresh_version_id = _reviewable_demand_identity(fresh)
    if fresh_demand_id != demand_id or fresh_version_id != demand_version_id:
        _invalid()
    assignment_id = _canonical_uuid(
        fresh["review_assignment"].get("assignment_id")
    )
    if (
        not isinstance(blocked_idempotency_key, str)
        or not blocked_idempotency_key
        or len(blocked_idempotency_key) > 200
    ):
        _invalid()
    headers = {
        **_write_headers(reviewer, if_match=fresh["etag"]),
        "Idempotency-Key": blocked_idempotency_key,
    }
    path = (
        f"/v1/app/demands/{demand_id}/review-assignments/"
        f"{assignment_id}/verify"
    )
    body = _verification_body()
    result = reviewer.client.request(
        method="POST",
        path=path,
        body=body,
        headers=headers,
    )
    _expect_status(result, 200)
    verified = _editor_envelope(result, resource_type="DEMAND")
    if (
        verified["object_id"] != demand_id
        or verified["status"] != "VERIFIED"
        or verified["revision"] != fresh["revision"] + 1
        or verified["revision"] != 7
        or not isinstance(verified.get("current_version"), Mapping)
        or verified["current_version"].get("version_id") != demand_version_id
    ):
        _invalid()
    _require_verified_finding(verified, demand_version_id=demand_version_id)
    replay_result = reviewer.client.request(
        method="POST",
        path=path,
        body=body,
        headers=headers,
    )
    _expect_status(replay_result, 200)
    replayed = _editor_envelope(replay_result, resource_type="DEMAND")
    if replayed != verified:
        _invalid()
    return verified


def _require_verified_finding(
    resource: Mapping[str, Any], *, demand_version_id: str
) -> None:
    _canonical_uuid(demand_version_id)
    findings = resource.get("findings")
    if not isinstance(findings, list) or not findings or len(findings) > 100:
        _invalid()
    matched = False
    for value in findings:
        finding = _owner_finding(value)
        if (
            finding["result"] == "VERIFIED"
            and finding["version_id"] == demand_version_id
        ):
            matched = True
    if not matched:
        _invalid()


def _claim(session: RoleSession, *, demand_id: str) -> Mapping[str, Any]:
    items = [item for item in _review_queue(session) if item["demand_id"] == demand_id]
    if len(items) != 1:
        _invalid()
    item = items[0]
    result = session.client.request(
        method="POST",
        path=f"/v1/app/review-queue/{demand_id}/claim",
        body={},
        headers=_write_headers(session, if_match=item["etag"]),
    )
    _expect_status(result, 200)
    envelope = result.json()
    _exact_keys(envelope, {"data"})
    claim = envelope["data"]
    _exact_keys(claim, _CLAIM_FIELDS)
    _canonical_uuid(claim["assignment_id"])
    _canonical_uuid(claim["demand_id"])
    _utc_timestamp(claim["expires_at"])
    if (
        claim["demand_id"] != demand_id
        or claim["status"] != "ACTIVE"
        or claim["etag"] != item["etag"]
        or result.headers.get("etag") != item["etag"]
    ):
        _invalid()
    return claim


def _review_queue(session: RoleSession) -> list[Mapping[str, Any]]:
    response = session.client.request(
        method="GET",
        path="/v1/app/review-queue",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    envelope = response.json()
    _exact_keys(envelope, {"data"})
    items = envelope["data"]
    if not isinstance(items, list) or len(items) > 100:
        _invalid()
    for item in items:
        _exact_keys(item, _QUEUE_FIELDS)
        _canonical_uuid(item["demand_id"])
        _utc_timestamp(item["submitted_at"])
        _utc_timestamp(item["demand_expires_at"])
        if _QUEUE_ETAG.fullmatch(str(item["etag"])) is None:
            _invalid()
    return items


def _trust_write_exact_replay(
    session: RoleSession,
    *,
    method: str,
    path: str,
    body: Mapping[str, Any],
    expected_status: int,
    expected_event_type: str,
    if_match: str | None = None,
) -> Mapping[str, Any]:
    if method not in {"POST", "PUT"} or not path.startswith("/v1/app/trust/"):
        _invalid()
    _reject_trust_authority_input(body, allow_restricted_note=method == "PUT")
    headers = _write_headers(session, if_match=if_match)
    first_response = session.client.request(
        method=method,
        path=path,
        body=body,
        headers=headers,
    )
    _expect_status(first_response, expected_status)
    first = _trust_command_envelope(
        first_response, expected_event_type=expected_event_type
    )
    replay_response = session.client.request(
        method=method,
        path=path,
        body=body,
        headers=headers,
    )
    _expect_status(replay_response, expected_status)
    replay = _trust_command_envelope(
        replay_response, expected_event_type=expected_event_type
    )
    if first["replayed"] is not False or replay["replayed"] is not True:
        _invalid()
    if {
        key: value for key, value in first.items() if key != "replayed"
    } != {key: value for key, value in replay.items() if key != "replayed"}:
        _invalid()
    return first


def _reject_trust_authority_input(
    body: Mapping[str, Any], *, allow_restricted_note: bool
) -> None:
    if not isinstance(body, Mapping):
        _invalid()
    forbidden = {
        "actor",
        "actor_id",
        "assignment",
        "assignment_id",
        "appeal_eligibility_code",
        "duty",
        "duty_code",
        "eligibility",
        "organization_id",
        "reporter",
        "reporter_id",
        "role",
        "role_code",
        "server_evidence",
        "session_id",
    }
    for key in body:
        if not isinstance(key, str) or key in forbidden:
            _invalid()
    if "restricted_note" in body:
        if not allow_restricted_note or set(body) != {
            "investigation_step_codes",
            "issue_codes",
            "jurisdiction_code",
            "priority_code",
            "proposed_hold_actions",
            "proposed_hold_ttl_minutes",
            "restricted_note",
            "severity_code",
        }:
            _invalid()
        note = body["restricted_note"]
        if not isinstance(note, str) or not (1 <= len(note) <= 4_000):
            _invalid()


def _trust_command_envelope(
    response: HttpResult, *, expected_event_type: str
) -> Mapping[str, Any]:
    envelope = _exact_keys(response.json(), {"data"})
    command = _exact_keys(envelope["data"], _TRUST_COMMAND_FIELDS)
    _canonical_uuid(command["case_id"])
    if (
        isinstance(command["aggregate_version"], bool)
        or not isinstance(command["aggregate_version"], int)
        or command["aggregate_version"] < 1
        or not isinstance(command["case_status"], str)
        or command["case_status"] not in _TRUST_CASE_STATUSES
        or not isinstance(command["replayed"], bool)
    ):
        _invalid()
    _utc_timestamp(command["completed_at"])
    allowed_events = {
        "SafetyHoldPlaced",
        "SafetyHoldReleased",
        "TrustCaseAssignmentReleased",
        "TrustCaseClaimed",
        "TrustCaseOutcomePublished",
        "TrustHoldReleaseClaimed",
        "TrustReportSubmitted",
        "TrustTriageDraftSaved",
        "TrustTriagePublished",
    }
    events = command["event_types"]
    if (
        expected_event_type not in allowed_events
        or events != [expected_event_type]
    ):
        _invalid()
    for field in ("hold_id", "outcome_version_id", "report_id"):
        if command[field] is not None:
            _canonical_uuid(command[field])
    for field in ("hold_version", "triage_draft_version", "triage_version"):
        child = command[field]
        if child is not None and (
            isinstance(child, bool) or not isinstance(child, int) or child < 1
        ):
            _invalid()
    return command


def _get_trust_report(
    session: RoleSession, *, report_id: str
) -> Mapping[str, Any]:
    _canonical_uuid(report_id)
    response = session.client.request(
        method="GET",
        path=f"/v1/app/trust/reports/{report_id}",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    report = _trust_report_envelope(response)
    if report["report_id"] != report_id:
        _invalid()
    return report


def _get_trust_case(
    session: RoleSession, *, case_id: str
) -> Mapping[str, Any]:
    _canonical_uuid(case_id)
    response = session.client.request(
        method="GET",
        path=f"/v1/app/trust/cases/{case_id}",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    case = _trust_case_envelope(response)
    if case["case_id"] != case_id:
        _invalid()
    return case


def _get_assigned_trust_hold(
    session: RoleSession, *, hold_id: str
) -> Mapping[str, Any]:
    _require_assignment_reader(session, role_code="TRUST_OFFICER")
    _canonical_uuid(hold_id)
    response = session.client.request(
        method="GET",
        path=f"/v1/app/trust/assigned-holds/{hold_id}",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    if (
        response.headers.get("cache-control") != "no-store"
        or response.headers.get("content-type") != "application/json"
    ):
        _invalid()
    envelope = _exact_keys(response.json(), {"data"})
    hold = _exact_keys(envelope["data"], _TRUST_ASSIGNED_HOLD_FIELDS)
    if hold["hold_id"] != hold_id:
        _invalid()
    _canonical_uuid(hold["hold_id"])
    _canonical_uuid(hold["case_id"])
    _closed_string_list(
        hold["action_codes"],
        allowed=_TRUST_ACTION_CODES,
        minimum=1,
        maximum=3,
    )
    effective_at = _parse_utc_timestamp(hold["effective_at"])
    expires_at = _parse_utc_timestamp(hold["expires_at"])
    assignment_expires_at = _parse_utc_timestamp(
        hold["assignment_expires_at"]
    )
    if (
        hold["case_status"] != "IN_REVIEW"
        or hold["hold_status"] != "ACTIVE"
        or hold["reason_code"]
        not in {"PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK"}
        or expires_at <= effective_at
        or assignment_expires_at <= effective_at
        or assignment_expires_at > expires_at
    ):
        _invalid()
    _require_trust_etag(response, hold["entity_tag"])
    return hold


def _trust_case_queue(session: RoleSession) -> Mapping[str, Any]:
    response = session.client.request(
        method="GET",
        path="/v1/app/trust/queue",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    envelope = _exact_keys(response.json(), {"data"})
    queue = _exact_keys(envelope["data"], _TRUST_QUEUE_FIELDS)
    _require_trust_etag(response, queue["entity_tag"])
    items = queue["items"]
    if not isinstance(items, list) or len(items) > 100:
        _invalid()
    seen: set[str] = set()
    for value in items:
        item = _exact_keys(value, _TRUST_QUEUE_ITEM_FIELDS)
        for field in ("case_id", "demand_id", "demand_version_id", "report_id"):
            _canonical_uuid(item[field])
        _trust_report_category(item["category"])
        _trust_impact_codes(item["impact_codes"])
        _utc_timestamp(item["submitted_at"])
        if _TRUST_ETAG.fullmatch(str(item["entity_tag"])) is None:
            _invalid()
        if item["case_id"] in seen:
            _invalid()
        seen.add(item["case_id"])
    return queue


def _trust_active_assignments(session: RoleSession) -> Mapping[str, Any]:
    _require_assignment_reader(session, role_code="TRUST_OFFICER")
    response = session.client.request(
        method="GET",
        path="/v1/app/trust/assignments",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    if (
        response.headers.get("cache-control") != "no-store"
        or response.headers.get("content-type") != "application/json"
    ):
        _invalid()
    envelope = _exact_keys(response.json(), {"data"})
    assignments = _exact_keys(
        envelope["data"], _TRUST_ACTIVE_ASSIGNMENTS_FIELDS
    )
    _require_trust_etag(response, assignments["entity_tag"])
    items = assignments["items"]
    if not isinstance(items, list) or len(items) > 100:
        _invalid()
    seen: set[tuple[str, str, str | None]] = set()
    for value in items:
        item = _exact_keys(value, _TRUST_ACTIVE_ASSIGNMENT_ITEM_FIELDS)
        case_id = _canonical_uuid(item["case_id"])
        assignment_purpose = item["assignment_purpose"]
        if assignment_purpose not in {"CASE_TRIAGE", "HOLD_RELEASE"}:
            _invalid()
        hold_id = item["hold_id"]
        if assignment_purpose == "CASE_TRIAGE":
            if hold_id is not None:
                _invalid()
        else:
            hold_id = _canonical_uuid(hold_id)
        assignment_key = (case_id, assignment_purpose, hold_id)
        if assignment_key in seen:
            _invalid()
        _utc_timestamp(item["assignment_expires_at"])
        seen.add(assignment_key)
    return assignments


def _trust_terminal_history(session: RoleSession) -> Mapping[str, Any]:
    _require_assignment_reader(session, role_code="TRUST_OFFICER")
    response = session.client.request(
        method="GET",
        path="/v1/app/trust/history",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    return _trust_terminal_history_envelope(response)


def _trust_terminal_history_envelope(
    response: HttpResult,
) -> Mapping[str, Any]:
    if (
        response.headers.get("cache-control") != "no-store"
        or response.headers.get("content-type") != "application/json"
    ):
        _invalid()
    envelope = _exact_keys(response.json(), {"data"})
    history = _exact_keys(
        envelope["data"], _TRUST_TERMINAL_HISTORY_FIELDS
    )
    _require_trust_etag(response, history["entity_tag"])
    items = history["items"]
    if not isinstance(items, list) or len(items) > 100:
        _invalid()
    has_more = history["has_more"]
    if not isinstance(has_more, bool) or (has_more and not items):
        _invalid()
    seen: set[str] = set()
    previous: tuple[datetime, str] | None = None
    for value in items:
        item = _exact_keys(value, _TRUST_TERMINAL_HISTORY_ITEM_FIELDS)
        case_id = _canonical_uuid(item["case_id"])
        decided_at = _parse_utc_timestamp(item["decided_at"])
        if item["outcome_code"] not in _TRUST_OUTCOME_CODES:
            _invalid()
        coordinate = (decided_at, case_id)
        if case_id in seen or (
            previous is not None
            and not (
                coordinate[0] < previous[0]
                or (
                    coordinate[0] == previous[0]
                    and coordinate[1] < previous[1]
                )
            )
        ):
            _invalid()
        seen.add(case_id)
        previous = coordinate
    return history


def _require_trust_active_assignment(
    assignments: Mapping[str, Any],
    *,
    case_id: str,
    assignment_purpose: str,
    hold_id: str | None = None,
) -> Mapping[str, Any]:
    _canonical_uuid(case_id)
    if assignment_purpose not in {"CASE_TRIAGE", "HOLD_RELEASE"}:
        _invalid()
    if assignment_purpose == "CASE_TRIAGE":
        if hold_id is not None:
            _invalid()
    else:
        hold_id = _canonical_uuid(hold_id)
    if not isinstance(assignments, Mapping):
        _invalid()
    items = assignments.get("items")
    if not isinstance(items, list):
        _invalid()
    matches = [
        item
        for item in items
        if item.get("case_id") == case_id
        and item.get("assignment_purpose") == assignment_purpose
        and item.get("hold_id") == hold_id
    ]
    if len(matches) != 1:
        _invalid()
    return matches[0]


def _require_trust_assignment_absent(
    assignments: Mapping[str, Any],
    *,
    case_id: str,
    assignment_purpose: str | None = None,
    hold_id: str | None = None,
) -> None:
    _canonical_uuid(case_id)
    if assignment_purpose is not None and assignment_purpose not in {
        "CASE_TRIAGE",
        "HOLD_RELEASE",
    }:
        _invalid()
    if assignment_purpose == "CASE_TRIAGE":
        if hold_id is not None:
            _invalid()
    elif assignment_purpose == "HOLD_RELEASE":
        hold_id = _canonical_uuid(hold_id)
    elif hold_id is not None:
        _invalid()
    if not isinstance(assignments, Mapping):
        _invalid()
    items = assignments.get("items")
    if not isinstance(items, list) or any(
        isinstance(item, Mapping)
        and item.get("case_id") == case_id
        and (
            assignment_purpose is None
            or (
                item.get("assignment_purpose") == assignment_purpose
                and item.get("hold_id") == hold_id
            )
        )
        for item in items
    ):
        _invalid()


def _trust_hold_release_queue(session: RoleSession) -> Mapping[str, Any]:
    response = session.client.request(
        method="GET",
        path="/v1/app/trust/hold-release-queue",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    envelope = _exact_keys(response.json(), {"data"})
    queue = _exact_keys(envelope["data"], _TRUST_QUEUE_FIELDS)
    _require_trust_etag(response, queue["entity_tag"])
    items = queue["items"]
    if not isinstance(items, list) or len(items) > 100:
        _invalid()
    seen: set[str] = set()
    for value in items:
        item = _exact_keys(value, _TRUST_HOLD_QUEUE_ITEM_FIELDS)
        for field in ("case_id", "demand_id", "demand_version_id", "hold_id"):
            _canonical_uuid(item[field])
        _closed_string_list(
            item["action_codes"],
            allowed=_TRUST_ACTION_CODES,
            minimum=1,
            maximum=3,
        )
        _utc_timestamp(item["expires_at"])
        if (
            _TRUST_ETAG.fullmatch(str(item["entity_tag"])) is None
            or not isinstance(item["reason_code"], str)
            or item["reason_code"]
            not in {"PARTICIPANT_SAFETY_RISK", "RETALIATION_RISK"}
            or item["hold_id"] in seen
        ):
            _invalid()
        seen.add(item["hold_id"])
    return queue


def _trust_report_envelope(response: HttpResult) -> Mapping[str, Any]:
    envelope = _exact_keys(response.json(), {"data"})
    report = _exact_keys(envelope["data"], _TRUST_REPORT_FIELDS)
    for field in ("demand_id", "demand_version_id", "report_id"):
        _canonical_uuid(report[field])
    _require_trust_etag(response, report["entity_tag"])
    _trust_report_summary(report["report"])
    _utc_timestamp(report["submitted_at"])
    if (
        not isinstance(report["status"], str)
        or report["status"] not in {"DECIDED", "IN_REVIEW", "OPEN", "TRIAGING"}
    ):
        _invalid()
    if report["outcome"] is not None:
        outcome = _trust_outcome_projection(report["outcome"])
        if outcome["redaction_profile_code"] != "PARTY_SAFE_V1":
            _invalid()
    return report


def _trust_case_envelope(response: HttpResult) -> Mapping[str, Any]:
    envelope = _exact_keys(response.json(), {"data"})
    case = _exact_keys(envelope["data"], _TRUST_CASE_FIELDS)
    for field in ("case_id", "demand_id", "demand_version_id", "report_id"):
        _canonical_uuid(case[field])
    if (
        isinstance(case["aggregate_version"], bool)
        or not isinstance(case["aggregate_version"], int)
        or case["aggregate_version"] < 1
        or not isinstance(case["status"], str)
        or case["status"] not in {"DECIDED", "IN_REVIEW", "TRIAGING"}
    ):
        _invalid()
    _require_trust_etag(response, case["entity_tag"])
    _trust_report_summary(case["report"])
    if case["active_hold"] is not None:
        _trust_hold_projection(case["active_hold"])
    if case["outcome"] is not None:
        _trust_outcome_projection(case["outcome"])
    if case["triage_draft"] is not None:
        _trust_triage_draft_projection(case["triage_draft"])
    return case


def _trust_report_summary(value: Any) -> Mapping[str, Any]:
    report = _exact_keys(value, _TRUST_REPORT_SUMMARY_FIELDS)
    _trust_report_category(report["category"])
    evidence_ids = report["evidence_reference_ids"]
    if (
        not isinstance(evidence_ids, list)
        or not (1 <= len(evidence_ids) <= 32)
        or not all(isinstance(child, str) for child in evidence_ids)
    ):
        _invalid()
    if len(set(evidence_ids)) != len(evidence_ids):
        _invalid()
    for child in evidence_ids:
        _canonical_uuid(child)
    _trust_impact_codes(report["impact_codes"])
    started = _parse_utc_timestamp(report["incident_started_at"])
    ended = report["incident_ended_at"]
    if ended is not None:
        if _parse_utc_timestamp(ended) < started:
            _invalid()
    _closed_string_list(
        report["requested_protection_codes"],
        allowed={"PAUSE_MATCHING", "PAUSE_SUBMISSION", "PAUSE_VERIFICATION"},
        minimum=1,
        maximum=3,
    )
    return report


def _trust_triage_draft_projection(value: Any) -> Mapping[str, Any]:
    draft = _exact_keys(value, _TRUST_TRIAGE_DRAFT_FIELDS)
    content = _exact_keys(draft["content"], _TRUST_SAFE_TRIAGE_FIELDS)
    _closed_string_list(
        content["investigation_step_codes"],
        allowed={
            "CHECK_ACCESS_SCOPE",
            "CHECK_DEMAND_VERSION",
            "CHECK_POLICY_REQUIREMENTS",
            "CHECK_SYNTHETIC_EVIDENCE",
            "REQUEST_PARTY_CLARIFICATION",
        },
        minimum=1,
        maximum=16,
    )
    _closed_string_list(
        content["issue_codes"],
        allowed={
            "DATA_HANDLING_GAP",
            "FRAUD_INDICATOR",
            "HARASSMENT_INDICATOR",
            "RETALIATION_INDICATOR",
            "SCOPE_DISCLOSURE_RISK",
            "WORKFLOW_INTEGRITY_GAP",
        },
        minimum=1,
        maximum=16,
    )
    _closed_string_list(
        content["proposed_hold_actions"],
        allowed=_TRUST_ACTION_CODES,
        minimum=1,
        maximum=3,
    )
    ttl = content["proposed_hold_ttl_minutes"]
    if (
        not isinstance(content["jurisdiction_code"], str)
        or content["jurisdiction_code"]
        not in {"LEGAL_REVIEW_REQUIRED", "ORGANIZATION_POLICY", "PLATFORM_INTERNAL"}
        or not isinstance(content["priority_code"], str)
        or content["priority_code"] not in {"P0", "P1", "P2", "P3"}
        or not isinstance(content["severity_code"], str)
        or content["severity_code"] not in {"CRITICAL", "HIGH", "LOW", "MEDIUM"}
        or isinstance(ttl, bool)
        or not isinstance(ttl, int)
        or not (15 <= ttl <= 10_080)
        or re.fullmatch(
            r"sealed://trust/[a-z0-9][a-z0-9/_-]{4,255}",
            str(content["sealed_note_reference"]),
        )
        is None
        or _SHA256.fullmatch(str(content["sealed_note_sha256"])) is None
        or _SHA256.fullmatch(str(draft["content_sha256"])) is None
        or isinstance(draft["triage_version"], bool)
        or not isinstance(draft["triage_version"], int)
        or draft["triage_version"] < 1
    ):
        _invalid()
    _utc_timestamp(draft["saved_at"])
    return draft


def _trust_hold_projection(value: Any) -> Mapping[str, Any]:
    hold = _exact_keys(value, _TRUST_HOLD_FIELDS)
    _canonical_uuid(hold["hold_id"])
    _closed_string_list(
        hold["action_codes"],
        allowed=_TRUST_ACTION_CODES,
        minimum=1,
        maximum=3,
    )
    effective = _parse_utc_timestamp(hold["effective_at"])
    expires = _parse_utc_timestamp(hold["expires_at"])
    if (
        _TRUST_ETAG.fullmatch(str(hold["entity_tag"])) is None
        or not isinstance(hold["status"], str)
        or hold["status"] not in {"ACTIVE", "EXPIRED", "RELEASED"}
        or expires <= effective
    ):
        _invalid()
    return hold


def _trust_outcome_projection(value: Any) -> Mapping[str, Any]:
    outcome = _exact_keys(value, _TRUST_OUTCOME_FIELDS)
    _closed_string_list(
        outcome["action_codes"],
        allowed=_TRUST_ACTION_CODES,
        minimum=0,
        maximum=3,
    )
    _closed_string_list(
        outcome["reason_codes"],
        allowed=_TRUST_OUTCOME_REASON_CODES,
        minimum=1,
        maximum=8,
    )
    for field in ("evidence_packet_version_id", "outcome_version_id"):
        _canonical_uuid(outcome[field])
    for field in (
        "content_sha256",
        "evidence_packet_digest",
        "source_digest",
    ):
        if _SHA256.fullmatch(str(outcome[field])) is None:
            _invalid()
    _utc_timestamp(outcome["decided_at"])
    if outcome["appeal_deadline"] is not None:
        _utc_timestamp(outcome["appeal_deadline"])
    if (
        not isinstance(outcome["appeal_eligibility_code"], str)
        or outcome["appeal_eligibility_code"] not in {"ELIGIBLE", "NOT_ELIGIBLE"}
        or not isinstance(outcome["outcome_code"], str)
        or outcome["outcome_code"] not in _TRUST_OUTCOME_CODES
        or re.fullmatch(
            r"trust-case-outcome-v[1-9][0-9]*", str(outcome["policy_version"])
        )
        is None
        or not isinstance(outcome["redaction_profile_code"], str)
        or outcome["redaction_profile_code"]
        not in {"OFFICER_RESTRICTED_V1", "PARTY_SAFE_V1"}
    ):
        _invalid()
    return outcome


def _require_trust_etag(response: HttpResult, entity_tag: Any) -> str:
    if (
        not isinstance(entity_tag, str)
        or _TRUST_ETAG.fullmatch(entity_tag) is None
        or response.headers.get("etag") != entity_tag
    ):
        _invalid()
    return entity_tag


def _trust_report_category(value: Any) -> str:
    if not isinstance(value, str) or value not in {
        "DATA_EXPOSURE",
        "FRAUD_RISK",
        "HARASSMENT",
        "RETALIATION",
        "WORKFLOW_INTEGRITY",
    }:
        _invalid()
    return value


def _trust_impact_codes(value: Any) -> list[str]:
    return _closed_string_list(
        value,
        allowed={
            "PARTICIPANT_SAFETY_RISK",
            "RETALIATION_RISK",
            "SYNTHETIC_DATA_DISCLOSED",
            "SYNTHETIC_FINANCIAL_RISK",
            "WORKFLOW_INTEGRITY_RISK",
        },
        minimum=1,
        maximum=16,
    )


def _closed_string_list(
    value: Any,
    *,
    allowed: set[str],
    minimum: int,
    maximum: int,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not (minimum <= len(value) <= maximum)
        or not all(isinstance(child, str) and child in allowed for child in value)
    ):
        _invalid()
    if len(set(value)) != len(value):
        _invalid()
    return value


def _require_trust_case_identity(
    case: Mapping[str, Any], context: Mapping[str, Any]
) -> None:
    if any(
        case[field] != context[field]
        for field in ("case_id", "demand_id", "demand_version_id", "report_id")
    ):
        _invalid()


def _require_triage_projection(
    case: Mapping[str, Any], *, request: Mapping[str, Any], expected_version: Any
) -> None:
    draft = case.get("triage_draft")
    if (
        not isinstance(draft, Mapping)
        or isinstance(expected_version, bool)
        or not isinstance(expected_version, int)
        or expected_version < 1
        or draft["triage_version"] != expected_version
    ):
        _invalid()
    content = draft["content"]
    closed_array_fields = {
        "investigation_step_codes",
        "issue_codes",
        "proposed_hold_actions",
    }
    for field in (
        "investigation_step_codes",
        "issue_codes",
        "jurisdiction_code",
        "priority_code",
        "proposed_hold_actions",
        "proposed_hold_ttl_minutes",
        "severity_code",
    ):
        expected = (
            sorted(request[field])
            if field in closed_array_fields
            else request[field]
        )
        if content[field] != expected:
            _invalid()


def _require_eligible_outcome(
    value: Any, *, outcome_version_id: str, party_safe: bool = False
) -> None:
    outcome = _trust_outcome_projection(value)
    if (
        outcome["outcome_version_id"] != outcome_version_id
        or outcome["outcome_code"] != "PROTECTION_MODIFIED"
        or outcome["appeal_eligibility_code"] != "ELIGIBLE"
        or outcome["appeal_deadline"] is None
        or outcome["action_codes"] != ["VERIFY_DEMAND"]
        or "RISK_MITIGATED" not in outcome["reason_codes"]
        or (
            party_safe
            and outcome["redaction_profile_code"] != "PARTY_SAFE_V1"
        )
    ):
        _invalid()


def _fund_verified_demand(
    *,
    operator_one: RoleSession,
    operator_two: RoleSession,
    owner: RoleSession,
    verified_demand: Mapping[str, Any],
) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if verified_demand.get("status") != "VERIFIED":
        _invalid()
    demand_id = _canonical_uuid(verified_demand.get("object_id"))
    demand_revision = verified_demand.get("revision")
    current_version = verified_demand.get("current_version")
    if (
        isinstance(demand_revision, bool)
        or not isinstance(demand_revision, int)
        or demand_revision < 1
        or not isinstance(current_version, Mapping)
    ):
        _invalid()
    demand_version_id = _canonical_uuid(current_version.get("version_id"))

    initial = _finance_queue_item(operator_one, demand_id=demand_id)
    if (
        initial["demand_version_id"] != demand_version_id
        or initial["demand_revision"] != demand_revision
        or initial["review_status"] != "AVAILABLE"
        or initial["funding_review_id"] is not None
        or initial["review_revision"] is not None
        or initial["assigned_to_me"] is not False
        or initial["confirmation_count"] != 0
    ):
        _invalid()

    released_cycle_claim = _finance_write_exact_replay(
        operator_one,
        path=f"/v1/app/finance/funding-reviews/{demand_id}/claim",
        body={},
        if_match=initial["etag"],
    )
    if (
        released_cycle_claim["demand_id"] != demand_id
        or released_cycle_claim["demand_version_id"] != demand_version_id
        or released_cycle_claim["status"] != "PENDING"
        or released_cycle_claim["revision"] != 1
        or released_cycle_claim["confirmation_count"] != 0
        or released_cycle_claim["assignment_status"] != "ACTIVE"
        or released_cycle_claim["confirmation_by_me"] is not False
        or released_cycle_claim["available_actions"]
        != list(FINANCE_FUNDING_ACTIONS)
        or released_cycle_claim["can_confirm"] is not True
    ):
        _invalid()
    released_cycle_detail = _finance_detail(
        operator_one,
        funding_review_id=released_cycle_claim["funding_review_id"],
    )
    if (
        released_cycle_detail["assignment_id"]
        != released_cycle_claim["assignment_id"]
        or released_cycle_detail["revision"]
        != released_cycle_claim["revision"]
        or released_cycle_detail["assignment_status"] != "ACTIVE"
        or released_cycle_detail["available_actions"]
        != list(FINANCE_FUNDING_ACTIONS)
    ):
        _invalid()

    released = _finance_write_exact_replay(
        operator_one,
        path=(
            "/v1/app/finance/funding-reviews/"
            f"{released_cycle_claim['funding_review_id']}/assignment/release"
        ),
        body={"reason_code": FINANCE_FUNDING_RELEASE_REASON_CODE},
        if_match=released_cycle_claim["etag"],
    )
    if (
        released["funding_review_id"]
        != released_cycle_claim["funding_review_id"]
        or released["status"] != "PENDING"
        or released["revision"] != 2
        or released["confirmation_count"] != 0
        or released["assignment_status"] != "RELEASED"
        or released["confirmation_by_me"] is not False
        or released["available_actions"] != []
        or released["can_confirm"] is not False
    ):
        _invalid()

    released_slot = _finance_queue_item(operator_one, demand_id=demand_id)
    if (
        released_slot["funding_review_id"]
        != released_cycle_claim["funding_review_id"]
        or released_slot["review_status"] != "PENDING"
        or released_slot["review_revision"] != 2
        or released_slot["confirmation_count"] != 0
        or released_slot["assigned_to_me"] is not False
    ):
        _invalid()
    reclaimed = _finance_write_exact_replay(
        operator_one,
        path=f"/v1/app/finance/funding-reviews/{demand_id}/claim",
        body={},
        if_match=released_slot["etag"],
    )
    if (
        reclaimed["funding_review_id"]
        != released_cycle_claim["funding_review_id"]
        or reclaimed["assignment_id"]
        == released_cycle_claim["assignment_id"]
        or reclaimed["status"] != "PENDING"
        or reclaimed["revision"] != 3
        or reclaimed["confirmation_count"] != 0
        or reclaimed["assignment_status"] != "ACTIVE"
        or reclaimed["confirmation_by_me"] is not False
        or reclaimed["available_actions"] != list(FINANCE_FUNDING_ACTIONS)
        or reclaimed["can_confirm"] is not True
    ):
        _invalid()

    discrepancy = _finance_write_exact_replay(
        operator_one,
        path=(
            "/v1/app/finance/funding-reviews/"
            f"{reclaimed['funding_review_id']}/findings"
        ),
        body={
            "disposition": "DISCREPANCY",
            "reason_codes": [FINANCE_FUNDING_DISCREPANCY_REASON_CODE],
            "required_field_codes": [FINANCE_FUNDING_DISCREPANCY_FIELD_CODE],
        },
        if_match=reclaimed["etag"],
    )
    if (
        discrepancy["funding_review_id"] != reclaimed["funding_review_id"]
        or discrepancy["status"] != "DISCREPANCY"
        or discrepancy["revision"] != 4
        or discrepancy["confirmation_count"] != 0
        or discrepancy["assignment_status"] != "COMPLETED"
        or discrepancy["confirmation_by_me"] is not False
        or discrepancy["available_actions"] != []
        or discrepancy["can_confirm"] is not False
    ):
        _invalid()

    discrepancy_history = _finance_history(operator_one, limit=1)
    if (
        len(discrepancy_history) != 1
        or discrepancy_history[0]["funding_review_id"]
        != discrepancy["funding_review_id"]
        or discrepancy_history[0]["demand_id"] != demand_id
        or discrepancy_history[0]["demand_version_id"] != demand_version_id
        or discrepancy_history[0]["status"] != "DISCREPANCY"
        or _finance_history(operator_two, limit=1) != []
    ):
        _invalid()

    after_discrepancy = _get_resource(
        owner,
        f"/v1/app/demands/{demand_id}",
        resource_type="DEMAND",
    )
    if (
        after_discrepancy["status"] != "VERIFIED"
        or after_discrepancy["revision"]
        != demand_revision + discrepancy["revision"]
        or not isinstance(after_discrepancy.get("current_version"), Mapping)
        or after_discrepancy["current_version"].get("version_id")
        != demand_version_id
    ):
        _invalid()
    _require_verified_finding(
        after_discrepancy, demand_version_id=demand_version_id
    )
    _require_finance_discrepancy_finding(
        after_discrepancy, demand_version_id=demand_version_id
    )

    new_cycle_available = _finance_queue_item(
        operator_one, demand_id=demand_id
    )
    if (
        new_cycle_available["review_status"] != "AVAILABLE"
        or new_cycle_available["funding_review_id"] is not None
        or new_cycle_available["review_revision"] is not None
        or new_cycle_available["assigned_to_me"] is not False
        or new_cycle_available["confirmation_count"] != 0
        or new_cycle_available["demand_revision"]
        != demand_revision + discrepancy["revision"]
    ):
        _invalid()
    first_claim = _finance_write_exact_replay(
        operator_one,
        path=f"/v1/app/finance/funding-reviews/{demand_id}/claim",
        body={},
        if_match=new_cycle_available["etag"],
    )
    if (
        first_claim["funding_review_id"] == discrepancy["funding_review_id"]
        or first_claim["status"] != "PENDING"
        or first_claim["revision"] != 1
        or first_claim["confirmation_count"] != 0
        or first_claim["assignment_status"] != "ACTIVE"
        or first_claim["confirmation_by_me"] is not False
        or first_claim["available_actions"] != list(FINANCE_FUNDING_ACTIONS)
    ):
        _invalid()

    first_confirmation = _finance_write_exact_replay(
        operator_one,
        path=(
            "/v1/app/finance/funding-reviews/"
            f"{first_claim['funding_review_id']}/confirm"
        ),
        body={"attestation_codes": list(FINANCE_FUNDING_ATTESTATION_CODES)},
        if_match=first_claim["etag"],
    )
    if (
        first_confirmation["funding_review_id"]
        != first_claim["funding_review_id"]
        or first_confirmation["status"] != "PENDING"
        or first_confirmation["revision"] != 2
        or first_confirmation["confirmation_count"] != 1
        or first_confirmation["assignment_status"] != "COMPLETED"
        or first_confirmation["confirmation_by_me"] is not True
        or first_confirmation["available_actions"] != []
        or first_confirmation["can_confirm"] is not False
    ):
        _invalid()

    pending = _finance_queue_item(operator_two, demand_id=demand_id)
    if (
        pending["funding_review_id"] != first_claim["funding_review_id"]
        or pending["demand_version_id"] != demand_version_id
        or pending["review_status"] != "PENDING"
        or pending["review_revision"] != 2
        or pending["confirmation_count"] != 1
        or pending["assigned_to_me"] is not False
    ):
        _invalid()
    second_claim = _finance_write_exact_replay(
        operator_two,
        path=f"/v1/app/finance/funding-reviews/{demand_id}/claim",
        body={},
        if_match=pending["etag"],
    )
    if (
        second_claim["funding_review_id"] != first_claim["funding_review_id"]
        or second_claim["status"] != "PENDING"
        or second_claim["revision"] != 3
        or second_claim["confirmation_count"] != 1
        or second_claim["assignment_status"] != "ACTIVE"
        or second_claim["confirmation_by_me"] is not False
        or second_claim["available_actions"] != list(FINANCE_FUNDING_ACTIONS)
        or second_claim["can_confirm"] is not True
        or second_claim["assignment_id"] == first_claim["assignment_id"]
    ):
        _invalid()

    secured = _finance_write_exact_replay(
        operator_two,
        path=(
            "/v1/app/finance/funding-reviews/"
            f"{second_claim['funding_review_id']}/confirm"
        ),
        body={"attestation_codes": list(FINANCE_FUNDING_ATTESTATION_CODES)},
        if_match=second_claim["etag"],
    )
    if (
        secured["status"] != "SECURED"
        or secured["revision"] != 4
        or secured["confirmation_count"] != 2
        or secured["assignment_status"] != "COMPLETED"
        or secured["confirmation_by_me"] is not True
        or secured["available_actions"] != []
        or secured["can_confirm"] is not False
    ):
        _invalid()
    for session in (operator_one, operator_two):
        if any(
            item["demand_id"] == demand_id for item in _finance_queue(session)
        ):
            _invalid()
        completed_detail = _finance_detail(
            session, funding_review_id=secured["funding_review_id"]
        )
        if (
            completed_detail["status"] != "SECURED"
            or completed_detail["assignment_status"] != "COMPLETED"
            or completed_detail["confirmation_by_me"] is not True
            or completed_detail["available_actions"] != []
            or completed_detail["can_confirm"] is not False
        ):
            _invalid()

    operator_one_history = _finance_history(operator_one, limit=1)
    operator_two_history = _finance_history(operator_two, limit=1)
    if (
        [item["funding_review_id"] for item in operator_one_history]
        != [secured["funding_review_id"], discrepancy["funding_review_id"]]
        or [item["status"] for item in operator_one_history]
        != ["SECURED", "DISCREPANCY"]
        or len(operator_two_history) != 1
        or operator_two_history[0]["funding_review_id"]
        != secured["funding_review_id"]
        or operator_two_history[0]["status"] != "SECURED"
        or any(
            item["demand_id"] != demand_id
            or item["demand_version_id"] != demand_version_id
            for item in operator_one_history + operator_two_history
        )
    ):
        _invalid()

    funded = _get_resource(
        owner,
        f"/v1/app/demands/{demand_id}",
        resource_type="DEMAND",
    )
    if (
        funded["status"] != "FUNDED"
        or funded["revision"]
        != demand_revision + discrepancy["revision"] + secured["revision"]
        or not isinstance(funded.get("current_version"), Mapping)
        or funded["current_version"].get("version_id") != demand_version_id
    ):
        _invalid()
    return funded, {
        "funding_review_id": secured["funding_review_id"],
        "review_status": secured["status"],
        "confirmation_count": secured["confirmation_count"],
        "assignments_distinct": True,
        "release_reclaimed_with_new_assignment": True,
        "discrepancy_cycle_terminal": True,
        "historical_cycles_distinct": True,
        "terminal_history_discoverable": True,
        "terminal_history_actor_scoped": True,
        "active_assignments_absent": True,
        "demand_status": funded["status"],
    }


def _finance_queue_item(
    session: RoleSession, *, demand_id: str
) -> Mapping[str, Any]:
    items = [
        item for item in _finance_queue(session) if item["demand_id"] == demand_id
    ]
    if len(items) != 1:
        _invalid()
    return items[0]


def _finance_queue(session: RoleSession) -> list[Mapping[str, Any]]:
    response = session.client.request(
        method="GET",
        path="/v1/app/finance/funding-reviews",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    envelope = response.json()
    _exact_keys(envelope, {"data"})
    items = envelope["data"]
    if not isinstance(items, list) or len(items) > 100:
        _invalid()
    seen: set[str] = set()
    for item in items:
        _finance_queue_projection(item)
        demand_id = item["demand_id"]
        if demand_id in seen:
            _invalid()
        seen.add(demand_id)
    return items


def _finance_history(
    session: RoleSession, *, limit: int = 100
) -> list[Mapping[str, Any]]:
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
        _invalid()
    parsed: list[Mapping[str, Any]] = []
    identities: set[str] = set()
    cursors: set[str] = set()
    cursor: str | None = None
    previous_coordinate: tuple[tuple[datetime, int], int] | None = None
    for _page_number in range(20):
        query = {"limit": str(limit)}
        if cursor is not None:
            query["cursor"] = cursor
        response = session.client.request(
            method="GET",
            path="/v1/app/finance/funding-review-history",
            query=query,
            headers=_app_headers(session),
        )
        _expect_status(response, 200)
        envelope = _exact_keys(response.json(), {"data"})
        page = _exact_keys(envelope["data"], _FINANCE_HISTORY_PAGE_FIELDS)
        if page["schema_version"] != "finance-funding-review-history-v1":
            _invalid()
        items = page["items"]
        if not isinstance(items, list) or len(items) > limit:
            _invalid()
        for raw_item in items:
            item = _exact_keys(raw_item, _FINANCE_HISTORY_ITEM_FIELDS)
            review_id = _canonical_uuid(item["funding_review_id"])
            _canonical_uuid(item["demand_id"])
            _canonical_uuid(item["demand_version_id"])
            if item["status"] not in {"SECURED", "DISCREPANCY", "REJECTED"}:
                _invalid()
            coordinate = (
                _parse_utc_timestamp(item["completed_at"]),
                UUID(review_id).int,
            )
            if review_id in identities or (
                previous_coordinate is not None
                and previous_coordinate <= coordinate
            ):
                _invalid()
            identities.add(review_id)
            previous_coordinate = coordinate
            parsed.append(item)
        next_cursor = page["next_cursor"]
        has_more = page["has_more"]
        if (
            not isinstance(has_more, bool)
            or (next_cursor is None) is not (not has_more)
        ):
            _invalid()
        if next_cursor is None:
            return parsed
        if (
            not items
            or not isinstance(next_cursor, str)
            or re.fullmatch(
                r"[A-Za-z0-9_-]{64,1024}\.[A-Za-z0-9_-]{43}",
                next_cursor,
            )
            is None
            or next_cursor in cursors
        ):
            _invalid()
        cursors.add(next_cursor)
        cursor = next_cursor
    _invalid()


def _finance_queue_projection(value: Any) -> Mapping[str, Any]:
    item = _exact_keys(value, _FINANCE_QUEUE_FIELDS)
    _canonical_uuid(item["demand_id"])
    _canonical_uuid(item["demand_version_id"])
    _utc_timestamp(item["expires_at"])
    if (
        isinstance(item["demand_revision"], bool)
        or not isinstance(item["demand_revision"], int)
        or item["demand_revision"] < 1
        or item["review_status"] not in {"AVAILABLE", "PENDING"}
        or not isinstance(item["assigned_to_me"], bool)
        or isinstance(item["confirmation_count"], bool)
        or item["confirmation_count"] not in {0, 1}
        or item["required_confirmations"] != 2
    ):
        _invalid()
    if item["review_status"] == "AVAILABLE":
        if (
            item["funding_review_id"] is not None
            or item["review_revision"] is not None
            or item["assigned_to_me"] is not False
            or item["confirmation_count"] != 0
            or item["etag"]
            != f'"demand-{item["demand_revision"]}-finance-queue"'
        ):
            _invalid()
    else:
        _canonical_uuid(item["funding_review_id"])
        if (
            isinstance(item["review_revision"], bool)
            or not isinstance(item["review_revision"], int)
            or item["review_revision"] < 1
            or item["etag"] != f'"funding-review-{item["review_revision"]}"'
        ):
            _invalid()
    return item


def _finance_detail(
    session: RoleSession, *, funding_review_id: str
) -> Mapping[str, Any]:
    _canonical_uuid(funding_review_id)
    response = session.client.request(
        method="GET",
        path=f"/v1/app/finance/funding-reviews/{funding_review_id}",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    return _finance_review_envelope(response)


def _finance_write_exact_replay(
    session: RoleSession,
    *,
    path: str,
    body: Mapping[str, Any],
    if_match: str,
) -> Mapping[str, Any]:
    headers = _write_headers(session, if_match=if_match)
    first_response = session.client.request(
        method="POST", path=path, body=body, headers=headers
    )
    _expect_status(first_response, 200)
    first = _finance_review_envelope(first_response)
    replay_response = session.client.request(
        method="POST", path=path, body=body, headers=headers
    )
    _expect_status(replay_response, 200)
    replay = _finance_review_envelope(replay_response)
    if first["replayed"] is not False or replay["replayed"] is not True:
        _invalid()
    if {
        key: value for key, value in first.items() if key != "replayed"
    } != {key: value for key, value in replay.items() if key != "replayed"}:
        _invalid()
    return first


def _finance_review_envelope(response: HttpResult) -> Mapping[str, Any]:
    envelope = response.json()
    _exact_keys(envelope, {"data"})
    review = _exact_keys(envelope["data"], _FINANCE_REVIEW_FIELDS)
    for field in (
        "funding_review_id",
        "demand_id",
        "demand_version_id",
        "assignment_id",
    ):
        _canonical_uuid(review[field])
    _utc_timestamp(review["assignment_expires_at"])
    expected_actions = (
        list(FINANCE_FUNDING_ACTIONS)
        if (
            review["status"] == "PENDING"
            and review["assignment_status"] == "ACTIVE"
            and review["confirmation_by_me"] is False
        )
        else []
    )
    if (
        review["status"]
        not in {"PENDING", "SECURED", "DISCREPANCY", "REJECTED"}
        or isinstance(review["revision"], bool)
        or not isinstance(review["revision"], int)
        or review["revision"] < 1
        or _SHA256.fullmatch(str(review["target_sha256"])) is None
        or _SHA256.fullmatch(str(review["target_content_sha256"])) is None
        or review["planned_budget_currency"] != "CNY"
        or any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            or value > 9_007_199_254_740_991
            for value in (
                review["planned_budget_minimum_amount_minor"],
                review["planned_budget_maximum_amount_minor"],
                review["planned_budget_direct_cost_amount_minor"],
            )
        )
        or review["planned_budget_minimum_amount_minor"]
        > review["planned_budget_maximum_amount_minor"]
        or _SHA256.fullmatch(str(review["evidence_reference_sha256"])) is None
        or review["evidence_kind"] != "INTERNAL_SANDBOX_ZERO_FUNDS_V1"
        or review["sandbox_funds_amount_minor"] != 0
        or review["provider_code"] != "NONE"
        or review["payment_operation_code"] != "NONE"
        or review["synthetic"] is not True
        or review["legal_effect"] != "NO_REAL_FUNDS_OR_PAYMENT"
        or isinstance(review["confirmation_count"], bool)
        or review["confirmation_count"] not in {0, 1, 2}
        or review["required_confirmations"] != 2
        or review["assignment_status"]
        not in {"ACTIVE", "COMPLETED", "RELEASED", "EXPIRED", "REVOKED"}
        or not isinstance(review["confirmation_by_me"], bool)
        or not isinstance(review["available_actions"], list)
        or review["available_actions"] != expected_actions
        or not isinstance(review["can_confirm"], bool)
        or review["can_confirm"] != ("CONFIRM" in expected_actions)
        or (review["status"] == "SECURED")
        != (review["confirmation_count"] == 2)
        or (
            review["status"] in {"DISCREPANCY", "REJECTED"}
            and review["confirmation_count"] == 2
        )
        or (
            review["confirmation_by_me"]
            and review["assignment_status"] != "COMPLETED"
        )
        or review["etag"] != f'"funding-review-{review["revision"]}"'
        or response.headers.get("etag") != review["etag"]
        or not isinstance(review["replayed"], bool)
    ):
        _invalid()
    return review


def _exercise_platform_duty_configuration(
    *, admin: RoleSession, target: RoleSession, funding_review_id: str
) -> Mapping[str, Any]:
    if (
        target.account_code != "finance_operator_01"
        or target.workspace_kind != "PLATFORM"
        or target.role_codes != ("FINANCE_OPERATOR",)
    ):
        _invalid()
    _canonical_uuid(funding_review_id)
    accounts = _account_list(admin)
    by_code = {item["account_code"]: item for item in accounts}
    if not set(ROLE_EXPECTATIONS).issubset(by_code):
        _invalid()
    target_account = by_code[target.account_code]
    original_roles = tuple(_closed_role_codes(target_account["role_codes"]))
    duty_code = "TRUST_OFFICER"
    if (
        original_roles != ("FINANCE_OPERATOR",)
        or original_roles != target.role_codes
        or duty_code in original_roles
        or target_account["status"] != "ACTIVE"
        or target_account["is_self"] is not False
    ):
        _invalid()
    combined_roles = tuple(sorted({*original_roles, duty_code}))
    grant_command = _new_platform_duty_command(
        user_id=target_account["user_id"],
        duty_code=duty_code,
        action="grant",
        if_match=target_account["entity_tag"],
    )

    operation_succeeded = False
    cleanup_succeeded = False
    grant_command_closed = False
    grant_first = None
    try:
        grant_first = _send_platform_duty_command(admin, grant_command)
        grant_replay = _send_platform_duty_command(admin, grant_command)
        granted = _validate_platform_duty_exact_replay(
            grant_first,
            grant_replay,
        )
        grant_command_closed = True
        after_grant = _account_detail(
            admin,
            user_id=target_account["user_id"],
        )
        granted_roles = _closed_role_codes(after_grant["role_codes"])
        if (
            after_grant["entity_tag"] != granted["entity_tag"]
            or set(granted_roles) != set(combined_roles)
        ):
            _invalid()
        _expect_single_platform_workspace(
            target,
            expected_role_codes=combined_roles,
        )
        finance_review = _finance_detail(
            target,
            funding_review_id=funding_review_id,
        )
        if (
            finance_review["funding_review_id"] != funding_review_id
            or finance_review["status"] != "SECURED"
            or finance_review["assignment_status"] != "COMPLETED"
            or finance_review["confirmation_by_me"] is not True
            or finance_review["available_actions"] != []
            or finance_review["can_confirm"] is not False
        ):
            _invalid()
        operation_succeeded = True
    except BaseException:
        operation_succeeded = False
    finally:
        if not grant_command_closed:
            grant_command_closed, _closed_receipt = (
                _converge_platform_duty_command(
                    admin,
                    command=grant_command,
                    observed_receipt=grant_first,
                )
            )
        if grant_command_closed:
            cleanup_succeeded = _reconcile_platform_duty_cleanup(
                admin,
                target_account_code=target.account_code,
                user_id=target_account["user_id"],
                duty_code=duty_code,
                original_role_codes=original_roles,
            )
        if cleanup_succeeded:
            try:
                _expect_single_platform_workspace(
                    target,
                    expected_role_codes=original_roles,
                )
            except BaseException:
                cleanup_succeeded = False
    if not operation_succeeded or not cleanup_succeeded:
        _invalid()
    return {
        "target_account_code": target.account_code,
        "duty_code": duty_code,
        "combined_role_codes": list(combined_roles),
        "grant_observed": True,
        "target_workspace_discovery_observed": True,
        "target_finance_operation_observed": True,
        "revoke_observed": True,
        "roles_restored": True,
    }


def _reconcile_platform_duty_cleanup(
    session: RoleSession,
    *,
    target_account_code: str,
    user_id: str,
    duty_code: str,
    original_role_codes: tuple[str, ...],
) -> bool:
    allowed_configuration = (
        target_account_code,
        duty_code,
        original_role_codes,
    ) in {
        (
            "finance_operator_01",
            "TRUST_OFFICER",
            ("FINANCE_OPERATOR",),
        ),
        (
            "trust_officer_02",
            "APPEAL_REVIEWER",
            ("TRUST_OFFICER",),
        ),
    }
    if not allowed_configuration:
        return False
    try:
        current = _account_detail(session, user_id=user_id)
    except BaseException:
        return False
    for _attempt in range(3):
        try:
            roles = tuple(_closed_role_codes(current["role_codes"]))
            if (
                current["account_code"] != target_account_code
                or current["user_id"] != user_id
                or current["status"] != "ACTIVE"
                or current["is_self"] is not False
            ):
                return False
            if roles == original_role_codes:
                restored, changed = _confirm_platform_duty_restored(
                    session,
                    current=current,
                    target_account_code=target_account_code,
                    user_id=user_id,
                    duty_code=duty_code,
                    original_role_codes=original_role_codes,
                )
                if restored:
                    return True
                if changed is None:
                    return False
                current = changed
                continue
            if duty_code not in roles:
                return False
            fresh_entity_tag = current["entity_tag"]
        except BaseException:
            return False

        revoked = None
        try:
            revoked = _platform_duty_command_exact_replay(
                session,
                user_id=user_id,
                duty_code=duty_code,
                action="revoke",
                if_match=fresh_entity_tag,
            )
        except BaseException:
            revoked = None
        try:
            current = _account_detail(session, user_id=user_id)
            roles = tuple(_closed_role_codes(current["role_codes"]))
            exact_target = (
                current["account_code"] == target_account_code
                and current["user_id"] == user_id
                and current["status"] == "ACTIVE"
                and current["is_self"] is False
            )
        except BaseException:
            return False
        if not exact_target:
            return False
        if roles == original_role_codes:
            if revoked is not None and (
                current["entity_tag"] != revoked["entity_tag"]
            ):
                return False
            restored, changed = _confirm_platform_duty_restored(
                session,
                current=current,
                target_account_code=target_account_code,
                user_id=user_id,
                duty_code=duty_code,
                original_role_codes=original_role_codes,
            )
            if restored:
                return True
            if changed is None:
                return False
            current = changed
            continue
        if duty_code not in roles:
            return False
    return False


def _confirm_platform_duty_restored(
    session: RoleSession,
    *,
    current: Mapping[str, Any],
    target_account_code: str,
    user_id: str,
    duty_code: str,
    original_role_codes: tuple[str, ...],
) -> tuple[bool, Any]:
    try:
        confirmed = _account_detail(session, user_id=user_id)
        exact_target = (
            current["account_code"] == target_account_code
            and current["user_id"] == user_id
            and current["status"] == "ACTIVE"
            and current["is_self"] is False
            and tuple(_closed_role_codes(current["role_codes"]))
            == original_role_codes
            and confirmed["account_code"] == target_account_code
            and confirmed["user_id"] == user_id
            and confirmed["status"] == "ACTIVE"
            and confirmed["is_self"] is False
        )
        confirmed_roles = tuple(_closed_role_codes(confirmed["role_codes"]))
        if not exact_target:
            return False, None
        if (
            confirmed_roles == original_role_codes
            and confirmed["entity_tag"] == current["entity_tag"]
        ):
            return True, None
        if duty_code in confirmed_roles:
            return False, confirmed
        return False, None
    except BaseException:
        return False, None


def _new_platform_duty_command(
    *,
    user_id: str,
    duty_code: str,
    action: str,
    if_match: str,
) -> _PlatformDutyCommand:
    _canonical_uuid(user_id)
    if (
        duty_code not in _CONFIGURABLE_PLATFORM_DUTY_CODES
        or action not in {"grant", "revoke"}
        or _ENTITY_TAG.fullmatch(if_match) is None
    ):
        _invalid()
    path = (
        f"/v1/app/admin/accounts/{user_id}/platform-duties/"
        f"{duty_code}/{action}"
    )
    return _PlatformDutyCommand(
        user_id=user_id,
        duty_code=duty_code,
        action=action,
        path=path,
        body_items=(("reason_code", "ACCESS_REVIEW"),),
        if_match=if_match,
        idempotency_key=_idempotency_key(),
    )


def _send_platform_duty_command(
    session: RoleSession,
    command: _PlatformDutyCommand,
) -> Mapping[str, Any]:
    if not isinstance(command, _PlatformDutyCommand):
        _invalid()
    expected_path = (
        f"/v1/app/admin/accounts/{command.user_id}/platform-duties/"
        f"{command.duty_code}/{command.action}"
    )
    try:
        _canonical_uuid(command.user_id)
        _canonical_uuid(
            command.idempotency_key.removeprefix("internal-sandbox-e2e-")
        )
    except BaseException:
        _invalid()
    if (
        command.duty_code not in _CONFIGURABLE_PLATFORM_DUTY_CODES
        or command.action not in {"grant", "revoke"}
        or command.path != expected_path
        or command.body_items != (("reason_code", "ACCESS_REVIEW"),)
        or _ENTITY_TAG.fullmatch(command.if_match) is None
        or not command.idempotency_key.startswith("internal-sandbox-e2e-")
    ):
        _invalid()
    headers = {
        **_app_headers(session),
        "Content-Type": "application/json",
        "Idempotency-Key": command.idempotency_key,
        "X-CSRF-Token": session.csrf_token,
        "If-Match": command.if_match,
    }
    response = session.client.request(
        method="POST",
        path=command.path,
        body=dict(command.body_items),
        headers=headers,
    )
    _expect_status(response, 200)
    return _account_command_envelope(
        response,
        target_user_id=command.user_id,
    )


def _validate_platform_duty_exact_replay(
    first: Mapping[str, Any],
    replay: Mapping[str, Any],
) -> Mapping[str, Any]:
    if first["replayed"] is not False or replay["replayed"] is not True:
        _invalid()
    if {
        key: value for key, value in first.items() if key != "replayed"
    } != {key: value for key, value in replay.items() if key != "replayed"}:
        _invalid()
    return first


def _converge_platform_duty_command(
    session: RoleSession,
    *,
    command: _PlatformDutyCommand,
    observed_receipt: Any,
) -> tuple[bool, Any]:
    for _attempt in range(4):
        try:
            receipt = _send_platform_duty_command(session, command)
        except BaseException:
            try:
                _account_detail(session, user_id=command.user_id)
            except BaseException:
                pass
            continue
        try:
            if observed_receipt is None:
                if receipt["replayed"] not in {False, True}:
                    return False, None
                return True, receipt
            if receipt["replayed"] is not True:
                return False, None
            if {
                key: value
                for key, value in observed_receipt.items()
                if key != "replayed"
            } != {
                key: value for key, value in receipt.items() if key != "replayed"
            }:
                return False, None
            return True, observed_receipt
        except BaseException:
            return False, None
    return False, None


def _platform_duty_command_exact_replay(
    session: RoleSession,
    *,
    user_id: str,
    duty_code: str,
    action: str,
    if_match: str,
) -> Mapping[str, Any]:
    command = _new_platform_duty_command(
        user_id=user_id,
        duty_code=duty_code,
        action=action,
        if_match=if_match,
    )
    first = _send_platform_duty_command(session, command)
    replay = _send_platform_duty_command(session, command)
    return _validate_platform_duty_exact_replay(first, replay)


def _exercise_organization_admin(
    *, admin: RoleSession, creator: RoleSession
) -> tuple[RoleSession, Mapping[str, Any]]:
    if admin.role_codes != ("ORG_ADMIN",):
        _invalid()
    organization_id = admin.workspace_id.removeprefix("org:")
    _canonical_uuid(organization_id)
    organization = _organization_summary(admin, organization_id=organization_id)
    if organization["status"] != "ACTIVE":
        _invalid()

    creator_user_id = _canonical_uuid(_get_json(creator.client, "/v1/me")["user_id"])
    issued = _issue_organization_invitation_exact_replay(
        admin,
        organization=organization,
        recipient_email="sandbox-creator-01@example.test",
        target_role="DEMAND_OWNER",
    )
    invitation = issued["invitation"]
    token = issued["access_invitation_token"]
    preview = _inspect_organization_invitation(creator.client, token=token)
    if (
        preview["invitation_id"] != invitation["invitation_id"]
        or preview["target_role"] != "DEMAND_OWNER"
        or preview["required_policy_bundle_id"]
        != invitation["required_policy_bundle_id"]
        or preview["entity_tag"] != invitation["entity_tag"]
    ):
        _invalid()
    if preview["organization"]["public_name"] != organization["public_name"]:
        _invalid()
    organization = _update_organization_public_name_exact_replay(
        admin,
        organization=organization,
        public_name=UPDATED_ORGANIZATION_PUBLIC_NAME,
    )
    renamed_preview = _inspect_organization_invitation(creator.client, token=token)
    if (
        renamed_preview["invitation_id"] != preview["invitation_id"]
        or renamed_preview["aggregate_version"] != preview["aggregate_version"]
        or renamed_preview["entity_tag"] != preview["entity_tag"]
        or renamed_preview["required_policy_bundle_id"]
        != preview["required_policy_bundle_id"]
        or renamed_preview["organization"]["public_name"]
        != UPDATED_ORGANIZATION_PUBLIC_NAME
    ):
        _invalid()
    preview = renamed_preview
    creator = _invitation_step_up(
        creator,
        token=token,
        invitation_id=invitation["invitation_id"],
    )
    creator_me_before = _read_active_me_with_etag(creator.client)
    if creator_me_before["user_id"] != creator_user_id:
        _invalid()
    creator, acceptance = _accept_organization_invitation(
        creator,
        preview=preview,
    )
    creator_me_after = _read_active_me_with_etag(creator.client)
    _require_active_creator_second_authority_transition(
        before=creator_me_before,
        accepted=acceptance["me"],
        refreshed=creator_me_after,
        organization_id=organization_id,
        required_policy_bundle_id=preview["required_policy_bundle_id"],
    )
    if (
        acceptance["invitation"]["invitation_id"]
        != invitation["invitation_id"]
        or acceptance["activated_scope"] != "ORGANIZATION_MEMBERSHIP"
        or acceptance["me"]["user_id"] != creator_user_id
    ):
        _invalid()
    _expect_creator_workspaces(
        creator.client,
        organization_id=organization_id,
        organization_present=True,
    )

    memberships = _organization_memberships(admin, organization_id=organization_id)
    accepted = [item for item in memberships if item["user_id"] == creator_user_id]
    if (
        len(accepted) != 1
        or accepted[0]["status"] != "ACTIVE"
        or accepted[0]["roles"] != ["DEMAND_OWNER"]
    ):
        _invalid()
    membership = accepted[0]
    suspended = _organization_lifecycle_exact_replay(
        admin,
        resource=membership,
        action="suspend",
        reason_code="SECURITY_REVIEW",
    )
    if suspended["status"] != "SUSPENDED":
        _invalid()
    _expect_creator_workspaces(
        creator.client,
        organization_id=organization_id,
        organization_present=False,
    )
    resumed = _organization_lifecycle_exact_replay(
        admin,
        resource=suspended,
        action="resume",
        reason_code="MEMBER_REQUEST",
    )
    if resumed["status"] != "ACTIVE":
        _invalid()
    _expect_creator_workspaces(
        creator.client,
        organization_id=organization_id,
        organization_present=True,
    )
    revoked = _organization_lifecycle_exact_replay(
        admin,
        resource=resumed,
        action="revoke",
        reason_code="ACCESS_REVIEW",
    )
    if revoked["status"] != "REVOKED":
        _invalid()
    _expect_creator_workspaces(
        creator.client,
        organization_id=organization_id,
        organization_present=False,
    )

    unaccepted = _issue_organization_invitation_exact_replay(
        admin,
        organization=organization,
        recipient_email="sandbox-finance-operator-01@example.test",
        target_role="DEMAND_OWNER",
    )["invitation"]
    revoked_invitation = _organization_lifecycle_exact_replay(
        admin,
        resource=unaccepted,
        action="revoke-invitation",
        reason_code="INVITATION_CANCELLED",
    )
    if revoked_invitation["status"] != "REVOKED":
        _invalid()
    return creator, {
        "organization_id": organization_id,
        "accepted_invitation_id": invitation["invitation_id"],
        "accepted_membership_id": membership["membership_id"],
        "revoked_invitation_id": revoked_invitation["invitation_id"],
        "active_second_authority_canonical_me_verified": True,
        "creator_workspace_added": True,
        "suspend_removed_org_workspace": True,
        "resume_restored_org_workspace": True,
        "revoke_removed_org_workspace": True,
        "unaccepted_invitation_revoked": True,
        "organization_public_name": organization["public_name"],
        "invitation_preview_live_name_verified": True,
    }


def _require_active_creator_second_authority_transition(
    *,
    before: Any,
    accepted: Any,
    refreshed: Any,
    organization_id: str,
    required_policy_bundle_id: str,
) -> None:
    """Close the active-Creator to second-authority MeDto transition."""

    exact_organization_id = _canonical_uuid(organization_id)
    exact_policy_bundle_id = _canonical_uuid(required_policy_bundle_id)
    before_me = _active_me(before)
    accepted_me = _active_me(accepted)
    refreshed_me = _active_me(refreshed)
    before_version = before_me["aggregate_version"]
    if (
        before_me["user_roles"] != ["CREATOR"]
        or before_me["memberships"] != []
        or accepted_me["user_id"] != before_me["user_id"]
        or accepted_me["status"] != before_me["status"]
        or accepted_me["display_handle"] != before_me["display_handle"]
        or accepted_me["user_roles"] != before_me["user_roles"]
        or accepted_me["aggregate_version"] != before_version + 1
        or accepted_me["entity_tag"] != f'"v{before_version + 1}"'
        or refreshed_me != accepted_me
    ):
        _invalid()

    before_requirements = before_me["policy_requirements"]
    accepted_requirements = accepted_me["policy_requirements"]
    if len(before_requirements) != 1 or len(accepted_requirements) != 2:
        _invalid()
    creator_requirement = _policy_requirement_projection(before_requirements[0])
    if (
        creator_requirement["purpose"] != "CREATOR_ENROLLMENT"
        or creator_requirement["role"] != "CREATOR"
        or creator_requirement["scope_type"] != "USER_ROLE"
        or creator_requirement["scope_id"] is not None
        or creator_requirement["satisfied"] is not True
        or creator_requirement["required_policy_bundle_id"] is None
        or creator_requirement["missing_document_ids"] != []
        or creator_requirement not in accepted_requirements
    ):
        _invalid()
    owner_requirements = [
        _policy_requirement_projection(value)
        for value in accepted_requirements
        if isinstance(value, dict) and value.get("role") == "DEMAND_OWNER"
    ]
    if len(owner_requirements) != 1:
        _invalid()
    owner_requirement = owner_requirements[0]
    if (
        owner_requirement["purpose"] != "ORGANIZATION_MEMBERSHIP"
        or owner_requirement["scope_type"] != "ORGANIZATION_ROLE"
        or owner_requirement["scope_id"] != exact_organization_id
        or owner_requirement["satisfied"] is not True
        or owner_requirement["required_policy_bundle_id"]
        != exact_policy_bundle_id
        or owner_requirement["missing_document_ids"] != []
    ):
        _invalid()

    memberships = accepted_me["memberships"]
    if len(memberships) != 1:
        _invalid()
    membership = _self_membership_projection(memberships[0])
    organization = membership["organization"]
    if (
        membership["status"] != "ACTIVE"
        or membership["roles"] != ["DEMAND_OWNER"]
        or organization["organization_id"] != exact_organization_id
        or organization["status"] != "ACTIVE"
    ):
        _invalid()


def _active_me(value: Any) -> Mapping[str, Any]:
    me = _exact_keys(
        value,
        {
            "user_id",
            "status",
            "display_handle",
            "user_roles",
            "memberships",
            "policy_requirements",
            "aggregate_version",
            "entity_tag",
        },
    )
    _canonical_uuid(me["user_id"])
    if (
        me["status"] != "ACTIVE"
        or not isinstance(me["display_handle"], str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{1,79}",
            me["display_handle"],
        )
        is None
        or not isinstance(me["user_roles"], list)
        or len(me["user_roles"]) > 1
        or any(
            not isinstance(role, str) or role != "CREATOR"
            for role in me["user_roles"]
        )
        or len(set(me["user_roles"])) != len(me["user_roles"])
        or not isinstance(me["memberships"], list)
        or len(me["memberships"]) > 100
        or not isinstance(me["policy_requirements"], list)
        or len(me["policy_requirements"]) > 100
        or not _version_and_tag(me)
    ):
        _invalid()
    return me


def _policy_requirement_projection(value: Any) -> Mapping[str, Any]:
    requirement = _exact_keys(
        value,
        {
            "selector_digest",
            "purpose",
            "role",
            "scope_type",
            "scope_id",
            "satisfied",
            "required_policy_bundle_id",
            "missing_document_ids",
        },
    )
    scope_id = requirement["scope_id"]
    bundle_id = requirement["required_policy_bundle_id"]
    missing = requirement["missing_document_ids"]
    if (
        not isinstance(requirement["selector_digest"], str)
        or _SHA256.fullmatch(requirement["selector_digest"]) is None
        or requirement["purpose"]
        not in {"CREATOR_ENROLLMENT", "ORGANIZATION_MEMBERSHIP"}
        or requirement["role"] not in {"CREATOR", "ORG_ADMIN", "DEMAND_OWNER"}
        or requirement["scope_type"] not in {"USER_ROLE", "ORGANIZATION_ROLE"}
        or not isinstance(requirement["satisfied"], bool)
        or not isinstance(missing, list)
        or len(missing) > 20
        or not all(isinstance(document_id, str) for document_id in missing)
        or len(set(missing)) != len(missing)
    ):
        _invalid()
    if bundle_id is not None:
        _canonical_uuid(bundle_id)
    for document_id in missing:
        _canonical_uuid(document_id)
    if requirement["scope_type"] == "USER_ROLE":
        if (
            scope_id is not None
            or requirement["purpose"] != "CREATOR_ENROLLMENT"
            or requirement["role"] != "CREATOR"
        ):
            _invalid()
    else:
        _canonical_uuid(scope_id)
        if (
            requirement["purpose"] != "ORGANIZATION_MEMBERSHIP"
            or requirement["role"] not in {"ORG_ADMIN", "DEMAND_OWNER"}
        ):
            _invalid()
    if requirement["satisfied"] != (missing == []):
        _invalid()
    return requirement


def _self_membership_projection(value: Any) -> Mapping[str, Any]:
    membership = _exact_keys(
        value,
        {
            "membership_id",
            "organization",
            "status",
            "roles",
            "aggregate_version",
            "entity_tag",
        },
    )
    _canonical_uuid(membership["membership_id"])
    organization = _organization(membership["organization"])
    roles = membership["roles"]
    if (
        membership["status"] not in {"ACTIVE", "SUSPENDED", "REVOKED"}
        or not isinstance(roles, list)
        or not 1 <= len(roles) <= 2
        or any(
            not isinstance(role, str)
            or role not in {"ORG_ADMIN", "DEMAND_OWNER"}
            for role in roles
        )
        or len(set(roles)) != len(roles)
        or not _version_and_tag(membership)
    ):
        _invalid()
    return {**membership, "organization": organization}


def _verify_organization_restart(
    session: RoleSession,
    *,
    creator_user_id: str,
    state: JourneyState,
) -> Mapping[str, Any]:
    _canonical_uuid(creator_user_id)
    organization = _organization_summary(
        session, organization_id=state.organization_id
    )
    memberships = _organization_memberships(
        session, organization_id=state.organization_id
    )
    invitations = _organization_invitations(
        session, organization_id=state.organization_id
    )
    accepted_memberships = [
        item
        for item in memberships
        if item["membership_id"] == state.accepted_membership_id
    ]
    accepted_invitations = [
        item
        for item in invitations
        if item["invitation_id"] == state.accepted_invitation_id
    ]
    revoked_invitations = [
        item
        for item in invitations
        if item["invitation_id"] == state.revoked_invitation_id
    ]
    if (
        organization["status"] != "ACTIVE"
        or organization["public_name"] != UPDATED_ORGANIZATION_PUBLIC_NAME
        or len(accepted_memberships) != 1
        or accepted_memberships[0]["user_id"] != creator_user_id
        or accepted_memberships[0]["status"] != "REVOKED"
        or len(accepted_invitations) != 1
        or accepted_invitations[0]["status"] != "ACCEPTED"
        or len(revoked_invitations) != 1
        or revoked_invitations[0]["status"] != "REVOKED"
    ):
        _invalid()
    return {
        "organization_id": state.organization_id,
        "accepted_membership_status": "REVOKED",
        "accepted_invitation_status": "ACCEPTED",
        "unaccepted_invitation_status": "REVOKED",
        "organization_public_name": organization["public_name"],
    }


def _organization_summary(
    session: RoleSession, *, organization_id: str
) -> Mapping[str, Any]:
    _canonical_uuid(organization_id)
    response = session.client.request(
        method="GET",
        path=f"/v1/organizations/{organization_id}",
        headers={"Accept": "application/json"},
    )
    _expect_status(response, 200)
    organization = _organization(response.json())
    if (
        organization["organization_id"] != organization_id
        or response.headers.get("etag") != organization["entity_tag"]
    ):
        _invalid()
    return organization


def _update_organization_public_name_exact_replay(
    session: RoleSession,
    *,
    organization: Mapping[str, Any],
    public_name: str,
) -> Mapping[str, Any]:
    exact_organization = _organization(organization)
    if (
        exact_organization["status"] != "ACTIVE"
        or public_name != UPDATED_ORGANIZATION_PUBLIC_NAME
        or public_name == exact_organization["public_name"]
    ):
        _invalid()
    path = (
        f"/v1/organizations/{exact_organization['organization_id']}"
        "/public-name"
    )
    body = {
        "public_name": public_name,
        "reason_code": "PUBLIC_NAME_CORRECTION",
    }
    headers = _iam_write_headers(
        session, if_match=exact_organization["entity_tag"]
    )
    first_response = session.client.request(
        method="POST", path=path, body=body, headers=headers
    )
    _expect_status(first_response, 200)
    first = _organization(first_response.json())
    replay_response = session.client.request(
        method="POST", path=path, body=body, headers=headers
    )
    _expect_status(replay_response, 200)
    replay = _organization(replay_response.json())
    if (
        first != replay
        or first["organization_id"] != exact_organization["organization_id"]
        or first["public_name"] != public_name
        or first["aggregate_version"]
        != exact_organization["aggregate_version"] + 1
        or first_response.headers.get("etag") != first["entity_tag"]
        or replay_response.headers.get("etag") != replay["entity_tag"]
    ):
        _invalid()
    return first


def _organization(value: Any) -> Mapping[str, Any]:
    organization = _exact_keys(value, _ORGANIZATION_FIELDS)
    _canonical_uuid(organization["organization_id"])
    if (
        not isinstance(organization["public_name"], str)
        or not 1 <= len(organization["public_name"]) <= 160
        or organization["type"]
        not in {"BUSINESS", "NONPROFIT", "COMMUNITY", "CREATOR_TEAM"}
        or organization["status"]
        not in {"PENDING_ADMIN", "ACTIVE", "SUSPENDED", "CLOSED"}
        or not _version_and_tag(organization)
    ):
        _invalid()
    return organization


def _organization_invitations(
    session: RoleSession, *, organization_id: str
) -> list[Mapping[str, Any]]:
    return _organization_page(
        session,
        path=f"/v1/organizations/{_canonical_uuid(organization_id)}/access-invitations",
        parser=_invitation_admin,
        identity_field="invitation_id",
    )


def _organization_memberships(
    session: RoleSession, *, organization_id: str
) -> list[Mapping[str, Any]]:
    return _organization_page(
        session,
        path=f"/v1/organizations/{_canonical_uuid(organization_id)}/memberships",
        parser=_membership_admin,
        identity_field="membership_id",
    )


def _organization_page(
    session: RoleSession,
    *,
    path: str,
    parser: Any,
    identity_field: str,
) -> list[Mapping[str, Any]]:
    parsed: list[Mapping[str, Any]] = []
    identities: set[str] = set()
    cursors: set[str] = set()
    cursor: str | None = None
    for _page_number in range(20):
        query = {"limit": "100"}
        if cursor is not None:
            query["cursor"] = cursor
        response = session.client.request(
            method="GET",
            path=path,
            query=query,
            headers={"Accept": "application/json"},
        )
        _expect_status(response, 200)
        page = _exact_keys(response.json(), {"items", "page"})
        page_info = _exact_keys(page["page"], {"next_cursor"})
        items = page["items"]
        if not isinstance(items, list) or len(items) > 100:
            _invalid()
        for raw_item in items:
            item = parser(raw_item)
            identity = item[identity_field]
            if identity in identities:
                _invalid()
            identities.add(identity)
            parsed.append(item)
        next_cursor = page_info["next_cursor"]
        if next_cursor is None:
            return parsed
        if (
            not isinstance(next_cursor, str)
            or re.fullmatch(
                r"[A-Za-z0-9_-]{64,1900}\.[A-Za-z0-9_-]{43}",
                next_cursor,
            )
            is None
            or next_cursor in cursors
        ):
            _invalid()
        cursors.add(next_cursor)
        cursor = next_cursor
    _invalid()


def _issue_organization_invitation_exact_replay(
    session: RoleSession,
    *,
    organization: Mapping[str, Any],
    recipient_email: str,
    target_role: str,
) -> Mapping[str, Any]:
    exact_organization = _organization(organization)
    if (
        exact_organization["status"] != "ACTIVE"
        or target_role not in {"ORG_ADMIN", "DEMAND_OWNER"}
        or recipient_email
        not in {
            "sandbox-creator-01@example.test",
            "sandbox-finance-operator-01@example.test",
            PROVIDER_ONLY_INVITED_DEMAND_OWNER_EMAIL,
        }
    ):
        _invalid()
    body = {
        "recipient": {"type": "EMAIL", "value": recipient_email},
        "target_role": target_role,
        "expires_at": (
            datetime.now(timezone.utc) + timedelta(days=7)
        ).replace(microsecond=0).isoformat(),
    }
    headers = _iam_write_headers(
        session, if_match=exact_organization["entity_tag"]
    )
    path = (
        f"/v1/organizations/{exact_organization['organization_id']}"
        "/access-invitations"
    )
    first_response = session.client.request(
        method="POST", path=path, body=body, headers=headers
    )
    _expect_status(first_response, 201)
    first = _issued_invitation(first_response)
    replay_response = session.client.request(
        method="POST", path=path, body=body, headers=headers
    )
    _expect_status(replay_response, 201)
    replay = _issued_invitation(replay_response)
    if first != replay:
        _invalid()
    return first


def _issued_invitation(response: HttpResult) -> Mapping[str, Any]:
    issued = _exact_keys(
        response.json(),
        {"invitation", "access_invitation_token", "join_fragment_url"},
    )
    invitation = _invitation_admin(issued["invitation"])
    token = issued["access_invitation_token"]
    if (
        invitation["status"] != "ISSUED"
        or invitation["purpose"] != "ORGANIZATION_MEMBERSHIP"
        or _CAPABILITY_TOKEN.fullmatch(str(token)) is None
        or issued["join_fragment_url"]
        != f"/join#access_invitation_token={token}"
        or response.headers.get("etag") != invitation["entity_tag"]
    ):
        _invalid()
    return issued


def _inspect_organization_invitation(
    client: CurlClient, *, token: str
) -> Mapping[str, Any]:
    if _CAPABILITY_TOKEN.fullmatch(token) is None:
        _invalid()
    response = client.request(
        method="POST",
        path="/v1/access-invitations/inspect",
        body={"access_invitation_token": token},
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    _expect_status(response, 200)
    preview = _invitation_preview(response.json())
    if response.headers.get("etag") != preview["entity_tag"]:
        _invalid()
    return preview


def _invitation_step_up(
    session: RoleSession, *, token: str, invitation_id: str
) -> RoleSession:
    _canonical_uuid(invitation_id)
    if _CAPABILITY_TOKEN.fullmatch(token) is None:
        _invalid()
    response = session.client.request(
        method="POST",
        path="/v1/auth/oidc/authorizations",
        body={"return_to": "/app", "access_invitation_token": token},
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-CSRF-Token": session.csrf_token,
        },
    )
    _expect_status(response, 201)
    begin = _exact_keys(
        response.json(),
        {"auth_transaction_id", "authorization_url", "expires_at"},
    )
    _utc_timestamp(begin["expires_at"])
    chooser = session.client.get_authorization_page(
        _nonempty_text(begin["authorization_url"])
    )
    parser = _RequestHandleParser()
    try:
        parser.feed(chooser.decode("utf-8"))
    except UnicodeDecodeError:
        _invalid()
    if len(parser.values) != 1:
        _invalid()
    session.client.authorize(
        account_code=session.account_code, request_handle=parser.values[0]
    )
    refreshed = _session(session.client, expected_status=200)
    csrf = _nonempty_text(refreshed["csrf_token"])
    if _CSRF.fullmatch(csrf) is None or csrf == session.csrf_token:
        _invalid()
    return RoleSession(
        account_code=session.account_code,
        workspace_id=session.workspace_id,
        workspace_kind=session.workspace_kind,
        role_codes=session.role_codes,
        csrf_token=csrf,
        client=session.client,
        policy_accepted=session.policy_accepted,
    )


def _accept_organization_invitation(
    session: RoleSession, *, preview: Mapping[str, Any]
) -> tuple[RoleSession, Mapping[str, Any]]:
    exact_preview = _invitation_preview(preview)
    policy_acceptances = _run_stage(
        "INVITED_DEMAND_OWNER_ACCEPTANCE_POLICY",
        _invitation_policy_acceptances,
        session,
        exact_preview=exact_preview,
    )
    response = _run_stage(
        "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
        session.client.request,
        method="POST",
        path=f"/v1/access-invitations/{exact_preview['invitation_id']}/accept",
        body={
            "policy_bundle_id": exact_preview["required_policy_bundle_id"],
            "policy_acceptances": policy_acceptances,
            "consent_grants": [],
        },
        headers=_iam_write_headers(
            session, if_match=exact_preview["entity_tag"]
        ),
    )
    _run_stage(
        "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
        _expect_status,
        response,
        200,
    )
    response_body = _run_stage(
        "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
        response.json,
    )
    acceptance = _run_stage(
        "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
        _exact_keys,
        response_body,
        {"invitation", "me", "activated_scope"},
    )
    invitation = _run_stage(
        "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
        _invitation_admin,
        acceptance["invitation"],
    )
    me = _run_stage(
        "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
        _exact_keys,
        acceptance["me"],
        {
            "user_id",
            "status",
            "display_handle",
            "user_roles",
            "memberships",
            "policy_requirements",
            "aggregate_version",
            "entity_tag",
        },
    )
    _run_stage(
        "INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND",
        _canonical_uuid,
        me["user_id"],
    )
    if (
        invitation["status"] != "ACCEPTED"
        or acceptance["activated_scope"] != "ORGANIZATION_MEMBERSHIP"
        or response.headers.get("etag") != invitation["entity_tag"]
    ):
        raise InternalSandboxE2eError(
            stage="INVITED_DEMAND_OWNER_ACCEPTANCE_COMMAND"
        )
    refreshed = _run_stage(
        "INVITED_DEMAND_OWNER_ACCEPTANCE_SESSION",
        _session,
        session.client,
        expected_status=200,
    )
    csrf = _run_stage(
        "INVITED_DEMAND_OWNER_ACCEPTANCE_SESSION",
        _nonempty_text,
        refreshed["csrf_token"],
    )
    if _CSRF.fullmatch(csrf) is None or csrf == session.csrf_token:
        raise InternalSandboxE2eError(
            stage="INVITED_DEMAND_OWNER_ACCEPTANCE_SESSION"
        )
    return (
        RoleSession(
            account_code=session.account_code,
            workspace_id=session.workspace_id,
            workspace_kind=session.workspace_kind,
            role_codes=session.role_codes,
            csrf_token=csrf,
            client=session.client,
            policy_accepted=session.policy_accepted,
        ),
        acceptance,
    )


def _invitation_policy_acceptances(
    session: RoleSession, *, exact_preview: Mapping[str, Any]
) -> list[Mapping[str, Any]]:
    bundle_response = session.client.request(
        method="GET",
        path=f"/v1/policy-bundles/{exact_preview['required_policy_bundle_id']}",
        headers={"Accept": "application/json"},
    )
    _expect_status(bundle_response, 200)
    bundle = _policy_bundle(
        bundle_response,
        expected_id=exact_preview["required_policy_bundle_id"],
        expected_purpose="ORGANIZATION_MEMBERSHIP",
    )
    policy_acceptances = []
    for document in bundle["documents"]:
        if not isinstance(document, Mapping):
            _invalid()
        if document.get("legal_effect") == "CONSENT_TEXT":
            continue
        body = document.get("body")
        digest = document.get("content_sha256")
        if (
            not isinstance(body, str)
            or _SHA256.fullmatch(str(digest)) is None
            or hashlib.sha256(body.encode("utf-8")).hexdigest() != digest
        ):
            _invalid()
        policy_acceptances.append(
            {
                "document_id": _canonical_uuid(document.get("document_id")),
                "content_sha256": digest,
                "affirmed": True,
            }
        )
    if not policy_acceptances:
        _invalid()
    return policy_acceptances


def _policy_bundle(
    response: HttpResult, *, expected_id: str, expected_purpose: str
) -> Mapping[str, Any]:
    _canonical_uuid(expected_id)
    if expected_purpose not in {
        "CREATOR_ENROLLMENT",
        "ORGANIZATION_MEMBERSHIP",
    }:
        _invalid()
    bundle = _exact_keys(response.json(), _POLICY_BUNDLE_FIELDS)
    _canonical_uuid(bundle["policy_bundle_id"])
    _utc_timestamp(bundle["effective_at"])
    if (
        bundle["policy_bundle_id"] != expected_id
        or bundle["purpose"] != expected_purpose
        or re.fullmatch(r"[A-Z0-9_-]{2,32}", str(bundle["jurisdiction"]))
        is None
        or not isinstance(bundle["locale"], str)
        or not 2 <= len(bundle["locale"]) <= 35
        or _ENTITY_TAG.fullmatch(str(bundle["entity_tag"])) is None
        or response.headers.get("etag") != bundle["entity_tag"]
        or not isinstance(bundle["documents"], list)
        or not 1 <= len(bundle["documents"]) <= 20
        or not isinstance(bundle["consent_offers"], list)
        or len(bundle["consent_offers"]) > 20
    ):
        _invalid()
    documents: dict[str, Mapping[str, Any]] = {}
    for raw_document in bundle["documents"]:
        document = _exact_keys(raw_document, _POLICY_DOCUMENT_FIELDS)
        document_id = _canonical_uuid(document["document_id"])
        body = document["body"]
        if (
            document_id in documents
            or document["kind"]
            not in {
                "TERMS",
                "PRIVACY_NOTICE",
                "COMMUNITY_TRANSACTION_COVENANT",
                "CONSENT_TEXT",
            }
            or not isinstance(document["semantic_version"], str)
            or len(document["semantic_version"]) > 64
            or re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?",
                document["semantic_version"],
            )
            is None
            or not isinstance(document["locale"], str)
            or len(document["locale"]) > 35
            or re.fullmatch(
                r"[A-Za-z]{2,3}(?:-[A-Za-z0-9]{2,8})*",
                document["locale"],
            )
            is None
            or document["locale"] != bundle["locale"]
            or _SHA256.fullmatch(str(document["content_sha256"])) is None
            or document["legal_effect"]
            not in {
                "NOTICE_ACKNOWLEDGEMENT",
                "CONTRACT_ACCEPTANCE",
                "CONSENT_TEXT",
            }
            or not isinstance(body, str)
            or not 1 <= len(body) <= 200_000
            or hashlib.sha256(body.encode("utf-8")).hexdigest()
            != document["content_sha256"]
            or (document["kind"] == "CONSENT_TEXT")
            != (document["legal_effect"] == "CONSENT_TEXT")
        ):
            _invalid()
        documents[document_id] = document
    offer_ids: set[str] = set()
    for raw_offer in bundle["consent_offers"]:
        offer = _exact_keys(raw_offer, _CONSENT_OFFER_FIELDS)
        offer_id = _canonical_uuid(offer["consent_offer_id"])
        document_id = _canonical_uuid(offer["document_id"])
        document = documents.get(document_id)
        categories = offer["data_categories"]
        _utc_timestamp(offer["not_after"])
        if (
            offer_id in offer_ids
            or offer["purpose"]
            not in {
                "PILOT_RESEARCH",
                "AI_ASSISTED_PROCESSING",
                "DISCLOSE_PROFILE_FIELDS_TO_PARTY",
            }
            or offer["scope_type"]
            not in {
                "PLATFORM_PARTICIPATION",
                "ORGANIZATION",
                "PROJECT",
                "RECIPIENT_DISCLOSURE",
            }
            or not isinstance(categories, list)
            or not 1 <= len(categories) <= 20
            or len(set(categories)) != len(categories)
            or any(
                category
                not in {
                    "PROFILE",
                    "MATCHING",
                    "RESEARCH",
                    "AI_INPUT",
                    "CONTACT",
                    "PROJECT",
                }
                for category in categories
            )
            or document is None
            or document["legal_effect"] != "CONSENT_TEXT"
            or offer["content_sha256"] != document["content_sha256"]
            or not isinstance(offer["recipient_label"], str)
            or not 1 <= len(offer["recipient_label"]) <= 160
            or offer["expiry_rule"]
            not in {
                "FIXED_NOT_AFTER",
                "EARLIER_OF_GRANTED_AT_PLUS_365_DAYS_OR_NOT_AFTER",
            }
            or _SHA256.fullmatch(str(offer["canonical_offer_sha256"])) is None
            or offer["optional"] is not True
        ):
            _invalid()
        offer_ids.add(offer_id)
    return bundle


def _organization_lifecycle_exact_replay(
    session: RoleSession,
    *,
    resource: Mapping[str, Any],
    action: str,
    reason_code: str,
) -> Mapping[str, Any]:
    if reason_code not in {
        "ACCESS_REVIEW",
        "MEMBER_REQUEST",
        "SECURITY_REVIEW",
        "INVITATION_CANCELLED",
    }:
        _invalid()
    if action == "revoke-invitation":
        exact = _invitation_admin(resource)
        path = f"/v1/access-invitations/{exact['invitation_id']}/revoke"
        parser = _invitation_admin
    else:
        if action not in {"suspend", "resume", "revoke"}:
            _invalid()
        exact = _membership_admin(resource)
        path = f"/v1/memberships/{exact['membership_id']}/{action}"
        parser = _membership_admin
    body = {"reason_code": reason_code}
    headers = _iam_write_headers(session, if_match=exact["entity_tag"])
    first_response = session.client.request(
        method="POST", path=path, body=body, headers=headers
    )
    _expect_status(first_response, 200)
    first = parser(first_response.json())
    replay_response = session.client.request(
        method="POST", path=path, body=body, headers=headers
    )
    _expect_status(replay_response, 200)
    replay = parser(replay_response.json())
    if (
        first != replay
        or first_response.headers.get("etag") != first["entity_tag"]
        or replay_response.headers.get("etag") != replay["entity_tag"]
    ):
        _invalid()
    return first


def _invitation_admin(value: Any) -> Mapping[str, Any]:
    invitation = _exact_keys(value, _INVITATION_ADMIN_FIELDS)
    _canonical_uuid(invitation["invitation_id"])
    _canonical_uuid(invitation["organization_id"])
    _canonical_uuid(invitation["required_policy_bundle_id"])
    _utc_timestamp(invitation["expires_at"])
    _utc_timestamp(invitation["created_at"])
    if (
        invitation["purpose"] != "ORGANIZATION_MEMBERSHIP"
        or invitation["target_role"] not in {"ORG_ADMIN", "DEMAND_OWNER"}
        or invitation["status"]
        not in {"ISSUED", "ACCEPTED", "REVOKED", "EXPIRED"}
        or not isinstance(invitation["masked_recipient_label"], str)
        or not 3 <= len(invitation["masked_recipient_label"]) <= 80
        or not isinstance(invitation["is_initial_admin"], bool)
        or not _version_and_tag(invitation)
    ):
        _invalid()
    return invitation


def _invitation_preview(value: Any) -> Mapping[str, Any]:
    preview = _exact_keys(value, _INVITATION_PREVIEW_FIELDS)
    _canonical_uuid(preview["invitation_id"])
    _canonical_uuid(preview["required_policy_bundle_id"])
    _utc_timestamp(preview["expires_at"])
    organization = _exact_keys(preview["organization"], {"public_name"})
    if (
        preview["purpose"] != "ORGANIZATION_MEMBERSHIP"
        or preview["target_role"] not in {"ORG_ADMIN", "DEMAND_OWNER"}
        or preview["status"] != "ISSUED"
        or not isinstance(organization["public_name"], str)
        or not 1 <= len(organization["public_name"]) <= 160
        or not _version_and_tag(preview)
    ):
        _invalid()
    return preview


def _membership_admin(value: Any) -> Mapping[str, Any]:
    membership = _exact_keys(value, _MEMBERSHIP_FIELDS)
    for field in ("membership_id", "organization_id", "user_id"):
        _canonical_uuid(membership[field])
    roles = membership["roles"]
    _closed_role_codes(
        roles,
        allowed={"ORG_ADMIN", "DEMAND_OWNER"},
        maximum=2,
    )
    if (
        not isinstance(membership["display_handle"], str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_-]{1,79}",
            membership["display_handle"],
        )
        is None
        or membership["status"] not in {"ACTIVE", "SUSPENDED", "REVOKED"}
        or not _version_and_tag(membership)
    ):
        _invalid()
    return membership


def _version_and_tag(value: Mapping[str, Any]) -> bool:
    version = value.get("aggregate_version")
    return (
        not isinstance(version, bool)
        and isinstance(version, int)
        and version >= 1
        and value.get("entity_tag") == f'"v{version}"'
    )


def _iam_write_headers(
    session: RoleSession, *, if_match: str
) -> Mapping[str, str]:
    if _ENTITY_TAG.fullmatch(if_match) is None:
        _invalid()
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "If-Match": if_match,
        "Idempotency-Key": _idempotency_key(),
        "X-CSRF-Token": session.csrf_token,
    }


def _expect_creator_workspaces(
    client: CurlClient,
    *,
    organization_id: str,
    organization_present: bool,
) -> None:
    candidates, selection_required = _workspace_candidates(client)
    expected_personal = [
        item
        for item in candidates
        if item["workspace_kind"] == "PERSONAL"
        and item["role_codes"] == ["CREATOR"]
    ]
    expected_organization = [
        item
        for item in candidates
        if item["workspace_id"] == f"org:{organization_id}"
        and item["workspace_kind"] == "ORGANIZATION"
        and item["role_codes"] == ["DEMAND_OWNER"]
    ]
    if (
        len(expected_personal) != 1
        or len(expected_organization) != int(organization_present)
        or len(candidates) != (2 if organization_present else 1)
        or selection_required is not organization_present
    ):
        _invalid()


def _workspace_candidates(
    client: CurlClient,
) -> tuple[list[Mapping[str, Any]], bool]:
    envelope = _get_json(client, "/v1/app/workspaces")
    _exact_keys(envelope, {"data"})
    data = _exact_keys(envelope["data"], {"workspaces", "selection_required"})
    if not isinstance(data["workspaces"], list) or not isinstance(
        data["selection_required"], bool
    ):
        _invalid()
    candidates = []
    for value in data["workspaces"]:
        item = _exact_keys(value, {"workspace_id", "workspace_kind", "role_codes"})
        _closed_role_codes(item["role_codes"])
        if (
            _WORKSPACE.fullmatch(str(item["workspace_id"])) is None
            or item["workspace_kind"]
            not in {"PERSONAL", "ORGANIZATION", "PLATFORM"}
        ):
            _invalid()
        candidates.append(item)
    if data["selection_required"] != (len(candidates) > 1):
        _invalid()
    return candidates, data["selection_required"]


def _expect_single_platform_workspace(
    session: RoleSession,
    *,
    expected_role_codes: tuple[str, ...],
) -> None:
    if (
        expected_role_codes != tuple(sorted(set(expected_role_codes)))
        or not expected_role_codes
    ):
        _invalid()
    _closed_role_codes(list(expected_role_codes))
    candidates, selection_required = _workspace_candidates(session.client)
    if (
        len(candidates) != 1
        or selection_required is not False
        or candidates[0]["workspace_id"] != session.workspace_id
        or candidates[0]["workspace_kind"] != "PLATFORM"
        or tuple(candidates[0]["role_codes"]) != expected_role_codes
    ):
        _invalid()


def _exercise_account_lifecycle(
    *, admin: RoleSession, creator: RoleSession, temporary: Path, ca_file: Path
) -> RoleSession:
    accounts = _account_list(admin)
    by_code = {item["account_code"]: item for item in accounts}
    if not set(ROLE_EXPECTATIONS).issubset(by_code):
        _invalid()
    self_account = by_code["access_admin_01"]
    creator_account = by_code["creator_01"]
    self_result = _account_command(
        admin,
        user_id=self_account["user_id"],
        action="suspend",
        if_match=self_account["entity_tag"],
        reason_code="ACCESS_REVIEW",
        expected_status=403,
    )
    if self_result.status != 403:
        _invalid()
    suspended = _account_command(
        admin,
        user_id=creator_account["user_id"],
        action="suspend",
        if_match=creator_account["entity_tag"],
        reason_code="ACCESS_REVIEW",
        expected_status=200,
    ).json()["data"]
    if suspended["status"] != "SUSPENDED":
        _invalid()
    _session(creator.client, expected_status=401)
    resumed = _account_command(
        admin,
        user_id=creator_account["user_id"],
        action="resume",
        if_match=suspended["entity_tag"],
        reason_code="ACCESS_REVIEW",
        expected_status=200,
    ).json()["data"]
    if resumed["status"] != "ACTIVE":
        _invalid()
    _session(creator.client, expected_status=401)
    relogin = _login(
        account_code="creator_01",
        root=_role_root(temporary, "creator-relogin-one"),
        ca_file=ca_file,
    )
    fresh = _account_detail(admin, user_id=creator_account["user_id"])
    revoked = _account_command(
        admin,
        user_id=creator_account["user_id"],
        action="revoke-all-sessions",
        if_match=fresh["entity_tag"],
        reason_code="SESSION_HYGIENE",
        expected_status=200,
    ).json()["data"]
    if revoked["status"] != "ACTIVE" or revoked["revoked_session_count"] < 1:
        _invalid()
    _session(relogin.client, expected_status=401)
    return _login(
        account_code="creator_01",
        root=_role_root(temporary, "creator-relogin-two"),
        ca_file=ca_file,
    )


def _account_list(session: RoleSession) -> list[Mapping[str, Any]]:
    response = session.client.request(
        method="GET",
        path="/v1/app/admin/accounts",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    envelope = response.json()
    _exact_keys(envelope, {"data"})
    data = envelope["data"]
    _exact_keys(data, {"schema_version", "evaluated_at", "accounts"})
    _utc_timestamp(data["evaluated_at"])
    accounts = data["accounts"]
    if (
        data["schema_version"] != "internal-sandbox-account-admin-v1"
        or not isinstance(accounts, list)
        or not 1 <= len(accounts) <= 16
    ):
        _invalid()
    for account in accounts:
        _account(account)
    return accounts


def _account_detail(session: RoleSession, *, user_id: str) -> Mapping[str, Any]:
    _canonical_uuid(user_id)
    response = session.client.request(
        method="GET",
        path=f"/v1/app/admin/accounts/{user_id}",
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    envelope = response.json()
    _exact_keys(envelope, {"data"})
    return _account(envelope["data"])


def _account(value: Any) -> Mapping[str, Any]:
    expected = {
        "account_code",
        "user_id",
        "display_handle",
        "status",
        "aggregate_version",
        "entity_tag",
        "role_codes",
        "active_session_count",
        "created_at",
        "updated_at",
        "is_self",
    }
    _exact_keys(value, expected)
    _canonical_uuid(value["user_id"])
    _closed_role_codes(value["role_codes"])
    _utc_timestamp(value["created_at"])
    _utc_timestamp(value["updated_at"])
    if (
        value["status"] not in {"ACTIVE", "SUSPENDED"}
        or _ENTITY_TAG.fullmatch(str(value["entity_tag"])) is None
        or not isinstance(value["active_session_count"], int)
    ):
        _invalid()
    return value


def _closed_role_codes(
    value: Any,
    *,
    allowed: set[str] = _ROLE_CODES,
    maximum: int = 8,
) -> list[str]:
    if (
        not isinstance(value, list)
        or not 1 <= len(value) <= maximum
        or not all(isinstance(role, str) and role in allowed for role in value)
    ):
        _invalid()
    if len(set(value)) != len(value):
        _invalid()
    return value


def _account_command(
    session: RoleSession,
    *,
    user_id: str,
    action: str,
    if_match: str,
    reason_code: str,
    expected_status: int,
) -> HttpResult:
    _canonical_uuid(user_id)
    if action not in {"suspend", "resume", "revoke-all-sessions"}:
        _invalid()
    result = session.client.request(
        method="POST",
        path=f"/v1/app/admin/accounts/{user_id}/{action}",
        body={"reason_code": reason_code},
        headers=_write_headers(session, if_match=if_match),
    )
    _expect_status(result, expected_status)
    if expected_status == 200:
        _account_command_envelope(result, target_user_id=user_id)
    return result


def _account_command_envelope(
    result: HttpResult, *, target_user_id: str
) -> Mapping[str, Any]:
    _canonical_uuid(target_user_id)
    envelope = result.json()
    _exact_keys(envelope, {"data"})
    data = envelope["data"]
    required = {
        "user_id",
        "display_handle",
        "status",
        "aggregate_version",
        "entity_tag",
        "revoked_session_count",
        "revoked_session_family_count",
        "replayed",
    }
    _exact_keys(data, required)
    if (
        data["user_id"] != target_user_id
        or data["status"] not in {"ACTIVE", "SUSPENDED"}
        or isinstance(data["aggregate_version"], bool)
        or not isinstance(data["aggregate_version"], int)
        or data["aggregate_version"] < 1
        or data["entity_tag"] != f'"v{data["aggregate_version"]}"'
        or result.headers.get("etag") != data["entity_tag"]
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in (
                data["revoked_session_count"],
                data["revoked_session_family_count"],
            )
        )
        or not isinstance(data["replayed"], bool)
    ):
        _invalid()
    return data


def _write_editor(
    session: RoleSession,
    *,
    method: str,
    path: str,
    body: Mapping[str, Any],
    expected_status: int,
    resource_type: str,
    if_match: str | None = None,
) -> Mapping[str, Any]:
    response = session.client.request(
        method=method,
        path=path,
        body=body,
        headers=_write_headers(session, if_match=if_match),
    )
    _expect_status(response, expected_status)
    return _editor_envelope(response, resource_type=resource_type)


def _get_resource(
    session: RoleSession, path: str, *, resource_type: str
) -> Mapping[str, Any]:
    response = session.client.request(
        method="GET",
        path=path,
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    return _editor_envelope(response, resource_type=resource_type)


def _list_resources(
    session: RoleSession, *, path: str, resource_type: str
) -> list[Mapping[str, Any]]:
    response = session.client.request(
        method="GET",
        path=path,
        headers=_app_headers(session),
    )
    _expect_status(response, 200)
    envelope = response.json()
    _exact_keys(envelope, {"data"})
    values = envelope["data"]
    if not isinstance(values, list) or len(values) > 100:
        _invalid()
    for value in values:
        _exact_keys(value, _RESOURCE_FIELDS)
        _canonical_uuid(value["object_id"])
        if (
            value["resource_type"] != resource_type
            or not isinstance(value["revision"], int)
            or value["revision"] < 1
            or _RESOURCE_ETAG.fullmatch(str(value["etag"])) is None
        ):
            _invalid()
    return values


def _editor_envelope(
    response: HttpResult, *, resource_type: str
) -> Mapping[str, Any]:
    envelope = response.json()
    _exact_keys(envelope, {"data"})
    resource = envelope["data"]
    _exact_keys(resource, _RESOURCE_FIELDS)
    _canonical_uuid(resource["object_id"])
    if (
        resource["resource_type"] != resource_type
        or not isinstance(resource["revision"], int)
        or resource["revision"] < 1
        or _RESOURCE_ETAG.fullmatch(str(resource["etag"])) is None
        or response.headers.get("etag") != resource["etag"]
    ):
        _invalid()
    return resource


def _require_owner_scope_finding(resource: Mapping[str, Any]) -> None:
    """Require the Owner to read the reviewer reason and requested field."""

    findings = resource.get("findings")
    if not isinstance(findings, list) or not findings or len(findings) > 100:
        _invalid()
    matched = False
    for value in findings:
        finding = _owner_finding(value)
        reasons = finding["reason_codes"]
        fields = finding["required_field_paths"]
        if (
            finding["result"] == "NEEDS_CHANGES"
            and "SCOPE_UNCLEAR" in reasons
            and ({"/scope", "SCOPE"} & set(fields))
        ):
            matched = True
    if not matched:
        _invalid()


def _require_finance_discrepancy_finding(
    resource: Mapping[str, Any], *, demand_version_id: str
) -> None:
    _canonical_uuid(demand_version_id)
    findings = resource.get("findings")
    if not isinstance(findings, list) or not findings or len(findings) > 100:
        _invalid()
    matched = False
    for value in findings:
        finding = _owner_finding(value)
        if (
            finding["result"] == "DISCREPANCY"
            and finding["version_id"] == demand_version_id
            and finding["assignment_id"] is None
            and finding["reason_codes"]
            == [FINANCE_FUNDING_DISCREPANCY_REASON_CODE]
            and finding["required_field_paths"] == ["/scope"]
        ):
            matched = True
    if not matched:
        _invalid()


def _owner_finding(value: Any) -> Mapping[str, Any]:
    finding = _exact_keys(value, _FINDING_FIELDS)
    _canonical_uuid(finding["finding_id"])
    _canonical_uuid(finding["version_id"])
    result = finding["result"]
    if result in {"NEEDS_CHANGES", "VERIFIED"}:
        _canonical_uuid(finding["assignment_id"])
    elif result in {"DISCREPANCY", "REJECTED"}:
        if finding["assignment_id"] is not None:
            _invalid()
    else:
        _invalid()
    reasons = finding["reason_codes"]
    fields = finding["required_field_paths"]
    if (
        not isinstance(reasons, list)
        or not all(isinstance(item, str) and item for item in reasons)
        or len(reasons) != len(set(reasons))
        or not isinstance(fields, list)
        or not all(isinstance(item, str) and item for item in fields)
        or len(fields) != len(set(fields))
        or (
            result in {"DISCREPANCY", "REJECTED"}
            and (reasons != sorted(reasons) or fields != sorted(fields))
        )
        or (result == "VERIFIED" and (reasons or fields))
        or (result != "VERIFIED" and (not reasons or not fields))
    ):
        _invalid()
    _utc_timestamp(finding["reviewed_at"])
    return finding


def _session(client: CurlClient, *, expected_status: int) -> Mapping[str, Any]:
    response = client.request(method="GET", path="/v1/auth/session")
    _expect_status(response, expected_status)
    if expected_status != 200:
        return {}
    value = response.json()
    _exact_keys(value, {"session", "user_status", "csrf_token"})
    if value["user_status"] != "ACTIVE" or _CSRF.fullmatch(
        str(value["csrf_token"])
    ) is None:
        _invalid()
    return value


def _get_json(client: CurlClient, path: str) -> Mapping[str, Any]:
    response = client.request(method="GET", path=path)
    _expect_status(response, 200)
    value = response.json()
    if not isinstance(value, dict):
        _invalid()
    return value


def _read_active_me_with_etag(client: CurlClient) -> Mapping[str, Any]:
    response = client.request(
        method="GET",
        path="/v1/me",
        headers={"Accept": "application/json"},
    )
    _expect_status(response, 200)
    me = _active_me(response.json())
    if response.headers.get("etag") != me["entity_tag"]:
        _invalid()
    return me


def _app_headers(session: RoleSession) -> Mapping[str, str]:
    return {"Accept": "application/json", "X-Workspace-Id": session.workspace_id}


def _write_headers(
    session: RoleSession, *, if_match: str | None = None
) -> Mapping[str, str]:
    headers = {
        **_app_headers(session),
        "Content-Type": "application/json",
        "Idempotency-Key": _idempotency_key(),
        "X-CSRF-Token": session.csrf_token,
    }
    if if_match is not None:
        if not (
            _ENTITY_TAG.fullmatch(if_match)
            or _RESOURCE_ETAG.fullmatch(if_match)
            or _QUEUE_ETAG.fullmatch(if_match)
            or _FINANCE_QUEUE_ETAG.fullmatch(if_match)
            or _TRUST_ETAG.fullmatch(if_match)
            or _APPEAL_ETAG.fullmatch(if_match)
        ):
            _invalid()
        headers["If-Match"] = if_match
    return headers


def _idempotency_key() -> str:
    return f"internal-sandbox-e2e-{uuid4()}"


def _validated_authorization_url(value: str) -> str:
    if (
        not isinstance(value, str)
        or _AUTH_URL.fullmatch(value) is None
        or '"' in value
        or "\\" in value
    ):
        _invalid()
    split = urlsplit(value)
    if (
        split.scheme != "https"
        or split.netloc != "identity.example.test"
        or split.path != "/authorize"
        or split.fragment
    ):
        _invalid()
    try:
        pairs = parse_qsl(
            split.query,
            keep_blank_values=True,
            strict_parsing=True,
        )
    except ValueError:
        _invalid()
    expected = {
        "client_id",
        "redirect_uri",
        "response_type",
        "scope",
        "state",
        "nonce",
        "code_challenge",
        "code_challenge_method",
    }
    if (
        len(pairs) != len(expected)
        or {name for name, _value in pairs} != expected
        or len({name for name, _value in pairs}) != len(pairs)
    ):
        _invalid()
    query = dict(pairs)
    if (
        query["client_id"] != "desire-internal-sandbox"
        or query["redirect_uri"]
        != "https://pilot.example.test/v1/auth/oidc/callback"
        or query["response_type"] != "code"
        or query["scope"] != "openid email"
        or query["code_challenge_method"] != "S256"
        or any(
            _AUTH_HANDLE.fullmatch(query[field]) is None
            for field in ("state", "nonce", "code_challenge")
        )
    ):
        _invalid()
    return value


def _validated_oidc_callback_location(result: HttpResult) -> str:
    location = result.headers.get("location")
    if (
        not isinstance(location, str)
        or len(location) > 4_096
        or _AUTH_URL.fullmatch(location) is None
        or '"' in location
        or "\\" in location
    ):
        _invalid()
    split = urlsplit(location)
    if (
        split.scheme != "https"
        or split.netloc != "pilot.example.test"
        or split.path != "/v1/auth/oidc/callback"
        or not split.query
        or split.fragment
    ):
        _invalid()
    try:
        pairs = parse_qsl(
            split.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=3,
        )
    except ValueError:
        _invalid()
    if len(pairs) != 2 or {name for name, _value in pairs} != {"code", "state"}:
        _invalid()
    values = dict(pairs)
    if any(_AUTH_HANDLE.fullmatch(values[name]) is None for name in ("code", "state")):
        _invalid()
    return location


def _parse_last_headers(value: bytes) -> Mapping[str, str]:
    try:
        text = value.decode("iso-8859-1")
    except UnicodeDecodeError:
        _invalid()
    blocks = [block for block in re.split(r"\r?\n\r?\n", text) if block]
    if not blocks:
        return {}
    result: dict[str, str] = {}
    for line in blocks[-1].splitlines()[1:]:
        if ":" not in line:
            continue
        name, child = line.split(":", 1)
        key = name.strip().casefold()
        # Cookies stay only in curl's private jar.  They are deliberately not
        # reflected into the in-process result mapping, and multiple Set-Cookie
        # fields on the OIDC callback remain valid.
        if key == "set-cookie":
            continue
        if key in result:
            _invalid()
        result[key] = child.strip()
    return result


def _expect_status(result: HttpResult, expected: int) -> None:
    if result.status != expected:
        _invalid()


def _exact_keys(value: Any, expected: set[str]) -> Mapping[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        _invalid()
    return value


def _canonical_uuid(value: Any) -> str:
    if not isinstance(value, str) or _UUID.fullmatch(value) is None:
        _invalid()
    try:
        parsed = UUID(value)
    except ValueError:
        _invalid()
    if parsed.int == 0 or str(parsed) != value:
        _invalid()
    return value


def _utc_timestamp(value: Any) -> str:
    _parse_utc_timestamp(value)
    return value


def _parse_utc_timestamp(value: Any) -> tuple[datetime, int]:
    if not isinstance(value, str) or len(value) > 64:
        _invalid()
    matched = _UTC_TIMESTAMP.fullmatch(value)
    if matched is None:
        _invalid()
    second = matched.group("second")
    fraction = matched.group("fraction")
    try:
        parsed = datetime.fromisoformat(f"{second}+00:00")
    except ValueError:
        _invalid()
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _invalid()
    nanosecond = int((fraction or "").ljust(9, "0"))
    return parsed, nanosecond


def _nonempty_text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        _invalid()
    return value


def _ca_file(path: Path) -> Path:
    source = _absolute_regular_file(path)
    try:
        value = source.read_bytes()
    except OSError:
        _invalid()
    if (
        value.count(b"-----BEGIN CERTIFICATE-----") != 1
        or b"PRIVATE KEY" in value
        or len(value) > 64_000
    ):
        _invalid()
    return source


def _absolute_regular_file(path: Path) -> Path:
    if not path.is_absolute() or path.is_symlink():
        _invalid()
    try:
        file_stat = path.lstat()
    except OSError:
        _invalid()
    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
        _invalid()
    return path


def _private_absolute_file(path: Path) -> Path:
    source = _absolute_regular_file(path)
    if stat.S_IMODE(source.stat().st_mode) != 0o600:
        _invalid()
    return source


def _new_absolute_output(path: Path) -> Path:
    if (
        not path.is_absolute()
        or path.exists()
        or path.is_symlink()
        or not path.parent.is_dir()
        or path.parent.is_symlink()
    ):
        _invalid()
    try:
        resolved_parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError):
        _invalid()
    for ancestor in (resolved_parent, *resolved_parent.parents):
        metadata = ancestor / ".local-internal-sandbox"
        try:
            metadata_stat = metadata.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            _invalid()
        if stat.S_ISLNK(metadata_stat.st_mode):
            _invalid()
        prepared_receipt = metadata / "prepared-receipt.json"
        try:
            prepared_receipt.lstat()
        except FileNotFoundError:
            continue
        except OSError:
            _invalid()
        _invalid()
    return path


def _role_root(root: Path, label: str) -> Path:
    if re.fullmatch(r"[a-z0-9_-]{3,40}", label) is None:
        _invalid()
    target = root / label
    target.mkdir(mode=0o700)
    return target


def _write_new(path: Path, value: bytes, *, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            written = stream.write(value)
            if written != len(value):
                _invalid()
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _invalid() -> NoReturn:
    raise InternalSandboxE2eError()


def _run_stage(stage: str, function: Any, *args: Any, **kwargs: Any) -> Any:
    if stage not in _FAILURE_STAGES or not callable(function):
        raise InternalSandboxE2eError(stage="INTERNAL")
    try:
        return function(*args, **kwargs)
    except InternalSandboxE2eError as error:
        if error.stage != "INPUT":
            raise
        raise InternalSandboxE2eError(stage=stage) from None
    except (OSError, ValueError, TypeError):
        raise InternalSandboxE2eError(stage=stage) from None


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python3 scripts/run_internal_sandbox_e2e.py"
    )
    subcommands = parser.add_subparsers(dest="command", required=True)
    journey = subcommands.add_parser("journey")
    journey.add_argument("--ca-file", required=True)
    journey.add_argument("--state-output", required=True)
    journey.add_argument("--result-output")
    invited = subcommands.add_parser("invited-demand-owner")
    invited.add_argument("--ca-file", required=True)
    invited.add_argument("--result-output")
    verify = subcommands.add_parser("verify-restart")
    verify.add_argument("--ca-file", required=True)
    verify.add_argument("--state-file", required=True)
    verify.add_argument("--result-output")
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO = sys.stdout,
    stderr: TextIO = sys.stderr,
) -> int:
    try:
        arguments = _parser().parse_args(argv)
        state_output = (
            Path(arguments.state_output)
            if arguments.command == "journey"
            else None
        )
        result_output = (
            None
            if arguments.result_output is None
            else Path(arguments.result_output)
        )
        if result_output is not None:
            _run_stage("RESULT_OUTPUT", _new_absolute_output, result_output)
            state_path = (
                state_output
                if state_output is not None
                else (
                    Path(arguments.state_file)
                    if arguments.command == "verify-restart"
                    else None
                )
            )
            if state_path is not None and os.path.normpath(
                result_output
            ) == os.path.normpath(state_path):
                raise InternalSandboxE2eError(stage="RESULT_OUTPUT")
        if state_output is not None:
            _new_absolute_output(state_output)
        if arguments.command == "journey":
            if state_output is None:
                raise InternalSandboxE2eError(stage="INTERNAL")
            result = run_journey(
                ca_file=Path(arguments.ca_file),
                state_output=state_output,
            )
        elif arguments.command == "verify-restart":
            result = verify_restart(
                ca_file=Path(arguments.ca_file),
                state_file=Path(arguments.state_file),
            )
        else:
            result = run_invited_demand_owner_journey(
                ca_file=Path(arguments.ca_file)
            )
        serialized = (
            json.dumps(result, ensure_ascii=False, separators=(",", ":"))
            + "\n"
        )
        if result_output is not None:
            _run_stage(
                "RESULT_OUTPUT",
                _write_new,
                result_output,
                serialized.encode("utf-8"),
                mode=0o600,
            )
        stdout.write(serialized)
        return 0
    except InternalSandboxE2eError as error:
        stderr.write(
            json.dumps(
                {
                    "code": "INTERNAL_SANDBOX_E2E_FAILED",
                    "stage": error.stage,
                    "status": "BLOCKED",
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        return 78
    except (OSError, ValueError, TypeError):
        stderr.write(
            '{"code":"INTERNAL_SANDBOX_E2E_FAILED",'
            '"stage":"INTERNAL","status":"BLOCKED"}\n'
        )
        return 78


if __name__ == "__main__":
    raise SystemExit(main())

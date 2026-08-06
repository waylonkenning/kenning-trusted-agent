import json
import unittest
from pathlib import Path


SPEC_PATH = Path(__file__).parents[1] / "docs" / "openapi.json"


class OpenApiDocumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads(SPEC_PATH.read_text())

    def test_document_declares_expected_api_surface(self):
        self.assertEqual(self.spec["openapi"], "3.0.3")
        self.assertEqual(
            set(self.spec["paths"]),
            {
                "/auth/config",
                "/auth/login",
                "/auth/callback",
                "/auth/confirm",
                "/auth/confirm/resend",
                "/auth/reauth",
                "/auth/session",
                "/auth/logout",
                "/auth/csrf",
                "/health",
                "/mcp",
                "/mcp/agent-guard",
                "/mcp/citation-trust",
                "/mcp/agent-proof",
                "/mcp/agent-identity",
                "/v1/actions/evaluate",
                "/v1/actions/{actionId}/outcome",
                "/v1/approvals",
                "/v1/approvals/{approvalId}",
                "/v1/approvals/{approvalId}/decision",
                "/v1/approvals/{approvalId}/revoke",
                "/v1/grants",
                "/v1/grants/{grantId}/revoke",
                "/v1/consents",
                "/v1/consents/{consentId}/revoke",
                "/v1/audit",
                "/v1/security/events",
                "/v1/audit/events",
                "/v1/audit/export",
                "/v1/compliance/evidence",
                "/v1/metrics",
                "/v1/management-reviews",
                "/v1/nonconformities",
                "/v1/nonconformities/{ncId}/resolve",
                "/v1/concerns",
                "/v1/agents",
                "/v1/models",
                "/v1/models/{modelId}",
                "/v1/models/{modelId}/data-resources",
                "/v1/suppliers",
                "/v1/agents/{agentId}",
                "/v1/agents/{agentId}/impact-assessments",
                "/v1/agents/{agentId}/revoke",
                "/v1/agents/{agentId}/credentials",
                "/v1/agents/{agentId}/credentials/{credentialId}",
                "/v1/agents/{agentId}/credentials/{credentialId}/revoke",
                "/v1/citations/verify",
                "/v1/citation-reports/extract",
                "/v1/policies",
                "/v1/compliance/coverage",
                "/v1/policies/{policyId}",
                "/v1/policies/{policyId}/publish",
                "/v1/policies/{policyId}/suspend",
                "/v1/policies/{policyId}/reactivate",
                "/v1/policies/{policyId}/simulate",
                "/v1/policies/{policyId}/test",
                "/v1/proofs",
                "/v1/proofs/{proofId}",
                "/v1/proofs/{proofId}/report",
                "/v1/proofs/{proofId}/verify",
                "/v1/receipts/public-key",
                "/v1/tokens",
                "/v1/tokens/{tokenId}/revoke",
                "/v1/tenants",
                "/v1/tenants/{tenantId}",
                "/v1/tenants/{tenantId}/starter-rules",
                "/v1/tenants/{tenantId}/starter-rules/simulate",
                "/v1/tenants/{tenantId}/environments",
                "/v1/tenants/{tenantId}/environments/{environmentId}",
                "/v1/tenants/{tenantId}/retention/run",
                "/v1/me",
                "/v1/platform/access-grants",
                "/v1/platform/access-grants/{grantId}/revoke",
                "/v1/platform/support/read",
                "/v1/tenants/{tenantId}/members",
                "/v1/tenants/{tenantId}/members/{subject}",
                "/v1/tenants/{tenantId}/invitations",
                "/v1/tenants/{tenantId}/invitations/{invitationId}/revoke",
                "/v1/invitations/redeem",
                "/v1/invitations/accept",
            },
        )

    def test_document_uses_bearer_pat_security(self):
        scheme = self.spec["components"]["securitySchemes"]["bearerAuth"]
        self.assertEqual(scheme["type"], "http")
        self.assertEqual(scheme["scheme"], "bearer")
        self.assertEqual(scheme["bearerFormat"], "PAT")
        self.assertEqual(self.spec["security"], [{"bearerAuth": []}])
        self.assertEqual(self.spec["paths"]["/health"]["get"]["security"], [])
        self.assertEqual(self.spec["components"]["securitySchemes"]["sessionCookie"]["in"], "cookie")

    def test_document_describes_provider_logout_redirect(self):
        endpoint = self.spec["paths"]["/auth/logout"]["get"]
        self.assertIn("identity provider", endpoint["summary"])
        self.assertIn("302", endpoint["responses"])

    def test_report_extraction_is_documented_as_bounded_and_hashable(self):
        endpoint = self.spec["paths"]["/v1/citation-reports/extract"]["post"]
        self.assertEqual(endpoint["requestBody"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/CitationReportExtractRequest")
        request = self.spec["components"]["schemas"]["CitationReportExtractRequest"]
        self.assertEqual(request["properties"]["report_text"]["maxLength"], 5000000)
        self.assertEqual(
            endpoint["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/CitationReportExtractResponse",
        )
        citation_schema = self.spec["components"]["schemas"]["CitationReportExtractResponse"]["properties"]["citations"]["items"]
        self.assertIn("source", citation_schema["properties"]["category"]["enum"])

    def test_platform_support_access_is_documented_as_a_separate_admin_path(self):
        endpoint = self.spec["paths"]["/v1/platform/access-grants"]["post"]
        self.assertEqual(endpoint["requestBody"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/PlatformAccessGrantRequest")
        self.assertEqual(endpoint["responses"]["201"]["content"]["application/json"]["schema"]["$ref"], "#/components/schemas/PlatformAccessGrant")
        self.assertIn("reason", self.spec["components"]["schemas"]["PlatformAccessGrantRequest"]["required"])

    def test_aws_workload_identity_configuration_is_documented(self):
        scheme = self.spec["components"]["securitySchemes"]["awsIamAuth"]
        self.assertEqual(scheme["name"], "Authorization")
        self.assertEqual(scheme["in"], "header")
        workload = self.spec["components"]["schemas"]["WorkloadIdentity"]
        self.assertEqual(workload["properties"]["provider"]["enum"], ["aws_iam"])
        mapping = self.spec["components"]["schemas"]["WorkloadIdentityMapping"]
        self.assertIn("guard:evaluate", mapping["properties"]["scopes"]["items"]["enum"])
        self.assertNotIn("token:admin", mapping["properties"]["scopes"]["items"]["enum"])
        self.assertEqual(
            self.spec["components"]["schemas"]["TenantConfigRequest"]["properties"]["workload_identity"]["$ref"],
            "#/components/schemas/WorkloadIdentity",
        )

    def test_guard_unavailability_is_documented_as_fail_closed(self):
        response = self.spec["paths"]["/v1/actions/evaluate"]["post"]["responses"]["503"]
        self.assertEqual(
            response["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/GuardUnavailableResponse",
        )
        schema = self.spec["components"]["schemas"]["GuardUnavailableResponse"]
        self.assertEqual(schema["properties"]["enforcement"]["enum"], ["fail_closed"])
        self.assertEqual(schema["properties"]["decision"]["enum"], ["deny"])
        self.assertEqual(
            self.spec["paths"]["/mcp"]["post"]["responses"]["503"]["description"].split(".")[0],
            "Guard evaluation is unavailable",
        )

    def test_evaluation_retries_are_documented_as_idempotent(self):
        schema = self.spec["components"]["schemas"]["GuardDecision"]
        self.assertIn("idempotent", schema["properties"])
        self.assertIn("action_id", self.spec["components"]["schemas"]["Context"]["properties"])
        response = self.spec["paths"]["/v1/actions/evaluate"]["post"]["responses"]
        self.assertIn("409", response)

    def test_action_risk_context_is_documented(self):
        action = self.spec["components"]["schemas"]["Action"]
        self.assertIn("intent", action["properties"])
        self.assertTrue(action["properties"]["model_id"]["nullable"])
        self.assertTrue(action["properties"]["model_version"]["nullable"])
        self.assertEqual(action["properties"]["model_risk_tier"]["enum"], ["low", "medium", "high"])
        self.assertIn("affected_resource_count", action["properties"]["parameters"]["description"])
        self.assertIn("FINANCIAL_TRANSACTION", action["properties"]["parameters"]["description"])
        self.assertIn("execution_context", action["properties"]["parameters"]["description"])
        self.assertEqual(action["properties"]["shell_context"]["$ref"], "#/components/schemas/ShellContext")
        self.assertIn("environment_variables", self.spec["components"]["schemas"]["ShellContext"]["properties"])

    def test_mcp_request_id_uses_openapi_3_nullable_syntax(self):
        identifier = self.spec["components"]["schemas"]["McpRequest"]["properties"]["id"]
        self.assertEqual(identifier["oneOf"], [{"type": "string"}, {"type": "integer"}])
        self.assertTrue(identifier["nullable"])
        self.assertNotIn({"type": "null"}, identifier["oneOf"])

    def test_approval_lifecycle_is_documented(self):
        statuses = self.spec["components"]["schemas"]["Approval"]["properties"]["status"]["enum"]
        self.assertEqual(set(statuses), {"pending", "approved", "denied", "expired", "revoked", "consumed"})
        self.assertIn("approval_requirements", self.spec["components"]["schemas"]["Approval"]["properties"])
        revoke = self.spec["paths"]["/v1/approvals/{approvalId}/revoke"]["post"]
        self.assertEqual(revoke["operationId"], "revokeApproval")
        self.assertEqual(
            revoke["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ApprovalRevokeRequest",
        )

    def test_approval_queue_is_documented(self):
        endpoint = self.spec["paths"]["/v1/approvals"]["get"]
        self.assertEqual(endpoint["operationId"], "listApprovals")
        self.assertEqual(
            {parameter["name"] for parameter in endpoint["parameters"]},
            {"tenant_id", "status", "agent_id", "environment", "limit"},
        )
        self.assertEqual(
            endpoint["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/ApprovalListResponse",
        )

    def test_audit_supports_end_to_end_correlation_keys(self):
        for path in ("/v1/audit", "/v1/audit/export"):
            names = {parameter["name"] for parameter in self.spec["paths"][path]["get"]["parameters"]}
            self.assertTrue({"action_hash", "receipt_id", "proof_id", "approval_id"}.issubset(names))

    def test_audit_ingestion_is_documented(self):
        endpoint = self.spec["paths"]["/v1/audit/events"]["post"]
        self.assertEqual(endpoint["operationId"], "ingestAuditEvent")
        self.assertEqual(
            endpoint["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/AuditEventIngestRequest",
        )
        self.assertIn("audit:write", self.spec["components"]["securitySchemes"]["bearerAuth"]["description"])

    def test_metrics_endpoint_is_documented(self):
        metrics = self.spec["paths"]["/v1/metrics"]["get"]
        self.assertEqual(metrics["operationId"], "getOperationalMetrics")
        self.assertEqual(
            {parameter["name"] for parameter in metrics["parameters"]},
            {"tenant_id", "start_time", "end_time"},
        )
        latency = metrics["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["metrics"]["properties"]["latency_ms"]["properties"]
        self.assertTrue({"average", "p50", "p95", "p99"}.issubset(latency))

    def test_tenant_capture_policy_is_documented(self):
        schema = self.spec["components"]["schemas"]["CapturePolicy"]
        self.assertEqual(schema["properties"]["max_field_length"]["minimum"], 64)
        self.assertEqual(
            self.spec["components"]["schemas"]["TenantConfigRequest"]["properties"]["capture_policy"]["$ref"],
            "#/components/schemas/CapturePolicy",
        )

    def test_tenant_citation_policy_is_documented(self):
        schema = self.spec["components"]["schemas"]["CitationPolicy"]
        self.assertEqual(schema["properties"]["max_citations"]["maximum"], 100)
        self.assertTrue(schema["properties"]["respect_robots"]["default"])
        self.assertIn("trusted_domains", schema["properties"])
        self.assertEqual(
            schema["properties"]["claim_type_policies"]["additionalProperties"]["$ref"],
            "#/components/schemas/ClaimTypeCitationPolicy",
        )
        self.assertIn("claim_type", self.spec["components"]["schemas"]["CitationFinding"]["properties"])
        self.assertIn("source_hash_verified", self.spec["components"]["schemas"]["CitationFinding"]["properties"])
        self.assertIn("source_verified", self.spec["components"]["schemas"]["CitationFinding"]["properties"])
        self.assertIn("source_score", self.spec["components"]["schemas"]["CitationFinding"]["properties"])
        self.assertIn("claim_support_score", self.spec["components"]["schemas"]["CitationFinding"]["properties"])
        self.assertIn("reference_verified", self.spec["components"]["schemas"]["CitationFinding"]["properties"])
        self.assertIn("reference_metadata_score", self.spec["components"]["schemas"]["CitationFinding"]["properties"])
        self.assertIn("reference_metadata", self.spec["components"]["schemas"]["CitationVerifyRequest"]["properties"]["citations"]["items"]["properties"])
        report_schema = self.spec["components"]["schemas"]["CitationReportExtractResponse"]
        self.assertIn("bibliographic_references", report_schema["required"])
        self.assertIn("reference_claims", report_schema["required"])
        self.assertIn("source_hash", self.spec["components"]["schemas"]["CitationVerifyRequest"]["properties"]["citations"]["items"]["properties"])
        self.assertIn("reference_sources", self.spec["components"]["schemas"]["CitationVerifyRequest"]["properties"])
        self.assertIn("reference_findings", self.spec["components"]["schemas"]["CitationVerifyResponse"]["properties"])
        self.assertEqual(
            self.spec["components"]["schemas"]["TenantConfigRequest"]["properties"]["citation_policy"]["$ref"],
            "#/components/schemas/CitationPolicy",
        )

    def test_tenant_legal_hold_and_data_residency_are_documented(self):
        request = self.spec["components"]["schemas"]["TenantConfigRequest"]["properties"]
        self.assertIn("legal_hold_enabled", request)
        self.assertIn("legal_hold_reason", request)
        self.assertIn("data_residency_region", request)
        config = self.spec["components"]["schemas"]["TenantConfig"]["allOf"][1]["properties"]
        self.assertIn("legal_hold_updated_at", config)
        self.assertIn("data_residency_region", config)
        retention = self.spec["components"]["schemas"]["RetentionRunResponse"]["properties"]
        self.assertIn("legal_hold_enabled", retention)
        self.assertIn("data_residency_region", retention)

    def test_agent_delegation_time_limits_are_documented(self):
        conditions = self.spec["components"]["schemas"]["AgentRegistrationRequest"]["properties"]["conditions"]["properties"]
        self.assertEqual(conditions["not_before"]["format"], "date-time")
        self.assertEqual(conditions["not_after"]["format"], "date-time")
        self.assertIn("time_window", conditions)

    def test_agent_authority_and_delegation_chain_are_documented(self):
        request = self.spec["components"]["schemas"]["AgentRegistrationRequest"]["properties"]
        self.assertEqual(request["maximum_authority"]["enum"], ["read", "standard", "high", "admin"])
        self.assertIn("parent_agent_id", request)
        self.assertTrue(request["conditions"]["properties"]["can_delegate_agents"]["description"])
        record = self.spec["components"]["schemas"]["AgentRecord"]["allOf"][1]["properties"]
        self.assertEqual(record["delegation_chain"]["maxItems"], 8)
        scopes = self.spec["components"]["schemas"]["AgentCredentialIssueRequest"]["properties"]["scopes"]["items"]["enum"]
        self.assertIn("identity:write", scopes)

    def test_tenant_registry_is_documented(self):
        endpoint = self.spec["paths"]["/v1/tenants"]["get"]
        self.assertEqual(endpoint["operationId"], "listTenants")
        self.assertEqual(
            {parameter["name"] for parameter in endpoint["parameters"]},
            {"tenant_id", "status", "limit"},
        )
        self.assertEqual(
            endpoint["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/TenantListResponse",
        )

    def test_policy_test_cases_are_documented(self):
        endpoint = self.spec["paths"]["/v1/policies/{policyId}/test"]["post"]
        self.assertEqual(endpoint["operationId"], "testPolicy")
        self.assertEqual(
            endpoint["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/PolicyTestRunRequest",
        )
        self.assertEqual(
            endpoint["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/PolicyTestRunResponse",
        )

    def test_draft_policy_lifecycle_is_documented(self):
        policy = self.spec["paths"]["/v1/policies/{policyId}"]
        self.assertEqual(policy["put"]["operationId"], "updateDraftPolicy")
        self.assertEqual(policy["delete"]["operationId"], "deleteDraftPolicy")
        self.assertIn("version", policy["delete"]["requestBody"]["content"]["application/json"]["schema"]["required"])
        self.assertIn("draft", policy["put"]["description"])

    def test_agent_registry_supports_listing(self):
        endpoint = self.spec["paths"]["/v1/agents"]["get"]
        self.assertEqual(endpoint["operationId"], "listAgents")

    def test_policy_simulation_supports_historical_actions(self):
        request_schema = self.spec["paths"]["/v1/policies/{policyId}/simulate"]["post"]["requestBody"]["content"]["application/json"]["schema"]
        self.assertEqual(request_schema["$ref"], "#/components/schemas/PolicySimulationRequest")
        self.assertEqual(
            self.spec["components"]["schemas"]["PolicySimulationRequest"]["oneOf"],
            [{"required": ["action"]}, {"required": ["source_action_id"]}],
        )
        self.assertIn("simulation_source", self.spec["components"]["schemas"]["GuardDecision"]["properties"])
        self.assertEqual(
            self.spec["components"]["schemas"]["PolicyResolution"]["properties"]["strategy"]["enum"],
            ["most_restrictive_wins"],
        )
        self.assertIn("policy_resolution", self.spec["components"]["schemas"]["GuardDecision"]["properties"])

    def test_proof_integrity_verification_is_documented(self):
        endpoint = self.spec["paths"]["/v1/proofs/{proofId}/verify"]["get"]
        self.assertEqual(endpoint["operationId"], "verifyProofIntegrity")
        schema = endpoint["responses"]["200"]["content"]["application/json"]["schema"]
        self.assertEqual(schema["$ref"], "#/components/schemas/ProofVerificationResponse")

    def test_receipt_public_key_discovery_is_documented(self):
        endpoint = self.spec["paths"]["/v1/receipts/public-key"]["get"]
        self.assertEqual(endpoint["operationId"], "getReceiptPublicKey")

    def test_pat_control_plane_is_documented(self):
        create = self.spec["paths"]["/v1/tokens"]["post"]
        self.assertEqual(create["operationId"], "createPersonalAccessToken")
        self.assertEqual(
            create["requestBody"]["content"]["application/json"]["schema"]["$ref"],
            "#/components/schemas/TokenCreateRequest",
        )
        self.assertIn("exactly once", create["description"])
        revoke = self.spec["paths"]["/v1/tokens/{tokenId}/revoke"]["post"]
        self.assertEqual(revoke["operationId"], "revokePersonalAccessToken")
        self.assertEqual(
            self.spec["components"]["schemas"]["TokenMetadata"]["properties"]["token_type"]["enum"],
            ["pat"],
        )
        self.assertIn("groups", self.spec["components"]["schemas"]["TokenCreateRequest"]["properties"])

    def test_policy_and_federation_group_controls_are_documented(self):
        self.assertIn("approver_groups", self.spec["components"]["schemas"]["PolicyRule"]["properties"])
        self.assertEqual(
            self.spec["components"]["schemas"]["IdentityProvider"]["properties"]["groups_claim"]["default"],
            "groups",
        )


if __name__ == "__main__":
    unittest.main()

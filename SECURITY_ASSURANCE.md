# Kenning Trusted Agent security and assurance evidence

This document records the security controls implemented in the public source,
the evidence that can be reproduced locally, and the work that still requires
an operator, independent reviewer, or customer-specific assurance activity. It
is not a certification or a penetration-test report.

The public release supports customer-owned AWS single-tenant deployments.
Hosted controls, private release evidence, customer findings, and Kenning
marketing operations are outside this document's scope.

## Scope and trust boundaries

The prototype evaluates proposed actions and records decisions. It does not
execute shell commands, SQL, cloud mutations, GitHub changes, or outbound
messages. The protected trust boundary is:

`agent or MCP client -> PAT/OIDC/OAuth2/AWS IAM authentication -> tenant binding -> Guard -> Proof/receipt -> audit store`

The caller remains responsible for ensuring that the agent cannot invoke the
underlying tool through an unprotected path when enforcement is required. The
regional API Gateway and the private REST API deployment option provide control
points, but network and tool-side enforcement must be configured per customer.

## Control evidence

| Control | Implemented evidence | Current verification |
|---|---|---|
| Tenant isolation | Authenticated tenant binding, tenant-scoped DynamoDB keys, policy and approval filters | Local tenant boundary tests; deployed verification is operator-specific |
| Least-privilege API access | PAT and agent-credential scopes, expiry, revocation, delegated scope restrictions, authority ceilings, bounded delegation chains, OIDC JWT validation, OAuth 2.0 introspection, AWS IAM role-to-agent mappings, account allowlists, and verified subject binding | Identity/workload tests, hosted parent/child delegation flow, federation tests, hosted API tests, and `scripts/access_review.py`; live AWS_IAM route validation remains pilot-specific |
| Secret minimisation | Hash-only PAT storage, capture redaction/hashing, no raw secret environment values in Proof/audit | Capture, tenant, and hosted shell-context tests |
| Action integrity | Semantic action hash, action-bound approvals, idempotent approval transitions | Approval replay, mismatch, revoke, and outcome tests |
| Receipt integrity | SHA-256 Proof integrity and KMS RSA-PSS signatures in AWS | Receipt verification tests and hosted API checks |
| Fail-closed enforcement | Guard-unavailable responses deny high-risk execution and identify retryability | Local HTTP/MCP unavailable-path tests |
| Durable recording | Decision is returned only after Proof and audit persistence paths complete | Hosted audit acceptance latency measurements |
| Recovery | DynamoDB PITR, on-demand backup/restore design, cleanup verification | Template validation; recovery execution remains operator-specific |
| Operational detection | Lambda, API Gateway, DynamoDB, and policy-evaluation alarms plus CloudWatch dashboard | Template validation; alarm routing remains operator-specific |
| Private deployment | Optional VPC configuration for an operator-owned AWS account | CloudFormation validation; live VPC deployment remains environment-specific |

OAuth 2.0 introspection uses an HTTPS endpoint and a tenant-scoped Secrets
Manager ARN under `kenning/tenants/{tenant_id}/oauth/`. The opaque token is
sent only to that endpoint after the secret ARN is bound to the authenticating
tenant; the authenticated subject, tenant, scopes, groups, expiry, and
optional agent identity are the only resulting identity fields retained.

## Threat model summary

| Threat | Mitigation | Residual risk or follow-up |
|---|---|---|
| Stolen PAT | Hash-only storage, scoped tokens, expiry, revocation, access-review report | Long-lived POC PATs require periodic operator review; production should prefer short expiry and secret-manager delivery |
| Cross-tenant confused deputy | Auth-derived tenant binding and tenant-local lookup paths | Platform-admin operations require separate privileged access review |
| Approval tampering or replay | Exact action hash, conditional status transitions, expiry, revocation, consumed state | Independent security testing of all adapter-specific canonicalisation remains required |
| Agent bypasses Guard | API/MCP control point, private/gateway deployment patterns, explicit trust-boundary documentation | Hook/proxy enforcement must be deployed around each underlying tool |
| Secret capture in evidence | Field redaction, hashing, bounded capture, no chain-of-thought requirement | Customer-specific sensitive-field policies need design-partner review |
| Audit sink failure | Durable local event first, delivery status recorded separately, retryable sink path | SIEM-specific delivery and replay drills remain customer-specific |
| Citation source manipulation | HTTPS/redirect/authenticity checks, optional SHA-256 source binding, source-quality and currency policies, bounded retrieval | Source reputation heuristics require domain-specific evaluation and false-positive measurement |
| Service outage or data loss | Fail-closed response, alarms, PITR, recovery drill | 99.9% monthly availability and RTO/RPO require sustained measurement and a production topology |

## Operational procedures

1. Run `python3 scripts/access_review.py` during each access-review cycle. Investigate active `long_lived`, `high_privilege`, `broad_scope`, and grouped tokens; revoke through the control plane or `scripts/manage_pat.py`.
2. If Guard returns `503 guard_unavailable`, do not execute the proposed action. Check Lambda errors/throttles, DynamoDB alarms, KMS access, and the CloudWatch dashboard before retrying.
3. Run `scripts/verify_backup_configuration.sh` routinely and run `scripts/backup_recovery_drill.sh --execute` during a scheduled recovery exercise.
4. For network-isolated customers, deploy `scripts/deploy_private_api_gateway.sh` with a reviewed execute-api VPC endpoint and validate private DNS and VPC endpoint policy.
5. Export audit records before retention deletion or legal-hold changes and preserve the exported evidence according to the customer’s retention policy.

## Assurance backlog

These items are deliberately not represented as completed merely because the
prototype has a corresponding control:

- Independent threat-model review and penetration test.
- Formal operator and tenant-admin access reviews in each production account.
- Incident-response exercise, recovery-time objective, and recovery-point objective evidence.
- Sustained 99.9% availability measurement with an agreed service definition.
- Live private deployment validation in a customer or isolated VPC.
- Dependency, container/runtime, and infrastructure supply-chain review.
- Customer-specific data residency, legal hold, compliance, and SIEM assurance.

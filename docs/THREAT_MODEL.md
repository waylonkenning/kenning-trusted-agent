# Threat model

## Scope

The system evaluates proposed agent actions, applies tenant policy, records a
decision and proof, and exposes the result through an API or MCP endpoint. It
does not execute the underlying shell, SQL, filesystem, or cloud action.

## Trust boundaries

```text
agent or client
  -> API/MCP authentication
  -> tenant and agent binding
  -> Guard policy evaluation
  -> proof and audit persistence
  -> operator-owned AWS resources
```

The client or tool owner must prevent a direct bypass around Guard. A hook or
proxy integration is part of the enforcement boundary; instructions and MCP
tools alone are not sufficient.

## Main threats and controls

| Threat | Control | Residual responsibility |
| --- | --- | --- |
| Stolen PAT or agent credential | Hash-only storage, scopes, expiry, revocation, and one-time display | Operator access review and secret rotation |
| Cross-tenant access | Auth-derived tenant binding and single-tenant pinning | Correct identity-provider and account configuration |
| Approval replay or mutation | Action hash, expiry, conditional state changes, and proof | Review adapter canonicalisation and client retries |
| Guard outage | Fail-closed high-risk evaluation responses | Operator alarms, quotas, and recovery |
| Evidence disclosure | Redaction, bounded capture, retention controls, and access policy | Operator data classification and legal hold |
| Source retrieval abuse | HTTPS, bounded retrieval, robots and policy checks | Disable or isolate retrieval for restricted networks |
| Infrastructure compromise | Customer IAM, KMS, TLS, VPC, CloudFront, and CloudWatch controls | AWS account owner and incident response |

The application does not prove that a caller's underlying tool cannot be
invoked by another path. Review this boundary before relying on Guard for
high-impact operations.

## Known gaps

Independent penetration testing, customer-specific compliance evidence, a
sustained availability target, and a customer VPC deployment are operator or
future assurance work. They are not implied by the MIT license or by the
presence of a policy, audit, or proof record.

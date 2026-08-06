# Operations guide

This guide covers a self-hosted AWS single-tenant deployment. The AWS account
owner remains responsible for operational decisions and evidence.

## Health and release identity

Check the stack outputs and the unauthenticated health endpoint:

```bash
aws cloudformation describe-stacks --region "$AWS_REGION" \
  --stack-name "$KTA_STACK_NAME" \
  --query 'Stacks[0].{status:StackStatus,outputs:Outputs}'
curl --fail-with-body -sS "$KENNING_API_URL/health"
```

The response includes `release_id`, `source_commit`, `release_name`, and
`release_version`. Compare them with the artifact manifest before approving a
promotion.

## Backups and recovery

The template enables DynamoDB point-in-time recovery, S3 versioning, and
retention policies for important resources. The operator must set backup
retention, legal-hold, and restore approval rules for the account. A recovery
exercise should restore the audit and token tables into an isolated name,
deploy the same immutable artifacts, validate health and a Guard decision, and
record duration, data point, and unresolved gaps.

KMS keys and Cognito pools are not interchangeable between deployments. Keep
their configuration and retention evidence in restricted operator storage.

## Logs, data, and deletion

Application logs can contain request errors and bounded audit metadata. Do not
send credentials, raw PATs, or customer payloads to logs. Set CloudWatch log
retention to the approved period and restrict access. Run the tenant retention
operation before deleting data, and preserve records subject to a legal hold.

For retirement, export approved evidence, revoke PATs and agent credentials,
disable optional pipelines and cross-account roles, confirm backup status, then
delete the stack in a reviewed change window. Retained DynamoDB, S3, KMS, and
Cognito resources require explicit deletion after legal and backup review.

## Incident boundary

The operator investigates AWS account, network, identity, quota, backup, and
data incidents. Report application vulnerabilities through the private channel
in [`SECURITY.md`](../SECURITY.md). Do not publish exploit details, customer
data, credentials, or live infrastructure identifiers in an issue.

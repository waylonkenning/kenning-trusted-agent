"""DynamoDB persistence layer for Kenning Agent Guard.

The AuditStore owns all reads and writes to the audit, token, and tenant
tables. It was extracted from lambda_function.py (#249) so the HTTP/MCP
adapter can stay focused on request handling.
"""

from __future__ import annotations

import copy
import sys
import time
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

try:  # pragma: no cover
    from boto3.dynamodb.conditions import Attr, Key
    from botocore.exceptions import ClientError
except ModuleNotFoundError:  # Keep dependency-free unit tests importable locally.

    class _Condition:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            self.field = str(args[0]) if args else kwargs.get("field")
            self.operator = kwargs.get("operator")
            self.value = kwargs.get("value")
            self.clauses = kwargs.get("clauses")

        def eq(self, value: Any) -> "_Condition":
            return _Condition(field=self.field, operator="eq", value=value)

        def begins_with(self, value: Any) -> "_Condition":
            return _Condition(field=self.field, operator="begins_with", value=value)

        def between(self, start: Any, end: Any) -> "_Condition":
            return _Condition(field=self.field, operator="between", value=(start, end))

        def not_exists(self) -> "_Condition":
            return _Condition(field=self.field, operator="not_exists")

        def __and__(self, other: Any) -> "_Condition":
            return _Condition(clauses=[self, other])

    Attr = _Condition
    Key = _Condition

    class ClientError(Exception):
        pass

try:  # pragma: no cover
    from audit import event_matches
    from guard import action_hash, utc_now
    from metrics import aggregate, metric_updates
    from tenant import is_retained_item, retention_cutoff
    from audit_delivery import deliver_event
    from policy_bundle import build_policy_bundle, is_current_bundle
except ModuleNotFoundError:  # Local package import during tests.
    from .audit import event_matches
    from .guard import action_hash, utc_now
    from .metrics import aggregate, metric_updates
    from .tenant import is_retained_item, retention_cutoff
    from .audit_delivery import deliver_event
    from .policy_bundle import build_policy_bundle, is_current_bundle

# Serialisation helpers live in the adapter module. Import them lazily-safe at
# module load; lambda_function defines them before it imports this module, so
# the circular reference resolves cleanly.
try:  # pragma: no cover
    from lambda_function import _dynamodb_safe, _is_conditional_check_failure
except ModuleNotFoundError:  # Local package import during tests.
    from .lambda_function import _dynamodb_safe, _is_conditional_check_failure


class AuditStore:
    def __init__(self, dynamodb_table: Any, secret_manager: Any = None) -> None:
        self.table = dynamodb_table
        self.secret_manager = secret_manager
        # A single request may apply the same tenant retention and runtime
        # configuration to an approval, Proof record, and audit event. Keep
        # that read request-local so the authoritative DynamoDB record is not
        # repeatedly fetched during one decision.
        self._tenant_config_cache: dict[str, dict[str, Any] | None] = {}

    def _with_retention_expiry(self, item: dict[str, Any]) -> dict[str, Any]:
        """Attach a DynamoDB TTL value when the tenant has enabled retention."""

        tenant_id = str(item.get("tenant_id") or "")
        if not tenant_id or item.get("item_type") == "tenant_config":
            return item
        config = self.get_tenant_config(tenant_id)
        if config and config.get("legal_hold_enabled"):
            return item
        cutoff = retention_cutoff(config or {})
        if cutoff is None:
            return item
        created_at = str(item.get("created_at") or "")
        try:
            created_epoch = int(datetime.fromisoformat(created_at.replace("Z", "+00:00")).timestamp())
        except (TypeError, ValueError):
            created_epoch = int(time.time())
        item["retention_expires_at"] = created_epoch + int(config["retention_days"]) * 86400
        return item

    def put_event(self, event: dict[str, Any]) -> dict[str, Any]:
        timestamp = event.get("created_at") or utc_now()
        event_id = event.get("event_id") or f"evt-{uuid.uuid4().hex[:16]}"
        config = self.get_tenant_config(str(event["tenant_id"])) or {}
        sink = config.get("audit_sink") if isinstance(config.get("audit_sink"), dict) else None
        idempotency_key = str(event.get("idempotency_key") or "").strip()
        item = {
            "pk": f"TENANT#{event['tenant_id']}",
            "sk": f"EVENT#IDEMPOTENT#{idempotency_key}" if idempotency_key else f"EVENT#{timestamp}#{time.time_ns():020d}#{event_id}",
            "event_id": event_id,
            "delivery_status": "pending" if sink and sink.get("enabled") else "disabled",
            **event,
        }
        put_kwargs: dict[str, Any] = {"Item": _dynamodb_safe(self._with_retention_expiry(item))}
        if idempotency_key:
            put_kwargs["ConditionExpression"] = "attribute_not_exists(pk)"
        try:
            self.table.put_item(**put_kwargs)
        except Exception as exc:
            if idempotency_key and _is_conditional_check_failure(exc):
                return {"status": "duplicate", "delivered": False, "idempotent": True}
            raise
        self.record_metrics(event, delivery_status=None if sink and sink.get("enabled") else "disabled")
        if not sink or not sink.get("enabled"):
            return {"status": "disabled", "delivered": False}
        delivery = deliver_event(event, sink, self.secret_manager)
        self.record_metrics(event, delivery_status=str(delivery.get("status") or "failed"), include_event=False)
        try:
            self.mark_event_delivery(item, delivery)
        except Exception:
            # The event is durable and the Guard decision must not fail because
            # a delivery status update is temporarily unavailable.
            pass
        return delivery

    def record_metrics(
        self,
        event: dict[str, Any],
        delivery_status: str | None = None,
        include_event: bool = True,
    ) -> None:
        """Best-effort aggregate metrics; metric failure never blocks Guard."""

        for update in metric_updates(event, delivery_status=delivery_status, include_event=include_event):
            try:
                key = {
                    "pk": f"METRICS#{update['tenant_id']}",
                    "sk": f"DAY#{update['metric_day']}#{update['dimension']}#{update['name']}",
                }
                names = {"#tenant": "tenant_id", "#type": "item_type", "#day": "metric_day", "#dimension": "dimension", "#name": "name", "#updated": "updated_at", "#count": "metric_count"}
                values: dict[str, Any] = {
                    ":tenant": update["tenant_id"],
                    ":type": "metric",
                    ":day": update["metric_day"],
                    ":dimension": update["dimension"],
                    ":name": update["name"],
                    ":updated": utc_now(),
                    ":count": int(update.get("count") or 1),
                }
                assignments = ["#tenant = :tenant", "#type = :type", "#day = :day", "#dimension = :dimension", "#name = :name", "#updated = :updated"]
                additions = ["#count :count"]
                if update.get("value") is not None:
                    names["#value_sum"] = "value_sum"
                    values[":value"] = Decimal(str(update["value"]))
                    additions.append("#value_sum :value")
                self.table.update_item(
                    Key=key,
                    UpdateExpression="SET " + ", ".join(assignments) + " ADD " + ", ".join(additions),
                    ExpressionAttributeNames=names,
                    ExpressionAttributeValues=values,
                )
            except Exception:
                # Metrics are operational telemetry, never an authorization
                # dependency. The durable event remains the source of truth.
                continue

    def get_metrics(self, tenant_id: str, start_day: str | None = None, end_day: str | None = None) -> dict[str, Any]:
        result = self.table.query(
            KeyConditionExpression=Key("pk").eq(f"METRICS#{tenant_id}") & Key("sk").begins_with("DAY#"),
            Limit=500,
            ScanIndexForward=False,
        )
        items = [item for item in result.get("Items", []) if item.get("item_type") == "metric"]
        return aggregate(items, start_day=start_day, end_day=end_day)

    def mark_event_delivery(self, item: dict[str, Any], delivery: dict[str, Any]) -> None:
        values = {
            ":status": str(delivery.get("status") or "failed"),
            ":attempted": utc_now(),
        }
        assignments = ["delivery_status = :status", "delivery_attempted_at = :attempted"]
        if delivery.get("http_status") is not None:
            assignments.append("delivery_http_status = :http_status")
            values[":http_status"] = int(delivery["http_status"])
        if delivery.get("error_code"):
            assignments.append("delivery_error_code = :error_code")
            values[":error_code"] = str(delivery["error_code"])
        self.table.update_item(
            Key={"pk": item["pk"], "sk": item["sk"]},
            UpdateExpression="SET " + ", ".join(assignments),
            ExpressionAttributeValues=values,
        )

    def put_approval(self, approval: dict[str, Any]) -> None:
        approval_item = self._with_retention_expiry({
            "pk": f"APPROVAL#{approval['approval_id']}",
            "sk": "METADATA",
            **approval,
        })
        self.table.put_item(Item=_dynamodb_safe(approval_item))
        # Keep a tenant-local lookup record so reviewer queues use a DynamoDB
        # Query instead of scanning the complete audit table.  The primary
        # approval record remains the source of truth; the index is deliberately
        # best effort so a temporary index write failure cannot change the
        # Guard decision or approval semantics.
        try:
            index_item = {
                "pk": f"TENANT#{approval['tenant_id']}",
                "sk": f"APPROVAL#{approval['created_at']}#{approval['approval_id']}",
                "item_type": "approval_index",
                "tenant_id": approval["tenant_id"],
                "approval_id": approval["approval_id"],
                "created_at": approval["created_at"],
            }
            if approval_item.get("retention_expires_at") is not None:
                index_item["retention_expires_at"] = approval_item["retention_expires_at"]
            self.table.put_item(Item=_dynamodb_safe(index_item))
        except Exception:
            # The legacy bounded scan below keeps older deployments and
            # partially indexed data usable while the index catches up.
            pass

    def get_approval(self, approval_id: str) -> dict[str, Any] | None:
        result = self.table.get_item(Key={"pk": f"APPROVAL#{approval_id}", "sk": "METADATA"})
        approval = result.get("Item")
        if approval and approval.get("status") == "pending" and int(approval.get("expires_at", 0)) <= int(time.time()):
            approval = self.expire_approval(dict(approval))
        return approval

    def list_approvals(
        self,
        tenant_id: str,
        statuses: set[str] | None = None,
        agent_id: str | None = None,
        environment: str | None = None,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """List tenant-scoped approval records for reviewer queues.

        New approvals have a tenant-local lookup record, making this a bounded
        DynamoDB Query. A small paginated scan remains as a migration fallback
        for approvals written before the lookup records existed.
        """

        limit = max(1, min(int(limit), 100))
        statuses = {str(status) for status in (statuses or set())}
        records: list[dict[str, Any]] = []

        indexed_items: list[dict[str, Any]] = []
        indexed_seen = False
        try:
            query_kwargs: dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq(f"TENANT#{tenant_id}") & Key("sk").begins_with("APPROVAL#"),
                "Limit": 100,
                "ScanIndexForward": False,
                "ConsistentRead": True,
            }
            pages = 0
            while pages < 10 and len(indexed_items) < max(limit, 100):
                result = self.table.query(**query_kwargs)
                page_items = [
                    dict(item) for item in result.get("Items", [])
                    if item.get("item_type") == "approval_index" and item.get("approval_id")
                ]
                if page_items:
                    indexed_seen = True
                    indexed_items.extend(page_items)
                last_key = result.get("LastEvaluatedKey")
                pages += 1
                if not last_key:
                    break
                query_kwargs["ExclusiveStartKey"] = last_key
        except Exception:
            # Fall through to the bounded legacy scan. Query failures must not
            # turn a reviewer queue into an authorization or execution failure.
            indexed_items = []

        candidate_items = indexed_items
        if not indexed_seen:
            # Migration fallback for pre-index approvals. This is intentionally
            # bounded so a legacy table cannot make the request run forever.
            scan_kwargs: dict[str, Any] = {"Limit": 100}
            pages = 0
            while pages < 5:
                result = self.table.scan(**scan_kwargs)
                for item in result.get("Items", []):
                    if str(item.get("pk") or "")[:9] != "APPROVAL#" or item.get("sk") != "METADATA":
                        continue
                    if str(item.get("tenant_id") or "") != tenant_id:
                        continue
                    candidate_items.append(dict(item))
                last_key = result.get("LastEvaluatedKey")
                pages += 1
                if not last_key:
                    break
                scan_kwargs["ExclusiveStartKey"] = last_key

        seen_approval_ids: set[str] = set()
        for item in candidate_items:
            approval_id = str(item.get("approval_id") or "")
            if not approval_id or approval_id in seen_approval_ids:
                continue
            seen_approval_ids.add(approval_id)
            current = item if item.get("item_type") != "approval_index" else self.get_approval(approval_id)
            if not current or str(current.get("tenant_id") or "") != tenant_id:
                continue
            if statuses and str(current.get("status") or "") not in statuses:
                continue
            if agent_id and str(current.get("agent_id") or "") != agent_id:
                continue
            if environment and str(current.get("environment") or "") != environment:
                continue
            records.append(current)

        records.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return records[:limit]

    def put_grant(self, grant: dict[str, Any]) -> None:
        """Persist a duration-based approval grant.

        The grant is keyed by tenant and action hash so evaluation can look up an
        active grant with a bounded Query. The primary record is the source of
        truth; a tenant-local lookup record keeps the grants list bounded.
        """
        grant_item = self._with_retention_expiry({
            "pk": f"GRANT#{grant['grant_id']}",
            "sk": "METADATA",
            **grant,
        })
        self.table.put_item(Item=_dynamodb_safe(grant_item))
        try:
            index_item = {
                "pk": f"TENANT#{grant['tenant_id']}",
                "sk": f"GRANT#{grant['action_hash']}#{grant['grant_id']}",
                "item_type": "grant_index",
                "tenant_id": grant["tenant_id"],
                "grant_id": grant["grant_id"],
                "action_hash": grant["action_hash"],
                "expires_at": grant["expires_at"],
                "created_at": grant["created_at"],
            }
            if grant_item.get("retention_expires_at") is not None:
                index_item["retention_expires_at"] = grant_item["retention_expires_at"]
            self.table.put_item(Item=_dynamodb_safe(index_item))
        except Exception:
            pass

    def get_grant(self, grant_id: str) -> dict[str, Any] | None:
        result = self.table.get_item(Key={"pk": f"GRANT#{grant_id}", "sk": "METADATA"})
        return result.get("Item")

    def find_active_grant(self, tenant_id: str, action_hash: str, now: int | None = None) -> dict[str, Any] | None:
        """Return the newest active grant matching a tenant and action hash."""
        now = int(time.time()) if now is None else int(now)
        try:
            result = self.table.query(
                KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant_id}")
                & Key("sk").begins_with(f"GRANT#{action_hash}#"),
                ScanIndexForward=False,
                ConsistentRead=True,
                Limit=20,
            )
            grant_ids = [
                str(item.get("grant_id"))
                for item in result.get("Items", [])
                if item.get("item_type") == "grant_index" and item.get("grant_id")
            ]
        except Exception:
            grant_ids = []
        for grant_id in grant_ids:
            grant = self.get_grant(grant_id)
            if not grant or str(grant.get("tenant_id") or "") != tenant_id:
                continue
            if str(grant.get("action_hash") or "") != action_hash:
                continue
            if str(grant.get("status") or "active") != "active":
                continue
            if int(grant.get("expires_at", 0)) <= now:
                continue
            return grant
        return None

    def list_grants(self, tenant_id: str, limit: int = 50) -> list[dict[str, Any]]:
        limit = max(1, min(int(limit), 100))
        records: list[dict[str, Any]] = []
        try:
            result = self.table.query(
                KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant_id}")
                & Key("sk").begins_with("GRANT#"),
                ScanIndexForward=False,
                ConsistentRead=True,
                Limit=100,
            )
            grant_ids = [
                str(item.get("grant_id"))
                for item in result.get("Items", [])
                if item.get("item_type") == "grant_index" and item.get("grant_id")
            ]
        except Exception:
            grant_ids = []
        seen: set[str] = set()
        for grant_id in grant_ids:
            if grant_id in seen:
                continue
            seen.add(grant_id)
            grant = self.get_grant(grant_id)
            if grant and str(grant.get("tenant_id") or "") == tenant_id:
                records.append(grant)
        records.sort(key=lambda item: str(item.get("created_at") or ""), reverse=True)
        return records[:limit]

    def revoke_grant(self, grant_id: str, revoked_by: str, revoked_at: str) -> dict[str, Any] | None:
        try:
            result = self.table.update_item(
                Key={"pk": f"GRANT#{grant_id}", "sk": "METADATA"},
                UpdateExpression="SET #status = :revoked, revoked_by = :revoked_by, revoked_at = :revoked_at",
                ConditionExpression="#status = :active",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={":revoked": "revoked", ":active": "active", ":revoked_by": revoked_by, ":revoked_at": revoked_at},
                ReturnValues="ALL_NEW",
            )
            return result.get("Attributes")
        except Exception as exc:
            if _is_conditional_check_failure(exc):
                return None
            raise

    def expire_approval(self, approval: dict[str, Any], now: int | None = None) -> dict[str, Any]:
        """Persist an expired status exactly once and emit an audit event."""

        now = int(time.time()) if now is None else int(now)
        if approval.get("status") != "pending" or int(approval.get("expires_at", 0)) > now:
            return approval
        expired_at = utc_now()
        try:
            result = self.table.update_item(
                Key={"pk": f"APPROVAL#{approval['approval_id']}", "sk": "METADATA"},
                UpdateExpression="SET #status = :expired, expired_at = :expired_at",
                ConditionExpression="#status = :pending AND expires_at <= :now",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":expired": "expired",
                    ":pending": "pending",
                    ":expired_at": expired_at,
                    ":now": now,
                },
                ReturnValues="ALL_NEW",
            )
            expired = result.get("Attributes") or {**approval, "status": "expired", "expired_at": expired_at}
            self.put_event(
                {
                    "event_type": "approval.expired",
                    "tenant_id": expired["tenant_id"],
                    "run_id": expired["run_id"],
                    "action_id": expired["action_id"],
                    "agent_id": expired["agent_id"],
                    "created_at": expired_at,
                    "approval_id": expired["approval_id"],
                    "status": "expired",
                    "action_hash": expired.get("action_hash"),
                }
            )
            return expired
        except Exception as exc:
            if not _is_conditional_check_failure(exc):
                raise
            current = self.table.get_item(Key={"pk": f"APPROVAL#{approval['approval_id']}", "sk": "METADATA"}).get("Item")
            return current or {**approval, "status": "expired", "expired_at": expired_at}

    def revoke_approval(
        self,
        approval_id: str,
        revoked_by: str,
        revoked_at: str,
        reason: str = "",
    ) -> tuple[dict[str, Any] | None, bool]:
        """Revoke a pending or approved approval; consumed approvals cannot be replayed."""

        current = self.table.get_item(Key={"pk": f"APPROVAL#{approval_id}", "sk": "METADATA"}).get("Item")
        if not current:
            return None, False
        current = self.get_approval(approval_id) or current
        if current.get("status") == "revoked":
            return current, False
        if current.get("status") not in {"pending", "approved"}:
            return current, False
        try:
            result = self.table.update_item(
                Key={"pk": f"APPROVAL#{approval_id}", "sk": "METADATA"},
                UpdateExpression="SET #status = :revoked, revoked_by = :revoked_by, revoked_at = :revoked_at, revocation_reason = :reason",
                ConditionExpression="#status = :pending OR #status = :approved",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":revoked": "revoked",
                    ":pending": "pending",
                    ":approved": "approved",
                    ":revoked_by": str(revoked_by or "unknown-revoker"),
                    ":revoked_at": revoked_at,
                    ":reason": str(reason or "").strip(),
                },
                ReturnValues="ALL_NEW",
            )
            return result.get("Attributes") or {**current, "status": "revoked", "revoked_by": revoked_by, "revoked_at": revoked_at}, True
        except Exception as exc:
            if not _is_conditional_check_failure(exc):
                raise
            latest = self.table.get_item(Key={"pk": f"APPROVAL#{approval_id}", "sk": "METADATA"}).get("Item")
            return latest or current, False

    def consume_approval(
        self,
        approval_id: str,
        consumed_by: str,
        consumed_at: str,
        action_id: str,
        action_hash: str,
    ) -> dict[str, Any] | None:
        """Mark an approved action as consumed using a conditional update."""

        approval = self.table.get_item(Key={"pk": f"APPROVAL#{approval_id}", "sk": "METADATA"}).get("Item")
        if not approval or approval.get("status") != "approved":
            return None
        try:
            result = self.table.update_item(
                Key={"pk": f"APPROVAL#{approval_id}", "sk": "METADATA"},
                UpdateExpression="SET #status = :consumed, consumed_by = :consumed_by, consumed_at = :consumed_at, consumed_action_id = :action_id, consumed_action_hash = :action_hash",
                ConditionExpression="#status = :approved",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":consumed": "consumed",
                    ":approved": "approved",
                    ":consumed_by": str(consumed_by or "unknown-executor"),
                    ":consumed_at": consumed_at,
                    ":action_id": str(action_id),
                    ":action_hash": str(action_hash),
                },
                ReturnValues="ALL_NEW",
            )
            return result.get("Attributes")
        except Exception as exc:
            if _is_conditional_check_failure(exc):
                return None
            raise

    def get_action_outcome(self, tenant_id: str, action_id: str) -> dict[str, Any] | None:
        outcomes = self.list_events(
            tenant_id,
            limit=10,
            filters={"action_id": action_id, "event_type": "action.outcome", "limit": 10},
        )
        authoritative = [outcome for outcome in outcomes if outcome.get("source") != "external"]
        return authoritative[0] if authoritative else None

    def update_approval(
        self,
        approval_id: str,
        status: str,
        approver: str,
        decided_at: str,
        approver_principal: str | None = None,
        approver_auth_source: str | None = None,
    ) -> dict[str, Any]:
        assignments = ["#status = :status", "approver = :approver", "decided_at = :decided_at"]
        values: dict[str, Any] = {
            ":status": status,
            ":pending": "pending",
            ":approver": approver,
            ":decided_at": decided_at,
            ":now": int(datetime.now(timezone.utc).timestamp()),
        }
        if approver_principal:
            assignments.append("approver_principal = :approver_principal")
            values[":approver_principal"] = approver_principal
        if approver_auth_source:
            assignments.append("approver_auth_source = :approver_auth_source")
            values[":approver_auth_source"] = approver_auth_source
        result = self.table.update_item(
            Key={"pk": f"APPROVAL#{approval_id}", "sk": "METADATA"},
            UpdateExpression="SET " + ", ".join(assignments),
            ConditionExpression="#status = :pending AND expires_at > :now",
            ExpressionAttributeNames={"#status": "status"},
            ExpressionAttributeValues=values,
            ReturnValues="ALL_NEW",
        )
        return result["Attributes"]

    def update_approval_chain(
        self,
        approval_id: str,
        chain_steps: list[dict[str, Any]],
        current_step: int,
        status: str,
        decided_at: str | None = None,
        approver: str | None = None,
        approver_principal: str | None = None,
    ) -> dict[str, Any] | None:
        """Persist multi-step chain progress (#245).

        Writes the updated per-step status list and current step. When the final
        status is approved or denied, records the deciding approver and timestamp.
        """
        assignments = ["chain_steps = :chain_steps", "current_step = :current_step", "#status = :status"]
        values: dict[str, Any] = {
            ":chain_steps": _dynamodb_safe(chain_steps),
            ":current_step": current_step,
            ":status": status,
            ":pending": "pending",
        }
        if decided_at:
            assignments.append("decided_at = :decided_at")
            values[":decided_at"] = decided_at
        if approver:
            assignments.append("approver = :approver")
            values[":approver"] = approver
        if approver_principal:
            assignments.append("approver_principal = :approver_principal")
            values[":approver_principal"] = approver_principal
        try:
            result = self.table.update_item(
                Key={"pk": f"APPROVAL#{approval_id}", "sk": "METADATA"},
                UpdateExpression="SET " + ", ".join(assignments),
                ConditionExpression="#status = :pending",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues=values,
                ReturnValues="ALL_NEW",
            )
            return result.get("Attributes")
        except Exception as exc:
            if _is_conditional_check_failure(exc):
                return None
            raise

    def list_events(
        self,
        tenant_id: str,
        limit: int = 50,
        filters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        filters = dict(filters or {})
        limit = max(1, min(int(filters.get("limit", limit)), 100))
        start_time = str(filters.get("start_time") or "")
        end_time = str(filters.get("end_time") or "")
        key_conditions = [
            Key("pk").eq(f"TENANT#{tenant_id}") & Key("sk").between(
                f"EVENT#{start_time or '0000-01-01T00:00:00Z'}",
                f"EVENT#{end_time or '9999-12-31T23:59:59Z'}\uffff",
            )
        ]
        if not start_time and not end_time:
            # Older idempotent events used a stable non-timestamped sort-key
            # prefix. Query that range separately so it cannot hide newer
            # timestamped records when DynamoDB returns descending results.
            key_conditions.append(Key("pk").eq(f"TENANT#{tenant_id}") & Key("sk").begins_with("EVENT#IDEMPOTENT#"))

        matched: dict[tuple[str, str], dict[str, Any]] = {}
        for key_condition in key_conditions:
            query_kwargs: dict[str, Any] = {
                "KeyConditionExpression": key_condition,
                "Limit": 100,
                "ScanIndexForward": False,
                "ConsistentRead": True,
            }
            collected = 0
            while collected < limit:
                result = self.table.query(**query_kwargs)
                for item in result.get("Items", []):
                    key = (str(item.get("pk") or ""), str(item.get("sk") or ""))
                    if key in matched or not item.get("event_type"):
                        continue
                    if event_matches(item, filters):
                        matched[key] = item
                        collected += 1
                        if collected >= limit:
                            break
                last_key = result.get("LastEvaluatedKey")
                if not last_key:
                    break
                query_kwargs["ExclusiveStartKey"] = last_key

        events = list(matched.values())
        events.sort(
            key=lambda item: (
                str(item.get("created_at") or ""),
                0 if str(item.get("sk") or "").startswith("EVENT#IDEMPOTENT#") else 1,
                str(item.get("sk") or ""),
            ),
            reverse=True,
        )
        return events[:limit]

    def get_action_evaluation(self, tenant_id: str, action_id: str) -> dict[str, Any] | None:
        events = self.list_events(
            tenant_id,
            limit=100,
            filters={"action_id": action_id, "event_type": "action.evaluated", "limit": 100},
        )
        authoritative = [event for event in events if event.get("source") != "external"]
        return authoritative[0] if authoritative else None

    def proof_key(self, tenant_id: str, proof_id: str) -> dict[str, str]:
        return {"pk": f"TENANT#{tenant_id}", "sk": f"PROOF#{proof_id}"}

    def put_proof(self, proof: dict[str, Any], *, create_only: bool = False) -> None:
        item = _dynamodb_safe(self._with_retention_expiry({
            **self.proof_key(str(proof["tenant_id"]), str(proof["proof_id"])),
            **proof,
        }))
        put_kwargs: dict[str, Any] = {"Item": item}
        if create_only:
            put_kwargs["ConditionExpression"] = Attr("pk").not_exists() & Attr("sk").not_exists()
        self.table.put_item(**put_kwargs)

    def get_proof(self, proof_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
        if tenant_id:
            result = self.table.get_item(Key=self.proof_key(str(tenant_id), str(proof_id)))
            return result.get("Item")
        result = self.table.get_item(Key={"pk": f"PROOF#{proof_id}", "sk": "METADATA"})
        return result.get("Item")


    @staticmethod
    def _policy_bundle_key(tenant_id: str) -> dict[str, str]:
        return {"pk": f"TENANT#{tenant_id}", "sk": "POLICY_BUNDLE"}

    def _invalidate_policy_bundle(self, tenant_id: str) -> None:
        """Remove the materialised bundle before policy/config changes take effect."""
        try:
            self.table.delete_item(Key=self._policy_bundle_key(str(tenant_id)))
        except Exception:
            # Evaluation will refuse a missing or stale bundle and rebuild it.
            pass

    def _bump_policy_bundle_revision(self, tenant_id: str) -> int:
        """Advance the authoritative revision used to reject stale bundles."""
        if self.get_tenant_config(str(tenant_id)) is None:
            self._invalidate_policy_bundle(str(tenant_id))
            return 0
        try:
            result = self.table.update_item(
                Key={"pk": f"TENANT#{tenant_id}", "sk": "CONFIG"},
                UpdateExpression="SET policy_bundle_revision = if_not_exists(policy_bundle_revision, :zero) + :one",
                ExpressionAttributeValues={":zero": 0, ":one": 1},
                ReturnValues="ALL_NEW",
            )
        except (KeyError, TypeError, ValueError):
            # Keep the in-process DynamoDB test double compatible while the
            # production path uses the atomic if_not_exists expression.
            current = self.get_tenant_config(str(tenant_id)) or {}
            next_revision = int(current.get("policy_bundle_revision") or 0) + 1
            result = self.table.update_item(
                Key={"pk": f"TENANT#{tenant_id}", "sk": "CONFIG"},
                UpdateExpression="SET policy_bundle_revision = :revision",
                ExpressionAttributeValues={":revision": next_revision},
                ReturnValues="ALL_NEW",
            )
        except Exception as exc:
            self._invalidate_policy_bundle(tenant_id)
            raise RuntimeError("Could not advance the tenant policy bundle revision.") from exc
        revision = int((result.get("Attributes") or {}).get("policy_bundle_revision") or 0)
        if revision:
            cached = self._tenant_config_cache.get(str(tenant_id))
            if isinstance(cached, dict):
                cached = dict(cached)
                cached["policy_bundle_revision"] = revision
                self._tenant_config_cache[str(tenant_id)] = cached
            return revision
        refreshed = self.get_tenant_config(str(tenant_id)) or {}
        return int(refreshed.get("policy_bundle_revision") or 0)

    def _refresh_policy_bundle(
        self,
        tenant_id: str,
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        effective_config = dict(config or self.get_tenant_config(tenant_id) or {})
        policies = self.list_policies(tenant_id, published_only=True)
        bundle = build_policy_bundle(tenant_id, effective_config, policies)
        self.table.put_item(
            Item=_dynamodb_safe({
                **self._policy_bundle_key(tenant_id),
                "item_type": "policy_bundle",
                "tenant_id": str(tenant_id),
                "bundle_id": bundle["bundle_id"],
                "bundle_hash": bundle["bundle_hash"],
                "config_version": bundle["config_version"],
                "policy_bundle_revision": bundle["policy_bundle_revision"],
                "bundle": bundle,
            })
        )
        return bundle

    def get_policy_bundle(
        self,
        tenant_id: str,
        config: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Load the current materialised policy set with one authoritative read.

        A missing or stale bundle is rebuilt from the versioned policy records.
        If that rebuild cannot be persisted, evaluation fails closed instead of
        silently using stale policy data.
        """

        tenant_id = str(tenant_id)
        effective_config = dict(config or {})
        if not {"config_version", "policy_bundle_revision"} <= set(effective_config):
            stored_config = self.get_tenant_config(tenant_id) or {}
            stored_config.update(effective_config)
            effective_config = stored_config
        result = self.table.get_item(
            Key=self._policy_bundle_key(tenant_id),
            ConsistentRead=True,
        )
        item = result.get("Item")
        bundle = item.get("bundle") if isinstance(item, dict) else None
        if is_current_bundle(bundle, tenant_id, effective_config):
            return copy.deepcopy(bundle)
        try:
            return self._refresh_policy_bundle(tenant_id, effective_config)
        except Exception as exc:
            raise RuntimeError(
                "Guard policy bundle is unavailable; refusing to evaluate against stale policy rules."
            ) from exc

    def get_tenant_config(self, tenant_id: str) -> dict[str, Any] | None:
        tenant_id = str(tenant_id)
        if tenant_id in self._tenant_config_cache:
            return self._tenant_config_cache[tenant_id]
        result = self.table.get_item(
            Key={"pk": f"TENANT#{tenant_id}", "sk": "CONFIG"},
            ConsistentRead=True,
        )
        config = result.get("Item")
        self._tenant_config_cache[tenant_id] = config
        return config

    def list_tenant_configs(
        self,
        tenant_id: str | None = None,
        status: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        """List persisted tenant configurations for the control plane."""

        limit = max(1, min(int(limit), 100))

        # Tenant-scoped callers can read their single configuration directly.
        # This is the normal request path and avoids a table scan entirely.
        if tenant_id:
            config = self.get_tenant_config(tenant_id)
            if not config or config.get("item_type") != "tenant_config":
                return []
            if status and str(config.get("status") or "") != status:
                return []
            return [config]

        records: list[dict[str, Any]] = []
        indexed_items: list[dict[str, Any]] = []
        indexed_seen = False
        try:
            query_kwargs: dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq("TENANT_REGISTRY"),
                "Limit": 100,
                "ScanIndexForward": True,
                "ConsistentRead": True,
            }
            pages = 0
            while pages < 10 and len(indexed_items) < limit:
                result = self.table.query(**query_kwargs)
                page_items = [
                    dict(item) for item in result.get("Items", [])
                    if item.get("item_type") == "tenant_registry" and item.get("tenant_id")
                ]
                if page_items:
                    indexed_seen = True
                    indexed_items.extend(page_items)
                last_key = result.get("LastEvaluatedKey")
                pages += 1
                if not last_key:
                    break
                query_kwargs["ExclusiveStartKey"] = last_key
        except Exception:
            indexed_items = []

        if indexed_seen:
            for registry_item in indexed_items:
                config = self.get_tenant_config(str(registry_item.get("tenant_id") or ""))
                if not config or config.get("item_type") != "tenant_config":
                    continue
                if status and str(config.get("status") or "") != status:
                    continue
                records.append(config)
        else:
            # Migration fallback for configurations written before the tenant
            # registry records existed. Keep this bounded for large tenants.
            scan_kwargs: dict[str, Any] = {"Limit": 100}
            pages = 0
            while pages < 5:
                result = self.table.scan(**scan_kwargs)
                for item in result.get("Items", []):
                    if str(item.get("pk") or "")[:7] != "TENANT#" or item.get("sk") != "CONFIG":
                        continue
                    if item.get("item_type") != "tenant_config":
                        continue
                    if status and str(item.get("status") or "") != status:
                        continue
                    records.append(dict(item))
                last_key = result.get("LastEvaluatedKey")
                pages += 1
                if not last_key:
                    break
                scan_kwargs["ExclusiveStartKey"] = last_key
        records.sort(key=lambda item: str(item.get("tenant_id") or ""))
        return records[:limit]

    def put_tenant_config(self, config: dict[str, Any]) -> None:
        config = dict(config)
        tenant_id = str(config["tenant_id"])
        if "policy_bundle_revision" not in config:
            existing = self._tenant_config_cache.get(tenant_id) or {}
            config["policy_bundle_revision"] = int(existing.get("policy_bundle_revision") or 0)
        self._tenant_config_cache[tenant_id] = config
        self._invalidate_policy_bundle(tenant_id)
        self.table.put_item(
            Item=_dynamodb_safe({
                "pk": f"TENANT#{config['tenant_id']}",
                "sk": "CONFIG",
                **config,
            })
        )
        # A compact registry record gives platform administrators a bounded
        # query path without exposing the full tenant configuration in the
        # cross-tenant listing operation.
        try:
            self.table.put_item(
                Item=_dynamodb_safe({
                    "pk": "TENANT_REGISTRY",
                    "sk": f"TENANT#{config['tenant_id']}",
                    "item_type": "tenant_registry",
                    "tenant_id": config["tenant_id"],
                    "name": config.get("name"),
                    "status": config.get("status"),
                    "configured": bool(config.get("configured")),
                    "config_version": config.get("config_version"),
                    "created_at": config.get("created_at"),
                    "updated_at": config.get("updated_at"),
                })
            )
        except Exception:
            # The configuration record is authoritative; the bounded legacy
            # scan keeps the listing path usable if registry persistence fails.
            pass

    def get_membership(self, subject: str, tenant_id: str) -> dict[str, Any] | None:
        result = self.table.get_item(Key={"pk": f"USER#{subject}", "sk": f"MEMBERSHIP#{tenant_id}"})
        return result.get("Item")

    def list_memberships(self, subject: str) -> list[dict[str, Any]]:
        result = self.table.query(
            KeyConditionExpression=Key("pk").eq(f"USER#{subject}") & Key("sk").begins_with("MEMBERSHIP#"),
            Limit=100,
            ScanIndexForward=True,
            ConsistentRead=True,
        )
        return sorted(
            [dict(item) for item in result.get("Items", []) if item.get("item_type") == "tenant_membership"],
            key=lambda item: str(item.get("tenant_id") or ""),
        )

    def list_tenant_memberships(self, tenant_id: str) -> list[dict[str, Any]]:
        result = self.table.query(
            KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant_id}") & Key("sk").begins_with("MEMBER#"),
            Limit=100,
            ScanIndexForward=True,
            ConsistentRead=True,
        )
        memberships: list[dict[str, Any]] = []
        for index_item in result.get("Items", []):
            subject = str(index_item.get("subject") or "")
            if not subject:
                continue
            record = self.get_membership(subject, tenant_id)
            if record and record.get("item_type") == "tenant_membership":
                memberships.append(record)
        return sorted(memberships, key=lambda item: str(item.get("subject") or ""))

    def put_membership(self, membership: dict[str, Any]) -> None:
        tenant_id = str(membership["tenant_id"])
        subject = str(membership["subject"])
        self.table.put_item(
            Item=_dynamodb_safe({
                "pk": f"USER#{subject}",
                "sk": f"MEMBERSHIP#{tenant_id}",
                **membership,
            })
        )
        self.table.put_item(
            Item=_dynamodb_safe({
                "pk": f"TENANT#{tenant_id}",
                "sk": f"MEMBER#{subject}",
                "item_type": "membership_index",
                "tenant_id": tenant_id,
                "subject": subject,
                "role": membership.get("role"),
                "status": membership.get("status"),
                "updated_at": membership.get("updated_at"),
            })
        )

    def put_invitation(self, invitation: dict[str, Any]) -> None:
        """Persist an invitation record plus a tenant-scoped listing index.

        The authoritative record is keyed by the invitation token hash (the
        redemption lookup key); the tenant index carries only display fields
        and the hash so an admin can list and revoke without the secret token.
        """

        tenant_id = str(invitation["tenant_id"])
        invitation_id = str(invitation["invitation_id"])
        token_hash = str(invitation["token_hash"])
        self.table.put_item(
            Item=_dynamodb_safe({
                "pk": f"INVITATION#{token_hash}",
                "sk": "METADATA",
                **invitation,
            })
        )
        self.table.put_item(
            Item=_dynamodb_safe({
                "pk": f"TENANT#{tenant_id}",
                "sk": f"INVITATION#{invitation_id}",
                "item_type": "invitation_index",
                "tenant_id": tenant_id,
                "invitation_id": invitation_id,
                "role": invitation.get("role"),
                "status": invitation.get("status"),
                "created_by": invitation.get("created_by"),
                "created_at": invitation.get("created_at"),
                "expires_at": invitation.get("expires_at"),
                "max_uses": invitation.get("max_uses"),
                "use_count": invitation.get("use_count"),
                "token_hash": token_hash,
            })
        )

    def get_invitation_by_token_hash(self, token_hash: str) -> dict[str, Any] | None:
        result = self.table.get_item(Key={"pk": f"INVITATION#{token_hash}", "sk": "METADATA"})
        item = result.get("Item")
        return dict(item) if item and item.get("item_type") == "tenant_invitation" else None

    def get_invitation_index(self, invitation_id: str, tenant_id: str) -> dict[str, Any] | None:
        result = self.table.get_item(Key={"pk": f"TENANT#{tenant_id}", "sk": f"INVITATION#{invitation_id}"})
        item = result.get("Item")
        return dict(item) if item and item.get("item_type") == "invitation_index" else None

    def list_tenant_invitations(self, tenant_id: str) -> list[dict[str, Any]]:
        result = self.table.query(
            KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant_id}") & Key("sk").begins_with("INVITATION#"),
            Limit=100,
            ScanIndexForward=False,
            ConsistentRead=True,
        )
        return sorted(
            [dict(item) for item in result.get("Items", []) if item.get("item_type") == "invitation_index"],
            key=lambda item: str(item.get("created_at") or ""),
            reverse=True,
        )

    def put_platform_access_grant(self, grant: dict[str, Any]) -> None:
        """Persist a short-lived, reason-bound operator support grant."""

        self.table.put_item(
            Item=_dynamodb_safe({
                "pk": f"PLATFORM_ACCESS#{grant['grant_id']}",
                "sk": "METADATA",
                **grant,
            })
        )
        # Keep a bounded queryable registry for the platform console. The
        # primary grant remains the source of truth; this item only makes
        # listing grants efficient on a table that also stores audit records.
        self.table.put_item(
            Item=_dynamodb_safe({
                "pk": "PLATFORM_ACCESS",
                "sk": f"GRANT#{grant['created_at']}#{grant['grant_id']}",
                "item_type": "platform_access_grant_index",
                "grant_id": grant["grant_id"],
                "tenant_id": grant["tenant_id"],
                "created_at": grant["created_at"],
            })
        )

    def get_platform_access_grant(self, grant_id: str) -> dict[str, Any] | None:
        result = self.table.get_item(Key={"pk": f"PLATFORM_ACCESS#{grant_id}", "sk": "METADATA"})
        return result.get("Item")

    def list_platform_access_grants(self, tenant_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """List bounded grant metadata for the separate platform operator path."""

        requested_limit = max(1, min(int(limit), 100))
        result = self.table.query(
            KeyConditionExpression=Key("pk").eq("PLATFORM_ACCESS"),
            ScanIndexForward=False,
            Limit=requested_limit,
            ConsistentRead=True,
        )
        records: list[dict[str, Any]] = []
        for index_item in result.get("Items", []):
            if index_item.get("item_type") != "platform_access_grant_index":
                continue
            if tenant_id not in (None, "") and str(index_item.get("tenant_id")) != str(tenant_id):
                continue
            current = self.get_platform_access_grant(str(index_item.get("grant_id") or ""))
            if current:
                records.append(current)
            if len(records) >= requested_limit:
                break
        return records[:requested_limit]

    def list_retention_candidates(self, tenant_id: str, cutoff: int) -> list[dict[str, Any]]:
        candidates: list[dict[str, Any]] = []
        scan_kwargs: dict[str, Any] = {
            "FilterExpression": Attr("tenant_id").eq(tenant_id),
            "Limit": 100,
        }
        while True:
            result = self.table.scan(**scan_kwargs)
            candidates.extend(
                item for item in result.get("Items", []) if is_retained_item(item, tenant_id, cutoff)
            )
            last_key = result.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
        return candidates

    def clear_retention_expiry(self, tenant_id: str) -> int:
        """Remove DynamoDB TTL markers when a tenant enters legal hold."""

        cleared = 0
        scan_kwargs: dict[str, Any] = {
            "FilterExpression": Attr("tenant_id").eq(tenant_id),
            "Limit": 100,
        }
        while True:
            result = self.table.scan(**scan_kwargs)
            for item in result.get("Items", []):
                if item.get("item_type") == "tenant_config" or "retention_expires_at" not in item:
                    continue
                item = dict(item)
                item.pop("retention_expires_at", None)
                self.table.put_item(Item=_dynamodb_safe(item))
                cleared += 1
            last_key = result.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
        return cleared

    def delete_record(self, item: dict[str, Any]) -> None:
        self.table.delete_item(Key={"pk": item["pk"], "sk": item["sk"]})

    @staticmethod
    def _agent_pk(agent_id: str, tenant_id: str) -> str:
        return f"TENANT#{tenant_id}#AGENT#{agent_id}"

    def put_agent(self, agent: dict[str, Any], *, require_absent: bool = False) -> None:
        item = _dynamodb_safe({
            "pk": self._agent_pk(str(agent["agent_id"]), str(agent["tenant_id"])),
            "sk": "METADATA",
            **agent,
        })
        put_kwargs: dict[str, Any] = {"Item": item}
        if require_absent:
            put_kwargs["ConditionExpression"] = Attr("pk").not_exists() & Attr("sk").not_exists()
        self.table.put_item(**put_kwargs)
        try:
            self.table.put_item(
                Item=_dynamodb_safe({
                    "pk": f"TENANT#{agent['tenant_id']}",
                    "sk": f"AGENT#{agent['agent_id']}",
                    "item_type": "agent_index",
                    "tenant_id": agent["tenant_id"],
                    "agent_id": agent["agent_id"],
                    "status": agent.get("status"),
                    "updated_at": agent.get("updated_at"),
                })
            )
        except Exception:
            # The primary identity record remains authoritative. The bounded
            # legacy scan below keeps listings usable during index migration.
            pass

    def get_agent(self, agent_id: str, tenant_id: str | None = None) -> dict[str, Any] | None:
        if tenant_id:
            result = self.table.get_item(Key={"pk": self._agent_pk(str(agent_id), str(tenant_id)), "sk": "METADATA"})
            if result.get("Item"):
                return result.get("Item")
        result = self.table.get_item(Key={"pk": f"AGENT#{agent_id}", "sk": "METADATA"})
        item = result.get("Item")
        if tenant_id and item and str(item.get("tenant_id") or "") != str(tenant_id):
            return None
        return item

    def list_agents(self, tenant_id: str) -> list[dict[str, Any]]:
        """List registered agent identities for one tenant."""

        indexed_items: list[dict[str, Any]] = []
        indexed_seen = False
        try:
            query_kwargs: dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq(f"TENANT#{tenant_id}") & Key("sk").begins_with("AGENT#"),
                "Limit": 100,
                "ScanIndexForward": True,
                "ConsistentRead": True,
            }
            pages = 0
            while pages < 10 and len(indexed_items) < 100:
                result = self.table.query(**query_kwargs)
                page_items = [
                    dict(item) for item in result.get("Items", [])
                    if item.get("item_type") == "agent_index" and item.get("agent_id")
                ]
                if page_items:
                    indexed_seen = True
                    indexed_items.extend(page_items)
                last_key = result.get("LastEvaluatedKey")
                pages += 1
                if not last_key:
                    break
                query_kwargs["ExclusiveStartKey"] = last_key
        except Exception:
            indexed_items = []

        items: list[dict[str, Any]] = []
        if indexed_seen:
            for index_item in indexed_items:
                agent = self.get_agent(str(index_item.get("agent_id") or ""), tenant_id)
                if agent and str(agent.get("tenant_id") or "") == tenant_id:
                    items.append(agent)
        else:
            # Migration fallback for agents created before tenant-local lookup
            # records were introduced. Keep this bounded for large tables.
            scan_kwargs: dict[str, Any] = {
                "FilterExpression": Attr("tenant_id").eq(tenant_id),
                "Limit": 100,
            }
            pages = 0
            while pages < 5 and len(items) < 100:
                result = self.table.scan(**scan_kwargs)
                items.extend(
                    item for item in result.get("Items", [])
                    if str(item.get("pk") or "").startswith("AGENT#")
                )
                last_key = result.get("LastEvaluatedKey")
                pages += 1
                if not last_key:
                    break
                scan_kwargs["ExclusiveStartKey"] = last_key
        return sorted(items[:100], key=lambda item: str(item.get("agent_id") or ""))

    @staticmethod
    def _model_pk(model_id: str, tenant_id: str) -> str:
        return f"TENANT#{tenant_id}#MODEL#{model_id}"

    def put_model(self, model: dict[str, Any], *, require_absent: bool = False) -> None:
        item = _dynamodb_safe(
            {
                "pk": self._model_pk(str(model["model_id"]), str(model["tenant_id"])),
                "sk": f"VERSION#{model['version']}",
                **model,
            }
        )
        put_kwargs: dict[str, Any] = {"Item": item}
        if require_absent:
            put_kwargs["ConditionExpression"] = Attr("pk").not_exists() & Attr("sk").not_exists()
        self.table.put_item(**put_kwargs)
        try:
            self.table.put_item(
                Item=_dynamodb_safe(
                    {
                        "pk": f"TENANT#{model['tenant_id']}",
                        "sk": f"MODEL#{model['model_id']}#VERSION#{model['version']}",
                        "item_type": "ai_model_index",
                        "tenant_id": model["tenant_id"],
                        "model_id": model["model_id"],
                        "version": model["version"],
                        "risk_tier": model.get("risk_tier"),
                        "updated_at": model.get("updated_at"),
                    }
                )
            )
        except Exception:
            # The model record is authoritative; the bounded scan fallback
            # keeps listings usable while an index write is unavailable.
            pass

    def list_model_versions(self, model_id: str, tenant_id: str) -> list[dict[str, Any]]:
        result = self.table.query(
            KeyConditionExpression=Key("pk").eq(self._model_pk(model_id, tenant_id)),
            Limit=100,
            ScanIndexForward=False,
            ConsistentRead=True,
        )
        return [item for item in result.get("Items", []) if item.get("item_type") == "ai_model"]

    def get_model(self, model_id: str, tenant_id: str, version: str | None = None) -> dict[str, Any] | None:
        if version is not None:
            result = self.table.get_item(
                Key={"pk": self._model_pk(model_id, tenant_id), "sk": f"VERSION#{version}"},
                ConsistentRead=True,
            )
            return result.get("Item")
        versions = self.list_model_versions(model_id, tenant_id)
        return versions[0] if versions else None

    def list_models(self, tenant_id: str) -> list[dict[str, Any]]:
        indexed_items: list[dict[str, Any]] = []
        try:
            result = self.table.query(
                KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant_id}") & Key("sk").begins_with("MODEL#"),
                Limit=100,
                ScanIndexForward=True,
                ConsistentRead=True,
            )
            indexed_items = [
                item
                for item in result.get("Items", [])
                if item.get("item_type") == "ai_model_index" and item.get("model_id")
            ]
        except Exception:
            indexed_items = []
        models: list[dict[str, Any]] = []
        if indexed_items:
            for index_item in indexed_items:
                model = self.get_model(
                    str(index_item.get("model_id") or ""),
                    tenant_id,
                    str(index_item.get("version") or ""),
                )
                if model:
                    models.append(model)
        else:
            scan_result = self.table.scan(Limit=100)
            models = [
                item
                for item in scan_result.get("Items", [])
                if item.get("item_type") == "ai_model" and str(item.get("tenant_id") or "") == tenant_id
            ]
        return sorted(models[:100], key=lambda item: (str(item.get("model_id") or ""), str(item.get("version") or "")))

    @staticmethod
    def _supplier_pk(supplier_id: str, tenant_id: str) -> str:
        # The supplier ID is globally unique. The durable tenant_id field and
        # the tenant-local index enforce tenant scoping on every read/list.
        return f"SUPPLIER#{supplier_id}"

    def put_supplier(self, supplier: dict[str, Any], *, require_absent: bool = False) -> None:
        """Persist a tenant-scoped supplier registry record and index."""

        item = _dynamodb_safe(
            {
                "pk": self._supplier_pk(str(supplier["supplier_id"]), str(supplier["tenant_id"])),
                "sk": "METADATA",
                "item_type": "supplier",
                **supplier,
            }
        )
        put_kwargs: dict[str, Any] = {"Item": item}
        if require_absent:
            put_kwargs["ConditionExpression"] = Attr("pk").not_exists() & Attr("sk").not_exists()
        self.table.put_item(**put_kwargs)
        try:
            self.table.put_item(
                Item=_dynamodb_safe(
                    {
                        "pk": f"TENANT#{supplier['tenant_id']}",
                        "sk": f"SUPPLIER#{supplier['supplier_id']}",
                        "item_type": "supplier_index",
                        "tenant_id": supplier["tenant_id"],
                        "supplier_id": supplier["supplier_id"],
                        "name": supplier.get("name"),
                        "role": supplier.get("role"),
                        "risk_rating": supplier.get("risk_rating"),
                        "updated_at": supplier.get("updated_at"),
                    }
                )
            )
        except Exception:
            # The primary record is authoritative. The bounded scan fallback
            # keeps listings available if an index write is unavailable.
            pass

    def get_supplier(self, supplier_id: str, tenant_id: str) -> dict[str, Any] | None:
        result = self.table.get_item(
            Key={"pk": self._supplier_pk(str(supplier_id), str(tenant_id)), "sk": "METADATA"},
            ConsistentRead=True,
        )
        item = result.get("Item")
        return item if item and str(item.get("tenant_id") or "") == str(tenant_id) else None

    def list_suppliers(self, tenant_id: str) -> list[dict[str, Any]]:
        indexed_items: list[dict[str, Any]] = []
        try:
            result = self.table.query(
                KeyConditionExpression=Key("pk").eq(f"TENANT#{tenant_id}") & Key("sk").begins_with("SUPPLIER#"),
                Limit=100,
                ScanIndexForward=True,
                ConsistentRead=True,
            )
            indexed_items = [
                item
                for item in result.get("Items", [])
                if item.get("item_type") == "supplier_index" and item.get("supplier_id")
            ]
        except Exception:
            indexed_items = []
        suppliers: list[dict[str, Any]] = []
        if indexed_items:
            for index_item in indexed_items:
                supplier = self.get_supplier(str(index_item.get("supplier_id") or ""), tenant_id)
                if supplier:
                    suppliers.append(supplier)
        else:
            scan_result = self.table.scan(Limit=100)
            suppliers = [
                item
                for item in scan_result.get("Items", [])
                if item.get("item_type") == "supplier" and str(item.get("tenant_id") or "") == tenant_id
            ]
        return sorted(suppliers[:100], key=lambda item: str(item.get("name") or "").lower())

    def _policy_pk(self, policy_id: str, tenant_id: str) -> str:
        return f"TENANT#{tenant_id}#POLICY#{policy_id}"

    def put_policy(self, policy: dict[str, Any]) -> None:
        version = int(policy["version"])
        self.table.put_item(
            Item=_dynamodb_safe({
                "pk": self._policy_pk(str(policy["policy_id"]), str(policy["tenant_id"])),
                "sk": f"VERSION#{version:010d}",
                **policy,
            })
        )
        try:
            self.table.put_item(
                Item=_dynamodb_safe({
                    "pk": f"TENANT#{policy['tenant_id']}",
                    "sk": f"POLICY#{policy['policy_id']}#VERSION#{version:010d}",
                    "item_type": "policy_index",
                    "tenant_id": policy["tenant_id"],
                    "policy_id": policy["policy_id"],
                    "version": version,
                    "status": policy.get("status"),
                    "created_at": policy.get("created_at"),
                    "updated_at": policy.get("updated_at"),
                })
            )
        except Exception:
            # The versioned policy record is authoritative; the bounded legacy
            # scan remains available if index persistence is temporarily down.
            pass
        self._bump_policy_bundle_revision(str(policy["tenant_id"]))

    def get_policy(self, policy_id: str, version: int | None = None, tenant_id: str | None = None) -> dict[str, Any] | None:
        if tenant_id:
            if version is not None:
                result = self.table.get_item(Key={"pk": self._policy_pk(policy_id, tenant_id), "sk": f"VERSION#{int(version):010d}"})
                policy = result.get("Item")
                if policy:
                    return policy
            else:
                policies = self.list_policy_versions(policy_id, tenant_id)
                published = [item for item in policies if item.get("status") == "published"]
                return (published or policies)[0] if (published or policies) else None

            # Migration fallback for policy versions written before policy keys
            # were tenant-scoped. The tenant check prevents cross-tenant reads
            # from legacy global policy partitions.
            result = self.table.get_item(Key={"pk": f"POLICY#{policy_id}", "sk": f"VERSION#{int(version):010d}"})
            policy = result.get("Item")
            return policy if policy and str(policy.get("tenant_id") or "") == tenant_id else None

        if version is not None:
            result = self.table.get_item(Key={"pk": f"POLICY#{policy_id}", "sk": f"VERSION#{int(version):010d}"})
            return result.get("Item")
        result = self.table.query(
            KeyConditionExpression=Key("pk").eq(f"POLICY#{policy_id}"),
            Limit=100,
            ScanIndexForward=False,
            ConsistentRead=True,
        )
        policies = [item for item in result.get("Items", []) if item.get("item_type") == "policy"]
        active = [item for item in policies if item.get("status") in {"published", "suspended"}]
        return (active or policies)[0] if (active or policies) else None

    def list_policy_versions(self, policy_id: str, tenant_id: str | None = None) -> list[dict[str, Any]]:
        if tenant_id:
            result = self.table.query(
                KeyConditionExpression=Key("pk").eq(self._policy_pk(policy_id, tenant_id)),
                Limit=100,
                ScanIndexForward=False,
            )
            policies = [item for item in result.get("Items", []) if item.get("item_type") == "policy"]
            if policies:
                return policies
            # Migration fallback for versions written before tenant-scoped keys.
            return [item for item in self.list_policy_versions(policy_id) if str(item.get("tenant_id") or "") == tenant_id]
        result = self.table.query(
            KeyConditionExpression=Key("pk").eq(f"POLICY#{policy_id}"),
            Limit=100,
            ScanIndexForward=False,
            ConsistentRead=True,
        )
        return [item for item in result.get("Items", []) if item.get("item_type") == "policy"]

    def list_policies(self, tenant_id: str, published_only: bool = False) -> list[dict[str, Any]]:
        indexed_items: list[dict[str, Any]] = []
        indexed_seen = False
        try:
            query_kwargs: dict[str, Any] = {
                "KeyConditionExpression": Key("pk").eq(f"TENANT#{tenant_id}") & Key("sk").begins_with("POLICY#"),
                "Limit": 100,
                "ScanIndexForward": False,
                "ConsistentRead": True,
            }
            pages = 0
            while pages < 10 and len(indexed_items) < 100:
                result = self.table.query(**query_kwargs)
                page_items = [
                    dict(item) for item in result.get("Items", [])
                    if item.get("item_type") == "policy_index" and item.get("policy_id")
                ]
                if page_items:
                    indexed_seen = True
                    indexed_items.extend(page_items)
                last_key = result.get("LastEvaluatedKey")
                pages += 1
                if not last_key:
                    break
                query_kwargs["ExclusiveStartKey"] = last_key
        except Exception:
            indexed_items = []

        items: list[dict[str, Any]] = []
        if indexed_seen:
            for index_item in indexed_items:
                if published_only and index_item.get("status") != "published":
                    continue
                try:
                    version = int(index_item.get("version"))
                except (TypeError, ValueError):
                    continue
                policy = self.get_policy(str(index_item.get("policy_id") or ""), version, tenant_id)
                if policy and str(policy.get("tenant_id") or "") == tenant_id:
                    items.append(policy)
        else:
            # Migration fallback for policy versions created before the index.
            scan_kwargs: dict[str, Any] = {
                "FilterExpression": Attr("item_type").eq("policy") & Attr("tenant_id").eq(tenant_id),
                "Limit": 100,
            }
            pages = 0
            while pages < 5 and len(items) < 100:
                result = self.table.scan(**scan_kwargs)
                items.extend(
                    item for item in result.get("Items", [])
                    if item.get("item_type") == "policy" and str(item.get("tenant_id") or "") == tenant_id
                )
                last_key = result.get("LastEvaluatedKey")
                pages += 1
                if not last_key:
                    break
                scan_kwargs["ExclusiveStartKey"] = last_key
            if published_only:
                items = [item for item in items if item.get("status") == "published"]
        return items[:100]

    def publish_policy(self, policy_id: str, version: int, tenant_id: str | None = None) -> dict[str, Any] | None:
        target = self.get_policy(policy_id, version, tenant_id)
        if not target:
            return None
        effective_tenant_id = str(tenant_id or target.get("tenant_id") or "")
        for existing in self.list_policy_versions(policy_id, effective_tenant_id):
            if existing.get("status") == "published" and int(existing.get("version", 0)) != int(version):
                existing["status"] = "archived"
                existing["updated_at"] = utc_now()
                self.put_policy(existing)
        target["status"] = "published"
        target["published_at"] = utc_now()
        target["updated_at"] = target["published_at"]
        self.put_policy(target)
        return target

    def delete_policy(self, policy_id: str, tenant_id: str) -> list[int]:
        """Delete every version and tenant index for one tenant-owned policy."""

        versions = self.list_policy_versions(policy_id, tenant_id)
        for policy in versions:
            version = int(policy["version"])
            self.table.delete_item(Key={"pk": self._policy_pk(policy_id, tenant_id), "sk": f"VERSION#{version:010d}"})
            self.table.delete_item(Key={"pk": f"TENANT#{tenant_id}", "sk": f"POLICY#{policy_id}#VERSION#{version:010d}"})
        self._bump_policy_bundle_revision(str(tenant_id))
        return sorted((int(item["version"]) for item in versions), reverse=True)

    def delete_policy_version(self, policy_id: str, version: int, tenant_id: str | None = None) -> None:
        """Remove a policy version and its tenant list index."""

        policy = self.get_policy(policy_id, version, tenant_id)
        effective_tenant = tenant_id or (policy or {}).get("tenant_id")
        if effective_tenant:
            self.table.delete_item(Key={"pk": self._policy_pk(policy_id, str(effective_tenant)), "sk": f"VERSION#{int(version):010d}"})
            self.table.delete_item(
                Key={
                    "pk": f"TENANT#{effective_tenant}",
                    "sk": f"POLICY#{policy_id}#VERSION#{int(version):010d}",
                }
            )
            self._bump_policy_bundle_revision(str(effective_tenant))
        else:
            self.table.delete_item(Key={"pk": f"POLICY#{policy_id}", "sk": f"VERSION#{int(version):010d}"})


def store() -> AuditStore:
    # Resolve the live table and secrets client from the adapter module so that
    # tests which reassign lambda_function.table keep working.
    adapter = sys.modules.get("lambda_function") or sys.modules.get("app.lambda_function")
    table = getattr(adapter, "table", None)
    secrets_client = getattr(adapter, "secrets_client", None)
    if table is None:
        raise RuntimeError("AUDIT_TABLE_NAME is not configured.")
    return AuditStore(table, secrets_client)

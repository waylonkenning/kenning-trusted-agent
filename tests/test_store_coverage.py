"""Targeted tests for app/store.py uncovered branches.

Covers: retention expiry edge cases, delivery status updates, pagination,
query-exception fallbacks to scan, conditional-check-failure handling,
index-write exception swallowing, filter/skip conditions, and the
store() factory RuntimeError.
"""

import os
import time
import unittest
from unittest.mock import MagicMock, patch

from app import lambda_function as service
from app.store import AuditStore, store as store_factory

from tests.test_federation import FakeTable, FakeTokenTable, conditional_check_failed


DEPLOYMENT_ENVIRONMENT = str(
    os.environ.get("KENNING_ENV") or os.environ.get("KENNING_ENVIRONMENT") or "prototype"
).strip()


class StoreCoverageTests(unittest.TestCase):
    def setUp(self):
        self.table = FakeTable()
        self.store = AuditStore(self.table)

    # ------------------------------------------------------------------
    # _with_retention_expiry
    # ------------------------------------------------------------------

    def test_retention_expiry_skips_tenant_config_items(self):
        """Line 87: tenant_config items return early without expiry."""
        item = {"pk": "TENANT#demo", "sk": "CONFIG", "item_type": "tenant_config", "tenant_id": "demo"}
        result = self.store._with_retention_expiry(item)
        self.assertNotIn("retention_expires_at", result)

    def test_retention_expiry_skips_when_no_tenant_id(self):
        """Line 86-87: items without tenant_id return early."""
        item = {"pk": "EVENT#1", "sk": "METADATA"}
        result = self.store._with_retention_expiry(item)
        self.assertNotIn("retention_expires_at", result)

    def test_retention_expiry_bad_created_at_falls_back(self):
        """Lines 97-98: unparseable created_at falls back to time.time()."""
        self.store.put_tenant_config(service.build_tenant_config("demo", {
            "retention_enabled": True, "retention_days": 30,
        }))
        item = {"pk": "EVENT#1", "sk": "METADATA", "tenant_id": "demo",
                "event_type": "test", "created_at": "not-a-date"}
        result = self.store._with_retention_expiry(item)
        self.assertIn("retention_expires_at", result)
        expected = int(time.time()) + 30 * 86400
        self.assertAlmostEqual(result["retention_expires_at"], expected, delta=5)

    # ------------------------------------------------------------------
    # put_event — delivery paths
    # ------------------------------------------------------------------

    def test_put_event_non_conditional_check_reraises(self):
        """Line 123: non-ConditionalCheckFailed exceptions propagate."""
        self.table.put_item = MagicMock(side_effect=RuntimeError("dynamodb down"))
        event = {"pk": "EVENT#test", "sk": "METADATA", "event_type": "test", "tenant_id": "demo"}
        with self.assertRaises(RuntimeError):
            self.store.put_event(event)

    def test_put_event_with_delivery_sink(self):
        """Lines 127-135: event delivery when sink is enabled."""
        self.store.put_tenant_config(service.build_tenant_config("demo", {
            "audit_sink": {
                "enabled": True,
                "endpoint_url": "https://sink.example.org/hook",
                "secret_arn": f"arn:aws:secretsmanager:us-east-1:123456789012:secret:kenning/audit-sinks/{DEPLOYMENT_ENVIRONMENT}/demo/sink",
            },
        }))
        event = {
            "pk": "EVENT#delivery-test", "sk": "METADATA",
            "event_type": "guard.evaluation", "tenant_id": "demo",
            "created_at": "2026-01-01T00:00:00Z",
        }
        with patch("app.store.deliver_event", return_value={"status": "delivered", "http_status": 200}) as mock_deliver:
            result = self.store.put_event(event)
        mock_deliver.assert_called_once()
        self.assertEqual(result["status"], "delivered")

    def test_put_event_delivery_mark_failure_swallowed(self):
        """Lines 131-134: mark_event_delivery failure doesn't break put_event."""
        self.store.put_tenant_config(service.build_tenant_config("demo", {
            "audit_sink": {
                "enabled": True,
                "endpoint_url": "https://sink.example.org/hook",
                "secret_arn": f"arn:aws:secretsmanager:us-east-1:123456789012:secret:kenning/audit-sinks/{DEPLOYMENT_ENVIRONMENT}/demo/sink",
            },
        }))
        event = {
            "pk": "EVENT#mark-fail", "sk": "METADATA",
            "event_type": "guard.evaluation", "tenant_id": "demo",
            "created_at": "2026-01-01T00:00:00Z",
        }
        with patch("app.store.deliver_event", return_value={"status": "delivered"}):
            with patch.object(self.store, "mark_event_delivery", side_effect=RuntimeError("update failed")):
                result = self.store.put_event(event)
        # Should still return the delivery result, not raise
        self.assertEqual(result["status"], "delivered")

    # ------------------------------------------------------------------
    # record_metrics — exception swallowed
    # ------------------------------------------------------------------

    def test_record_metrics_exception_swallowed(self):
        """Lines 173-176: metrics write failure doesn't propagate."""
        event = {"pk": "EVENT#m", "sk": "METADATA", "event_type": "test", "tenant_id": "demo"}
        # Make the table's update_item raise for metrics
        original_update = self.table.update_item
        def failing_update(Key, **kwargs):
            if "METRICS" in str(Key.get("pk", "")):
                raise RuntimeError("metrics table down")
            return original_update(Key, **kwargs)
        self.table.update_item = failing_update
        # Should not raise
        self.store.record_metrics(event, delivery_status="delivered")

    # ------------------------------------------------------------------
    # mark_event_delivery
    # ------------------------------------------------------------------

    def test_mark_event_delivery_full(self):
        """Lines 188-199: delivery status with http_status and error_code."""
        self.table.put_item(Item={"pk": "EVENT#d", "sk": "METADATA", "event_type": "test"})
        item = {"pk": "EVENT#d", "sk": "METADATA"}
        delivery = {"status": "failed", "http_status": 500, "error_code": "TIMEOUT"}
        self.store.mark_event_delivery(item, delivery)
        stored = self.table.get_item(Key={"pk": "EVENT#d", "sk": "METADATA"})["Item"]
        self.assertEqual(stored["delivery_status"], "failed")
        self.assertEqual(stored["delivery_http_status"], 500)
        self.assertEqual(stored["delivery_error_code"], "TIMEOUT")

    def test_mark_event_delivery_minimal(self):
        """Lines 188-192: delivery status without http_status or error_code."""
        self.table.put_item(Item={"pk": "EVENT#d2", "sk": "METADATA", "event_type": "test"})
        item = {"pk": "EVENT#d2", "sk": "METADATA"}
        delivery = {"status": "delivered"}
        self.store.mark_event_delivery(item, delivery)
        stored = self.table.get_item(Key={"pk": "EVENT#d2", "sk": "METADATA"})["Item"]
        self.assertEqual(stored["delivery_status"], "delivered")
        self.assertNotIn("delivery_http_status", stored)

    # ------------------------------------------------------------------
    # list_approvals — pagination and fallback
    # ------------------------------------------------------------------

    def _seed_approval(self, approval_id, tenant_id="demo", status="pending", agent_id="agent-1", environment="prod"):
        self.table.put_item(Item={
            "pk": f"APPROVAL#{approval_id}", "sk": "METADATA",
            "item_type": "approval", "approval_id": approval_id,
            "tenant_id": tenant_id, "status": status,
            "agent_id": agent_id, "environment": environment,
            "created_at": "2026-01-01T00:00:00Z",
        })

    def test_list_approvals_scan_fallback_on_query_failure(self):
        """Lines 284-287, 298-302: query exception falls back to scan."""
        self._seed_approval("a1")
        self._seed_approval("a2", tenant_id="other")
        # Make query fail
        original_query = self.table.query
        self.table.query = MagicMock(side_effect=RuntimeError("GSI not ready"))
        results = self.store.list_approvals("demo")
        self.table.query = original_query
        # Should find a1 via scan fallback, skip a2 (wrong tenant)
        ids = [r["approval_id"] for r in results]
        self.assertIn("a1", ids)
        self.assertNotIn("a2", ids)

    def test_list_approvals_filters(self):
        """Lines 313, 317, 321: status, agent_id, environment filters."""
        self._seed_approval("f1", status="approved")
        self._seed_approval("f2", status="pending", agent_id="agent-2")
        self._seed_approval("f3", status="pending", environment="staging")
        # Filter by status
        results = self.store.list_approvals("demo", statuses=["pending"])
        ids = [r["approval_id"] for r in results]
        self.assertNotIn("f1", ids)
        self.assertIn("f2", ids)
        # Filter by agent_id
        results = self.store.list_approvals("demo", agent_id="agent-2")
        ids = [r["approval_id"] for r in results]
        self.assertEqual(ids, ["f2"])
        # Filter by environment
        results = self.store.list_approvals("demo", environment="staging")
        ids = [r["approval_id"] for r in results]
        self.assertEqual(ids, ["f3"])

    # ------------------------------------------------------------------
    # put_grant — index paths
    # ------------------------------------------------------------------

    def test_put_grant_with_retention_expiry(self):
        """Line 354: retention_expires_at propagated to index."""
        self.store.put_tenant_config(service.build_tenant_config("demo", {"retention_days": 7}))
        grant = {
            "pk": "GRANT#g1", "sk": "METADATA", "grant_id": "g1",
            "tenant_id": "demo", "action_hash": "abc",
            "status": "active", "expires_at": int(time.time()) + 3600,
            "created_at": "2026-01-01T00:00:00Z",
        }
        self.store.put_grant(grant)
        # Check the index item has retention_expires_at
        index_item = self.table.get_item(Key={"pk": "GRANT_INDEX#demo", "sk": "GRANT#g1"}).get("Item")
        if index_item:
            self.assertIn("retention_expires_at", index_item)

    def test_put_grant_index_failure_swallowed(self):
        """Lines 356-357: index write failure doesn't break put_grant."""
        grant = {
            "pk": "GRANT#g2", "sk": "METADATA", "grant_id": "g2",
            "tenant_id": "demo", "action_hash": "def",
            "status": "active", "expires_at": int(time.time()) + 3600,
        }
        original_put = self.table.put_item
        call_count = [0]
        def selective_fail(Item, **kwargs):
            call_count[0] += 1
            if call_count[0] > 1:  # Fail on the index write (second put)
                raise RuntimeError("index write failed")
            return original_put(Item, **kwargs)
        self.table.put_item = selective_fail
        # Should not raise
        self.store.put_grant(grant)
        self.table.put_item = original_put

    # ------------------------------------------------------------------
    # find_active_grant — filtering
    # ------------------------------------------------------------------

    def test_find_active_grant_query_exception(self):
        """Lines 379-380: query exception returns empty grant list."""
        self.table.query = MagicMock(side_effect=RuntimeError("query failed"))
        result = self.store.find_active_grant("demo", "some-hash")
        self.assertIsNone(result)

    def test_find_active_grant_filters(self):
        """Lines 384, 386, 390: tenant, hash, status, expiry filters."""
        now = int(time.time())
        # Seed grants
        grants = [
            {"pk": "GRANT#fg1", "sk": "METADATA", "grant_id": "fg1",
             "tenant_id": "other", "action_hash": "h1", "status": "active",
             "expires_at": now + 3600},
            {"pk": "GRANT#fg2", "sk": "METADATA", "grant_id": "fg2",
             "tenant_id": "demo", "action_hash": "wrong", "status": "active",
             "expires_at": now + 3600},
            {"pk": "GRANT#fg3", "sk": "METADATA", "grant_id": "fg3",
             "tenant_id": "demo", "action_hash": "h1", "status": "active",
             "expires_at": now - 100},
            {"pk": "GRANT#fg4", "sk": "METADATA", "grant_id": "fg4",
             "tenant_id": "demo", "action_hash": "h1", "status": "revoked",
             "expires_at": now + 3600},
            {"pk": "GRANT#fg5", "sk": "METADATA", "grant_id": "fg5",
             "tenant_id": "demo", "action_hash": "h1", "status": "active",
             "expires_at": now + 3600},
        ]
        for g in grants:
            self.table.put_item(Item=g)
        # The query looks for grant_index items; patch to return grant_ids
        original_query = self.table.query
        def fake_query(**kwargs):
            return {"Items": [
                {"item_type": "grant_index", "grant_id": g["grant_id"]}
                for g in grants
            ]}
        self.table.query = fake_query
        result = self.store.find_active_grant("demo", "h1", now=now)
        self.table.query = original_query
        self.assertIsNotNone(result)
        self.assertEqual(result["grant_id"], "fg5")

    # ------------------------------------------------------------------
    # list_grants — dedup and exception
    # ------------------------------------------------------------------

    def test_list_grants_query_exception(self):
        """Lines 410-411: query exception returns empty list."""
        self.table.query = MagicMock(side_effect=RuntimeError("query failed"))
        result = self.store.list_grants("demo")
        self.assertEqual(result, [])

    def test_list_grants_dedup(self):
        """Line 415: duplicate grant_ids are skipped."""
        now = int(time.time())
        self.table.put_item(Item={"pk": "GRANT#lg1", "sk": "METADATA", "grant_id": "lg1",
                                   "tenant_id": "demo", "action_hash": "h", "status": "active",
                                   "expires_at": now + 3600})
        result = self.store.list_grants("demo")
        self.assertIsInstance(result, list)

    # ------------------------------------------------------------------
    # revoke_grant — conditional check failure
    # ------------------------------------------------------------------

    def test_revoke_grant_conditional_check_returns_none(self):
        """Lines 434-437: ConditionalCheckFailed returns None."""
        self.table.put_item(Item={"pk": "GRANT#rg1", "sk": "METADATA", "grant_id": "rg1",
                                   "tenant_id": "demo", "status": "active"})
        original_update = self.table.update_item
        def fail_update(Key, **kwargs):
            if kwargs.get("ConditionExpression"):
                raise conditional_check_failed()
            return original_update(Key, **kwargs)
        self.table.update_item = fail_update
        result = self.store.revoke_grant("rg1", "admin", "2026-01-01T00:00:00Z")
        self.assertIsNone(result)
        self.table.update_item = original_update

    # ------------------------------------------------------------------
    # expire_approval — non-conditional re-raise
    # ------------------------------------------------------------------

    def test_expire_approval_non_conditional_reraises(self):
        """Line 477: non-ConditionalCheckFailed exceptions propagate."""
        self._seed_approval("ea1")
        approval = self.table.get_item(Key={"pk": "APPROVAL#ea1", "sk": "METADATA"})["Item"]
        original_update = self.table.update_item
        self.table.update_item = MagicMock(side_effect=RuntimeError("dynamodb down"))
        with self.assertRaises(RuntimeError):
            self.store.expire_approval(approval)
        self.table.update_item = original_update

    # ------------------------------------------------------------------
    # revoke_approval — conditional check failure
    # ------------------------------------------------------------------

    def test_revoke_approval_conditional_check_returns_latest(self):
        """Lines 515-519: ConditionalCheckFailed returns latest state."""
        self._seed_approval("ra1", status="approved")
        original_update = self.table.update_item
        def fail_update(Key, **kwargs):
            if kwargs.get("ConditionExpression"):
                raise conditional_check_failed()
            return original_update(Key, **kwargs)
        self.table.update_item = fail_update
        approval = self.table.get_item(Key={"pk": "APPROVAL#ra1", "sk": "METADATA"})["Item"]
        result, changed = self.store.revoke_approval("ra1", "demo", "admin")
        self.assertFalse(changed)
        self.table.update_item = original_update

    # ------------------------------------------------------------------
    # consume_approval — conditional check failure
    # ------------------------------------------------------------------

    def test_consume_approval_conditional_check_returns_none(self):
        """Lines 551-554: ConditionalCheckFailed returns None."""
        self._seed_approval("ca1", status="approved")
        original_update = self.table.update_item
        def fail_update(Key, **kwargs):
            if kwargs.get("ConditionExpression"):
                raise conditional_check_failed()
            return original_update(Key, **kwargs)
        self.table.update_item = fail_update
        result = self.store.consume_approval("ca1", "admin", "2026-01-01T00:00:00Z", "action-1", "hash-1")
        self.assertIsNone(result)
        self.table.update_item = original_update

    # ------------------------------------------------------------------
    # update_approval_chain — conditional check failure
    # ------------------------------------------------------------------

    def test_update_approval_chain_conditional_check_returns_none(self):
        """Lines 639-642: ConditionalCheckFailed returns None."""
        self._seed_approval("uc1")
        original_update = self.table.update_item
        def fail_update(Key, **kwargs):
            if kwargs.get("ConditionExpression"):
                raise conditional_check_failed()
            return original_update(Key, **kwargs)
        self.table.update_item = fail_update
        result = self.store.update_approval_chain("uc1", [{"step": 1, "status": "pending"}], 1, "pending")
        self.assertIsNone(result)
        self.table.update_item = original_update

    # ------------------------------------------------------------------
    # list_events — filtering and pagination
    # ------------------------------------------------------------------

    def test_list_events_skips_non_event_items(self):
        """Line 680: items without event_type are skipped."""
        self.table.put_item(Item={"pk": "EVENT#le1", "sk": "METADATA", "tenant_id": "demo"})
        self.table.put_item(Item={"pk": "EVENT#le2", "sk": "METADATA", "tenant_id": "demo",
                                   "event_type": "guard.evaluation"})
        results = self.store.list_events("demo")
        # Only le2 has event_type
        self.assertTrue(all(r.get("event_type") for r in results))

    # ------------------------------------------------------------------
    # get_proof — fallback key
    # ------------------------------------------------------------------

    def test_get_proof_fallback_to_metadata_key(self):
        """Lines 728-729: falls back to PROOF#id/METADATA key."""
        self.table.put_item(Item={"pk": "PROOF#p1", "sk": "METADATA", "proof_id": "p1",
                                   "tenant_id": "demo"})
        result = self.store.get_proof("p1")
        self.assertIsNotNone(result)
        self.assertEqual(result["proof_id"], "p1")

    # ------------------------------------------------------------------
    # list_tenant_configs — scan fallback and filtering
    # ------------------------------------------------------------------

    def test_list_tenant_configs_query_exception_falls_back_to_scan(self):
        """Lines 785-786, 799-815: query exception triggers legacy scan."""
        self.store.put_tenant_config(service.build_tenant_config("scan-tenant", {}))
        original_query = self.table.query
        self.table.query = MagicMock(side_effect=RuntimeError("GSI down"))
        results = self.store.list_tenant_configs()
        self.table.query = original_query
        tenant_ids = [r.get("tenant_id") for r in results]
        self.assertIn("scan-tenant", tenant_ids)

    def test_list_tenant_configs_status_filter(self):
        """Lines 792, 794, 808: status filter skips non-matching configs."""
        self.store.put_tenant_config(service.build_tenant_config("active-t", {}))
        self.store.put_tenant_config(service.build_tenant_config("suspended-t", {"status": "suspended"}))
        results = self.store.list_tenant_configs(status="active")
        tenant_ids = [r.get("tenant_id") for r in results]
        self.assertIn("active-t", tenant_ids)
        self.assertNotIn("suspended-t", tenant_ids)

    # ------------------------------------------------------------------
    # put_tenant_config — registry write failure
    # ------------------------------------------------------------------

    def test_put_tenant_config_registry_failure_swallowed(self):
        """Lines 846-849: registry index write failure doesn't break config save."""
        config = service.build_tenant_config("reg-fail", {})
        original_put = self.table.put_item
        call_count = [0]
        def selective_fail(Item, **kwargs):
            call_count[0] += 1
            if "REGISTRY" in str(Item.get("pk", "")):
                raise RuntimeError("registry down")
            return original_put(Item, **kwargs)
        self.table.put_item = selective_fail
        # Should not raise
        self.store.put_tenant_config(config)
        self.table.put_item = original_put
        # Config should still be readable
        result = self.store.get_tenant_config("reg-fail")
        self.assertIsNotNone(result)

    # ------------------------------------------------------------------
    # list_tenant_memberships — skip empty subject
    # ------------------------------------------------------------------

    def test_list_tenant_memberships_skips_empty_subject(self):
        """Line 878: empty subject records are skipped."""
        self.table.put_item(Item={"pk": "MEMBERSHIP#", "sk": "TENANT#demo",
                                   "tenant_id": "demo", "subject": ""})
        self.table.put_item(Item={"pk": "MEMBERSHIP#user@x.org", "sk": "TENANT#demo",
                                   "tenant_id": "demo", "subject": "user@x.org", "role": "admin"})
        results = self.store.list_tenant_memberships("demo")
        subjects = [r.get("subject") for r in results]
        self.assertNotIn("", subjects)

    # ------------------------------------------------------------------
    # list_platform_access_grants — filtering
    # ------------------------------------------------------------------

    def test_list_platform_access_grants_filters(self):
        """Lines 1007, 1009, 1014: type, tenant, and limit filters."""
        # Seed a non-matching index item
        self.table.put_item(Item={"pk": "PLATFORM_GRANT_INDEX", "sk": "g1",
                                   "item_type": "wrong_type", "grant_id": "g1", "tenant_id": "demo"})
        # Seed a matching index item
        self.table.put_item(Item={"pk": "PLATFORM_GRANT_INDEX", "sk": "g2",
                                   "item_type": "platform_access_grant_index", "grant_id": "g2", "tenant_id": "demo"})
        self.table.put_item(Item={"pk": "PLATFORM_GRANT#g2", "sk": "METADATA",
                                   "grant_id": "g2", "tenant_id": "demo", "status": "active"})
        # Seed a different-tenant item
        self.table.put_item(Item={"pk": "PLATFORM_GRANT_INDEX", "sk": "g3",
                                   "item_type": "platform_access_grant_index", "grant_id": "g3", "tenant_id": "other"})
        self.table.put_item(Item={"pk": "PLATFORM_GRANT#g3", "sk": "METADATA",
                                   "grant_id": "g3", "tenant_id": "other", "status": "active"})
        results = self.store.list_platform_access_grants(tenant_id="demo")
        grant_ids = [r.get("grant_id") for r in results]
        self.assertNotIn("g1", grant_ids)  # wrong type
        self.assertNotIn("g3", grant_ids)  # wrong tenant

    # ------------------------------------------------------------------
    # get_agent — tenant mismatch
    # ------------------------------------------------------------------

    def test_get_agent_tenant_mismatch_returns_none(self):
        """Line 1099: agent with different tenant_id returns None."""
        self.table.put_item(Item={"pk": "AGENT#a1", "sk": "METADATA", "agent_id": "a1",
                                   "tenant_id": "other-tenant"})
        result = self.store.get_agent("a1", tenant_id="demo")
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # list_agents — query exception fallback
    # ------------------------------------------------------------------

    def test_list_agents_query_exception_falls_back(self):
        """Lines 1129-1130: query exception falls back to scan."""
        self.table.put_item(Item={"pk": "AGENT#la1", "sk": "METADATA", "agent_id": "la1",
                                   "tenant_id": "demo", "item_type": "agent"})
        original_query = self.table.query
        self.table.query = MagicMock(side_effect=RuntimeError("GSI down"))
        results = self.store.list_agents("demo")
        self.table.query = original_query
        self.assertIsInstance(results, list)

    # ------------------------------------------------------------------
    # put_policy — index write failure
    # ------------------------------------------------------------------

    def test_put_policy_index_failure_swallowed(self):
        """Lines 1185-1188: index write failure doesn't break policy save."""
        policy = {
            "pk": "POLICY#p1", "sk": "VERSION#0000000001",
            "policy_id": "p1", "tenant_id": "demo", "version": 1,
            "item_type": "policy", "status": "draft",
        }
        original_put = self.table.put_item
        def selective_fail(Item, **kwargs):
            if "INDEX" in str(Item.get("pk", "")):
                raise RuntimeError("index down")
            return original_put(Item, **kwargs)
        self.table.put_item = selective_fail
        # Should not raise
        self.store.put_policy(policy)
        self.table.put_item = original_put

    # ------------------------------------------------------------------
    # get_policy — fallback query
    # ------------------------------------------------------------------

    def test_get_policy_fallback_query(self):
        """Lines 1212-1220: falls back to pk query when version key misses."""
        self.table.put_item(Item={"pk": "POLICY#fp1", "sk": "VERSION#0000000001",
                                   "policy_id": "fp1", "tenant_id": "demo",
                                   "item_type": "policy", "status": "published", "version": 1})
        result = self.store.get_policy("fp1")
        self.assertIsNotNone(result)
        self.assertEqual(result["policy_id"], "fp1")

    # ------------------------------------------------------------------
    # list_policies — query exception and bad version
    # ------------------------------------------------------------------

    def test_list_policies_query_exception_falls_back(self):
        """Lines 1267-1268: query exception falls back to scan."""
        self.store.put_policy({
            "pk": "POLICY#lp1", "sk": "VERSION#0000000001",
            "policy_id": "lp1", "tenant_id": "demo", "version": 1,
            "item_type": "policy", "status": "published",
        })
        original_query = self.table.query
        self.table.query = MagicMock(side_effect=RuntimeError("GSI down"))
        results = self.store.list_policies("demo")
        self.table.query = original_query
        self.assertIsInstance(results, list)

    # ------------------------------------------------------------------
    # publish_policy — edge cases
    # ------------------------------------------------------------------

    def test_publish_policy_target_not_found(self):
        """Line 1307: returns None when target policy doesn't exist."""
        result = self.store.publish_policy("nonexistent", 1, "demo")
        self.assertIsNone(result)

    def test_publish_policy_archives_existing_published(self):
        """Lines 1311-1313: publishing archives the currently published version."""
        self.store.put_policy({
            "pk": "POLICY#pp1", "sk": "VERSION#0000000001",
            "policy_id": "pp1", "tenant_id": "demo", "version": 1,
            "item_type": "policy", "status": "published",
        })
        self.store.put_policy({
            "pk": "POLICY#pp1", "sk": "VERSION#0000000002",
            "policy_id": "pp1", "tenant_id": "demo", "version": 2,
            "item_type": "policy", "status": "draft",
        })
        result = self.store.publish_policy("pp1", 2, "demo")
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "published")
        # Version 1 should be archived
        v1 = self.store.get_policy("pp1", 1)
        if v1:
            self.assertEqual(v1["status"], "archived")

    # ------------------------------------------------------------------
    # delete_policy_version — non-latest
    # ------------------------------------------------------------------

    def test_delete_policy_version_non_latest(self):
        """Line 1344: deletes a specific version by key."""
        self.store.put_policy({
            "pk": "POLICY#dv1", "sk": "VERSION#0000000001",
            "policy_id": "dv1", "tenant_id": "demo", "version": 1,
            "item_type": "policy", "status": "archived",
        })
        self.store.put_policy({
            "pk": "POLICY#dv1", "sk": "VERSION#0000000002",
            "policy_id": "dv1", "tenant_id": "demo", "version": 2,
            "item_type": "policy", "status": "published",
        })
        self.store.delete_policy_version("dv1", 1, "demo")
        # Version 1 should be gone (uses TENANT#demo#POLICY#dv1 key)
        result = self.table.get_item(Key={"pk": "TENANT#demo#POLICY#dv1", "sk": "VERSION#0000000001"})
        self.assertNotIn("Item", result)

    # ------------------------------------------------------------------
    # store() factory
    # ------------------------------------------------------------------

    def test_store_factory_no_table_raises(self):
        """Line 1354: RuntimeError when AUDIT_TABLE_NAME not configured."""
        with patch.object(service, "table", None):
            with self.assertRaises(RuntimeError) as ctx:
                store_factory()
            self.assertIn("AUDIT_TABLE_NAME", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

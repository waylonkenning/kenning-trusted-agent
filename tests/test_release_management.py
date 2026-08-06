import json
import importlib.util
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from scripts.release_manifest import (
    REQUIRED_CHECKS,
    REQUIRED_PRODUCTION_CHECKS,
    REQUIRED_ROLLBACK_CHECKS,
    build_manifest,
    build_rollback_record,
    promote_manifest,
    validate_artifact_metadata,
    validate_manifest,
    validate_production_manifest,
)
from scripts.release_links import resolve_links


class ReleaseManifestTests(unittest.TestCase):
    CONFIGURATION_DIGEST = "sha256:" + ("a" * 64)

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        for name, content in {
            "lambda.zip": b"lambda",
            "citation-fetcher.zip": b"fetcher",
            "web.tar.gz": b"web",
        }.items():
            (self.root / name).write_bytes(content)

    def tearDown(self):
        self.temp_dir.cleanup()

    def checks(self):
        return [
            {
                "name": name,
                "command": f"command-for-{name}",
                "run_id": f"run-{index}",
                "result": "passed",
            }
            for index, name in enumerate(REQUIRED_CHECKS)
        ]

    def test_build_manifest_records_artifact_digests_and_validates(self):
        manifest = build_manifest(
            release_id="release-development-001",
            source_commit="a" * 40,
            environment="development",
            artifact_root=self.root,
            checks=self.checks(),
            deployment_id="deployment-001",
        )

        validate_manifest(manifest, artifact_root=self.root, expected_source_commit="a" * 40)
        self.assertEqual(manifest["environment"], "development")
        self.assertEqual(manifest["development"]["verification"], "passed")
        self.assertEqual(len(manifest["artifacts"]), 3)
        self.assertTrue(all(len(record["sha256"]) == 64 for record in manifest["artifacts"].values()))

    def test_manifest_rejects_missing_or_failed_checks(self):
        checks = self.checks()[:-1]
        with self.assertRaisesRegex(ValueError, "missing required checks"):
            build_manifest(
                release_id="release-development-002",
                source_commit="b" * 40,
                environment="development",
                artifact_root=self.root,
                checks=checks,
                deployment_id="deployment-002",
            )

        checks = self.checks()
        checks[0]["result"] = "skipped"
        with self.assertRaisesRegex(ValueError, "did not pass"):
            build_manifest(
                release_id="release-development-003",
                source_commit="c" * 40,
                environment="development",
                artifact_root=self.root,
                checks=checks,
                deployment_id="deployment-003",
            )

    def test_manifest_rejects_digest_tampering_and_credentials(self):
        manifest = build_manifest(
            release_id="release-development-004",
            source_commit="d" * 40,
            environment="development",
            artifact_root=self.root,
            checks=self.checks(),
            deployment_id="deployment-004",
        )
        (self.root / "web.tar.gz").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            validate_manifest(manifest, artifact_root=self.root)

        manifest = json.loads(json.dumps(manifest))
        manifest["development"]["secret"] = "must-not-be-stored"
        with self.assertRaisesRegex(ValueError, "forbidden credential field"):
            validate_manifest(manifest)

    def test_manifest_requires_release_audit_context(self):
        manifest = build_manifest(
            release_id="release-development-context",
            source_commit="e" * 40,
            environment="development",
            artifact_root=self.root,
            checks=self.checks(),
            deployment_id="deployment-context",
        )
        manifest["release_context"]["created_by"] = ""
        with self.assertRaisesRegex(ValueError, "release_context.created_by"):
            validate_manifest(manifest)

    def test_manifest_requires_known_limitations(self):
        manifest = build_manifest(
            release_id="release-development-limitations",
            source_commit="e" * 40,
            environment="development",
            artifact_root=self.root,
            checks=self.checks(),
            deployment_id="deployment-limitations",
        )
        self.assertEqual(manifest["release_context"]["known_limitations"], "None recorded")
        manifest["release_context"]["known_limitations"] = "  "
        with self.assertRaisesRegex(ValueError, "known_limitations"):
            validate_manifest(manifest)

    def test_artifact_metadata_binds_source_environment_and_digests(self):
        metadata = {
            "schema_version": 1,
            "environment": "development",
            "release_id": "release-development-metadata",
            "source_commit": "f" * 40,
            "artifacts": {
                "lambda": {"path": "lambda.zip", "sha256": ""},
                "citation_fetcher": {"path": "citation-fetcher.zip", "sha256": ""},
                "web": {"path": "web.tar.gz", "sha256": ""},
            },
        }
        from scripts.release_manifest import sha256_file

        for record in metadata["artifacts"].values():
            record["sha256"] = sha256_file(self.root / record["path"])
        validate_artifact_metadata(
            metadata,
            artifact_root=self.root,
            expected_source_commit="f" * 40,
            expected_release_id="release-development-metadata",
        )
        metadata["source_commit"] = "0" * 40
        with self.assertRaisesRegex(ValueError, "does not match"):
            validate_artifact_metadata(metadata, artifact_root=self.root, expected_source_commit="f" * 40)

    def test_required_test_runner_rejects_skips(self):
        script = Path(__file__).resolve().parents[1] / "scripts" / "run_required_tests.py"
        spec = importlib.util.spec_from_file_location("run_required_tests", script)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        class SkippingSuite(unittest.TestCase):
            @unittest.skip("gate test")
            def test_skip(self):
                pass

        with open('/dev/null', 'w') as sink:
            result = unittest.TextTestRunner(stream=sink).run(unittest.defaultTestLoader.loadTestsFromTestCase(SkippingSuite))
        self.assertEqual(len(result.skipped), 1)
        self.assertFalse(module.result_is_acceptable(result))

    def test_candidate_freshness_rejects_old_required_checks(self):
        manifest = build_manifest(
            release_id="release-development-stale",
            source_commit="1" * 40,
            environment="development",
            artifact_root=self.root,
            checks=self.checks(),
            deployment_id="deployment-stale",
        )
        old = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat().replace("+00:00", "Z")
        manifest["checks_completed_at"] = old
        for check in manifest["checks"]:
            check["completed_at"] = old
        with self.assertRaisesRegex(ValueError, "stale"):
            validate_manifest(manifest, artifact_root=self.root, max_age_hours=24)

    def test_candidate_freshness_rejects_one_old_check_even_with_recent_summary(self):
        manifest = build_manifest(
            release_id="release-development-one-old-check",
            source_commit="9" * 40,
            environment="development",
            artifact_root=self.root,
            checks=self.checks(),
            deployment_id="deployment-one-old-check",
        )
        old = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat().replace("+00:00", "Z")
        manifest["checks"][0]["completed_at"] = old
        with self.assertRaisesRegex(ValueError, "unit-and-contract"):
            validate_manifest(manifest, artifact_root=self.root, max_age_hours=24)

    def test_release_links_combine_manual_refs_and_associated_pull_request_closures(self):
        links = resolve_links(
            manual_ticket_refs="#7, https://github.com/example/repo/issues/8",
            manual_pull_request_refs="#12",
            associated_pull_requests=[
                {"number": 13, "body": "Fixes #42 and closes https://github.com/example/repo/issues/43."}
            ],
        )
        self.assertEqual(links["ticket_refs"], ["#7", "#8", "#42"])
        self.assertEqual(links["pull_request_refs"], ["#12", "#13"])

    def test_production_manifest_requires_verification_and_binds_same_artifacts(self):
        candidate = build_manifest(
            release_id="release-development-promotable",
            source_commit="2" * 40,
            environment="development",
            artifact_root=self.root,
            checks=self.checks(),
            deployment_id="development-001",
        )
        verification = {
            "result": "passed",
            "completed_at": "2026-07-19T00:00:00Z",
            "run_id": "production-run-001",
            "checks": list(REQUIRED_PRODUCTION_CHECKS),
        }
        released = promote_manifest(
            candidate,
            artifact_root=self.root,
            deployment_id="production-001",
            approval_user="local",
            approval_source="solo-operator-confirmation",
            account_id="123456789012",
            region="us-east-1",
            verification=verification,
            configuration_digest=self.CONFIGURATION_DIGEST,
            rollback_target="production-release-previous",
            promoted_at="2026-07-19T00:00:00Z",
            migration_plan="none",
        )
        validate_production_manifest(released, artifact_root=self.root, expected_source_commit="2" * 40)
        self.assertEqual(released["production"]["artifact_digests"], {
            key: record["sha256"] for key, record in candidate["artifacts"].items()
        })
        self.assertEqual(
            released["production"]["deployment_started_at"],
            released["production"]["deployment_completed_at"],
        )
        self.assertEqual(released["production"]["approval"]["approved_at"], "2026-07-19T00:00:00Z")
        released["production"]["artifact_digests"]["web"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "artifact_digests"):
            validate_production_manifest(released, artifact_root=self.root)

        with self.assertRaisesRegex(ValueError, "approval source"):
            promote_manifest(
                candidate,
                artifact_root=self.root,
                deployment_id="production-001b",
                approval_user="local",
                approval_source="manual",
                account_id="123456789012",
                region="us-east-1",
                verification={
                    "result": "passed",
                    "completed_at": "2026-07-19T00:00:00Z",
                    "run_id": "production-run-001b",
                    "checks": list(REQUIRED_PRODUCTION_CHECKS),
                },
                configuration_digest=self.CONFIGURATION_DIGEST,
                promoted_at="2026-07-19T00:00:00Z",
            )

    def test_rollback_record_requires_a_previously_released_target(self):
        candidate = build_manifest(
            release_id="release-development-rollback-target",
            source_commit="3" * 40,
            environment="development",
            artifact_root=self.root,
            checks=self.checks(),
            deployment_id="development-002",
        )
        released = promote_manifest(
            candidate,
            artifact_root=self.root,
            deployment_id="production-002",
            approval_user="local",
            approval_source="solo-operator-confirmation",
            account_id="123456789012",
            region="us-east-1",
            verification={
                "result": "passed",
                "completed_at": "2026-07-19T00:00:00Z",
                "run_id": "run-002",
                "checks": list(REQUIRED_PRODUCTION_CHECKS),
            },
            configuration_digest=self.CONFIGURATION_DIGEST,
            promoted_at="2026-07-19T00:00:00Z",
        )
        record = build_rollback_record(
            released,
            artifact_root=self.root,
            rollback_id="rollback-001",
            failed_release_id="release-development-failed",
            incident_ref="#99",
            reason="production health check failed",
            requested_by="operator@example.com",
            approval_user="operator@example.com",
            approval_source="solo-operator-confirmation",
            deployment_id="rollback-001",
            account_id="123456789012",
            region="us-east-1",
            verification={
                "result": "passed",
                "completed_at": "2026-07-19T00:00:00Z",
                "run_id": "run-rollback",
                "checks": list(REQUIRED_ROLLBACK_CHECKS),
            },
            configuration_digest=self.CONFIGURATION_DIGEST,
            completed_at="2026-07-19T00:00:00Z",
            approved_at="2026-07-18T23:55:00Z",
        )
        self.assertEqual(record["target_release_id"], released["release_id"])
        self.assertEqual(record["failed_release_id"], "release-development-failed")
        self.assertEqual(record["approval"]["approved_at"], "2026-07-18T23:55:00Z")
        self.assertIn("started_at", record["production"])

    def test_solo_operator_confirmation_allows_same_authenticated_release_owner(self):
        candidate = build_manifest(
            release_id="release-development-solo-confirmed",
            source_commit="5" * 40,
            environment="development",
            artifact_root=self.root,
            checks=self.checks(),
            deployment_id="development-solo-confirmed",
            created_by="waylonkenning",
        )
        verification = {
            "result": "passed",
            "completed_at": "2026-07-19T00:00:00Z",
            "run_id": "production-solo-confirmed",
            "checks": list(REQUIRED_PRODUCTION_CHECKS),
        }
        released = promote_manifest(
            candidate,
            artifact_root=self.root,
            deployment_id="production-solo-confirmed",
            approval_user="WaylonKenning",
            approval_source="solo-operator-confirmation",
            account_id="123456789012",
            region="us-east-1",
            verification=verification,
            configuration_digest=self.CONFIGURATION_DIGEST,
            promoted_at="2026-07-19T00:00:00Z",
        )
        validate_production_manifest(released, artifact_root=self.root)
        malformed = json.loads(json.dumps(released))
        malformed["production"]["approval"]["user"] = {"login": "waylonkenning"}
        with self.assertRaisesRegex(ValueError, "production approval"):
            validate_production_manifest(malformed, artifact_root=self.root)
        record = build_rollback_record(
            released,
            artifact_root=self.root,
            rollback_id="rollback-solo-confirmed",
            failed_release_id="failed-solo-confirmed",
            incident_ref="#solo-confirmed",
            reason="verification failed",
            requested_by="waylonkenning",
            approval_user="WAYLONKENNING",
            approval_source="solo-operator-confirmation",
            deployment_id="rollback-solo-confirmed",
            account_id="123456789012",
            region="us-east-1",
            verification={
                "result": "passed",
                "completed_at": "2026-07-19T00:00:00Z",
                "run_id": "rollback-solo-confirmed",
                "checks": list(REQUIRED_ROLLBACK_CHECKS),
            },
            configuration_digest=self.CONFIGURATION_DIGEST,
            approved_at="2026-07-19T00:00:00Z",
        )
        self.assertEqual(record["approval"]["source"], "solo-operator-confirmation")

    def test_aws_codepipeline_approval_allows_pipeline_created_candidate(self):
        candidate = build_manifest(
            release_id="release-development-aws-pipeline",
            source_commit="6" * 40,
            environment="development",
            artifact_root=self.root,
            checks=self.checks(),
            deployment_id="development-aws-pipeline",
            created_by="aws-codepipeline",
        )
        released = promote_manifest(
            candidate,
            artifact_root=self.root,
            deployment_id="production-aws-pipeline",
            approval_user="aws-codepipeline",
            approval_source="aws-codepipeline-manual-approval",
            account_id="123456789012",
            region="us-east-1",
            verification={
                "result": "passed",
                "completed_at": "2026-07-19T00:00:00Z",
                "run_id": "run-aws-pipeline",
                "checks": list(REQUIRED_PRODUCTION_CHECKS),
            },
            configuration_digest=self.CONFIGURATION_DIGEST,
            promoted_at="2026-07-19T00:00:00Z",
        )
        validate_production_manifest(released, artifact_root=self.root)
        self.assertEqual(
            released["production"]["approval"]["source"],
            "aws-codepipeline-manual-approval",
        )

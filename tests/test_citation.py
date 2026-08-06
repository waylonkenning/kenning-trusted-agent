import unittest

import app.citation as citation_module
from app.citation import _currency, _robots_decision, extract_citations, normalise_citation_policy, retrieve_source, verify_citation, verify_response


class CitationTrustTests(unittest.TestCase):
    def test_extracts_urls_documents_identifiers_and_footnotes(self):
        extracted = extract_citations(
            "See [the policy](https://example.govt.nz/policy) and proposal-a.pdf [1]. Reference GOV/2026-42."
        )
        self.assertEqual(extracted["urls"], ["https://example.govt.nz/policy"])
        self.assertEqual(extracted["documents"], ["proposal-a.pdf"])
        self.assertEqual(extracted["identifiers"], ["GOV/2026-42"])
        self.assertEqual(extracted["footnotes"], ["1"])

    def test_non_url_references_are_unresolved_without_source_metadata(self):
        result = verify_response({"response": "See proposal-a.pdf [1]. Reference GOV/2026-42."})
        self.assertEqual(len(result["reference_findings"]), 3)
        self.assertTrue(all(not item["verified"] for item in result["reference_findings"]))
        self.assertEqual(result["status"], "fail")

    def test_reference_sources_can_verify_documents_identifiers_and_footnotes(self):
        sources = [
            {"type": "document", "reference": "proposal-a.pdf", "claim": "proposal-a.pdf", "source_text": "proposal-a.pdf", "source_hash": "0" * 64},
            {"type": "identifier", "reference": "GOV/2026-42", "claim": "GOV/2026-42", "source_text": "GOV/2026-42", "source_hash": "0" * 64},
            {"type": "footnote", "reference": "1", "claim": "1", "source_text": "1", "source_hash": "0" * 64},
        ]
        import hashlib

        for item in sources:
            item["source_hash"] = hashlib.sha256(item["source_text"].encode("utf-8")).hexdigest()
        result = verify_response(
            {"response": "See proposal-a.pdf [1]. Reference GOV/2026-42."},
            policy={"allow_inline_source_text": False},
        )
        self.assertEqual(result["status"], "fail")
        verified = verify_response(
            {
                "response": "See proposal-a.pdf [1]. Reference GOV/2026-42.",
                "reference_sources": sources,
            },
            policy={"allow_inline_source_text": False},
        )
        self.assertEqual(verified["status"], "pass")
        self.assertTrue(all(item["verified"] for item in verified["reference_findings"]))

    def test_supported_inline_claim_passes(self):
        result = verify_citation(
            {
                "url": "https://example.govt.nz/policy",
                "claim": "The policy applies to all public agencies",
                "source_text": "The policy applies to all public agencies in New Zealand.",
            }
        )
        self.assertTrue(result["exists"])
        self.assertTrue(result["accessible"])
        self.assertTrue(result["supports_claim"])
        self.assertEqual(result["source_quality"], "authoritative")
        self.assertTrue(result["source_verified"])
        self.assertEqual(result["source_score"], 100)
        self.assertEqual(result["claim_support_score"], 98)
        self.assertGreater(result["confidence"], 0.8)

    def test_bibliographic_metadata_matches_without_being_treated_as_a_claim(self):
        result = verify_citation(
            {
                "url": "https://example.org/report",
                "claim": "",
                "claim_support_required": False,
                "reference_metadata": {
                    "title": "Digital Government Outlook 2026",
                    "year": "2026",
                    "publisher": "OECD Publishing",
                },
                "source_text": "Digital Government Outlook 2026. Published by OECD Publishing in 2026.",
            }
        )
        self.assertTrue(result["source_verified"])
        self.assertIsNone(result["supports_claim"])
        self.assertFalse(result["claim_support_required"])
        self.assertTrue(result["reference_verified"])
        self.assertEqual(result["reference_metadata_score"], 100)

    def test_bibliographic_metadata_mismatch_is_reported_separately(self):
        result = verify_citation(
            {
                "url": "https://example.org/report",
                "claim": "",
                "claim_support_required": False,
                "reference_metadata": {"title": "Expected Report", "year": "2026"},
                "source_text": "A different report published in 2024.",
            }
        )
        self.assertTrue(result["source_verified"])
        self.assertIsNone(result["supports_claim"])
        self.assertFalse(result["reference_verified"])
        self.assertEqual(result["reference_metadata_score"], 0)
        self.assertIn("Bibliography metadata", result["reason"])

    def test_source_only_bibliography_check_can_pass_without_a_claim(self):
        result = verify_response(
            {
                "response": "",
                "citations": [
                    {
                        "url": "https://example.org/report",
                        "claim": "",
                        "claim_support_required": False,
                        "reference_metadata": {"title": "Example Report", "year": "2026"},
                        "source_text": "Example Report. Published in 2026.",
                    }
                ],
            }
        )
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["trust_score"], 100)
        self.assertIsNone(result["citations"][0]["supports_claim"])
        self.assertTrue(result["citations"][0]["reference_verified"])

    def test_bibliographic_metadata_mismatch_lowers_source_only_trust_score(self):
        result = verify_response(
            {
                "response": "",
                "citations": [
                    {
                        "url": "https://example.org/report",
                        "claim_support_required": False,
                        "reference_metadata": {"title": "Expected Report", "year": "2026"},
                        "source_text": "A different report published in 2024.",
                    }
                ],
            }
        )
        self.assertEqual(result["trust_score"], 0)
        self.assertEqual(result["status"], "fail")

    def test_numeric_mismatch_warns_about_entailment(self):
        result = verify_citation(
            {
                "url": "https://example.com/report",
                "claim": "The report found 42 affected records",
                "source_text": "The report found 24 affected records.",
            }
        )
        self.assertFalse(result["supports_claim"])
        self.assertIn("numeric values", result["reason"])
        self.assertTrue(result["source_verified"])
        self.assertEqual(result["source_score"], 100)
        self.assertEqual(result["claim_support_score"], 0)
        self.assertEqual(result["confidence"], 0.0)

    def test_numeric_values_must_match_in_the_same_source_context(self):
        result = verify_citation(
            {
                "url": "https://example.govt.nz/report",
                "claim": "The DGI average rose from 0.61 to 0.90 in 2025",
                "source_text": "The DGI average rose from 0.61 to 0.70 in 2025. Another metric reached 0.90 in 2024.",
            }
        )
        self.assertFalse(result["supports_claim"])
        self.assertEqual(result["claim_support_score"], 0)
        self.assertIn("same context", result["reason"])

    def test_failed_retrieval_has_zero_confidence(self):
        result = verify_citation(
            {
                "url": "https://kenning-trust-independent-review.example/research/2026-results",
                "claim": "Kenning Citation Trust guarantees perfect citation accuracy in every test",
            },
            retriever=lambda _url: {
                "exists": False,
                "accessible": False,
                "authenticity": False,
                "error": "The source could not be retrieved.",
            },
        )
        self.assertFalse(result["exists"])
        self.assertFalse(result["accessible"])
        self.assertFalse(result["supports_claim"])
        self.assertEqual(result["confidence"], 0.0)
        self.assertEqual(result["reason"], "The source could not be retrieved.")

    def test_remote_fetcher_uses_common_source_parser(self):
        citation_module.set_source_remote_retriever(
            lambda _url, _max_bytes, _timeout, _user_agent: {
                "retrieval_status": "success",
                "status_code": 200,
                "final_url": "https://example.org/policy",
                "content_type": "text/html; charset=utf-8",
                "headers": {"last-modified": "Fri, 17 Jul 2026 19:57:31 GMT"},
                "raw_bytes": b"<html><head><title>Example policy</title></head><body>The policy applies to all agencies.</body></html>",
            }
        )
        try:
            result = retrieve_source("https://example.org/policy", respect_robots=False)
        finally:
            citation_module.set_source_remote_retriever(None)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["retrieval_strategy"], "node_fetcher")
        self.assertEqual(result["retrieval_attempts"], 1)
        self.assertIn("The policy applies to all agencies.", result["text"])
        self.assertEqual(result["source_metadata_text"], "Example policy")

    def test_inaccessible_http_source_has_zero_confidence(self):
        result = verify_citation(
            {
                "url": "https://example.com/missing",
                "claim": "This claim is supported",
            },
            retriever=lambda _url: {
                "exists": False,
                "accessible": False,
                "authenticity": False,
                "status_code": 404,
                "final_url": "https://example.com/missing",
                "error": "Source returned HTTP 404.",
            },
        )
        self.assertEqual(result["confidence"], 0.0)
        self.assertFalse(result["supports_claim"])

    def test_source_hash_binds_citation_to_exact_content(self):
        import hashlib

        source_text = "The policy applies to all public agencies."
        source_hash = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        verified = verify_citation(
            {
                "url": "https://example.govt.nz/policy",
                "claim": "The policy applies to all public agencies.",
                "source_text": source_text,
                "source_hash": f"sha256:{source_hash}",
            }
        )
        self.assertTrue(verified["source_hash_verified"])
        self.assertTrue(verified["authenticity"])

        mismatched = verify_citation(
            {
                "url": "https://example.govt.nz/policy",
                "claim": "The policy applies to all public agencies.",
                "source_text": source_text,
                "source_hash": "0" * 64,
            }
        )
        self.assertFalse(mismatched["source_hash_verified"])
        self.assertFalse(mismatched["authenticity"])
        self.assertIn("does not match", mismatched["reason"])
        response = verify_response(
            {
                "response": "The policy applies to all public agencies.",
                "citations": [
                    {
                        "url": "https://example.govt.nz/policy",
                        "claim": "The policy applies to all public agencies.",
                        "source_text": source_text,
                        "source_hash": "0" * 64,
                    }
                ],
            }
        )
        self.assertNotEqual(response["status"], "pass")

    def test_response_returns_warning_for_unsupported_citation(self):
        result = verify_response(
            {
                "response": "The report found 42 affected records. See https://example.com/report.",
                "citations": [
                    {
                        "url": "https://example.com/report",
                        "claim": "The report found 42 affected records",
                        "source_text": "The report found 24 affected records.",
                    }
                ],
            }
        )
        self.assertEqual(result["status"], "warning")
        self.assertEqual(result["trust_score"], 0)
        self.assertEqual(result["citations"][0]["supports_claim"], False)

    def test_first_party_domain_is_primary_without_affecting_default_score(self):
        result = verify_response(
            {
                "response": "The product is trusted. https://example.org/about/",
                "citations": [
                    {
                        "url": "https://example.org/about/",
                        "claim": "The product is trusted",
                        "source_text": "The product is trusted.",
                    }
                ],
            },
            policy={"trusted_domains": ["example.org"]},
        )
        finding = result["citations"][0]
        self.assertEqual(finding["source_quality"], "primary")
        self.assertTrue(finding["source_verified"])
        self.assertEqual(finding["source_score"], 100)
        self.assertEqual(finding["claim_support_score"], 98)
        self.assertEqual(result["trust_score"], 98)

    def test_invalid_url_fails(self):
        result = verify_citation({"url": "not-a-url", "claim": "A claim"})
        self.assertFalse(result["exists"])
        self.assertFalse(result["accessible"])
        self.assertEqual(result["source_quality"], "low-quality")

    def test_secondary_sources_are_distinguished_from_unknown_sources(self):
        result = verify_citation(
            {
                "url": "https://news.example.com/article/agent-assurance",
                "claim": "The article describes agent assurance.",
                "source_text": "The article describes agent assurance.",
            }
        )
        self.assertEqual(result["source_quality"], "secondary")

        unknown = verify_citation(
            {
                "url": "https://example.com/resource",
                "claim": "The resource describes agent assurance.",
                "source_text": "The resource describes agent assurance.",
            }
        )
        self.assertEqual(unknown["source_quality"], "unknown")

    def test_claim_type_policy_overrides_quality_and_currency_thresholds(self):
        policy = normalise_citation_policy(
            {
                "minimum_source_quality": "unknown",
                "claim_type_policies": {
                    "legal": {
                        "minimum_source_quality": "authoritative",
                        "max_age_days": 30,
                        "require_currency": True,
                    }
                },
            }
        )
        result = verify_citation(
            {
                "url": "https://example.govt.nz/policy",
                "claim": "The policy applies to public agencies.",
                "claim_type": "Legal",
                "published_at": "2026-07-16T00:00:00Z",
                "source_text": "The policy applies to public agencies.",
            },
            policy=policy,
        )
        self.assertEqual(result["claim_type"], "legal")
        self.assertEqual(result["policy_scope"]["minimum_source_quality"], "authoritative")
        self.assertEqual(result["policy_scope"]["max_age_days"], 30)
        self.assertTrue(result["policy_scope"]["require_currency"])
        self.assertTrue(result["source_quality_acceptable"])
        self.assertTrue(result["currency_acceptable"])

        stale = verify_citation(
            {
                "url": "https://example.govt.nz/policy",
                "claim": "The policy applies to public agencies.",
                "claim_type": "legal",
                "published_at": "2020-07-16T00:00:00Z",
                "source_text": "The policy applies to public agencies.",
            },
            policy=policy,
        )
        self.assertFalse(stale["currency_acceptable"])
        self.assertIn("currency requirement", stale["reason"])

    def test_currency_accepts_rfc_http_and_iso_dates(self):
        from datetime import datetime, timezone
        from email.utils import format_datetime

        now = datetime.now(timezone.utc).replace(microsecond=0)
        rfc_result = _currency({"last-modified": format_datetime(now)})
        self.assertEqual(rfc_result[0], "recent")
        self.assertEqual(rfc_result[1], 1.0)

        iso_result = _currency({}, now.isoformat().replace("+00:00", "Z"))
        self.assertEqual(iso_result[0], "recent")
        self.assertEqual(iso_result[1], 1.0)

    def test_tenant_policy_blocks_unapproved_retrieval_and_inline_text(self):
        policy = normalise_citation_policy(
            {
                "allowed_domains": ["*.govt.nz"],
                "require_https": True,
                "allow_inline_source_text": False,
                "minimum_source_quality": "authoritative",
            }
        )
        result = verify_citation(
            {"url": "http://example.com/report", "claim": "A claim", "source_text": "A claim"},
            policy=policy,
        )
        self.assertTrue(result["retrieval_blocked"])
        self.assertIn("requires HTTPS", result["reason"])

        blocked_domain = verify_citation(
            {"url": "https://example.com/report", "claim": "A claim", "source_text": "A claim"},
            policy=policy,
        )
        self.assertTrue(blocked_domain["retrieval_blocked"])
        self.assertIn("allowlisted", blocked_domain["reason"])

    def test_tenant_policy_checks_redirect_destination(self):
        def redirected(_url):
            return {
                "exists": True,
                "accessible": True,
                "authenticity": True,
                "final_url": "https://blocked.example.org/policy",
                "text": "The source supports this claim.",
                "headers": {},
            }

        result = verify_citation(
            {"url": "https://allowed.example.org/source", "claim": "The source supports this claim."},
            retriever=redirected,
            policy={"allowed_domains": ["allowed.example.org"]},
        )
        self.assertTrue(result["retrieval_blocked"])
        self.assertIsNone(result["supports_claim"])
        self.assertIn("allowlisted", result["reason"])

    def test_robots_policy_blocks_disallowed_source(self):
        class RobotsResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"User-agent: *\nDisallow: /private\n"

        decision = _robots_decision(
            "https://example.org/private/policy",
            opener=lambda _request, timeout: RobotsResponse(),
        )
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["status"], "blocked")

    def test_robots_forbidden_is_unavailable_and_non_blocking_by_default(self):
        import urllib.error

        def opener(_request, timeout):
            raise urllib.error.HTTPError(
                "https://example.org/robots.txt",
                403,
                "Forbidden",
                {},
                None,
            )

        decision = _robots_decision("https://example.org/policy", opener=opener)
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["status"], "unavailable")

        from unittest.mock import patch

        class SourceHeaders:
            def get(self, name, default=None):
                return {"content-type": "text/plain"}.get(name, default)

            def get_content_charset(self):
                return "utf-8"

            def items(self):
                return [("content-type", "text/plain")]

        class SourceResponse:
            status = 200
            headers = SourceHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"The source supports this claim."

            def geturl(self):
                return "https://example.org/policy"

        opened_requests = []

        def source_opener(request, timeout):
            opened_requests.append(request)
            return SourceResponse()

        with patch(
            "app.citation._robots_decision",
            return_value={
                "allowed": True,
                "status": "unavailable",
                "robots_url": "https://example.org/robots.txt",
                "error": "robots.txt returned HTTP 403.",
            },
        ), patch("app.citation.urllib.request.urlopen", side_effect=source_opener):
            result = retrieve_source("https://example.org/policy")
        self.assertTrue(result["accessible"])
        self.assertTrue(result["robots_allowed"])
        self.assertEqual(result["robots_status"], "unavailable")
        request_headers = {name.lower(): value for name, value in opened_requests[0].header_items()}
        self.assertEqual(
            request_headers["accept"],
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        )
        self.assertEqual(request_headers["upgrade-insecure-requests"], "1")

    def test_source_retrieval_retries_with_browser_fallback_after_transport_error(self):
        from unittest.mock import patch

        class SourceHeaders:
            def get(self, name, default=None):
                return {"content-type": "text/plain"}.get(name, default)

            def get_content_charset(self):
                return "utf-8"

            def items(self):
                return [("content-type", "text/plain")]

        class SourceResponse:
            status = 200
            headers = SourceHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"The source supports this claim."

            def geturl(self):
                return "https://example.org/policy"

        opened_requests = []

        def source_opener(request, timeout):
            opened_requests.append(request)
            if len(opened_requests) == 1:
                raise TimeoutError("temporary upstream timeout")
            return SourceResponse()

        with patch("app.citation._robots_decision", return_value={"allowed": True, "status": "disabled", "robots_url": None}), patch(
            "app.citation.urllib.request.urlopen", side_effect=source_opener
        ), patch("app.citation.time.sleep"):
            result = retrieve_source("https://example.org/policy")

        self.assertTrue(result["accessible"])
        self.assertEqual(result["retrieval_attempts"], 2)
        self.assertEqual(result["retrieval_strategy"], "browser_fallback")
        self.assertEqual(len(result["retrieval_diagnostics"]), 1)
        first_headers = {name.lower(): value for name, value in opened_requests[0].header_items()}
        second_headers = {name.lower(): value for name, value in opened_requests[1].header_items()}
        self.assertEqual(first_headers["user-agent"], "Kenning-Citation-Trust/0.1")
        self.assertIn("Mozilla/5.0", second_headers["user-agent"])
        self.assertEqual(second_headers["accept-encoding"], "identity")

    def test_source_retrieval_reports_bounded_transport_diagnostics(self):
        from unittest.mock import patch

        with patch("app.citation._robots_decision", return_value={"allowed": True, "status": "disabled", "robots_url": None}), patch(
            "app.citation.urllib.request.urlopen", side_effect=TimeoutError("upstream timeout")
        ), patch("app.citation.time.sleep"):
            result = retrieve_source("https://example.org/policy")

        self.assertFalse(result["accessible"])
        self.assertEqual(result["retrieval_status"], "transport_error")
        self.assertEqual(result["retrieval_attempts"], 3)
        self.assertEqual(len(result["retrieval_diagnostics"]), 3)
        self.assertEqual(result["error"], "upstream timeout")

    def test_doi_redirect_is_authentic_and_html_metadata_is_available(self):
        from unittest.mock import patch

        class SourceHeaders:
            def get(self, name, default=None):
                return {"content-type": "text/html; charset=utf-8"}.get(name, default)

            def get_content_charset(self):
                return "utf-8"

            def items(self):
                return [("content-type", "text/html; charset=utf-8")]

        class SourceResponse:
            status = 200
            headers = SourceHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b'<html><head><title>Digital Government Outlook 2026</title><meta content="OECD" name="citation_author"></head><body>Digital Government Outlook 2026</body></html>'

            def geturl(self):
                return "https://publisher.example.org/digital-government-outlook-2026"

        with patch("app.citation._robots_decision", return_value={"allowed": True, "status": "allowed", "robots_url": "https://doi.org/robots.txt"}), patch(
            "app.citation.urllib.request.urlopen", return_value=SourceResponse()
        ):
            result = retrieve_source("https://doi.org/10.1787/example-en")

        self.assertTrue(result["authenticity"])
        self.assertEqual(result["final_url"], "https://publisher.example.org/digital-government-outlook-2026")
        self.assertIn("Digital Government Outlook 2026", result["source_metadata_text"])

    def test_pdf_metadata_is_available_for_direct_bibliographic_pdf_urls(self):
        from unittest.mock import patch

        class SourceHeaders:
            def get(self, name, default=None):
                return {"content-type": "application/pdf"}.get(name, default)

            def get_content_charset(self):
                return "utf-8"

            def items(self):
                return [("content-type", "application/pdf")]

        class SourceResponse:
            status = 200
            headers = SourceHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"%PDF-1.7 /Title (Digital Government Outlook 2026) /Author (OECD)"

            def geturl(self):
                return "https://publisher.example.org/digital-government-outlook-2026.pdf"

        with patch("app.citation._robots_decision", return_value={"allowed": True, "status": "allowed", "robots_url": "https://publisher.example.org/robots.txt"}), patch(
            "app.citation.urllib.request.urlopen", return_value=SourceResponse()
        ):
            result = retrieve_source("https://publisher.example.org/digital-government-outlook-2026.pdf")

        self.assertIn("Digital Government Outlook 2026", result["source_metadata_text"])
        self.assertIn("OECD", result["source_metadata_text"])

    def test_robots_fail_closed_blocks_when_robots_are_unavailable(self):
        from unittest.mock import patch

        with patch(
            "app.citation._robots_decision",
            return_value={"allowed": True, "status": "unavailable", "robots_url": "https://example.org/robots.txt"},
        ):
            result = retrieve_source("https://example.org/policy", robots_fail_closed=True)
        self.assertFalse(result["accessible"])
        self.assertFalse(result["robots_allowed"])
        self.assertEqual(result["robots_status"], "unavailable")

    def test_quality_currency_and_citation_count_thresholds_are_applied(self):
        policy = normalise_citation_policy(
            {
                "max_citations": 1,
                "minimum_source_quality": "authoritative",
                "require_currency": True,
            }
        )
        result = verify_response(
            {
                "response": "Supported claim https://example.com/report and another https://example.com/other",
                "citations": [
                    {"url": "https://example.com/report", "claim": "Supported claim", "source_text": "Supported claim"},
                    {"url": "https://example.com/other", "claim": "Other claim", "source_text": "Other claim"},
                ],
            },
            policy=policy,
        )
        self.assertEqual(len(result["citations"]), 1)
        self.assertEqual(result["citation_policy"]["minimum_source_quality"], "authoritative")
        self.assertFalse(result["citations"][0]["source_quality_acceptable"])
        self.assertEqual(result["status"], "warning")

    def test_citation_policy_validation_rejects_invalid_domain_and_limits(self):
        with self.assertRaises(ValueError):
            normalise_citation_policy({"allowed_domains": ["https://example.com"]})
        with self.assertRaises(ValueError):
            normalise_citation_policy({"trusted_domains": ["https://example.org"]})
        with self.assertRaises(ValueError):
            normalise_citation_policy({"max_source_bytes": 1024})
        with self.assertRaises(ValueError):
            normalise_citation_policy({"respect_robots": "yes"})
        with self.assertRaises(ValueError):
            normalise_citation_policy({"claim_type_policies": {"legal": {"require_currency": "yes"}}})
        with self.assertRaises(ValueError):
            normalise_citation_policy({"claim_type_policies": {"legal": {"unsupported": True}}})

    # --- Policy validation edge cases ---

    def test_string_list_coerces_string_and_rejects_non_list(self):
        policy = normalise_citation_policy({"allowed_domains": "example.com"})
        self.assertEqual(policy["allowed_domains"], ["example.com"])
        with self.assertRaises(ValueError):
            normalise_citation_policy({"allowed_domains": 123})

    def test_string_list_rejects_over_100_and_duplicates(self):
        with self.assertRaises(ValueError):
            normalise_citation_policy({"allowed_domains": [f"host{i}.com" for i in range(101)]})
        with self.assertRaises(ValueError):
            normalise_citation_policy({"blocked_domains": ["example.com", "example.com"]})

    def test_max_age_days_rejects_non_integer_and_out_of_range(self):
        with self.assertRaises(ValueError):
            normalise_citation_policy({"max_age_days": "not-a-number"})
        with self.assertRaises(ValueError):
            normalise_citation_policy({"max_age_days": 0})
        with self.assertRaises(ValueError):
            normalise_citation_policy({"max_age_days": 9999})

    def test_claim_type_policies_non_dict_and_too_many(self):
        with self.assertRaises(ValueError):
            normalise_citation_policy({"claim_type_policies": "not-a-dict"})
        with self.assertRaises(ValueError):
            normalise_citation_policy(
                {"claim_type_policies": {f"type{i}": {} for i in range(51)}}
            )

    def test_claim_type_policies_invalid_key_and_non_dict_override(self):
        with self.assertRaises(ValueError):
            normalise_citation_policy({"claim_type_policies": {"": {}}})
        with self.assertRaises(ValueError):
            normalise_citation_policy({"claim_type_policies": {"legal": "not-a-dict"}})

    def test_claim_type_policies_invalid_minimum_source_quality(self):
        with self.assertRaises(ValueError):
            normalise_citation_policy(
                {"claim_type_policies": {"legal": {"minimum_source_quality": "invalid-tier"}}}
            )

    def test_normalise_policy_rejects_non_dict(self):
        with self.assertRaises(ValueError):
            normalise_citation_policy("not-a-dict")

    def test_normalise_policy_rejects_non_integer_numerics(self):
        with self.assertRaises(ValueError):
            normalise_citation_policy({"max_citations": "abc"})

    def test_normalise_policy_rejects_out_of_range_max_citations(self):
        with self.assertRaises(ValueError):
            normalise_citation_policy({"max_citations": 0})
        with self.assertRaises(ValueError):
            normalise_citation_policy({"max_citations": 101})

    def test_normalise_policy_rejects_invalid_minimum_source_quality(self):
        with self.assertRaises(ValueError):
            normalise_citation_policy({"minimum_source_quality": "invalid-tier"})

    # --- Entailment edge cases ---

    def test_entailment_empty_claim_returns_none(self):
        from app.citation import _entailment

        supports, score, reason = _entailment("", "some source text")
        self.assertIsNone(supports)
        self.assertEqual(score, 0.5)

    def test_entailment_empty_source_returns_false(self):
        from app.citation import _entailment

        supports, score, reason = _entailment("a claim", "")
        self.assertFalse(supports)
        self.assertEqual(score, 0.0)

    def test_entailment_no_content_words_returns_none(self):
        from app.citation import _entailment

        supports, score, reason = _entailment("the a an is", "some source text here")
        self.assertIsNone(supports)
        self.assertEqual(score, 0.5)

    def test_entailment_high_partial_overlap_supports_claim(self):
        from app.citation import _entailment

        supports, score, reason = _entailment(
            "government digital policy framework",
            "The government published a digital policy framework for agencies.",
        )
        self.assertTrue(supports)
        self.assertGreaterEqual(score, 0.55)
        self.assertIn("Most claim terms", reason)

    def test_entailment_medium_overlap_does_not_support(self):
        from app.citation import _entailment

        # 5 claim tokens, 3 overlap → ratio 0.6 (between 0.45 and 0.75)
        supports, score, reason = _entailment(
            "government digital policy framework standards",
            "The government published a digital report about policy.",
        )
        self.assertFalse(supports)
        self.assertIn("related terms", reason)

    def test_entailment_low_overlap_does_not_support(self):
        from app.citation import _entailment

        supports, score, reason = _entailment(
            "quantum computing encryption protocols advanced",
            "The report discusses basic network security.",
        )
        self.assertFalse(supports)
        self.assertIn("not contain enough", reason)

    def test_numeric_sequence_found_in_source_context(self):
        from app.citation import _entailment

        supports, score, reason = _entailment(
            "GDP growth reached 3 percent in 2025",
            "National GDP growth reached 3 percent in 2025 according to official data.",
        )
        self.assertTrue(supports)

    # --- Source quality ---

    def test_source_quality_educational_hosts(self):
        from app.citation import _source_quality

        quality, score = _source_quality("https://example.edu/research")
        self.assertEqual(quality, "primary")
        self.assertEqual(score, 0.9)
        quality, score = _source_quality("https://example.ac.nz/research")
        self.assertEqual(quality, "primary")

    def test_source_quality_path_markers_make_primary(self):
        from app.citation import _source_quality

        quality, score = _source_quality("https://example.com/report/annual")
        self.assertEqual(quality, "primary")
        self.assertEqual(score, 0.8)

    def test_source_quality_secondary_hosts(self):
        from app.citation import _source_quality

        quality, _ = _source_quality("https://medium.com/some-post")
        self.assertEqual(quality, "secondary")

    def test_source_quality_no_host_is_low_quality(self):
        from app.citation import _source_quality

        quality, score = _source_quality("not-a-url")
        self.assertEqual(quality, "low-quality")
        self.assertEqual(score, 0.1)

    # --- Reference metadata verification ---

    def test_reference_metadata_no_comparable_fields(self):
        from app.citation import _verify_reference_metadata

        verified, score, checks, reason = _verify_reference_metadata(
            {"authors": "AB"}, "some source text"
        )
        self.assertFalse(verified)
        self.assertEqual(score, 0)
        self.assertIn("No comparable bibliography metadata", reason)

    def test_reference_metadata_partial_match_reports_failed_fields(self):
        from app.citation import _verify_reference_metadata

        verified, score, checks, reason = _verify_reference_metadata(
            {"title": "Quantum Physics Advances", "year": "2026"},
            "Quantum Physics Advances published in 2024.",
        )
        self.assertFalse(verified)
        self.assertIn("year", reason)

    # --- Redirect authenticity ---

    def test_redirect_authenticity_missing_hosts(self):
        from app.citation import _redirect_authenticity

        self.assertFalse(_redirect_authenticity("", "https://example.com"))
        self.assertFalse(_redirect_authenticity("https://example.com", ""))

    def test_redirect_authenticity_www_prefix_match(self):
        from app.citation import _redirect_authenticity

        self.assertTrue(
            _redirect_authenticity("https://www.example.com/page", "https://example.com/page")
        )

    def test_redirect_authenticity_unrelated_hosts(self):
        from app.citation import _redirect_authenticity

        self.assertFalse(
            _redirect_authenticity("https://example.com/page", "https://other.org/page")
        )

    # --- HTML/PDF metadata extraction ---

    def test_html_metadata_skips_unrecognised_meta_names(self):
        from app.citation import _html_metadata_text

        html_source = (
            '<html><head><title>Test</title>'
            '<meta name="unrecognised" content="skip this">'
            '<meta name="og:title" content="OG Title">'
            '<meta name="citation_author" content="Author Name">'
            "</head><body></body></html>"
        )
        result = _html_metadata_text(html_source)
        self.assertIn("Test", result)
        self.assertIn("OG Title", result)
        self.assertIn("Author Name", result)
        self.assertNotIn("skip this", result)

    def test_pdf_metadata_xmp_dc_fields(self):
        from app.citation import _pdf_metadata_text

        pdf_bytes = (
            b"%PDF-1.7 /Title (Report Title) /Subject (Subject Here) "
            b"<dc:title><rdf:li>XMP Title</rdf:li></dc:title> "
            b"<dc:creator><rdf:li>XMP Creator</rdf:li></dc:creator> "
            b"<dc:description><rdf:li>XMP Description</rdf:li></dc:description>"
        )
        result = _pdf_metadata_text(pdf_bytes)
        self.assertIn("Report Title", result)
        self.assertIn("Subject Here", result)
        self.assertIn("XMP Title", result)
        self.assertIn("XMP Creator", result)
        self.assertIn("XMP Description", result)

    # --- Currency ---

    def test_currency_unparseable_date_returns_unknown(self):
        status, score, value = _currency({}, "not-a-date-at-all")
        self.assertEqual(status, "unknown")
        self.assertEqual(score, 0.5)
        self.assertEqual(value, "not-a-date-at-all")

    def test_currency_stale_date(self):
        status, score, value = _currency({}, "2020-01-01T00:00:00Z", max_age_days=365)
        self.assertEqual(status, "stale")
        self.assertEqual(score, 0.25)

    def test_currency_max_age_none_always_recent(self):
        status, score, value = _currency({}, "2020-01-01T00:00:00Z", max_age_days=None)
        self.assertEqual(status, "recent")
        self.assertEqual(score, 1.0)

    # --- Robots decision ---

    def test_robots_too_large_is_blocked(self):
        class LargeRobotsResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"x" * 262_145

        decision = _robots_decision(
            "https://example.org/policy",
            opener=lambda _request, timeout: LargeRobotsResponse(),
        )
        self.assertFalse(decision["allowed"])
        self.assertEqual(decision["status"], "too_large")

    def test_robots_not_found_allows_fetch(self):
        import urllib.error

        def opener(_request, timeout):
            raise urllib.error.HTTPError(
                "https://example.org/robots.txt", 404, "Not Found", {}, None
            )

        decision = _robots_decision("https://example.org/policy", opener=opener)
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["status"], "not_found")

    def test_robots_transport_error_returns_unavailable(self):
        import urllib.error

        def opener(_request, timeout):
            raise urllib.error.URLError("connection refused")

        decision = _robots_decision("https://example.org/policy", opener=opener)
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["status"], "unavailable")

    # --- Transport error helper ---

    def test_transport_error_uses_reason_attribute(self):
        from app.citation import _transport_error
        import urllib.error

        error = urllib.error.URLError("dns resolution failed")
        self.assertEqual(_transport_error(error), "dns resolution failed")

    # --- Remote retriever paths ---

    def test_remote_retriever_exception_falls_through_to_direct(self):
        from unittest.mock import patch

        citation_module.set_source_remote_retriever(
            lambda _url, _max_bytes, _timeout, _ua: (_ for _ in ()).throw(ConnectionError("remote down"))
        )

        class SourceHeaders:
            def get(self, name, default=None):
                return {"content-type": "text/plain"}.get(name, default)

            def get_content_charset(self):
                return "utf-8"

            def items(self):
                return [("content-type", "text/plain")]

        class SourceResponse:
            status = 200
            headers = SourceHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"Direct fetch content."

            def geturl(self):
                return "https://example.org/policy"

        try:
            with patch(
                "app.citation._robots_decision",
                return_value={"allowed": True, "status": "disabled", "robots_url": None},
            ), patch("app.citation.urllib.request.urlopen", return_value=SourceResponse()):
                result = retrieve_source("https://example.org/policy")
        finally:
            citation_module.set_source_remote_retriever(None)
        self.assertTrue(result["accessible"])
        self.assertEqual(result["retrieval_strategy"], "browser_fallback")

    def test_remote_retriever_http_error_non_transient_returns_immediately(self):
        citation_module.set_source_remote_retriever(
            lambda _url, _max_bytes, _timeout, _ua: {
                "retrieval_status": "http_error",
                "status_code": 404,
                "final_url": "https://example.org/missing",
                "error": "Source returned HTTP 404.",
            }
        )
        try:
            result = retrieve_source("https://example.org/missing", respect_robots=False)
        finally:
            citation_module.set_source_remote_retriever(None)
        self.assertFalse(result["accessible"])
        self.assertEqual(result["status_code"], 404)
        self.assertEqual(result["retrieval_status"], "http_error")

    def test_remote_retriever_http_error_transient_falls_through(self):
        from unittest.mock import patch

        citation_module.set_source_remote_retriever(
            lambda _url, _max_bytes, _timeout, _ua: {
                "retrieval_status": "http_error",
                "status_code": 503,
                "final_url": "https://example.org/policy",
                "error": "Source returned HTTP 503.",
            }
        )

        class SourceHeaders:
            def get(self, name, default=None):
                return {"content-type": "text/plain"}.get(name, default)

            def get_content_charset(self):
                return "utf-8"

            def items(self):
                return [("content-type", "text/plain")]

        class SourceResponse:
            status = 200
            headers = SourceHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"Direct fallback content."

            def geturl(self):
                return "https://example.org/policy"

        try:
            with patch(
                "app.citation._robots_decision",
                return_value={"allowed": True, "status": "disabled", "robots_url": None},
            ), patch("app.citation.urllib.request.urlopen", return_value=SourceResponse()):
                result = retrieve_source("https://example.org/policy")
        finally:
            citation_module.set_source_remote_retriever(None)
        self.assertTrue(result["accessible"])

    # --- Retrieve source edge cases ---

    def test_retrieve_source_non_transient_exception_returns_immediately(self):
        from unittest.mock import patch

        with patch(
            "app.citation._robots_decision",
            return_value={"allowed": True, "status": "disabled", "robots_url": None},
        ), patch(
            "app.citation.urllib.request.urlopen",
            side_effect=ValueError("invalid URL structure"),
        ):
            result = retrieve_source("https://example.org/policy")
        self.assertFalse(result["accessible"])
        self.assertEqual(result["retrieval_status"], "transport_error")
        self.assertEqual(result["retrieval_attempts"], 1)
        self.assertIn("invalid URL structure", result["error"])

    def test_retrieve_source_http_error_exception_non_transient(self):
        import urllib.error
        from unittest.mock import patch

        def opener(request, timeout):
            raise urllib.error.HTTPError(
                "https://example.org/policy", 404, "Not Found", {}, None
            )

        with patch(
            "app.citation._robots_decision",
            return_value={"allowed": True, "status": "disabled", "robots_url": None},
        ), patch("app.citation.urllib.request.urlopen", side_effect=opener):
            result = retrieve_source("https://example.org/policy")
        self.assertFalse(result["accessible"])
        self.assertEqual(result["status_code"], 404)
        self.assertEqual(result["retrieval_status"], "http_error")

    def test_retrieve_source_transient_http_error_retries_then_reports(self):
        import urllib.error
        from unittest.mock import patch

        call_count = [0]

        def opener(request, timeout):
            call_count[0] += 1
            raise urllib.error.HTTPError(
                "https://example.org/policy", 503, "Service Unavailable", {}, None
            )

        with patch(
            "app.citation._robots_decision",
            return_value={"allowed": True, "status": "disabled", "robots_url": None},
        ), patch("app.citation.urllib.request.urlopen", side_effect=opener), patch(
            "app.citation.time.sleep"
        ):
            result = retrieve_source("https://example.org/policy")
        self.assertFalse(result["accessible"])
        self.assertEqual(result["status_code"], 503)
        self.assertEqual(result["retrieval_attempts"], 3)
        self.assertEqual(call_count[0], 3)

    def test_retrieve_source_invalid_scheme(self):
        result = retrieve_source("ftp://example.org/file")
        self.assertFalse(result["exists"])
        self.assertFalse(result["accessible"])
        self.assertIn("Only HTTP and HTTPS", result["error"])

    # --- Reference sources validation ---

    def test_normalise_reference_sources_rejects_non_list(self):
        from app.citation import _normalise_reference_sources

        with self.assertRaises(ValueError):
            _normalise_reference_sources("not-a-list")

    def test_normalise_reference_sources_rejects_too_many(self):
        from app.citation import _normalise_reference_sources

        with self.assertRaises(ValueError):
            _normalise_reference_sources(
                [{"type": "document", "reference": f"doc{i}.pdf"} for i in range(101)]
            )

    def test_normalise_reference_sources_rejects_non_dict_item(self):
        from app.citation import _normalise_reference_sources

        with self.assertRaises(ValueError):
            _normalise_reference_sources(["not-a-dict"])

    def test_normalise_reference_sources_rejects_invalid_type(self):
        from app.citation import _normalise_reference_sources

        with self.assertRaises(ValueError):
            _normalise_reference_sources([{"type": "invalid", "reference": "doc.pdf"}])

    def test_normalise_reference_sources_rejects_missing_reference(self):
        from app.citation import _normalise_reference_sources

        with self.assertRaises(ValueError):
            _normalise_reference_sources([{"type": "document"}])

    def test_normalise_reference_sources_rejects_duplicates(self):
        from app.citation import _normalise_reference_sources

        with self.assertRaises(ValueError):
            _normalise_reference_sources(
                [
                    {"type": "document", "reference": "doc.pdf"},
                    {"type": "document", "reference": "doc.pdf"},
                ]
            )

    # --- Verify reference ---

    def test_verify_reference_with_source_url_delegates_to_verify_citation(self):
        from app.citation import _verify_reference

        policy = normalise_citation_policy()
        source = {
            "type": "document",
            "reference": "report.pdf",
            "source_url": "https://example.govt.nz/report",
            "claim": "The report confirms the finding.",
            "source_text": "The report confirms the finding.",
            "source_hash": "",
        }
        finding = _verify_reference("document", "report.pdf", source, policy)
        self.assertTrue(finding["resolved"])
        self.assertTrue(finding["exists"])
        self.assertTrue(finding["accessible"])
        self.assertIn("citation", finding)

    def test_verify_reference_metadata_only_without_hash(self):
        from app.citation import _verify_reference

        policy = normalise_citation_policy()
        source = {
            "type": "document",
            "reference": "report.pdf",
            "source_url": "",
            "claim": "",
            "source_text": None,
            "source_hash": "",
        }
        finding = _verify_reference("document", "report.pdf", source, policy)
        self.assertTrue(finding["exists"])
        self.assertFalse(finding["verified"])
        self.assertIn("source_url or source_text plus source_hash", finding["reason"])

    def test_verify_reference_inline_hash_mismatch(self):
        import hashlib
        from app.citation import _verify_reference

        policy = normalise_citation_policy()
        source = {
            "type": "document",
            "reference": "report.pdf",
            "source_url": "",
            "claim": "report.pdf",
            "source_text": "The report content.",
            "source_hash": "0" * 64,
        }
        finding = _verify_reference("document", "report.pdf", source, policy)
        self.assertFalse(finding["verified"])
        self.assertFalse(finding["authenticity"])

    # --- Verify citation edge cases ---

    def test_verify_citation_empty_url(self):
        result = verify_citation({"url": "", "claim": "A claim"})
        self.assertEqual(result["source_quality"], "low-quality")
        self.assertIn("No source URL", result["reason"])

    def test_verify_citation_no_url_key(self):
        result = verify_citation({"claim": "A claim"})
        self.assertEqual(result["source_quality"], "low-quality")
        self.assertIn("No source URL", result["reason"])

    def test_verify_citation_robots_blocked_source(self):
        result = verify_citation(
            {"url": "https://example.org/private", "claim": "A claim"},
            retriever=lambda _url: {
                "exists": False,
                "accessible": False,
                "authenticity": True,
                "robots_allowed": False,
                "robots_status": "blocked",
                "robots_url": "https://example.org/robots.txt",
                "error": "Source retrieval is disallowed by robots.txt.",
            },
        )
        self.assertTrue(result["retrieval_blocked"])
        self.assertIsNone(result["supports_claim"])
        self.assertEqual(result["confidence"], 0.0)

    def test_verify_citation_invalid_hash_format(self):
        result = verify_citation(
            {
                "url": "https://example.org/report",
                "claim": "A claim",
                "source_text": "A claim supported.",
                "source_hash": "not-a-valid-sha256",
            }
        )
        self.assertFalse(result["source_hash_verified"])
        self.assertFalse(result["authenticity"])
        self.assertIn("not a SHA-256 digest", result["reason"])

    def test_verify_citation_blocked_domain_policy(self):
        policy = normalise_citation_policy({"blocked_domains": ["blocked.com"]})
        result = verify_citation(
            {"url": "https://blocked.com/page", "claim": "A claim"},
            policy=policy,
        )
        self.assertTrue(result["retrieval_blocked"])
        self.assertIn("blocked", result["reason"])

    def test_verify_citation_source_only_inaccessible(self):
        result = verify_citation(
            {
                "url": "https://example.org/report",
                "claim": "",
                "claim_support_required": False,
            },
            retriever=lambda _url: {
                "exists": False,
                "accessible": False,
                "authenticity": False,
                "error": "Source returned HTTP 404.",
            },
        )
        self.assertIsNone(result["supports_claim"])
        self.assertEqual(result["confidence"], 0.0)

    # --- Overall status and verify_response ---

    def test_overall_status_no_citations_returns_warning(self):
        from app.citation import _overall_status

        self.assertEqual(_overall_status(0, [], []), "warning")

    def test_verify_response_string_citation_items(self):
        result = verify_response(
            {
                "response": "",
                "citations": ["https://example.govt.nz/policy"],
            }
        )
        self.assertEqual(len(result["citations"]), 1)
        self.assertEqual(result["citations"][0]["url"], "https://example.govt.nz/policy")

    def test_verify_response_source_only_no_reference_metadata_score(self):
        result = verify_response(
            {
                "response": "",
                "citations": [
                    {
                        "url": "https://example.org/report",
                        "claim": "",
                        "claim_support_required": False,
                        "source_text": "Example report content.",
                    }
                ],
            }
        )
        self.assertEqual(result["trust_score"], 100)
        self.assertEqual(result["status"], "pass")

    def test_verify_response_uses_answer_and_text_keys(self):
        result = verify_response({"answer": "See https://example.govt.nz/policy"})
        self.assertEqual(len(result["citations"]), 1)
        result2 = verify_response({"text": "See https://example.govt.nz/policy"})
        self.assertEqual(len(result2["citations"]), 1)

    def test_verify_response_extracted_urls_become_citations(self):
        result = verify_response(
            {"response": "See https://example.govt.nz/policy for details."}
        )
        self.assertEqual(len(result["citations"]), 1)
        self.assertEqual(result["citations"][0]["url"], "https://example.govt.nz/policy")

    # --- Bounded float and retry helpers ---

    def test_bounded_float_handles_invalid_values(self):
        from app.citation import _bounded_float

        self.assertEqual(_bounded_float("not-a-number", 5.0, 1.0, 10.0), 5.0)
        self.assertEqual(_bounded_float(None, 5.0, 1.0, 10.0), 5.0)
        self.assertEqual(_bounded_float(100.0, 5.0, 1.0, 10.0), 10.0)
        self.assertEqual(_bounded_float(-5.0, 5.0, 1.0, 10.0), 1.0)

    def test_source_retry_attempts_env_override(self):
        from unittest.mock import patch
        from app.citation import _source_retry_attempts

        with patch.dict("os.environ", {"CITATION_FETCH_RETRY_ATTEMPTS": "2"}):
            self.assertEqual(_source_retry_attempts(), 2)
        with patch.dict("os.environ", {"CITATION_FETCH_RETRY_ATTEMPTS": "invalid"}):
            self.assertEqual(_source_retry_attempts(), 3)
        with patch.dict("os.environ", {"CITATION_FETCH_RETRY_ATTEMPTS": "99"}):
            self.assertEqual(_source_retry_attempts(), 4)

    def test_source_fetch_budget_env_override(self):
        from unittest.mock import patch
        from app.citation import _source_fetch_budget

        with patch.dict("os.environ", {"CITATION_FETCH_BUDGET_SECONDS": "5.0"}):
            budget = _source_fetch_budget(8)
            self.assertLessEqual(budget, 5.0)

    # --- Source user agents and request headers ---

    def test_source_user_agents_includes_product_and_browser(self):
        from app.citation import _source_user_agents

        agents = _source_user_agents()
        self.assertIn("Kenning-Citation-Trust/0.1", agents)
        self.assertTrue(any("Mozilla" in ua for ua in agents))

    def test_source_request_headers_structure(self):
        from app.citation import _source_request_headers

        headers = _source_request_headers("TestAgent/1.0")
        self.assertEqual(headers["User-Agent"], "TestAgent/1.0")
        self.assertIn("Accept", headers)
        self.assertEqual(headers["Sec-Fetch-Mode"], "navigate")

    # --- Remaining coverage gaps ---

    def test_numeric_sequence_found_without_exact_phrase_match(self):
        from app.citation import _entailment

        # Claim is NOT a substring of source, but numbers appear in sequence
        supports, score, reason = _entailment(
            "inflation rate 4 unemployment 7",
            "The inflation rate reached 4 percent while unemployment hit 7 percent nationally.",
        )
        # Numbers [4, 7] appear in sequence in one segment
        self.assertIsNotNone(supports)

    def test_currency_naive_datetime_gets_utc(self):
        # ISO date without timezone info → parsed.replace(tzinfo=utc)
        status, score, value = _currency({}, "2026-07-01T12:00:00")
        self.assertEqual(status, "recent")
        self.assertEqual(score, 1.0)

    def test_robots_generic_http_error_returns_unavailable(self):
        import urllib.error

        def opener(_request, timeout):
            raise urllib.error.HTTPError(
                "https://example.org/robots.txt", 500, "Internal Server Error", {}, None
            )

        decision = _robots_decision("https://example.org/policy", opener=opener)
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["status"], "unavailable")
        self.assertIn("HTTP 500", decision["error"])

    def test_retrieve_source_non_2xx_response_without_exception(self):
        from unittest.mock import patch

        class SourceHeaders:
            def get(self, name, default=None):
                return {"content-type": "text/plain"}.get(name, default)

            def get_content_charset(self):
                return "utf-8"

            def items(self):
                return [("content-type", "text/plain")]

        class SourceResponse:
            status = 404
            headers = SourceHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"not found"

            def geturl(self):
                return "https://example.org/missing"

        with patch(
            "app.citation._robots_decision",
            return_value={"allowed": True, "status": "disabled", "robots_url": None},
        ), patch("app.citation.urllib.request.urlopen", return_value=SourceResponse()):
            result = retrieve_source("https://example.org/missing")
        self.assertFalse(result["accessible"])
        self.assertEqual(result["status_code"], 404)
        self.assertEqual(result["retrieval_status"], "http_error")

    def test_retrieve_source_transient_status_response_retries(self):
        from unittest.mock import patch

        class SourceHeaders:
            def get(self, name, default=None):
                return {"content-type": "text/plain"}.get(name, default)

            def get_content_charset(self):
                return "utf-8"

            def items(self):
                return [("content-type", "text/plain")]

        class TransientResponse:
            status = 503
            headers = SourceHeaders()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return b"service unavailable"

            def geturl(self):
                return "https://example.org/policy"

        with patch(
            "app.citation._robots_decision",
            return_value={"allowed": True, "status": "disabled", "robots_url": None},
        ), patch(
            "app.citation.urllib.request.urlopen", return_value=TransientResponse()
        ), patch("app.citation.time.sleep"):
            result = retrieve_source("https://example.org/policy")
        self.assertFalse(result["accessible"])
        self.assertEqual(result["status_code"], 503)
        self.assertEqual(result["retrieval_attempts"], 3)

    def test_retrieve_source_budget_exhausted_before_loop(self):
        from unittest.mock import patch

        call_count = [0]

        def fake_monotonic():
            call_count[0] += 1
            # Call 1 sets deadline (= 0 + budget); call 2+ exceeds it
            if call_count[0] == 1:
                return 0.0
            return 9999.0

        with patch(
            "app.citation._robots_decision",
            return_value={"allowed": True, "status": "disabled", "robots_url": None},
        ), patch("app.citation.time.monotonic", side_effect=fake_monotonic), patch(
            "app.citation.time.sleep"
        ):
            result = retrieve_source("https://example.org/policy", timeout=1)
        self.assertFalse(result["accessible"])
        self.assertEqual(result["retrieval_status"], "transport_error")

    def test_verify_reference_source_url_failed_verification(self):
        from app.citation import _verify_reference

        source = {
            "type": "document",
            "reference": "report.pdf",
            "source_url": "https://blocked.com/report",
            "claim": "A claim",
            "source_text": None,
            "source_hash": "",
        }
        finding = _verify_reference(
            "document", "report.pdf", source,
            normalise_citation_policy({"blocked_domains": ["blocked.com"]}),
        )
        self.assertFalse(finding["verified"])
        self.assertIn("reason", finding)

    def test_verify_reference_sha256_prefixed_hash(self):
        import hashlib
        from app.citation import _verify_reference

        policy = normalise_citation_policy()
        source_text = "The report content is verified."
        actual_hash = hashlib.sha256(source_text.encode("utf-8")).hexdigest()
        source = {
            "type": "document",
            "reference": "report.pdf",
            "source_url": "",
            "claim": "The report content is verified.",
            "source_text": source_text,
            "source_hash": f"sha256:{actual_hash}",
        }
        finding = _verify_reference("document", "report.pdf", source, policy)
        self.assertTrue(finding["verified"])
        self.assertTrue(finding["source_hash_verified"])


if __name__ == "__main__":
    unittest.main()

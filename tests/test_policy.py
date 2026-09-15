#!/usr/bin/env python3
"""Tests for the license matrix, risk profiles, tiering and exceptions.

Run with:  python3 -m unittest discover -s tests -v
"""

import json
import os
import sys
import tempfile
import unittest
from datetime import date

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts"))

import license_check  # noqa: E402
from licensecheck import github, report, spdx  # noqa: E402
from licensecheck.policy import Policy  # noqa: E402

POLICY_DIR = os.path.join(REPO_ROOT, "policy")
FIXTURE = os.path.join(REPO_ROOT, "tests", "fixtures", "sample-report.json")


class NormalizationTests(unittest.TestCase):
    def test_separators_collapse(self):
        self.assertEqual(spdx.normalize("Apache-2.0"), "APACHE 2.0")
        self.assertEqual(spdx.normalize("BSD_3_Clause"), "BSD 3 CLAUSE")
        self.assertEqual(spdx.normalize("  GPL-2.0-only "), "GPL 2.0 ONLY")

    def test_version_punctuation_survives(self):
        self.assertEqual(spdx.normalize("GPL-2.0+"), "GPL 2.0+")
        self.assertNotEqual(spdx.normalize("GPL-2.0"), spdx.normalize("GPL-3.0"))

    def test_unknown_placeholders(self):
        for value in ("NOASSERTION", "NONE", "", None, "  "):
            self.assertTrue(spdx.is_unknown(value), value)
        self.assertFalse(spdx.is_unknown("MIT"))

    def test_version_range_suffixes_fold_away(self):
        for variant in ("GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-2.0+"):
            self.assertEqual(spdx.canonical(variant), "GPL 2.0", variant)

    def test_suffix_folding_reaches_inside_a_with_expression(self):
        self.assertEqual(
            spdx.canonical("GPL-2.0-only WITH Classpath-exception-2.0"),
            "GPL 2.0 WITH CLASSPATH EXCEPTION 2.0",
        )

    def test_folding_does_not_eat_a_license_named_or(self):
        # "CDDL or GPLv2 with exceptions" is a matrix entry; only the exact
        # " OR LATER" / " ONLY" markers may be stripped.
        self.assertEqual(
            spdx.canonical("CDDL or GPLv2 with exceptions"),
            "CDDL OR GPLV2 WITH EXCEPTIONS",
        )

    def test_opaque_versus_merely_unlisted(self):
        self.assertTrue(spdx.is_opaque("NOASSERTION"))
        self.assertTrue(spdx.is_opaque("LicenseRef-Vendor-Proprietary"))
        self.assertFalse(spdx.is_opaque("CDDL-1.1"))


class ExpressionTests(unittest.TestCase):
    def test_or_and_parsing(self):
        tree = spdx.split_expression("MIT OR Apache-2.0")
        self.assertEqual(tree[0], "OR")
        self.assertEqual(spdx.leaves(tree), ["MIT", "Apache-2.0"])

    def test_with_binds_into_the_leaf(self):
        tree = spdx.split_expression("GPL-2.0-only WITH Classpath-exception-2.0")
        self.assertEqual(tree, ("LEAF", "GPL-2.0-only WITH Classpath-exception-2.0"))

    def test_parentheses(self):
        tree = spdx.split_expression("(MIT OR Apache-2.0) AND BSD-3-Clause")
        self.assertEqual(tree[0], "AND")
        self.assertEqual(spdx.leaves(tree), ["MIT", "Apache-2.0", "BSD-3-Clause"])


class ResolverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = Policy(POLICY_DIR)
        cls.resolve = cls.policy.resolver.resolve_one

    def test_spdx_ids_map_to_oso_names(self):
        cases = {
            "Apache-2.0": "Apache 2.0",
            "BSD-3-Clause": "BSD 3",
            "0BSD": "BSD Zero",
            "MIT": "MIT",
            "AGPL-3.0-or-later": "AGPL 3.0",
            "GPL-2.0-only": "GPL 2.0",
            "LGPL-2.1-or-later": "LGPL 2.1",
            "MPL-2.0": "Mozilla 2.0",
            "EPL-2.0": "Eclipse 2.0",
            "EUPL-1.2": "European 1.2",
            "OSL-3.0": "Open Software 3.0",
            "OFL-1.1": "SIL Open Font 1.1",
            "BSL-1.0": "Boost",
            "GPL-2.0-only WITH Classpath-exception-2.0": "GPL 2.0 Classpath",
        }
        for spdx_id, expected in cases.items():
            self.assertEqual(self.resolve(spdx_id)[0], expected, spdx_id)

    def test_suspected_prefix_is_preserved(self):
        name, suspected = self.resolve("Suspected GPL 3.0")
        self.assertEqual(name, "Suspected GPL 3.0")
        self.assertTrue(suspected)

    def test_pattern_fallback_for_unlisted_variants(self):
        # Not in the alias table; the ^GPL family pattern should catch it.
        self.assertEqual(self.resolve("GPL-2.1-weird-variant")[0], "GPL")

    def test_license_ref_is_unknown(self):
        self.assertEqual(self.resolve("LicenseRef-Vendor-Proprietary")[0], spdx.UNKNOWN)


class ClassificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = Policy(POLICY_DIR)

    def tier(self, license_id, profile):
        return self.policy.classify_expression(license_id, profile)["tier"]

    def test_approved_licenses_are_green_everywhere(self):
        for profile in ("distributed", "server-side", "mobile", "internal"):
            for license_id in ("MIT", "Apache-2.0", "BSD-3-Clause", "ISC"):
                self.assertEqual(self.tier(license_id, profile), "green",
                                 "%s / %s" % (license_id, profile))

    def test_agpl_is_red_in_every_profile(self):
        for profile in ("distributed", "server-side", "mobile", "internal"):
            self.assertEqual(self.tier("AGPL-3.0-only", profile), "red", profile)

    def test_gpl_blocks_distribution_but_not_server_side(self):
        self.assertEqual(self.tier("GPL-2.0-only", "distributed"), "red")
        self.assertEqual(self.tier("GPL-2.0-only", "mobile"), "red")
        # Permitted server-side, but flagged so OSO knows it cannot ever ship.
        self.assertEqual(self.tier("GPL-2.0-only", "server-side"), "yellow")
        self.assertEqual(self.tier("GPL-2.0-only", "internal"), "yellow")

    def test_or_expression_picks_the_permissive_branch(self):
        self.assertEqual(self.tier("LGPL-2.1-or-later OR Apache-2.0", "distributed"), "green")

    def test_and_expression_picks_the_strict_branch(self):
        self.assertEqual(self.tier("MIT AND GPL-3.0-only", "distributed"), "red")

    def test_unknown_license_needs_review(self):
        result = self.policy.classify_expression("NOASSERTION", "server-side")
        self.assertEqual(result["tier"], "yellow")
        self.assertEqual(result["status"], "unknown")

    def test_unlisted_license_needs_review(self):
        result = self.policy.classify_expression("CDDL-1.1", "distributed")
        self.assertEqual(result["tier"], "yellow")
        self.assertEqual(result["status"], "review")
        # The raw identifier is kept so the reviewer can see what it was.
        self.assertEqual(result["licenses"], ["CDDL-1.1"])

    def test_gpl_version_variants_classify_identically(self):
        for variant in ("GPL-2.0", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-2.0+"):
            self.assertEqual(self.tier(variant, "distributed"), "red", variant)

    def test_classpath_exception_resolves_to_its_own_matrix_entry(self):
        result = self.policy.classify_expression(
            "GPL-2.0-only WITH Classpath-exception-2.0", "distributed"
        )
        self.assertEqual(result["licenses"], ["GPL 2.0 Classpath"])
        self.assertEqual(result["tier"], "red")

    def test_status_for_banned_versus_rejected(self):
        self.assertEqual(
            self.policy.classify_expression("AGPL-3.0-only", "distributed")["status"], "banned"
        )
        self.assertEqual(
            self.policy.classify_expression("GPL-3.0-only", "distributed")["status"], "rejected"
        )


class ProfileResolutionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = Policy(POLICY_DIR)

    def test_exact_match_wins(self):
        self.assertEqual(self.policy.profile_for("my-org/android-app"), "mobile")

    def test_wildcard_match(self):
        self.assertEqual(self.policy.profile_for("my-org/sdk-java"), "distributed")

    def test_unlisted_repo_gets_the_default(self):
        self.assertEqual(self.policy.profile_for("my-org/brand-new"), "server-side")

    def test_unknown_profile_is_rejected_loudly(self):
        with self.assertRaises(ValueError):
            self.policy.profile_config("not-a-profile")


class ExceptionTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        for name in ("license-matrix.json", "policy.json", "repo-profiles.json"):
            with open(os.path.join(POLICY_DIR, name), "r", encoding="utf-8") as src:
                with open(os.path.join(self.dir, name), "w", encoding="utf-8") as dst:
                    dst.write(src.read())

    def write_exceptions(self, approvals):
        with open(os.path.join(self.dir, "exceptions.json"), "w", encoding="utf-8") as handle:
            json.dump({"approvals": approvals}, handle)
        return Policy(self.dir)

    def test_approval_silences_a_finding(self):
        policy = self.write_exceptions([
            {"repo": "my-org/app", "license": "GPL 2.0", "tier": "green",
             "approved_by": "oso", "ticket": "OSO-1", "expires": "2099-01-01"}
        ])
        self.assertIsNotNone(policy.find_approval("my-org/app", ["GPL 2.0"], "anything"))

    def test_expired_approval_is_ignored_and_recorded(self):
        policy = self.write_exceptions([
            {"repo": "my-org/app", "license": "GPL 2.0", "tier": "green",
             "approved_by": "oso", "ticket": "OSO-1", "expires": "2020-01-01"}
        ])
        self.assertIsNone(policy.find_approval("my-org/app", ["GPL 2.0"], "pkg"))
        self.assertEqual(len(policy.expired_approvals), 1)

    def test_approval_is_scoped_to_its_repo_and_package(self):
        policy = self.write_exceptions([
            {"repo": "my-org/app", "license": "GPL 2.0", "package": "legacy-*",
             "tier": "green", "approved_by": "oso", "ticket": "OSO-1"}
        ])
        self.assertIsNotNone(policy.find_approval("my-org/app", ["GPL 2.0"], "legacy-etl"))
        self.assertIsNone(policy.find_approval("my-org/app", ["GPL 2.0"], "other-pkg"))
        self.assertIsNone(policy.find_approval("my-org/other", ["GPL 2.0"], "legacy-etl"))

    def test_malformed_expiry_is_an_error_not_a_silent_pass(self):
        policy = self.write_exceptions([
            {"repo": "*", "license": "*", "tier": "green",
             "approved_by": "oso", "ticket": "OSO-1", "expires": "next year"}
        ])
        with self.assertRaises(ValueError):
            policy.find_approval("my-org/app", ["GPL 2.0"], "pkg")


class EndToEndTests(unittest.TestCase):
    """Runs the real CLI over the fixture, offline."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.out = os.path.join(cls.tmp, "output")
        cls.state = os.path.join(cls.tmp, "state")
        cls.code = license_check.main([
            "--org", "my-org", "--from-report", FIXTURE,
            "--out-dir", cls.out, "--state-dir", cls.state, "--quiet",
        ])
        with open(os.path.join(cls.out, "report.json"), "r", encoding="utf-8") as handle:
            cls.results = json.load(handle)
        cls.by_repo = {r["full_name"]: r for r in cls.results["repos"]}

    def test_exit_code_signals_policy_failure(self):
        self.assertEqual(self.code, 2)

    def test_clean_repo_is_green(self):
        self.assertEqual(self.by_repo["my-org/api-server"]["tier"], "green")
        self.assertEqual(self.by_repo["my-org/api-server"]["findings"], [])

    def test_agpl_in_a_server_side_repo_is_red(self):
        repo = self.by_repo["my-org/analytics-api"]
        self.assertEqual(repo["tier"], "red")
        agpl = [f for f in repo["findings"] if f["package"] == "network-toolkit"][0]
        self.assertEqual(agpl["status"], "banned")

    def test_lgpl_in_a_mobile_repo_is_red(self):
        repo = self.by_repo["my-org/android-app"]
        self.assertEqual(repo["profile"], "mobile")
        self.assertEqual(repo["tier"], "red")

    def test_internal_repo_tolerates_gpl_but_not_agpl(self):
        repo = self.by_repo["my-org/internal-tools"]
        self.assertEqual(repo["profile"], "internal")
        self.assertEqual(repo["tier"], "red")  # AGPL is banned even internally
        gpl = [f for f in repo["findings"] if f["package"] == "reporting-lib"][0]
        self.assertEqual(gpl["tier"], "yellow")

    def test_fork_with_copyleft_is_red_cloned(self):
        repo = self.by_repo["my-org/forked-cache"]
        self.assertTrue(repo["cloned"])
        self.assertEqual(repo["tier"], "red-cloned")

    def test_existing_approval_is_applied(self):
        # policy/exceptions.json approves GPL 2.0 in my-org/data-pipeline.
        repo = self.by_repo["my-org/data-pipeline"]
        approved = [f for f in repo["findings"] if f["package"] == "legacy-etl"]
        self.assertEqual(approved[0]["tier"], "green")
        self.assertEqual(approved[0]["approval"]["ticket"], "OSO-1234")

    def test_ai_model_repo_is_always_reviewed(self):
        repo = self.by_repo["my-org/ml-models"]
        self.assertEqual(repo["tier"], "yellow")
        self.assertTrue(repo["notes"])

    def test_skipped_repos_are_reported(self):
        self.assertEqual(self.results["skipped"][0]["repo"], "my-org/legacy-app")

    def test_markdown_and_jira_artifacts_exist(self):
        for name in ("LICENSE_REPORT.md", "findings.json", "jira-tickets.json"):
            self.assertTrue(os.path.exists(os.path.join(self.out, name)), name)

    def test_jira_dry_run_files_tickets_for_blocked_repos(self):
        with open(os.path.join(self.out, "jira-tickets.json"), "r", encoding="utf-8") as handle:
            tickets = json.load(handle)
        repos = {t["repo"] for t in tickets}
        self.assertIn("my-org/analytics-api", repos)
        self.assertTrue(all(t["existing_issue"] is None for t in tickets))

    def test_findings_json_omits_full_package_lists(self):
        with open(os.path.join(self.out, "findings.json"), "r", encoding="utf-8") as handle:
            findings = json.load(handle)
        self.assertNotIn("packages", findings["repos"][0])

    def test_fail_on_never_exits_zero(self):
        code = license_check.main([
            "--org", "my-org", "--from-report", FIXTURE,
            "--out-dir", os.path.join(self.tmp, "o2"),
            "--state-dir", os.path.join(self.tmp, "s2"),
            "--fail-on", "never", "--quiet",
        ])
        self.assertEqual(code, 0)

    def test_profile_override_changes_the_verdict(self):
        out = os.path.join(self.tmp, "o3")
        license_check.main([
            "--org", "my-org", "--from-report", FIXTURE, "--profile", "distributed",
            "--out-dir", out, "--state-dir", os.path.join(self.tmp, "s3"),
            "--fail-on", "never", "--quiet",
        ])
        with open(os.path.join(out, "report.json"), "r", encoding="utf-8") as handle:
            forced = {r["full_name"]: r for r in json.load(handle)["repos"]}
        # GPL is only yellow server-side, but red once everything is distributed.
        self.assertEqual(forced["my-org/analytics-api"]["tier"], "red")


class IncrementalTests(unittest.TestCase):
    def test_second_run_reports_only_new_findings(self):
        tmp = tempfile.mkdtemp()
        out, state = os.path.join(tmp, "out"), os.path.join(tmp, "state")
        common = ["--org", "my-org", "--from-report", FIXTURE, "--out-dir", out,
                  "--state-dir", state, "--fail-on", "never", "--quiet"]

        license_check.main(common)
        with open(os.path.join(out, "report.json"), "r", encoding="utf-8") as handle:
            first = json.load(handle)
        self.assertTrue(first["incremental"]["first_run"])

        license_check.main(common)
        with open(os.path.join(out, "report.json"), "r", encoding="utf-8") as handle:
            second = json.load(handle)
        self.assertFalse(second["incremental"]["first_run"])
        self.assertEqual(second["incremental"]["new_findings"], 0)

    def test_a_changed_finding_shows_as_new(self):
        tmp = tempfile.mkdtemp()
        state = os.path.join(tmp, "state")
        os.makedirs(state)
        with open(os.path.join(state, "last-run.json"), "w", encoding="utf-8") as handle:
            json.dump({"generated_at": "2026-08-01T00:00:00+00:00",
                       "fingerprints": ["my-org/analytics-api|iuwsgi|2.0.21|GPL 2.0|"
                                        "rejected_by_stricter_profile"]}, handle)

        out = os.path.join(tmp, "out")
        license_check.main(["--org", "my-org", "--from-report", FIXTURE, "--out-dir", out,
                            "--state-dir", state, "--fail-on", "never", "--quiet"])
        with open(os.path.join(out, "report.json"), "r", encoding="utf-8") as handle:
            results = json.load(handle)

        self.assertGreater(results["incremental"]["new_findings"], 0)
        analytics = [r for r in results["repos"] if r["full_name"] == "my-org/analytics-api"][0]
        known = [f for f in analytics["findings"] if f["package"] == "iuwsgi"][0]
        self.assertFalse(known["new_since_last_run"])

    def test_fingerprint_is_stable_across_license_ordering(self):
        a = report.fingerprint("r", {"package": "p", "version": "1", "licenses": ["MIT", "GPL"],
                                     "status": "review"})
        b = report.fingerprint("r", {"package": "p", "version": "1", "licenses": ["GPL", "MIT"],
                                     "status": "review"})
        self.assertEqual(a, b)


class MessageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = Policy(POLICY_DIR)

    def test_license_specific_message_wins(self):
        message = self.policy.message_for("banned", {
            "license": "AGPL 3.0", "licenses": ["AGPL 3.0"], "package": "x",
            "version": "1", "repo": "my-org/a", "profile": "Web-based application",
        })
        self.assertIn("network", message)

    def test_generic_message_interpolates_context(self):
        message = self.policy.message_for("review", {
            "license": "Weird-1.0", "licenses": ["Weird-1.0"], "package": "pkg",
            "version": "2.0", "repo": "my-org/a", "profile": "Mobile app",
        })
        self.assertIn("pkg@2.0", message)
        self.assertIn("Weird-1.0", message)

    def test_every_message_template_renders(self):
        context = {"license": "L", "licenses": ["L"], "package": "p", "version": "1",
                   "repo": "r", "profile": "P"}
        for status in ("green", "banned", "rejected", "rejected_by_stricter_profile",
                       "review", "unknown", "cloned"):
            self.assertTrue(self.policy.message_for(status, context))


class MatrixIntegrityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.policy = Policy(POLICY_DIR)

    def test_no_license_is_both_approved_and_rejected(self):
        approved = self.policy._lists["approved"]
        for key in ("reject_server_side", "reject_distributed", "banned"):
            overlap = approved & self.policy._lists[key]
            self.assertEqual(overlap, set(), "approved overlaps %s: %s" % (key, overlap))

    def test_server_side_rejects_are_a_subset_of_distributed_rejects(self):
        missing = self.policy._lists["reject_server_side"] - self.policy._lists["reject_distributed"]
        self.assertEqual(missing, set(),
                         "rejected server-side but allowed when distributed: %s" % missing)

    def test_banned_licenses_are_rejected_everywhere(self):
        for key in ("reject_server_side", "reject_distributed"):
            missing = self.policy._lists["banned"] - self.policy._lists[key]
            self.assertEqual(missing, set(), "banned but absent from %s: %s" % (key, missing))

    def test_every_alias_target_exists_in_the_matrix(self):
        known = set()
        for key in ("approved", "reject_server_side", "reject_distributed", "banned"):
            known |= self.policy._lists[key]
        for alias, target in self.policy.matrix["aliases"].items():
            self.assertIn(spdx.normalize(target), known,
                          "alias %r points at unknown license %r" % (alias, target))

    def test_every_pattern_target_exists_in_the_matrix(self):
        known = set()
        for key in ("approved", "reject_server_side", "reject_distributed", "banned"):
            known |= self.policy._lists[key]
        for pattern in self.policy.matrix["patterns"]:
            self.assertIn(spdx.normalize(pattern["license"]), known, pattern)

    def test_every_profile_names_a_real_reject_list(self):
        for name, profile in self.policy.config["profiles"].items():
            reject_list = profile.get("reject_list")
            if reject_list is not None:
                self.assertIn(reject_list, self.policy._lists, name)

    def test_doc_counts_match_the_transcribed_matrix(self):
        # Guards against a truncated copy/paste from the requirements doc.
        self.assertEqual(len(self.policy.matrix["approved"]), 46)
        self.assertEqual(len(self.policy.matrix["reject_server_side"]), 26)
        # 118, not the 119 a naive comma-split of the doc suggests: one entry
        # ("Creative Commons GNU LGPL, Version 2.1") contains a comma itself.
        self.assertEqual(len(self.policy.matrix["reject_distributed"]), 118)


class GitHubClientTests(unittest.TestCase):
    """Repo listing has to work for both credential types.

    A plain PAT gets HTTP 403 from /installation/repositories -- that endpoint
    only accepts installation tokens -- so the 403 must be treated as "not an
    App token" and fall through to the org listing, not as a fatal error.
    """

    ORG_PAGE = [
        {"full_name": "yahoo-Edge/alpha", "owner": {"login": "yahoo-Edge"}},
        {"full_name": "yahoo-Edge/beta", "owner": {"login": "yahoo-Edge"}},
    ]

    def _client(self, on_installation):
        client = github.Client("token-placeholder", log=lambda _m: None)
        calls = []

        def fake_request(path, method="GET", body=None, accept=None):
            calls.append(path)
            if path.startswith("/installation/repositories"):
                return on_installation()
            if path.startswith("/orgs/"):
                return (200, self.ORG_PAGE) if path.endswith("page=1") else (200, [])
            raise AssertionError("unexpected path: %s" % path)

        client.request = fake_request
        return client, calls

    def test_pat_403_falls_back_to_the_org_listing(self):
        def deny():
            raise github.GitHubError(
                "HTTP 403: You must authenticate with an installation access token"
            )

        client, calls = self._client(deny)
        repos = list(client.list_repos("yahoo-Edge"))

        self.assertEqual([r["full_name"] for r in repos],
                         ["yahoo-Edge/alpha", "yahoo-Edge/beta"])
        self.assertTrue(any(p.startswith("/orgs/yahoo-Edge/repos") for p in calls),
                        "never fell back to the org listing: %s" % calls)

    def test_installation_token_uses_the_installation_listing(self):
        page = {"repositories": [
            {"full_name": "yahoo-Edge/alpha", "owner": {"login": "yahoo-Edge"}},
        ]}

        client = github.Client("token-placeholder", log=lambda _m: None)
        calls = []

        def fake_request(path, method="GET", body=None, accept=None):
            calls.append(path)
            if path.startswith("/installation/repositories"):
                return (200, page if path.endswith("page=1") else {"repositories": []})
            raise AssertionError("should not reach the org listing: %s" % path)

        client.request = fake_request
        repos = list(client.list_repos("yahoo-Edge"))
        self.assertEqual([r["full_name"] for r in repos], ["yahoo-Edge/alpha"])

    def test_owner_filter_is_case_insensitive(self):
        # GitHub org names are case-insensitive; "yahoo-Edge" and "yahoo-edge"
        # are the same org and must not filter each other out.
        page = {"repositories": [
            {"full_name": "yahoo-Edge/alpha", "owner": {"login": "yahoo-Edge"}},
        ]}

        client = github.Client("token-placeholder", log=lambda _m: None)

        def fake_request(path, method="GET", body=None, accept=None):
            if path.startswith("/installation/repositories"):
                return (200, page if path.endswith("page=1") else {"repositories": []})
            raise AssertionError("should not reach the org listing")

        client.request = fake_request
        self.assertEqual(len(list(client.list_repos("yahoo-edge"))), 1)

    def test_missing_org_with_a_pat_is_a_clear_error(self):
        def deny():
            raise github.GitHubError("HTTP 403")

        client, _ = self._client(deny)
        with self.assertRaises(github.GitHubError) as caught:
            list(client.list_repos(None))
        self.assertIn("organization name is required", str(caught.exception))


if __name__ == "__main__":
    unittest.main(verbosity=2)

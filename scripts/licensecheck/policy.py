"""The rule engine: license matrix + risk profile + exceptions -> tier.

Implements the four-tier model from the requirements doc:

    green   all licenses approved (or no open source at all)
    yellow  proceed, but the Open Source Office is notified
    red     blocked; the license is rejected for this repo's risk profile

Every repository is treated the same way: there is no separate handling for
forks or clones. See "Deviations from the requirements doc" in the README.
"""

import fnmatch
import json
import os
import re
from datetime import date

from . import spdx

TIER_ORDER = ["green", "yellow", "red"]


def tier_rank(tier):
    return TIER_ORDER.index(tier)


def worst(tiers):
    return max(tiers, key=tier_rank) if tiers else "green"


def _load_json(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


class Policy:
    def __init__(self, policy_dir):
        self.dir = policy_dir
        self.matrix = _load_json(os.path.join(policy_dir, "license-matrix.json"))
        self.config = _load_json(os.path.join(policy_dir, "policy.json"))
        self.repo_profiles = _load_json(os.path.join(policy_dir, "repo-profiles.json"))
        self.exceptions = _load_json(os.path.join(policy_dir, "exceptions.json"))

        self.resolver = spdx.Resolver(self.matrix)
        self._lists = {
            key: {spdx.canonical(n) for n in self.matrix.get(key, [])}
            for key in ("approved", "reject_server_side", "reject_distributed", "banned")
        }
        # Longest first so "AGPL" does not shadow a more specific prefix.
        self._by_license_messages = sorted(
            self.config["messages"].get("by_license", {}).items(),
            key=lambda kv: -len(kv[0]),
        )
        self.expired_approvals = []

    # ---------------------------------------------------------------- profiles

    def profile_for(self, repo_full_name):
        """Exact match wins over wildcard; unlisted repos get the default."""
        repos = self.repo_profiles.get("repos", {})
        if repo_full_name in repos:
            return repos[repo_full_name]
        for pattern, profile in repos.items():
            if "*" in pattern and fnmatch.fnmatch(repo_full_name, pattern):
                return profile
        return self.config.get("default_profile", "server-side")

    def profile_config(self, profile):
        profiles = self.config["profiles"]
        if profile not in profiles:
            raise ValueError(
                "Unknown risk profile %r. Valid profiles: %s"
                % (profile, ", ".join(sorted(profiles)))
            )
        return profiles[profile]

    # ------------------------------------------------------------- classifying

    def _list_for_profile(self, profile):
        key = self.profile_config(profile).get("reject_list")
        return self._lists.get(key, set()) if key else set()

    def _classify_name(self, oso_name, profile):
        """One resolved OSO license name -> (status, tier)."""
        if oso_name == spdx.UNKNOWN:
            return "unknown", "yellow"

        # "Suspected X" sits in the same lists as X, so match on the full name
        # first and fall back to the base name.
        norm = spdx.canonical(oso_name)
        base = norm[len("SUSPECTED "):] if norm.startswith("SUSPECTED ") else norm

        def in_list(key):
            return norm in self._lists[key] or base in self._lists[key]

        if in_list("banned"):
            return "banned", "red"
        if in_list("approved"):
            return "approved", "green"

        rejected = self._list_for_profile(profile)
        if norm in rejected or base in rejected:
            return "rejected", "red"

        if self.config.get("flag_rejected_by_stricter_profile", True):
            if in_list("reject_distributed") or in_list("reject_server_side"):
                return "rejected_by_stricter_profile", "yellow"

        return "review", "yellow"

    def classify_expression(self, raw_license, profile):
        """Classify a raw SBOM license string, honouring SPDX AND/OR semantics.

        OR is a choice, so the most permissive branch wins. AND means every
        license applies, so the strictest branch wins.
        """
        if spdx.is_unknown(raw_license):
            return {"status": "unknown", "tier": "yellow", "licenses": [], "raw": raw_license}

        tree = spdx.split_expression(raw_license)

        detected = self.detection_dump(tree)
        if detected is not None:
            result = self._classify_detected_set(detected, profile)
        else:
            result = self._walk(tree, profile)

        result["raw"] = raw_license
        return result

    def detection_dump(self, node):
        """Leaves of an AND chain that is a scan dump, or None if it is real.

        GitHub's SBOM does not always emit a legal expression. For many
        packages it joins every license text it detected anywhere in the
        tarball with AND:

            django: BSD-3-Clause AND Python-2.0 AND Python-2.0
                    AND GPL-1.0-or-later AND Python-2.0 AND BSD-3-Clause

        Django is BSD-3-Clause; the GPL term is a stray file. Applying SPDX
        conjunction semantics (all apply, so take the strictest) would call
        that GPL and block it. Three tells separate a dump from an authored
        expression: a real one never repeats a term, never cites a scanner's
        LicenseRef, and rarely chains more than a couple of licenses.
        """
        leaves = spdx.and_leaves(node)
        if leaves is None:
            return None

        canonical = [spdx.canonical(leaf) for leaf in leaves]
        if len(canonical) != len(set(canonical)):
            return leaves
        if any(spdx.is_opaque(leaf) for leaf in leaves):
            return leaves

        minimum = self.config.get("detection_dump_min_terms", 3)
        if len(leaves) >= minimum:
            return leaves
        return None

    def _classify_detected_set(self, leaves, profile):
        """A dump is a set of candidate licenses, not a conjunction."""
        licenses = []
        for leaf in leaves:
            oso_name, _suspected = self.resolver.resolve_one(leaf)
            name = leaf if oso_name == spdx.UNKNOWN else oso_name
            if name not in licenses:
                licenses.append(name)

        # A banned license among the detected texts is still reported red.
        # It is the hard legal line, so a person should confirm it really is
        # incidental rather than have the tool decide for them.
        for name in licenses:
            status, _tier = self._classify_name(name, profile)
            if status == "banned":
                return {"status": "banned", "tier": "red", "licenses": licenses}

        return {"status": "multiple_detected", "tier": "yellow", "licenses": licenses}

    def _walk(self, node, profile):
        kind, value = node
        if kind == "LEAF":
            oso_name, _suspected = self.resolver.resolve_one(value)
            if oso_name == spdx.UNKNOWN:
                # An opaque placeholder means nothing was declared; a real but
                # unlisted identifier is an OSO review item, and keeping the raw
                # string tells the reviewer what to look at.
                status = "unknown" if spdx.is_opaque(value) else "review"
                return {"status": status, "tier": "yellow", "licenses": [value]}

            status, tier = self._classify_name(oso_name, profile)
            return {"status": status, "tier": tier, "licenses": [oso_name]}

        branches = [self._walk(child, profile) for child in value]
        if kind == "OR":
            chosen = min(branches, key=lambda b: tier_rank(b["tier"]))
        else:
            chosen = max(branches, key=lambda b: tier_rank(b["tier"]))

        licenses = []
        for branch in branches:
            licenses.extend(branch["licenses"])
        return {"status": chosen["status"], "tier": chosen["tier"], "licenses": licenses}

    # -------------------------------------------------------------- exceptions

    def find_approval(self, repo_full_name, licenses, package_name, today=None):
        """The first matching, unexpired approval for this finding, if any."""
        today = today or date.today()
        for approval in self.exceptions.get("approvals", []):
            if not _matches(approval.get("repo", "*"), repo_full_name):
                continue
            if not _matches(approval.get("package", "*"), package_name):
                continue
            license_pattern = approval.get("license", "*")
            if license_pattern != "*" and not any(
                _matches(license_pattern, lic) for lic in licenses
            ):
                continue

            expires = approval.get("expires")
            if expires:
                try:
                    if date.fromisoformat(expires) < today:
                        self.expired_approvals.append(
                            {
                                "repo": repo_full_name,
                                "license": license_pattern,
                                "ticket": approval.get("ticket"),
                                "expired": expires,
                            }
                        )
                        continue
                except ValueError:
                    raise ValueError(
                        "Approval for %s has an invalid 'expires' value %r "
                        "(expected YYYY-MM-DD)" % (repo_full_name, expires)
                    )
            return approval
        return None

    # ---------------------------------------------------------------- messages

    def message_for(self, status, context):
        """Custom developer-facing text, per the doc's customizable warnings."""
        messages = self.config["messages"]
        # A per-license message asserts what that license requires, which would
        # contradict "several licenses detected, the effective one is unclear".
        family_override = status not in ("approved", "green", "multiple_detected")
        for prefix, text in self._by_license_messages:
            for lic in context.get("licenses", []):
                bare = re.sub(r"^Suspected ", "", lic or "")
                if bare.startswith(prefix) and family_override:
                    return text.format(**context)

        key = {"approved": "green"}.get(status, status)
        template = messages.get(key, messages["review"])
        return template.format(**context)


def _matches(pattern, value):
    if pattern == "*":
        return True
    if "*" in pattern:
        return fnmatch.fnmatch(value or "", pattern)
    return (value or "") == pattern

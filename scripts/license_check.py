#!/usr/bin/env python3
"""Monthly organization-wide dependency license check.

Collects the dependency graph (SBOM) for every repository in a GitHub
organization, applies the Open Source Office license matrix and risk-profile
rules, and reports each repository as green / yellow / red / red-cloned.

Exit codes:
    0  no findings at or above --fail-on
    1  the run itself failed (auth, network, bad policy file)
    2  policy failure -- findings at or above --fail-on
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from licensecheck import github, jira, report, spdx
from licensecheck.policy import Policy, tier_rank, worst

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXIT_POLICY_FAILURE = 2


def parse_args(argv):
    parser = argparse.ArgumentParser(
        prog="license_check.py",
        description="Organization-wide dependency license compliance check.",
    )
    parser.add_argument("--org", default=os.environ.get("ORG_NAME"),
                        help="GitHub organization (default: $ORG_NAME)")
    parser.add_argument("--repo", action="append", default=[], metavar="OWNER/NAME",
                        help="Check only these repositories; repeatable")
    parser.add_argument("--policy-dir", default=os.path.join(REPO_ROOT, "policy"))
    parser.add_argument("--out-dir", default=os.path.join(REPO_ROOT, "output"))
    parser.add_argument("--state-dir", default=os.path.join(REPO_ROOT, "state"))
    parser.add_argument("--profile", default=None,
                        help="Force a risk profile for every repo, ignoring repo-profiles.json")
    parser.add_argument("--fail-on", default=None,
                        choices=["green", "yellow", "red", "red-cloned", "never"],
                        help="Exit 2 at this tier or worse (default: policy.json fail_on)")
    parser.add_argument("--jira", action="store_true",
                        help="Actually create Jira tickets (default: write jira-tickets.json only)")
    parser.add_argument("--no-incremental", action="store_true",
                        help="Do not diff against the previous run")
    parser.add_argument("--from-report", metavar="PATH",
                        help="Re-evaluate a previously collected report.json instead of calling the API")
    parser.add_argument("--sbom", metavar="PATH",
                        help="Evaluate a single local SPDX SBOM file (offline; use with --repo)")
    parser.add_argument("--quiet", action="store_true")
    return parser.parse_args(argv)


def log_to(stream):
    def log(message):
        print(message, file=stream, flush=True)
    return log


# ------------------------------------------------------------------ collection


def extract_packages(sbom, repo_full_name):
    """SBOM packages, minus the SPDX document and the repository's own entry."""
    root_names = {
        "com.github." + repo_full_name,
        repo_full_name,
        repo_full_name.split("/")[-1],
    }
    packages = []
    for package in sbom.get("packages") or []:
        spdx_id = package.get("SPDXID") or ""
        if "SPDXRef-DOCUMENT" in spdx_id:
            continue
        name = package.get("name") or spdx_id
        if name in root_names:
            continue
        packages.append(
            {
                "name": name,
                "version": package.get("versionInfo"),
                "licenseConcluded": package.get("licenseConcluded"),
                "licenseDeclared": package.get("licenseDeclared"),
            }
        )
    return packages


def collect(args, log):
    """Returns (repos_metadata, skipped). Each repo carries its package list."""
    if args.from_report:
        with open(args.from_report, "r", encoding="utf-8") as handle:
            cached = json.load(handle)
        log("Re-evaluating %s (collected %s)" % (args.from_report, cached.get("generated_at")))
        return cached.get("repos", []), cached.get("skipped", [])

    if args.sbom:
        if not args.repo:
            raise SystemExit("--sbom needs --repo OWNER/NAME so the repo can be profiled")
        with open(args.sbom, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        sbom = document.get("sbom") or document
        full_name = args.repo[0]
        return [
            {
                "full_name": full_name,
                "fork": False,
                "archived": False,
                "packages": extract_packages(sbom, full_name),
            }
        ], []

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("APP_TOKEN")
    if not token:
        app_id = os.environ.get("APP_ID")
        private_key = os.environ.get("APP_PRIVATE_KEY")
        if app_id and private_key:
            if not args.org:
                raise SystemExit("--org is required when authenticating as a GitHub App")
            log("Minting an installation token for %s" % args.org)
            token = github.installation_token(app_id, private_key, args.org)
        else:
            raise SystemExit(
                "No credentials. Set GITHUB_TOKEN, or APP_ID + APP_PRIVATE_KEY."
            )

    client = github.Client(token, log=log)
    wanted = set(args.repo)
    repos, skipped = [], []

    for repo in client.list_repos(args.org):
        full_name = repo["full_name"]
        if wanted and full_name not in wanted:
            continue
        if repo.get("archived"):
            skipped.append({"repo": full_name, "reason": "archived"})
            continue

        log("[%s] fetching SBOM" % full_name)
        try:
            sbom = client.sbom(full_name)
        except github.GitHubError as err:
            log("[%s] ERROR %s" % (full_name, err))
            skipped.append({"repo": full_name, "reason": str(err)[:200]})
            continue

        if not sbom:
            skipped.append({"repo": full_name, "reason": "no dependency graph data"})
            continue

        packages = extract_packages(sbom, full_name)
        log("[%s] %d packages" % (full_name, len(packages)))
        repos.append(
            {
                "full_name": full_name,
                "fork": bool(repo.get("fork")),
                "archived": bool(repo.get("archived")),
                "packages": packages,
            }
        )

    if wanted:
        found = {r["full_name"] for r in repos} | {s["repo"] for s in skipped}
        for missing in sorted(wanted - found):
            skipped.append({"repo": missing, "reason": "not visible to this token"})

    return repos, skipped


# ------------------------------------------------------------------ evaluation


def effective_license(package):
    """Concluded wins; fall back to declared when it carries no information."""
    concluded = package.get("licenseConcluded")
    if concluded and not spdx.is_unknown(concluded):
        return concluded
    declared = package.get("licenseDeclared")
    if declared and not spdx.is_unknown(declared):
        return declared
    return concluded or declared or "NOASSERTION"


def evaluate(repos, skipped, policy, args, log):
    results = {
        "org": args.org or "installation",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy": {
            "matrix_source": policy.matrix.get("_source"),
            "default_profile": policy.config.get("default_profile"),
            "fail_on": args.fail_on or policy.config.get("fail_on", "red"),
        },
        "summary": {
            "repos_checked": 0,
            "repos_with_sbom": 0,
            "total_packages": 0,
            "tiers": {"green": 0, "yellow": 0, "red": 0, "red-cloned": 0},
        },
        "license_summary": {},
        "repos": [],
        "skipped": list(skipped),
        "expired_approvals": [],
    }

    include_green = policy.config["reporting"].get("include_green_packages", False)

    for repo in repos:
        full_name = repo["full_name"]
        profile_name = args.profile or policy.profile_for(full_name)
        profile = policy.profile_config(profile_name)
        cloned = policy.is_cloned(repo)

        findings = []
        notes = []
        tiers_seen = ["green"]

        for package in repo.get("packages", []):
            raw = effective_license(package)
            verdict = policy.classify_expression(raw, profile_name)
            tier = verdict["tier"]
            status = verdict["status"]
            licenses = verdict["licenses"]

            for license_name in licenses or [raw]:
                results["license_summary"][license_name] = (
                    results["license_summary"].get(license_name, 0) + 1
                )

            # Cloned-repo rule: copyleft inside a fork blocks patching outright.
            if cloned and tier_rank(tier) >= tier_rank("yellow"):
                if any(policy.is_copyleft(lic) for lic in licenses):
                    tier = "red-cloned"
                    status = "cloned"

            context = {
                "license": ", ".join(licenses) or raw,
                "licenses": licenses,
                "package": package["name"],
                "version": package.get("version") or "unknown",
                "repo": full_name,
                "profile": profile["label"],
            }
            message = policy.message_for(status, context)

            approval = None
            if tier != "green":
                approval = policy.find_approval(full_name, licenses, package["name"])
                if approval:
                    tier = approval.get("tier", "green")
                    message = "Approved by %s (%s)" % (
                        approval.get("approved_by", "?"),
                        approval.get("ticket", "no ticket"),
                    )

            tiers_seen.append(tier)
            # Approved findings stay in the report even though they are green:
            # the approval and its expiry are the audit trail for the exception.
            if tier == "green" and not approval and not include_green:
                continue

            findings.append(
                {
                    "package": package["name"],
                    "version": package.get("version"),
                    "raw_license": raw,
                    "licenses": licenses,
                    "status": status,
                    "tier": tier,
                    "message": message,
                    "approval": approval,
                }
            )

        if profile.get("always_review"):
            notes.append(profile.get("always_review_reason", "Requires OSO review."))
            tiers_seen.append("yellow")
        if cloned:
            notes.append(
                "Cloned/forked repository: patching copyleft-licensed code here "
                "requires Open Source Office approval."
            )

        repo_tier = worst(tiers_seen)
        results["summary"]["repos_checked"] += 1
        if repo.get("packages"):
            results["summary"]["repos_with_sbom"] += 1
        results["summary"]["total_packages"] += len(repo.get("packages", []))
        results["summary"]["tiers"][repo_tier] += 1

        results["repos"].append(
            {
                "full_name": full_name,
                "profile": profile_name,
                "profile_label": profile["label"],
                "cloned": cloned,
                "tier": repo_tier,
                "packages_total": len(repo.get("packages", [])),
                "packages": repo.get("packages", []),
                "findings": sorted(findings, key=lambda f: -tier_rank(f["tier"])),
                "notes": notes,
            }
        )

    results["expired_approvals"] = policy.expired_approvals
    return results


# --------------------------------------------------------------------- output


def write_outputs(results, policy, args, log):
    os.makedirs(args.out_dir, exist_ok=True)

    # findings.json omits the full package lists; report.json keeps everything.
    findings_only = json.loads(json.dumps(results))
    for repo in findings_only["repos"]:
        repo.pop("packages", None)

    paths = {
        "report": os.path.join(args.out_dir, "report.json"),
        "findings": os.path.join(args.out_dir, "findings.json"),
        "markdown": os.path.join(args.out_dir, "LICENSE_REPORT.md"),
        "jira": os.path.join(args.out_dir, "jira-tickets.json"),
    }

    with open(paths["report"], "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    with open(paths["findings"], "w", encoding="utf-8") as handle:
        json.dump(findings_only, handle, indent=2)
    with open(paths["markdown"], "w", encoding="utf-8") as handle:
        handle.write(report.to_markdown(results, policy))

    return paths


def handle_jira(results, policy, args, paths, log):
    index_path = os.path.join(args.state_dir, "jira-index.json")
    index = jira.load_index(index_path)
    tickets = jira.build_tickets(results, policy, index)

    if not tickets:
        log("Jira: nothing new to file.")
        with open(paths["jira"], "w", encoding="utf-8") as handle:
            json.dump([], handle, indent=2)
        return

    if not args.jira:
        with open(paths["jira"], "w", encoding="utf-8") as handle:
            json.dump(tickets, handle, indent=2)
        log("Jira: %d ticket(s) would be created (dry run). See %s; pass --jira to file them."
            % (len(tickets), paths["jira"]))
        return

    client = jira.from_environment()
    created = []
    for ticket in tickets:
        if ticket["existing_issue"]:
            log("Jira: %s already tracked by %s; skipping"
                % (ticket["repo"], ticket["existing_issue"]))
            continue
        issue_key = client.create(ticket)
        index[ticket["key"]] = issue_key
        created.append({"repo": ticket["repo"], "tier": ticket["tier"], "issue": issue_key})
        log("Jira: created %s for %s" % (issue_key, ticket["repo"]))

    jira.save_index(index_path, index)
    with open(paths["jira"], "w", encoding="utf-8") as handle:
        json.dump(created, handle, indent=2)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    log = (lambda _msg: None) if args.quiet else log_to(sys.stderr)

    try:
        policy = Policy(args.policy_dir)
    except (OSError, ValueError) as err:
        print("Could not load policy from %s: %s" % (args.policy_dir, err), file=sys.stderr)
        return 1

    try:
        repos, skipped = collect(args, log)
    except (github.GitHubError, OSError) as err:
        print("Collection failed: %s" % err, file=sys.stderr)
        return 1

    results = evaluate(repos, skipped, policy, args, log)

    state_path = os.path.join(args.state_dir, "last-run.json")
    if not args.no_incremental and policy.config["reporting"].get("incremental", True):
        report.mark_new_findings(results, report.load_state(state_path))

    paths = write_outputs(results, policy, args, log)

    try:
        handle_jira(results, policy, args, paths, log)
    except jira.JiraError as err:
        print("Jira step failed: %s" % err, file=sys.stderr)
        return 1

    if not args.no_incremental:
        report.save_state(state_path, results)

    if not args.quiet:
        print(report.summarize_for_console(results, policy))
        print("\nReports written to %s" % args.out_dir)
        sys.stdout.flush()

    fail_on = args.fail_on or policy.config.get("fail_on", "red")
    if fail_on == "never":
        return 0
    threshold = tier_rank(fail_on)
    blocked = [r for r in results["repos"] if tier_rank(r["tier"]) >= threshold]
    if blocked:
        print(
            "\nPolicy failure: %d repositor%s at or above '%s'."
            % (len(blocked), "y" if len(blocked) == 1 else "ies", fail_on),
            file=sys.stderr,
        )
        return EXIT_POLICY_FAILURE
    return 0


if __name__ == "__main__":
    sys.exit(main())

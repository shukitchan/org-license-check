#!/usr/bin/env python3
"""Monthly organization-wide dependency license check.

Collects the dependency graph (SBOM) for every repository in a GitHub
organization, applies the Open Source Office license matrix and risk-profile
rules, and reports each repository as green / yellow / red.

Exit codes:
    0  no findings at or above --fail-on
    1  the run itself failed (auth, network, bad policy file)
    2  policy failure -- findings at or above --fail-on
"""

import argparse
import json
import os
import re
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
    parser.add_argument("--org", action="append", default=None, metavar="ORG",
                        help="GitHub organization; repeatable to scan several in "
                             "one run (default: $ORG_NAME)")
    parser.add_argument("--repo", action="append", default=[], metavar="OWNER/NAME",
                        help="Check only these repositories; repeatable")
    parser.add_argument("--policy-dir", default=os.path.join(REPO_ROOT, "policy"))
    parser.add_argument("--out-dir", default=os.path.join(REPO_ROOT, "output"),
                        help="Parent directory; reports go to <out-dir>/<org>/")
    parser.add_argument("--state-dir", default=os.path.join(REPO_ROOT, "state"),
                        help="Parent directory; state goes to <state-dir>/<org>/")
    parser.add_argument("--profile", default=None,
                        help="Force a risk profile for every repo, ignoring repo-profiles.json")
    parser.add_argument("--fail-on", default=None,
                        choices=["green", "yellow", "red", "never"],
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


def package_ecosystem(package):
    """The purl type for a package: npm, pypi, golang, githubactions, ...

    Returns None when the SBOM carries no purl, which is how reports collected
    by older versions of this script look.
    """
    for ref in package.get("externalRefs") or []:
        if (ref.get("referenceType") or "").lower() != "purl":
            continue
        locator = ref.get("referenceLocator") or ""
        if locator.startswith("pkg:"):
            return locator[4:].split("/", 1)[0].split("@", 1)[0].strip().lower() or None
    return None


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
                "ecosystem": package_ecosystem(package),
            }
        )
    return packages


def collect(org, args, log):
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
            if not org:
                raise SystemExit("--org is required when authenticating as a GitHub App")
            log("Minting an installation token for %s" % org)
            token = github.installation_token(app_id, private_key, org)
        else:
            raise SystemExit(
                "No credentials. Set GITHUB_TOKEN, or APP_ID + APP_PRIVATE_KEY."
            )

    client = github.Client(token, log=log)
    wanted = set(args.repo)
    repos, skipped = [], []

    for repo in client.list_repos(org):
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


def evaluate(repos, skipped, policy, org, args, log):
    results = {
        "org": org or "installation",
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
            "packages_ignored": 0,
            "ignored_ecosystems": sorted(policy.config.get("ignore_ecosystems", [])),
            "tiers": {"green": 0, "yellow": 0, "red": 0},
        },
        "license_summary": {},
        "repos": [],
        "skipped": list(skipped),
        "expired_approvals": [],
    }

    include_green = policy.config["reporting"].get("include_green_packages", False)
    ignored_ecosystems = {e.strip().lower() for e in policy.config.get("ignore_ecosystems", [])}

    for repo in repos:
        full_name = repo["full_name"]
        profile_name = args.profile or policy.profile_for(full_name)
        profile = policy.profile_config(profile_name)

        findings = []
        notes = []
        tiers_seen = ["green"]

        ignored_here = 0

        for package in repo.get("packages", []):
            if package.get("ecosystem") in ignored_ecosystems:
                ignored_here += 1
                continue

            raw = effective_license(package)
            verdict = policy.classify_expression(raw, profile_name)
            tier = verdict["tier"]
            status = verdict["status"]
            licenses = verdict["licenses"]

            for license_name in licenses or [raw]:
                results["license_summary"][license_name] = (
                    results["license_summary"].get(license_name, 0) + 1
                )

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

        repo_tier = worst(tiers_seen)
        results["summary"]["repos_checked"] += 1
        if repo.get("packages"):
            results["summary"]["repos_with_sbom"] += 1
        results["summary"]["total_packages"] += len(repo.get("packages", []))
        results["summary"]["packages_ignored"] += ignored_here
        results["summary"]["tiers"][repo_tier] += 1

        results["repos"].append(
            {
                "full_name": full_name,
                "profile": profile_name,
                "profile_label": profile["label"],
                "tier": repo_tier,
                "packages_total": len(repo.get("packages", [])),
                "packages_ignored": ignored_here,
                "packages": repo.get("packages", []),
                "findings": sorted(findings, key=lambda f: -tier_rank(f["tier"])),
                "notes": notes,
            }
        )

    results["expired_approvals"] = policy.expired_approvals
    return results


# --------------------------------------------------------------------- output


_SLUG_UNSAFE = re.compile(r"[^a-z0-9._-]+")


def org_slug(org):
    """Directory name for one organization's reports and state.

    Lowercased on purpose: GitHub organization names are case-insensitive, so
    without folding, `--org Example-Org` and `--org example-org` would build two
    separate incremental baselines for the same organization on a
    case-sensitive filesystem, and each month's diff would be wrong.
    """
    slug = _SLUG_UNSAFE.sub("-", (org or "installation").strip().lower()).strip("-.")
    return slug or "installation"


def resolve_orgs(args):
    """The organizations to scan, de-duplicated, order preserved.

    `[None]` means "whatever this installation token can see", which is the
    App-credentials path where no org needs naming.
    """
    named = list(args.org or [])
    if not named and os.environ.get("ORG_NAME"):
        named = [os.environ["ORG_NAME"]]
    if not named:
        return [None]

    seen, orgs = set(), []
    for org in named:
        key = org.strip().lower()
        if key and key not in seen:
            seen.add(key)
            orgs.append(org.strip())
    return orgs or [None]


def write_outputs(results, policy, out_dir):
    os.makedirs(out_dir, exist_ok=True)

    # findings.json omits the full package lists; report.json keeps everything.
    findings_only = json.loads(json.dumps(results))
    for repo in findings_only["repos"]:
        repo.pop("packages", None)

    paths = {
        "report": os.path.join(out_dir, "report.json"),
        "findings": os.path.join(out_dir, "findings.json"),
        "markdown": os.path.join(out_dir, "LICENSE_REPORT.md"),
        "jira": os.path.join(out_dir, "jira-tickets.json"),
    }

    with open(paths["report"], "w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)
    with open(paths["findings"], "w", encoding="utf-8") as handle:
        json.dump(findings_only, handle, indent=2)
    with open(paths["markdown"], "w", encoding="utf-8") as handle:
        handle.write(report.to_markdown(results, policy))

    return paths


def handle_jira(results, policy, args, paths, state_dir, log):
    index_path = os.path.join(state_dir, "jira-index.json")
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


def run_one_org(org, args, log):
    """Scan one organization into its own output and state directories."""
    # A fresh Policy per organization: expired approvals accumulate on the
    # instance, and one org's expiries must not show up in another's report.
    policy = Policy(args.policy_dir)

    slug = org_slug(org)
    out_dir = os.path.join(args.out_dir, slug)
    state_dir = os.path.join(args.state_dir, slug)

    repos, skipped = collect(org, args, log)
    results = evaluate(repos, skipped, policy, org, args, log)
    results["output_dir"] = out_dir

    state_path = os.path.join(state_dir, "last-run.json")
    incremental = (not args.no_incremental
                   and policy.config["reporting"].get("incremental", True))
    if incremental:
        report.mark_new_findings(results, report.load_state(state_path))

    paths = write_outputs(results, policy, out_dir)
    handle_jira(results, policy, args, paths, state_dir, log)

    if not args.no_incremental:
        report.save_state(state_path, results)

    fail_on = args.fail_on or policy.config.get("fail_on", "red")
    blocked = []
    if fail_on != "never":
        threshold = tier_rank(fail_on)
        blocked = [r for r in results["repos"] if tier_rank(r["tier"]) >= threshold]

    return {
        "org": org or "installation",
        "slug": slug,
        "out_dir": out_dir,
        "results": results,
        "policy": policy,
        "blocked": blocked,
        "fail_on": fail_on,
    }


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    log = (lambda _msg: None) if args.quiet else log_to(sys.stderr)

    # Fail fast on a broken policy directory, before any network work.
    try:
        Policy(args.policy_dir)
    except (OSError, ValueError) as err:
        print("Could not load policy from %s: %s" % (args.policy_dir, err), file=sys.stderr)
        return 1

    orgs = resolve_orgs(args)

    if len(orgs) > 1:
        for flag, value in (("--from-report", args.from_report), ("--sbom", args.sbom)):
            if value:
                print("%s describes a single organization; pass one --org with it."
                      % flag, file=sys.stderr)
                return 1

    outcomes = []
    run_failed = False

    for org in orgs:
        if len(orgs) > 1:
            log("")
            log("===== %s =====" % (org or "installation"))
        try:
            outcomes.append(run_one_org(org, args, log))
        except (github.GitHubError, jira.JiraError, OSError, ValueError) as err:
            print("[%s] failed: %s" % (org or "installation", err), file=sys.stderr)
            run_failed = True

    if not outcomes:
        return 1

    if not args.quiet:
        for outcome in outcomes:
            print(report.summarize_for_console(outcome["results"], outcome["policy"]))
            print("\nReports written to %s" % outcome["out_dir"])
        if len(outcomes) > 1:
            print(_combined_summary(outcomes))
        sys.stdout.flush()

    blocking = [o for o in outcomes if o["blocked"]]
    for outcome in blocking:
        print(
            "\nPolicy failure: [%s] %d repositor%s at or above '%s'."
            % (outcome["org"], len(outcome["blocked"]),
               "y" if len(outcome["blocked"]) == 1 else "ies", outcome["fail_on"]),
            file=sys.stderr,
        )

    # A failed run outranks a policy failure: the report is incomplete, which
    # needs fixing before its verdict means anything.
    if run_failed:
        return 1
    return EXIT_POLICY_FAILURE if blocking else 0


def _combined_summary(outcomes):
    lines = ["", "All organizations:", ""]
    lines.append("  %-24s %7s %7s %7s %7s" % ("org", "repos", "green", "yellow", "red"))
    totals = {"repos": 0, "green": 0, "yellow": 0, "red": 0}
    for outcome in outcomes:
        summary = outcome["results"]["summary"]
        tiers = summary["tiers"]
        lines.append("  %-24s %7d %7d %7d %7d" % (
            outcome["org"][:24], summary["repos_checked"], tiers.get("green", 0),
            tiers.get("yellow", 0), tiers.get("red", 0)))
        totals["repos"] += summary["repos_checked"]
        for tier in ("green", "yellow", "red"):
            totals[tier] += tiers.get(tier, 0)
    lines.append("  %-24s %7d %7d %7d %7d" % (
        "TOTAL", totals["repos"], totals["green"], totals["yellow"], totals["red"]))
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())

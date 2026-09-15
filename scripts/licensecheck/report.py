"""Report rendering and incremental (new-since-last-run) diffing."""

import json
import os

from .policy import tier_rank

TIER_ICON = {"green": "🟢", "yellow": "🟡", "red": "🔴", "red-cloned": "🔴"}


def fingerprint(repo_name, finding):
    """Stable identity for a finding, used to detect what is new this month."""
    return "|".join(
        [
            repo_name,
            finding.get("package") or "",
            finding.get("version") or "",
            ",".join(sorted(finding.get("licenses") or [])),
            finding.get("status") or "",
        ]
    )


def load_state(path):
    if not os.path.exists(path):
        return {"fingerprints": [], "generated_at": None}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_state(path, results):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    seen = [
        fingerprint(repo["full_name"], finding)
        for repo in results["repos"]
        for finding in repo["findings"]
    ]
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(
            {"generated_at": results["generated_at"], "fingerprints": sorted(set(seen))},
            handle,
            indent=2,
        )


def mark_new_findings(results, state):
    """Tag each finding as new when it was absent from the previous run."""
    previous = set(state.get("fingerprints") or [])
    first_run = not previous
    new_count = 0
    for repo in results["repos"]:
        for finding in repo["findings"]:
            is_new = not first_run and fingerprint(repo["full_name"], finding) not in previous
            finding["new_since_last_run"] = is_new
            if is_new:
                new_count += 1
    results["incremental"] = {
        "previous_run": state.get("generated_at"),
        "first_run": first_run,
        "new_findings": new_count,
    }
    return results


# ------------------------------------------------------------------ markdown


def _escape(value):
    return str(value if value is not None else "-").replace("|", "\\|")


def to_markdown(results, policy):
    org = results["org"]
    summary = results["summary"]
    tiers = summary["tiers"]
    lines = [
        "# Open source license compliance report – %s" % org,
        "",
        "Generated: %s" % results["generated_at"],
        "",
        "| Metric | Value |",
        "|--------|-------|",
        "| Repositories checked | %d |" % summary["repos_checked"],
        "| Repositories with dependency data | %d |" % summary["repos_with_sbom"],
        "| Total packages | %d |" % summary["total_packages"],
        "| 🟢 Green | %d |" % tiers.get("green", 0),
        "| 🟡 Yellow (contact OSO) | %d |" % tiers.get("yellow", 0),
        "| 🔴 Red (blocked) | %d |" % tiers.get("red", 0),
        "| 🔴 Red – cloned repo | %d |" % tiers.get("red-cloned", 0),
        "",
    ]

    incremental = results.get("incremental")
    if incremental:
        if incremental["first_run"]:
            lines += ["> First run – every finding below is new.", ""]
        else:
            lines += [
                "> %d new finding(s) since the previous run on %s."
                % (incremental["new_findings"], incremental["previous_run"]),
                "",
            ]

    blocked = [r for r in results["repos"] if tier_rank(r["tier"]) >= tier_rank("red")]
    if blocked:
        lines += ["## 🔴 Blocked repositories", ""]
        lines += ["| Repository | Profile | Tier | Findings |", "|---|---|---|---|"]
        for repo in sorted(blocked, key=lambda r: r["full_name"]):
            offending = [f for f in repo["findings"] if tier_rank(f["tier"]) >= tier_rank("red")]
            lines.append(
                "| `%s` | %s | %s %s | %d |"
                % (
                    repo["full_name"],
                    repo["profile"],
                    TIER_ICON[repo["tier"]],
                    policy.config["tiers"][repo["tier"]]["label"],
                    len(offending),
                )
            )
        lines.append("")

    new_findings = [
        (repo, finding)
        for repo in results["repos"]
        for finding in repo["findings"]
        if finding.get("new_since_last_run")
    ]
    if new_findings:
        lines += ["## 🆕 New since last run", "", "| Repository | Package | License | Tier |", "|---|---|---|---|"]
        for repo, finding in sorted(new_findings, key=lambda p: (-tier_rank(p[1]["tier"]), p[0]["full_name"])):
            lines.append(
                "| `%s` | %s@%s | %s | %s |"
                % (
                    repo["full_name"],
                    _escape(finding["package"]),
                    _escape(finding["version"]),
                    _escape(", ".join(finding["licenses"]) or finding["raw_license"]),
                    TIER_ICON[finding["tier"]],
                )
            )
        lines.append("")

    lines += ["## License summary (all packages)", "", "| License | Count |", "|---------|-------|"]
    for license_name, count in sorted(
        results["license_summary"].items(), key=lambda kv: (-kv[1], kv[0])
    ):
        lines.append("| %s | %d |" % (_escape(license_name), count))
    lines.append("")

    lines += ["## Findings by repository", ""]
    limit = policy.config["reporting"].get("max_packages_per_repo_in_markdown", 100)
    for repo in sorted(
        results["repos"], key=lambda r: (-tier_rank(r["tier"]), r["full_name"])
    ):
        tier_label = policy.config["tiers"][repo["tier"]]["label"]
        lines.append(
            "### %s `%s` — %s"
            % (TIER_ICON[repo["tier"]], repo["full_name"], tier_label)
        )
        lines.append("")
        lines.append(
            "Risk profile: **%s** (%s)%s · %d packages"
            % (
                repo["profile"],
                repo["profile_label"],
                " · cloned/forked repository" if repo["cloned"] else "",
                repo["packages_total"],
            )
        )
        lines.append("")

        for note in repo.get("notes", []):
            lines.append("> %s" % note)
        if repo.get("notes"):
            lines.append("")

        if not repo["findings"]:
            lines += ["All dependency licenses are on the OSO approved list.", ""]
            continue

        lines += [
            "| Package | Version | License | Tier | Action |",
            "|---|---|---|---|---|",
        ]
        for finding in repo["findings"][:limit]:
            approval = finding.get("approval")
            action = finding["message"]
            if approval:
                action = "Approved by %s (%s)%s" % (
                    approval.get("approved_by", "?"),
                    approval.get("ticket", "no ticket"),
                    " – expires %s" % approval["expires"] if approval.get("expires") else "",
                )
            lines.append(
                "| %s | %s | %s | %s | %s |"
                % (
                    _escape(finding["package"]),
                    _escape(finding["version"]),
                    _escape(", ".join(finding["licenses"]) or finding["raw_license"]),
                    TIER_ICON[finding["tier"]],
                    _escape(action),
                )
            )
        if len(repo["findings"]) > limit:
            lines.append(
                "| … | %d more findings | | | see findings.json |"
                % (len(repo["findings"]) - limit)
            )
        lines.append("")

    if results.get("expired_approvals"):
        lines += ["## ⚠️ Expired approvals", ""]
        for expired in results["expired_approvals"]:
            lines.append(
                "- `%s` – %s (ticket %s) expired %s; the finding is being reported again."
                % (
                    expired["repo"],
                    expired["license"],
                    expired.get("ticket") or "none",
                    expired["expired"],
                )
            )
        lines.append("")

    if results.get("skipped"):
        lines += ["## Repositories skipped", ""]
        for entry in results["skipped"]:
            lines.append("- `%s`: %s" % (entry["repo"], entry["reason"]))
        lines.append("")

    lines += [
        "---",
        "",
        "Tiers follow the Open Source Office License Scanning Requirements: "
        "🟢 green proceeds, 🟡 yellow proceeds but notifies OSO, "
        "🔴 red blocks the build. Per-repo approvals live in `policy/exceptions.json`.",
        "",
    ]
    return "\n".join(lines)


def summarize_for_console(results, policy):
    tiers = results["summary"]["tiers"]
    out = [
        "",
        "%s  %d repos checked, %d packages"
        % (results["org"], results["summary"]["repos_checked"], results["summary"]["total_packages"]),
        "  🟢 green      %d" % tiers.get("green", 0),
        "  🟡 yellow     %d  (contact OSO)" % tiers.get("yellow", 0),
        "  🔴 red        %d  (blocked)" % tiers.get("red", 0),
        "  🔴 red-cloned %d  (blocked)" % tiers.get("red-cloned", 0),
    ]
    blocked = [r for r in results["repos"] if tier_rank(r["tier"]) >= tier_rank("red")]
    if blocked:
        out.append("")
        out.append("Blocked repositories:")
        for repo in sorted(blocked, key=lambda r: r["full_name"])[:20]:
            worst_findings = [
                f for f in repo["findings"] if tier_rank(f["tier"]) >= tier_rank("red")
            ]
            licenses = sorted({lic for f in worst_findings for lic in f["licenses"]})
            out.append(
                "  %s  %s  [%s]"
                % (repo["tier"].ljust(10), repo["full_name"], ", ".join(licenses[:5]))
            )
        if len(blocked) > 20:
            out.append("  … and %d more" % (len(blocked) - 20))
    return "\n".join(out)

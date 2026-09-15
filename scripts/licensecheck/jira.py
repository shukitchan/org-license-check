"""Auto-generate Jira tickets for repositories with unapproved licenses.

Doc requirement: "Ability auto generate jira tickets when a unapproved licenses
are found". Nothing is created unless --jira is passed; the default run writes
the intended tickets to jira-tickets.json so OSO can review them first.

One ticket per repository per tier. state/jira-index.json remembers which
(repo, tier) pairs already have a ticket so monthly runs do not re-file.
"""

import base64
import json
import os
import urllib.error
import urllib.request

from .policy import tier_rank


def load_index(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_index(path, index):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(index, handle, indent=2, sort_keys=True)


def build_tickets(results, policy, index):
    """Tickets that should exist for this run, minus the ones already filed."""
    config = policy.config["jira"]
    wanted_tiers = set(config.get("create_for_tiers", ["red", "red-cloned"]))
    tickets = []

    for repo in results["repos"]:
        if repo["tier"] not in wanted_tiers:
            continue
        findings = [
            f
            for f in repo["findings"]
            if f["tier"] == repo["tier"] and not f.get("approval")
        ]
        if not findings:
            continue

        key = "%s::%s" % (repo["full_name"], repo["tier"])
        existing = index.get(key)
        if existing and not _has_new_findings(findings):
            continue

        tickets.append(
            {
                "key": key,
                "existing_issue": existing,
                "repo": repo["full_name"],
                "tier": repo["tier"],
                "project": config.get("project_key", "OSO"),
                "issue_type": config.get("issue_type", "Task"),
                "labels": config.get("labels", []),
                "summary": config["summary_template"].format(
                    tier=policy.config["tiers"][repo["tier"]]["label"],
                    repo=repo["full_name"],
                    profile=repo["profile"],
                ),
                "description": _description(repo, findings, policy),
                "finding_count": len(findings),
            }
        )

    tickets.sort(key=lambda t: (-tier_rank(t["tier"]), t["repo"]))
    return tickets


def _has_new_findings(findings):
    return any(f.get("new_since_last_run") for f in findings)


def _description(repo, findings, policy):
    tier_label = policy.config["tiers"][repo["tier"]]["label"]
    profile = policy.profile_config(repo["profile"])
    lines = [
        "Automated finding from the monthly organization license scan.",
        "",
        "Repository: %s" % repo["full_name"],
        "Risk profile: %s (%s)" % (repo["profile"], profile["label"]),
        "Tier: %s" % tier_label,
    ]
    if repo["cloned"]:
        lines.append("This is a cloned/forked repository.")
    lines += ["", "Unapproved licenses:", ""]
    for finding in findings[:50]:
        lines.append(
            "* %s@%s — %s — %s"
            % (
                finding["package"],
                finding["version"] or "unknown version",
                ", ".join(finding["licenses"]) or finding["raw_license"],
                finding["message"],
            )
        )
    if len(findings) > 50:
        lines.append("* ... and %d more (see the attached report)" % (len(findings) - 50))
    lines += [
        "",
        "To approve an exception, add an entry to policy/exceptions.json in the "
        "org-license-check repository and reference this ticket.",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------------- client


class JiraError(Exception):
    pass


class Jira:
    def __init__(self, base_url, email, api_token):
        self.base_url = base_url.rstrip("/")
        auth = base64.b64encode(("%s:%s" % (email, api_token)).encode()).decode()
        self.auth_header = "Basic " + auth

    def create(self, ticket):
        payload = {
            "fields": {
                "project": {"key": ticket["project"]},
                "summary": ticket["summary"],
                "description": ticket["description"],
                "issuetype": {"name": ticket["issue_type"]},
                "labels": ticket["labels"],
            }
        }
        req = urllib.request.Request(
            self.base_url + "/rest/api/2/issue",
            data=json.dumps(payload).encode(),
            method="POST",
        )
        req.add_header("Authorization", self.auth_header)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                created = json.loads(response.read().decode())
                return created.get("key")
        except urllib.error.HTTPError as err:
            raise JiraError(
                "Jira returned HTTP %s: %s"
                % (err.code, err.read().decode("utf-8", "replace")[:400])
            )
        except urllib.error.URLError as err:
            raise JiraError("Could not reach Jira at %s: %s" % (self.base_url, err))


def from_environment():
    """Build a client from JIRA_BASE_URL / JIRA_EMAIL / JIRA_API_TOKEN."""
    base_url = os.environ.get("JIRA_BASE_URL")
    email = os.environ.get("JIRA_EMAIL")
    token = os.environ.get("JIRA_API_TOKEN")
    missing = [
        name
        for name, value in (
            ("JIRA_BASE_URL", base_url),
            ("JIRA_EMAIL", email),
            ("JIRA_API_TOKEN", token),
        )
        if not value
    ]
    if missing:
        raise JiraError(
            "--jira needs these environment variables: %s" % ", ".join(missing)
        )
    return Jira(base_url, email, token)

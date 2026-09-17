---
name: license-check
description: Run the organization-wide dependency license compliance scan (Open Source Office policy) and summarize the findings. Use when the user says "run the license check", "license scan", "monthly license report", "check dependency licenses", or asks which repos are blocked by unapproved licenses.
user-invocable: true
allowed-tools: ["Bash", "Read"]
---

# Org dependency license check

Scans every repo in a GitHub org against the OSO license matrix and reports each
as green / yellow / red. The engine lives in the `org-license-check` repo; this
skill runs it and interprets the result.

## Step 1 — Locate the repo

```bash
REPO="$(cd -P ~/.claude/skills/license-check && cd ../../.. && pwd)"
```

Everything below uses `"$REPO"`. Do not hardcode a path.

## Step 2 — Check credentials

The scan needs `GITHUB_TOKEN` (a PAT or an installation token), or `APP_ID` plus
`APP_PRIVATE_KEY`. If neither is set, **stop and tell the user** — do not guess a
token, read one out of a file, or try to mint one.

```bash
if [ -n "$GITHUB_TOKEN" ] || { [ -n "$APP_ID" ] && [ -n "$APP_PRIVATE_KEY" ]; }; then
  echo "credentials: present"
else
  echo "credentials: missing"
fi
```

## Step 3 — Run the scan

The org comes from the user's request or `$ORG_NAME`. If neither names one, ask —
never invent an org.

```bash
"$REPO/run-monthly.sh" --org <org>
```

For several organizations, pass `--org` more than once — each is reported into
its own folder and a combined summary is printed at the end:

```bash
"$REPO/run-monthly.sh" --org <org-a> --org <org-b>
```

This takes a while on a large org: one SBOM fetch per repository. Roughly half a
second per repo, so a 500-repo org is about five minutes.

## Exit codes — read this before reporting a failure

| Code | Meaning | What to do |
|---|---|---|
| 0 | No findings at or above the fail threshold | Report clean |
| 2 | **Policy violations found. The run succeeded.** | Report the findings |
| 1 | The run itself failed (auth, network, malformed policy file) | Report the error |

**Exit 2 is the expected outcome when repositories are blocked.** It is not a
crash, not a bug, and not something to retry, work around, or fix. Never re-run
with `--fail-on never` just to force a zero exit.

## Step 4 — Summarize

Reports are per organization, under `$REPO/output/<org-slug>/` (the slug is the
org name lowercased). Read `$REPO/output/<org-slug>/LICENSE_REPORT.md` and
report, per organization:

1. The tier counts (green / yellow / red / red-cloned)
2. Every **blocked** repository with its offending licenses
3. The **New since last run** section, if present — on a monthly run this is
   usually the only part that matters
4. Any expired approvals

`$REPO/output/<org-slug>/findings.json` holds the same data structured, if you
need to filter or count precisely. With several organizations, summarize each
one separately rather than merging them — the tiers depend on per-repo risk
profiles and are not comparable across orgs.

## Usage variants

| Intent | Command |
|---|---|
| One repo only | `"$REPO/run-monthly.sh" --org <org> --repo <owner>/<name> --no-incremental` |
| Re-evaluate without re-fetching | `"$REPO/run-monthly.sh" --org <org> --from-report "$REPO/output/<org-slug>/report.json"` |
| Test a profile change | add `--profile distributed` (or `server-side`, `mobile`, `internal`, `ai-model`) |
| Offline smoke test | `"$REPO/run-monthly.sh" --demo` |

## Notes

- **Never pass `--jira`.** The script can file Jira tickets; this skill does not.
  If the user wants tickets filed, tell them to run it themselves.
- **A normal run consumes the incremental state.** `state/<org-slug>/last-run.json` records
  what was seen, so the *next* run reports only what changed. For ad-hoc or
  exploratory runs use `--no-incremental` or `--from-report`, or you will burn
  the month's diff and the real run will report "0 new findings".
- Policy is data, not code: `policy/license-matrix.json` (the OSO matrix),
  `policy/policy.json` (tiers, messages, profiles), `policy/repo-profiles.json`
  (repo to risk profile), `policy/exceptions.json` (approvals). If the user wants
  a license unblocked for one repo, that is an `exceptions.json` entry — surface
  that, but make the edit outside this skill.
- A scan reads GitHub's dependency graph for each repo's **default branch**, so
  it will not catch a bad dependency still sitting in an open pull request.
- The report's "Packages excluded" row is expected, not a problem: GitHub
  Actions are filtered out via `ignore_ecosystems` because they are build
  tooling and carry no license in the SBOM. Mention the count if the user asks
  why a total looks low.
- A `multiple_detected` finding means GitHub reported several licenses for one
  package, so the effective license is unclear. Do not describe it as if the
  strictest one applies — it is a review item, not a violation.

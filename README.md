# Organization-wide dependency license check

A monthly script that checks **dependency licenses across every repository** in a
GitHub organization against the Open Source Office license matrix, and reports
each repository as 🟢 green / 🟡 yellow / 🔴 red.

It implements the rules in *Open Source Office – License Scanning Requirements
Document*: the license matrix, the four tiers, per-repo legal risk profiles,
customizable warning messages, admin overrides, build blocking, incremental
reporting, and automatic Jira ticket creation.

Python 3.8+, no third-party dependencies.

---

## Quick start

```bash
# Offline demo against the bundled fixture — no credentials needed
./run-monthly.sh --demo

# The real thing
export GITHUB_TOKEN=ghp_...          # or APP_ID + APP_PRIVATE_KEY
./run-monthly.sh --org my-org
```

Reports land in `output/`:

| File | Contents |
|------|----------|
| `LICENSE_REPORT.md` | Human-readable report: blocked repos, what's new, per-repo findings |
| `findings.json` | Machine-readable findings (no raw package dumps) |
| `report.json` | Everything, including the full package list per repo |
| `jira-tickets.json` | Tickets that were created, or would be created without `--jira` |

Exit codes: **0** clean · **1** the run itself failed · **2** policy failure
(findings at or above `--fail-on`).

---

## The four tiers

Straight from the requirements doc:

| Tier | Meaning | Build |
|------|---------|-------|
| 🟢 **Green** | Every license is on the approved list, or there is no open source | Proceeds |
| 🟡 **Yellow** | Proceeds, but OSO is notified and must review the use case | Proceeds |
| 🔴 **Red** | A license rejected for this repo's risk profile, or on the banned list | **Blocked** |
| 🔴 **Red – cloned repo** | Copyleft code inside a fork/clone; patching it needs OSO approval | **Blocked** |

A repository's tier is the worst tier among its dependencies.

## Legal risk profiles

The same license is fine in one context and forbidden in another, so each repo
is evaluated against a profile. `policy/repo-profiles.json` maps repositories to
profiles; anything unlisted uses `default_profile` (**server-side**).

| Profile | Applies to | Reject list used |
|---------|-----------|------------------|
| `distributed` | Shipped to customers | Reject Licenses Distributed Code |
| `server-side` | Yahoo-operated backends (default) | Reject Licenses Server-Side Only |
| `mobile` | App-store apps — distribution rules apply | Reject Licenses Distributed Code |
| `internal` | Never leaves Yahoo | Banned list only |
| `ai-model` | OSS AI models — always flagged for OSO review | Reject Licenses Distributed Code |

So GPL-2.0 is 🔴 red in a `distributed` repo, 🟡 yellow in a `server-side` one,
and AGPL is 🔴 red everywhere, including `internal`.

Wildcards are supported, exact matches win:

```json
{
  "repos": {
    "my-org/android-app": "mobile",
    "my-org/sdk-*": "distributed",
    "my-org/internal-tools": "internal"
  }
}
```

Override for one run with `--profile distributed`.

---

## Configuration

Everything an OSO admin needs to change lives in `policy/`. No code changes.

### `policy/license-matrix.json`

The doc's matrix, transcribed verbatim: 46 approved licenses, 26 rejected
server-side, 118 rejected for distributed code, plus the banned list.

SBOMs report SPDX identifiers (`Apache-2.0`) while the matrix uses OSO/Mend
display names (`Apache 2.0`), so the file also carries:

- **`aliases`** – SPDX id → OSO name (`BSD-3-Clause` → `BSD 3`)
- **`patterns`** – family fallbacks for unrecognised variants (`^LGPL` → `LGPL`)
- **`copyleft_families`** – what triggers the cloned-repo block

SPDX version suffixes are folded automatically, so `GPL-2.0`, `GPL-2.0-only`,
`GPL-2.0-or-later` and `GPL-2.0+` all resolve to `GPL 2.0`.

SPDX **expressions** are evaluated properly: `OR` is a choice so the most
permissive branch wins (`LGPL-2.1-or-later OR Apache-2.0` is green), `AND`
requires both so the strictest wins (`MIT AND GPL-3.0-only` is red).

A license that is neither approved nor rejected is 🟡 yellow for OSO review, and
its raw identifier is kept in the report so the reviewer can see what it was.

### `policy/policy.json`

Rules and messages:

- `default_profile`, `profiles` – which reject list each profile uses
- `messages` – the customizable warning text, per outcome and per license
  family, with `{license}`, `{package}`, `{version}`, `{repo}`, `{profile}`
- `flag_rejected_by_stricter_profile` – when true (default), a license that is
  permitted today but would block distribution is reported yellow rather than
  green. Set false to silence those.
- `cloned_repos` – forks are detected automatically; list non-fork clones here
- `jira` – project, issue type, which tiers get tickets
- `fail_on` – default tier that fails the run

### `policy/exceptions.json`

OSO approvals and admin overrides. Covers three requirements at once: recording
an approval so a repo stops being notified, unblocking a license for one repo,
and letting an admin override a red.

```json
{
  "approvals": [
    {
      "repo": "my-org/data-pipeline",
      "license": "GPL 2.0",
      "package": "legacy-*",
      "tier": "green",
      "approved_by": "oso-reviewer",
      "ticket": "OSO-1234",
      "expires": "2027-01-01"
    }
  ]
}
```

`repo`, `license` and `package` accept `*` and trailing-`*` wildcards. `tier`
is `green` to silence a finding entirely or `yellow` to downgrade a red to a
notification. **Approvals expire**: once past `expires` the finding comes back
and the report lists the approval under "Expired approvals". Approved findings
stay in the report — greyed to green, with the approver and ticket — so the
exception itself stays auditable.

---

## Reporting

The report is always complete, and adds a **"New since last run"** section by
diffing against `state/last-run.json`. That is what makes the monthly cadence
usable: month two shows the handful of things that changed, not all 4,000
packages again.

Findings are fingerprinted by repo + package + version + licenses + status, so
a version bump that keeps the same license does not resurface, while a license
change does. Run with `--no-incremental` for a standalone full report.

---

## Jira tickets

Per the doc's "auto generate jira tickets when unapproved licenses are found".

**Nothing is filed by default.** A normal run writes the tickets it *would*
create to `output/jira-tickets.json` so OSO can review them. Add `--jira` to
actually file them:

```bash
export JIRA_BASE_URL=https://my-org.atlassian.net
export JIRA_EMAIL=oso-bot@my-org.com
export JIRA_API_TOKEN=...
./run-monthly.sh --org my-org --jira
```

One ticket per repository per tier, deduplicated through
`state/jira-index.json` so the monthly run does not re-file the same problem —
a repo already tracked only gets a new ticket when new findings appear.

---

## Blocking builds early

The monthly sweep is the safety net. To catch a bad license when it lands,
`.github/workflows/license-gate.yml` is a reusable workflow other repos call
from their own build:

```yaml
jobs:
  licenses:
    uses: my-org/org-license-check/.github/workflows/license-gate.yml@main
    with:
      profile: distributed
    secrets:
      app-id: ${{ secrets.APP_ID }}
      app-private-key: ${{ secrets.APP_PRIVATE_KEY }}
```

It scans only the calling repository, uses the same central policy, and fails
the build on 🔴 red.

---

## CLI

```
./run-monthly.sh [options]

  --org NAME              GitHub organization (or $ORG_NAME)
  --repo OWNER/NAME       Check only these repos; repeatable
  --profile NAME          Force a risk profile for every repo
  --fail-on TIER          green | yellow | red | red-cloned | never
                          (default: policy.json fail_on, i.e. red)
  --jira                  Actually create Jira tickets
  --no-incremental        Skip the diff against the previous run
  --from-report PATH      Re-evaluate a saved report.json without calling the API
  --sbom PATH             Evaluate one local SPDX file (use with --repo)
  --policy-dir DIR        Default: policy/
  --out-dir DIR           Default: output/
  --state-dir DIR         Default: state/
  --demo                  Offline run against the bundled fixture
  --quiet
```

`--from-report` is worth knowing about: collecting SBOMs for a large org takes
the most time, so you can collect once and then re-run the policy repeatedly —
useful when tuning the matrix or testing an exception.

```bash
./run-monthly.sh --org my-org                                  # collect + evaluate
./run-monthly.sh --from-report output/report.json --profile distributed
```

---

## Authentication

Either works, locally and in CI:

**A token** — a PAT with `repo` scope, or an installation token:

```bash
export GITHUB_TOKEN=ghp_...
```

**GitHub App credentials** — the script mints the installation token itself
(RS256 signing is done with the `openssl` binary, so there is still nothing to
`pip install`):

```bash
export APP_ID=123456
export APP_PRIVATE_KEY="$(cat app-key.pem)"
./run-monthly.sh --org my-org
```

The App needs **Dependency graph: Read-only** and **Metadata: Read-only**, and
must be installed on the organization. With an installation token the script
lists repos via `/installation/repositories`; with a PAT it falls back to
`/orgs/{org}/repos`.

---

## Scheduling

`.github/workflows/license-check-monthly.yml` runs at 06:00 UTC on the 1st of
each month, uploads the reports as artifacts, writes the report into the job
summary, and carries `state/` between runs with `actions/cache` so the
incremental diff and Jira dedupe work.

Locally, via cron:

```cron
0 9 1 * * cd /path/to/org-license-check && GITHUB_TOKEN=... ./run-monthly.sh --org my-org
```

---

## Layout

| Path | Purpose |
|------|---------|
| `run-monthly.sh` | Entry point |
| `scripts/license_check.py` | CLI: collect → evaluate → report → Jira |
| `scripts/licensecheck/policy.py` | The rule engine (matrix + profile + exceptions → tier) |
| `scripts/licensecheck/spdx.py` | License normalization and SPDX expression parsing |
| `scripts/licensecheck/github.py` | REST client: App JWT, pagination, rate-limit retry |
| `scripts/licensecheck/report.py` | Markdown rendering and incremental diffing |
| `scripts/licensecheck/jira.py` | Ticket building and creation |
| `policy/` | Everything an OSO admin edits |
| `tests/` | `python3 -m unittest discover -s tests` |

---

## Tests

```bash
python3 -m unittest discover -s tests -v
```

59 tests covering license normalization, SPDX expression semantics, the tier
rules per profile, exceptions and expiry, incremental diffing, message
rendering, and an end-to-end run over a fixture. Several are integrity checks on
the matrix itself — that nothing is both approved and rejected, that the
server-side reject list is a subset of the distributed one, that every alias
points at a license that actually exists, and that the transcribed list lengths
still match the source document.

---

## Limitations

- **Dependency graph coverage.** Data comes from GitHub's SBOM API, so a repo
  needs a supported manifest (npm, pip, Maven, Go modules, …) or dependency
  submission. Repos without it are listed under "Repositories skipped" rather
  than passing silently. Ecosystems GitHub doesn't parse (plain C/C++ without
  Conan or Bazel) need a scanner like ScanCode feeding the submission API.
- **Declared licenses, not scanned ones.** The check trusts what packages
  declare. It will not find a vendored GPL file inside an MIT-declared package;
  that needs full-text scanning.
- **The matrix is a snapshot.** `policy/license-matrix.json` reflects the doc as
  written. When OSO revises it, update that file — the integrity tests will
  catch a contradictory edit.

## Open items from the requirements doc

Two action items are owned by OSO rather than this repo:

- **The authoritative license matrix.** The transcribed matrix is the Mend list
  from the doc. If OSO publishes a revised matrix, it replaces
  `policy/license-matrix.json`.
- **Reporting requirements** (incremental / full / license level). Implemented
  as described above; the knobs are under `reporting` in `policy/policy.json`.

One design decision worth confirming with OSO: repos not listed in
`repo-profiles.json` default to **server-side**, which permits GPL. If OSO would
rather unclassified repos be treated as distributed, change `default_profile` to
`distributed` — expect most repos to go red until they are classified.

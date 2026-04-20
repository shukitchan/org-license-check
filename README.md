# Organization-wide weekly dependency license check

A GitHub Actions workflow that runs **weekly** and checks **dependency licenses** for **all repositories** in a GitHub organization, using a **GitHub App** for authentication and the GitHub Dependency Graph (SBOM) API.

## How it works

1. **Weekly schedule**: The workflow runs every Sunday at 00:00 UTC (configurable via `cron`).
2. **GitHub App token**: The workflow uses `actions/create-github-app-token` to obtain an installation access token for your app.
3. **List repos**: It calls `GET /installation/repositories` to list every repository the app can access (all repos in the org, if the app is installed on the organization).
4. **Fetch SBOM per repo**: For each repo it calls `GET /repos/{owner}/{repo}/dependency-graph/sbom` to get the SPDX SBOM (only repos with dependency graph data will return results).
5. **Parse licenses**: Scripts extract `licenseConcluded` and `licenseDeclared` from each package in the SBOM.
6. **Report**: A JSON report and a Markdown summary are generated and uploaded as workflow artifacts. The job summary shows a short preview.

## Prerequisites

- A **GitHub App** installed on your **organization** (or on selected repositories).
- The app must have permission to read the **dependency graph** (and metadata/contents as required by the token action).
- A **repository** in that organization that will host this workflow (e.g. `org-license-check` or `org-automation`).

## 1. Create the GitHub App

1. Go to **GitHub** → **Settings** (for the org) → **Developer settings** → **GitHub Apps** → **New GitHub App** (or use an existing app).
2. Set:
  - **Name**: e.g. `Org License Check`
  - **Homepage URL**: your org or repo URL
  - **Webhook**: Uncheck "Active" unless you need webhooks
  - **Repository permissions**:
    - **Dependency graph**: Read-only
    - **Contents**: Read-only (optional; required by some token flows)
    - **Metadata**: Read-only (default)
3. Under **Where can this GitHub App be installed?** choose **Only on this account** (your org).
4. Click **Create GitHub App**.
5. Note the **App ID** (e.g. `123456`).
6. Generate a **Private key** and save the `.pem` file securely. You will store the **entire PEM contents** (including `-----BEGIN RSA PRIVATE KEY-----` and `-----END RSA PRIVATE KEY-----`) in a secret.

## 2. Install the app on the organization

1. Go to the app’s **Install App** (or from the app settings, "Install App").
2. Choose your **organization** and either **All repositories** or select the repos you want to include (the workflow will only see repos the installation can access).
3. Complete the installation.

## 3. Add secrets to the workflow repository

In the **repository** where this workflow lives (e.g. `my-org/org-license-check`):

1. **Settings** → **Secrets and variables** → **Actions**.
2. Add:
  - `**APP_ID`**: The GitHub App ID (numeric string).
  - `**APP_PRIVATE_KEY**`: The full contents of the app’s private key (the `.pem` file). Paste the whole key, including the BEGIN/END lines.

You do **not** need to store the Installation ID when using `actions/create-github-app-token` with `owner`; the action resolves the installation by owner (your org).

## 4. Optional: set the organization name

- By default the workflow uses the **repository owner** as the org (so in `my-org/org-license-check`, it uses `my-org`).
- To override (e.g. run from a personal repo and target an org):
  - Use **Variables** → **Organization variables** and set `ORG_NAME`, or
  - When running **workflow_dispatch**, use the input **Organization name**.

## 5. Enable dependency graph

- Dependency graph must be **enabled** for the organization and for the repos you care about (it’s usually on by default for public repos and for private repos when enabled in org settings).
- Only repos that have **dependency graph data** (from supported manifests/lockfiles or dependency submission) will have SBOM data; others will be listed as skipped in the report.

## Workflow and scripts


| Path                                         | Purpose                                                                        |
| -------------------------------------------- | ------------------------------------------------------------------------------ |
| `.github/workflows/license-check-weekly.yml` | Scheduled + manual workflow; generates token, runs scripts, uploads artifacts. |
| `scripts/collect-org-licenses.js`            | Lists installation repos, fetches SBOM for each, outputs JSON report.          |
| `scripts/report-to-markdown.js`              | Converts `report.json` to `LICENSE_REPORT.md`.                                 |


## Output

- **Job summary**: Short Markdown preview of the report.
- **Artifacts**: `license-report-<run_number>` containing:
  - `report.json` – full JSON (repos, packages, license counts).
  - `LICENSE_REPORT.md` – human-readable report.
  - `repos.log` – stderr from the collector (e.g. API errors).

## Limitations

- **Dependency graph only**: Data comes from GitHub’s dependency graph (SBOM). Repos without supported manifests (e.g. npm, pip, Maven, Go modules) or without dependency submission will have no or limited data.
- **No C/C++ etc.**: For ecosystems GitHub doesn’t parse (e.g. plain C/C++ without Conan/Bazel), consider adding a separate step that runs a license scanner (e.g. ScanCode) or uses the dependency submission API.
- **Rate limits**: For large orgs, many SBOM requests in one run may hit rate limits; the scripts do not currently add delays (you can add a short `sleep` in the script if needed).

## Running manually

Use **Actions** → **Weekly org dependency license check** → **Run workflow** and optionally set **Organization name**.

## Extending

- **Open an issue on findings**: In the workflow, add a step that reads `report.json`, checks for disallowed licenses, and uses `github.rest.issues.create` to open an issue (you’d need to pass a token with `issues: write` or use the default `GITHUB_TOKEN` for the same repo).
- **Slack/email**: Add a step that posts `LICENSE_REPORT.md` or a summary to Slack or sends an email (e.g. via a webhook or API).


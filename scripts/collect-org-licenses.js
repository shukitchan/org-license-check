#!/usr/bin/env node
/**
 * List all repos accessible to the GitHub App installation, fetch SBOM for each,
 * and output a JSON report of repo -> packages with license info.
 * Usage: node collect-org-licenses.js <org-name> <installation-access-token>
 */

const ORG = process.argv[2];
const TOKEN = process.argv[3];
const API_BASE = process.env.GITHUB_API_URL || 'https://api.github.com';
const PER_PAGE = 100;

if (!TOKEN) {
  console.error('Usage: node collect-org-licenses.js <org-name> <installation-access-token>');
  process.exit(1);
}

async function fetchJson(url, token) {
  const res = await fetch(url, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${token}`,
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });
  if (res.status === 404) return null;
  if (!res.ok) {
    const t = await res.text();
    throw new Error(`${res.status} ${url}: ${t}`);
  }
  return res.json();
}

async function* listInstallationRepos(token) {
  let page = 1;
  let total = 0;
  do {
    const url = `${API_BASE}/installation/repositories?per_page=${PER_PAGE}&page=${page}`;
    const data = await fetchJson(url, token);
    if (!data || !data.repositories) break;
    for (const repo of data.repositories) {
      if (ORG && repo.owner?.login !== ORG) continue;
      total++;
      yield repo;
    }
    if (!data.repositories.length) break;
    page++;
  } while (true);
}

function extractLicenses(sbom) {
  const packages = sbom?.packages || [];
  return packages
    .filter((p) => p.SPDXID && !p.SPDXID.includes('SPDXRef-DOCUMENT'))
    .map((p) => ({
      name: p.name || p.SPDXID,
      version: p.versionInfo || null,
      licenseConcluded: p.licenseConcluded || null,
      licenseDeclared: p.licenseDeclared || null,
    }));
}

async function main() {
  const report = {
    org: ORG || 'installation',
    generated_at: new Date().toISOString(),
    repos_checked: 0,
    repos_with_sbom: 0,
    repos_skipped: [],
    total_packages: 0,
    by_repo: {},
    license_summary: {},
  };

  for await (const repo of listInstallationRepos(TOKEN)) {
    const fullName = repo.full_name;
    const sbomUrl = `${API_BASE}/repos/${fullName}/dependency-graph/sbom`;

    let sbom;
    try {
      sbom = await fetchJson(sbomUrl, TOKEN);
    } catch (e) {
      report.repos_skipped.push({ repo: fullName, reason: e.message });
      continue;
    }

    if (!sbom) {
      report.repos_skipped.push({ repo: fullName, reason: 'no_sbom_or_404' });
      continue;
    }

    const packages = extractLicenses(sbom);
    report.repos_checked++;
    if (packages.length > 0) report.repos_with_sbom++;
    report.total_packages += packages.length;
    report.by_repo[fullName] = packages;

    for (const p of packages) {
      const lic = p.licenseConcluded || p.licenseDeclared || 'NOASSERTION';
      report.license_summary[lic] = (report.license_summary[lic] || 0) + 1;
    }
  }

  console.log(JSON.stringify(report, null, 2));
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});

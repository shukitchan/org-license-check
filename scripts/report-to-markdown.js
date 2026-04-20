#!/usr/bin/env node
/**
 * Read report.json (from collect-org-licenses.js) and write LICENSE_REPORT.md
 * Usage: node report-to-markdown.js [report.json]
 */

const fs = require('fs');
const path = process.argv[2] || 'report.json';

const report = JSON.parse(fs.readFileSync(path, 'utf8'));

const lines = [
  `# Dependency license report – ${report.org}`,
  '',
  `Generated: ${report.generated_at}`,
  '',
  `- Repositories checked: ${report.repos_checked}`,
  `- Repositories with dependency data: ${report.repos_with_sbom}`,
  `- Total packages: ${report.total_packages}`,
  '',
  '## License summary (all packages)',
  '',
  '| License | Count |',
  '|---------|-------|',
];

const sorted = Object.entries(report.license_summary || {}).sort((a, b) => b[1] - a[1]);
for (const [lic, count] of sorted) {
  lines.push(`| ${lic} | ${count} |`);
}

lines.push('', '## By repository', '');

const repoNames = Object.keys(report.by_repo || {}).sort();
for (const fullName of repoNames) {
  const packages = report.by_repo[fullName];
  if (packages.length === 0) continue;
  lines.push(`### ${fullName}`, '');
  lines.push('| Package | Version | Concluded | Declared |');
  lines.push('|---------|---------|-----------|----------|');
  for (const p of packages.slice(0, 100)) {
    const name = (p.name || '').replace(/\|/g, '\\|');
    const ver = (p.version || '-').replace(/\|/g, '\\|');
    const concl = (p.licenseConcluded || '-').replace(/\|/g, '\\|');
    const decl = (p.licenseDeclared || '-').replace(/\|/g, '\\|');
    lines.push(`| ${name} | ${ver} | ${concl} | ${decl} |`);
  }
  if (packages.length > 100) {
    lines.push(`| ... | ${packages.length - 100} more packages | | |`);
  }
  lines.push('');
}

if (report.repos_skipped?.length) {
  lines.push('## Repositories skipped', '');
  for (const { repo, reason } of report.repos_skipped) {
    lines.push(`- \`${repo}\`: ${reason}`);
  }
}

process.stdout.write(lines.join('\n'));

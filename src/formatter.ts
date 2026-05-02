import chalk from 'chalk';
import { Finding, FindingStatus } from './types';

interface ScanSummary {
  total: number;
  pass: number;
  fail: number;
  warn: number;
  skip: number;
  inconclusive: number;
}

const STATUS_ORDER: FindingStatus[] = ['FAIL', 'WARN', 'INCONCLUSIVE', 'PASS', 'SKIP'];

function summarize(findings: Finding[]): ScanSummary {
  return {
    total: findings.length,
    pass: findings.filter((f) => f.status === 'PASS').length,
    fail: findings.filter((f) => f.status === 'FAIL').length,
    warn: findings.filter((f) => f.status === 'WARN').length,
    skip: findings.filter((f) => f.status === 'SKIP').length,
    inconclusive: findings.filter((f) => f.status === 'INCONCLUSIVE').length,
  };
}

function groupByStatus(findings: Finding[]): Map<FindingStatus, Finding[]> {
  const groups = new Map<FindingStatus, Finding[]>();
  for (const status of STATUS_ORDER) groups.set(status, []);
  for (const f of findings) groups.get(f.status)!.push(f);
  return groups;
}

interface ParsedRef {
  framework: string; // "EU AI Act" / "NIST AI RMF" / "ISO/IEC 42001"
  items: { id: string; desc?: string }[];
}

// Parse the verbose reference strings from rules into structured (id, desc) pairs.
// Single source of truth so terminal and HTML can render compactly without
// asking each rule to duplicate data.
function parseRef(s: string | undefined, kind: 'eu' | 'nist' | 'iso'): ParsedRef | null {
  if (!s) return null;
  if (kind === 'eu') {
    // "EU AI Act Article 12(1) - Description"
    const m = s.match(/^EU AI Act\s+(.+?)\s+-\s+(.+)$/);
    if (!m) return { framework: 'EU AI Act', items: [{ id: s, desc: undefined }] };
    return { framework: 'EU AI Act', items: [{ id: m[1].trim(), desc: m[2].trim() }] };
  }
  // NIST/ISO share format: "<Framework>: <ID> (<desc>); <ID> (<desc>)"
  // Use the last ": " (colon-space) so we skip embedded version numbers like
  // "ISO/IEC 42001:2023 Annex A:" - the items start after the trailing ": ".
  const split = s.lastIndexOf(': ');
  if (split < 0) return { framework: kind === 'nist' ? 'NIST AI RMF' : 'ISO/IEC 42001', items: [] };
  const framework = kind === 'nist' ? 'NIST AI RMF' : 'ISO/IEC 42001';
  const rest = s.slice(split + 2).trim();
  const parts = rest.split(';').map((p) => p.trim()).filter(Boolean);
  const items = parts.map((p) => {
    const m = p.match(/^(.+?)\s*\(([^)]+)\)\s*$/);
    return m ? { id: m[1].trim(), desc: m[2].trim() } : { id: p, desc: undefined };
  });
  return { framework, items };
}

function findingRefs(f: Finding): ParsedRef[] {
  return [
    parseRef(f.regulatoryReference, 'eu'),
    parseRef(f.nistReference, 'nist'),
    parseRef(f.isoReference, 'iso'),
  ].filter((r): r is ParsedRef => r !== null && r.items.length > 0);
}

// ─────────────────────────────────────────────────────────────────────
// Terminal
// ─────────────────────────────────────────────────────────────────────

function statusIcon(status: FindingStatus): string {
  switch (status) {
    case 'PASS': return chalk.green('✓');
    case 'FAIL': return chalk.red('✗');
    case 'WARN': return chalk.yellow('⚠');
    case 'SKIP': return chalk.gray('-');
    case 'INCONCLUSIVE': return chalk.magenta('?');
  }
}

function statusColor(status: FindingStatus): (text: string) => string {
  switch (status) {
    case 'PASS': return chalk.green;
    case 'FAIL': return chalk.red;
    case 'WARN': return chalk.yellow;
    case 'SKIP': return chalk.gray;
    case 'INCONCLUSIVE': return chalk.magenta;
  }
}

function compactRefLine(refs: ParsedRef[]): string {
  // "EU 12(1) · NIST GOVERN 1.4, MEASURE 2.7 · ISO A.6.2.8, A.6.2.6"
  const shortName: Record<string, string> = {
    'EU AI Act': 'EU',
    'NIST AI RMF': 'NIST',
    'ISO/IEC 42001': 'ISO',
  };
  return refs
    .map((r) => `${shortName[r.framework] ?? r.framework} ${r.items.map((i) => i.id).join(', ')}`)
    .join('  ·  ');
}

export function formatTerminal(findings: Finding[]): string {
  const lines: string[] = [];
  const summary = summarize(findings);
  const groups = groupByStatus(findings);

  lines.push('');
  lines.push(chalk.bold('infrarails - Compliance Report'));
  lines.push(chalk.dim('EU AI Act Article 12  ·  NIST AI RMF  ·  ISO/IEC 42001'));
  lines.push('');

  // Top-line summary
  lines.push(
    `${chalk.green(`${summary.pass} passed`)}   ${chalk.red(`${summary.fail} failed`)}   ${chalk.yellow(`${summary.warn} warnings`)}   ${chalk.magenta(`${summary.inconclusive} inconclusive`)}   ${chalk.gray(`${summary.skip} skipped`)}`
  );
  lines.push('');

  for (const status of STATUS_ORDER) {
    const items = groups.get(status)!;
    if (items.length === 0) continue;

    const color = statusColor(status);
    lines.push(color(chalk.bold(`- ${status} (${items.length}) -`)));
    lines.push('');

    for (const f of items) {
      const icon = statusIcon(f.status);
      const location = f.filePath
        ? `${f.filePath}${f.line ? `:${f.line}` : ''}`
        : '';

      lines.push(`${icon} ${chalk.bold(f.ruleId)}  ${f.description}`);
      if (location) lines.push(`   ${chalk.dim(location)}`);
      if (f.remediation) lines.push(`   ${chalk.cyan('→')} ${f.remediation}`);

      const refs = findingRefs(f);
      if (refs.length > 0) lines.push(`   ${chalk.dim(compactRefLine(refs))}`);
      lines.push('');
    }
  }

  if (summary.inconclusive > 0) {
    lines.push(
      chalk.dim(
        'Note: INCONCLUSIVE = could not verify statically (variables, SSM, module outputs).\n' +
        '      For audit-grade evidence run against `terraform show -json`.'
      )
    );
    lines.push('');
  }

  lines.push(chalk.dim(
    'Disclaimer: This report reflects the findings of an automated static analysis of your AWS AI\n' +
    'infrastructure configuration against selected controls from the EU AI Act, NIST AI RMF, and\n' +
    'ISO/IEC 42001. A passing result indicates that the scanned Terraform configuration satisfies\n' +
    'the specific infrastructure-layer prerequisite checked - it does not constitute compliance with\n' +
    'any of these frameworks, nor does it substitute for a formal audit, certification, or conformity\n' +
    'assessment conducted by an accredited body. Compliance with the EU AI Act, NIST AI RMF, and\n' +
    'ISO/IEC 42001 requires organisational, procedural, and governance measures that are outside the\n' +
    'scope of infrastructure scanning. This report should be treated as a pre-audit readiness input,\n' +
    'not an attestation of conformance.'
  ));
  lines.push('');

  return lines.join('\n');
}

// ─────────────────────────────────────────────────────────────────────
// JSON
// ─────────────────────────────────────────────────────────────────────

export function formatJson(findings: Finding[]): string {
  const summary = summarize(findings);
  return JSON.stringify({ summary, findings }, null, 2);
}

// ─────────────────────────────────────────────────────────────────────
// HTML
// ─────────────────────────────────────────────────────────────────────

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function statusClass(status: FindingStatus): string {
  return status.toLowerCase();
}

function frameworkSlug(framework: string): string {
  if (framework === 'EU AI Act') return 'eu';
  if (framework === 'NIST AI RMF') return 'nist';
  if (framework === 'ISO/IEC 42001') return 'iso';
  return 'other';
}

function renderFindingCard(f: Finding): string {
  const cls = statusClass(f.status);
  const location = f.filePath
    ? `<span class="location">${escapeHtml(f.filePath)}${f.line ? `:${f.line}` : ''}</span>`
    : '';
  const remediation = f.remediation
    ? `<p class="remediation"><span class="arrow">&rarr;</span> ${escapeHtml(f.remediation)}</p>`
    : '';

  const refs = findingRefs(f);
  const refPills = refs
    .map((r) => {
      const slug = frameworkSlug(r.framework);
      const pills = r.items
        .map((i) => {
          const tooltip = i.desc ? ` title="${escapeHtml(i.desc)}"` : '';
          return `<span class="pill ${slug}"${tooltip}>${escapeHtml(i.id)}</span>`;
        })
        .join('');
      return `<span class="ref-group"><span class="fw-label">${escapeHtml(r.framework)}</span>${pills}</span>`;
    })
    .join('');

  return `      <article class="finding ${cls}">
        <div class="finding-head">
          <span class="status-pill ${cls}">${f.status}</span>
          <span class="rule-id">${escapeHtml(f.ruleId)}</span>
          ${location}
        </div>
        <p class="description">${escapeHtml(f.description)}</p>
        ${remediation}
        <div class="refs">${refPills}</div>
      </article>`;
}

const STATUS_LABELS: Record<FindingStatus, string> = {
  FAIL: 'Failures - fix these',
  WARN: 'Warnings',
  INCONCLUSIVE: 'Inconclusive - verify manually',
  PASS: 'Passing',
  SKIP: 'Skipped (not applicable)',
};

export function formatHtml(findings: Finding[]): string {
  const summary = summarize(findings);
  const groups = groupByStatus(findings);
  const generatedAt =
    new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

  const sections = STATUS_ORDER
    .map((status) => {
      const items = groups.get(status)!;
      if (items.length === 0) return '';
      const cls = statusClass(status);
      const cards = items.map(renderFindingCard).join('\n');
      // Default-collapse PASS and SKIP - they're not what you came here for.
      const open = status === 'PASS' || status === 'SKIP' ? '' : ' open';
      return `    <details class="group ${cls}"${open}>
      <summary>
        <span class="group-status ${cls}">${status}</span>
        <span class="group-label">${STATUS_LABELS[status]}</span>
        <span class="group-count">${items.length}</span>
      </summary>
${cards}
    </details>`;
    })
    .filter(Boolean)
    .join('\n');

  const note = summary.inconclusive > 0
    ? `<p class="note"><strong>About INCONCLUSIVE:</strong> the scanner could not verify these statically - typically because of variables without defaults, SSM parameters, or module outputs. For audit-grade evidence, run against <code>terraform show -json</code>.</p>`
    : '';

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>infrarails - Compliance Report</title>
<style>
  :root {
    --pass: #16a34a; --fail: #dc2626; --warn: #d97706;
    --skip: #6b7280; --inconclusive: #9333ea;
    --bg: #f8fafc; --card: #ffffff; --border: #e5e7eb;
    --text: #111827; --muted: #6b7280;
    --eu: #1e40af; --nist: #0f766e; --iso: #7e22ce;
  }
  * { box-sizing: border-box; }
  body {
    font: 15px/1.5 -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    background: var(--bg); color: var(--text);
    margin: 0; padding: 2rem 1rem;
  }
  .container { max-width: 880px; margin: 0 auto; }
  header.top { margin-bottom: 1.5rem; }
  header.top h1 { font-size: 1.5rem; margin: 0; }
  header.top .subtitle { color: var(--muted); margin: .25rem 0 0; font-size: .9rem; }
  header.top .meta { color: var(--muted); font-size: .8rem; margin-top: .5rem; }

  .summary-bar {
    display: flex; flex-wrap: wrap; gap: 1.25rem;
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 1.5rem;
  }
  .summary-bar .stat { display: flex; align-items: baseline; gap: .4rem; }
  .summary-bar .count { font-size: 1.5rem; font-weight: 700; }
  .summary-bar .label { color: var(--muted); font-size: .85rem; }
  .stat.pass .count { color: var(--pass); }
  .stat.fail .count { color: var(--fail); }
  .stat.warn .count { color: var(--warn); }
  .stat.inconclusive .count { color: var(--inconclusive); }
  .stat.skip .count { color: var(--skip); }

  details.group {
    background: var(--card); border: 1px solid var(--border);
    border-radius: 8px; margin-bottom: 1rem; overflow: hidden;
  }
  details.group > summary {
    list-style: none; cursor: pointer; padding: .85rem 1.25rem;
    display: flex; align-items: center; gap: .75rem;
    user-select: none;
  }
  details.group > summary::-webkit-details-marker { display: none; }
  details.group > summary::before {
    content: '\\25B8'; color: var(--muted); transition: transform .15s;
    display: inline-block; width: 1rem;
  }
  details.group[open] > summary::before { transform: rotate(90deg); }
  .group-status {
    font-size: .7rem; font-weight: 700; letter-spacing: .05em;
    padding: .2rem .55rem; border-radius: 4px; color: #fff;
  }
  .group-status.pass { background: var(--pass); }
  .group-status.fail { background: var(--fail); }
  .group-status.warn { background: var(--warn); }
  .group-status.skip { background: var(--skip); }
  .group-status.inconclusive { background: var(--inconclusive); }
  .group-label { font-weight: 600; flex: 1; }
  .group-count {
    background: #f3f4f6; color: var(--muted);
    padding: .15rem .55rem; border-radius: 999px; font-size: .8rem; font-weight: 600;
  }

  .finding {
    border-top: 1px solid var(--border);
    padding: 1rem 1.25rem;
  }
  .finding-head { display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; margin-bottom: .35rem; }
  .status-pill {
    font-size: .65rem; font-weight: 700; letter-spacing: .05em;
    padding: .15rem .45rem; border-radius: 3px; color: #fff;
  }
  .status-pill.pass { background: var(--pass); }
  .status-pill.fail { background: var(--fail); }
  .status-pill.warn { background: var(--warn); }
  .status-pill.skip { background: var(--skip); }
  .status-pill.inconclusive { background: var(--inconclusive); }
  .rule-id {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-weight: 600; font-size: .85rem;
  }
  .location {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: .75rem; color: var(--muted); margin-left: auto;
  }
  .description { margin: .35rem 0; }
  .remediation {
    background: #ecfdf5; border-left: 3px solid var(--pass);
    padding: .55rem .75rem; margin: .5rem 0; border-radius: 4px;
    font-size: .9rem;
  }
  .remediation .arrow { color: var(--pass); font-weight: 700; margin-right: .35rem; }

  .refs {
    display: flex; flex-wrap: wrap; gap: .65rem .85rem;
    margin-top: .65rem; align-items: center;
  }
  .ref-group { display: inline-flex; align-items: center; gap: .3rem; flex-wrap: wrap; }
  .fw-label { font-size: .7rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; font-weight: 600; }
  .pill {
    font-family: ui-monospace, 'SF Mono', Menlo, Consolas, monospace;
    font-size: .72rem; padding: .12rem .45rem;
    border-radius: 3px; cursor: help;
    border: 1px solid;
  }
  .pill.eu { background: #eff6ff; color: var(--eu); border-color: #bfdbfe; }
  .pill.nist { background: #f0fdfa; color: var(--nist); border-color: #99f6e4; }
  .pill.iso { background: #faf5ff; color: var(--iso); border-color: #e9d5ff; }

  .note {
    background: #faf5ff; border-left: 3px solid var(--inconclusive);
    padding: .75rem 1rem; margin-top: 1.5rem; border-radius: 4px;
    font-size: .85rem; color: #4b1d6f;
  }
  .disclaimer {
    background: #f8fafc; border: 1px solid var(--border); border-radius: 6px;
    padding: .85rem 1rem; margin-top: 2rem;
    font-size: .78rem; color: var(--muted); line-height: 1.6;
  }
  .disclaimer strong { display: block; margin-bottom: .25rem; color: var(--text); }
  code { background: #f3f4f6; padding: .1rem .3rem; border-radius: 3px; font-size: .9em; }

  @media print {
    body { background: #fff; padding: 0; font-size: 12px; }
    details.group { box-shadow: none; page-break-inside: avoid; }
    details.group:not([open]) { display: none; }
    .pill { cursor: default; }
  }
</style>
</head>
<body>
<div class="container">
  <header class="top">
    <h1>infrarails - Compliance Report</h1>
    <p class="subtitle">EU AI Act Article 12 &middot; NIST AI RMF &middot; ISO/IEC 42001</p>
    <p class="meta">${escapeHtml(generatedAt)} &middot; ${summary.total} findings</p>
  </header>

  <div class="summary-bar">
    <div class="stat fail"><span class="count">${summary.fail}</span><span class="label">failed</span></div>
    <div class="stat warn"><span class="count">${summary.warn}</span><span class="label">warnings</span></div>
    <div class="stat inconclusive"><span class="count">${summary.inconclusive}</span><span class="label">inconclusive</span></div>
    <div class="stat pass"><span class="count">${summary.pass}</span><span class="label">passed</span></div>
    <div class="stat skip"><span class="count">${summary.skip}</span><span class="label">skipped</span></div>
  </div>

${sections}

  ${note}

  <div class="disclaimer">
    <strong>Disclaimer</strong>
    This report reflects the findings of an automated static analysis of your AWS AI infrastructure configuration against selected controls from the EU AI Act, NIST AI RMF, and ISO/IEC 42001. A passing result indicates that the scanned Terraform configuration satisfies the specific infrastructure-layer prerequisite checked - it does not constitute compliance with any of these frameworks, nor does it substitute for a formal audit, certification, or conformity assessment conducted by an accredited body. Compliance with the EU AI Act, NIST AI RMF, and ISO/IEC 42001 requires organisational, procedural, and governance measures that are outside the scope of infrastructure scanning. This report should be treated as a pre-audit readiness input, not an attestation of conformance.
  </div>
</div>
</body>
</html>
`;
}

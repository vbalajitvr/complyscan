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

function statusIcon(status: FindingStatus): string {
  switch (status) {
    case 'PASS':
      return chalk.green('\u2713');
    case 'FAIL':
      return chalk.red('\u2717');
    case 'WARN':
      return chalk.yellow('\u26A0');
    case 'SKIP':
      return chalk.gray('-');
    case 'INCONCLUSIVE':
      return chalk.magenta('?');
  }
}

function statusColor(status: FindingStatus): (text: string) => string {
  switch (status) {
    case 'PASS':
      return chalk.green;
    case 'FAIL':
      return chalk.red;
    case 'WARN':
      return chalk.yellow;
    case 'SKIP':
      return chalk.gray;
    case 'INCONCLUSIVE':
      return chalk.magenta;
  }
}

export function formatTerminal(findings: Finding[]): string {
  const lines: string[] = [];
  const summary = summarize(findings);

  lines.push('');
  lines.push(chalk.bold('complyscan — EU AI Act Article 12 Compliance Scan'));
  lines.push('');

  for (const finding of findings) {
    const icon = statusIcon(finding.status);
    const color = statusColor(finding.status);
    const location = finding.filePath
      ? `${finding.filePath}${finding.line ? `:${finding.line}` : ''}`
      : '';

    lines.push(`${icon} ${color(`[${finding.status}]`)} ${chalk.bold(finding.ruleId)} ${finding.description}`);
    if (location) {
      lines.push(`  ${chalk.dim(location)}`);
    }
    if (finding.remediation) {
      lines.push(`  ${chalk.cyan('Remediation:')} ${finding.remediation}`);
    }
    lines.push(`  ${chalk.dim(finding.regulatoryReference)}`);
    lines.push('');
  }

  lines.push(chalk.bold('Summary:'));
  lines.push(
    `  ${chalk.green(`${summary.pass} passed`)}  ${chalk.red(`${summary.fail} failed`)}  ${chalk.yellow(`${summary.warn} warnings`)}  ${chalk.magenta(`${summary.inconclusive} inconclusive`)}  ${chalk.gray(`${summary.skip} skipped`)}`
  );
  if (summary.inconclusive > 0) {
    lines.push('');
    lines.push(
      chalk.magenta(
        '  Note: INCONCLUSIVE findings indicate references that could not be resolved statically'
      )
    );
    lines.push(
      chalk.magenta(
        '  (variables without defaults, SSM parameters, module outputs, etc.). Source-only scanning'
      )
    );
    lines.push(
      chalk.magenta(
        '  cannot verify these checks. For audit-grade evidence run against `terraform show -json`.'
      )
    );
  }
  lines.push('');

  return lines.join('\n');
}

export function formatJson(findings: Finding[]): string {
  const summary = summarize(findings);
  return JSON.stringify({ summary, findings }, null, 2);
}

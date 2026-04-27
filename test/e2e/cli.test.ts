import { describe, it, expect } from 'vitest';
import { execSync } from 'child_process';
import * as path from 'path';

function hcl2jsonAvailable(): boolean {
  try {
    execSync('hcl2json --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

const describeIf = hcl2jsonAvailable() ? describe : describe.skip;

const cliPath = path.resolve(__dirname, '../../dist/index.js');
const fixturesDir = path.resolve(__dirname, '../fixtures');

function runCli(args: string): { stdout: string; exitCode: number } {
  try {
    const stdout = execSync(`node ${cliPath} ${args}`, {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    return { stdout, exitCode: 0 };
  } catch (err: any) {
    return { stdout: err.stdout || '', exitCode: err.status ?? 1 };
  }
}

const combosDir = path.resolve(__dirname, '../fixtures/bedrock-logging-combos');

describeIf('CLI e2e', () => {
  it('should exit 0 for compliant fixtures', () => {
    const result = runCli(`${fixturesDir}/compliant`);
    expect(result.exitCode).toBe(0);
  });

  it('should exit 1 for non-compliant fixtures', () => {
    const result = runCli(`${fixturesDir}/non-compliant`);
    expect(result.exitCode).toBe(1);
  });

  it('should exit 1 for partial fixtures (has WARNs)', () => {
    const result = runCli(`${fixturesDir}/partial`);
    expect(result.exitCode).toBe(1);
  });

  it('should output valid JSON with --format json', () => {
    const result = runCli(`${fixturesDir}/non-compliant --format json`);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.summary).toBeDefined();
    expect(parsed.findings).toBeDefined();
    expect(parsed.summary.fail).toBeGreaterThan(0);
  });

  it('should exit 0 for directory with no .tf files', () => {
    const emptyDir = path.resolve(__dirname, '../../node_modules/.cache');
    execSync(`mkdir -p ${emptyDir}`);
    const result = runCli(emptyDir);
    expect(result.exitCode).toBe(0);
  });

  // Bedrock logging combo fixtures
  it('combo 1 (s3-only): should exit 0 for fully compliant s3-only config', () => {
    const result = runCli(`${combosDir}/s3-only`);
    expect(result.exitCode).toBe(0);
  });

  it('combo 2 (cw-only): should exit 0 for fully compliant cloudwatch-only config', () => {
    const result = runCli(`${combosDir}/cw-only`);
    expect(result.exitCode).toBe(0);
  });

  it('combo 3 (cw-and-s3): should exit 0 for fully compliant cloudwatch+s3 config', () => {
    const result = runCli(`${combosDir}/cw-and-s3`);
    expect(result.exitCode).toBe(0);
  });

  it('combo 4 (cw-large-data): should exit 0 for fully compliant cloudwatch+large-data-s3 config', () => {
    const result = runCli(`${combosDir}/cw-large-data`);
    expect(result.exitCode).toBe(0);
  });

  it('combo 5 (cw-s3-large-data): should exit 0 for fully compliant cloudwatch+s3+large-data-s3 config', () => {
    const result = runCli(`${combosDir}/cw-s3-large-data`);
    expect(result.exitCode).toBe(0);
  });

  it('usage-no-logging: Bedrock resources without invocation logging should FAIL S-12.1.1', () => {
    const result = runCli(`${combosDir}/usage-no-logging --format json`);
    expect(result.exitCode).toBe(1);
    const parsed = JSON.parse(result.stdout);
    const finding = parsed.findings.find(
      (f: { ruleId: string; status: string }) => f.ruleId === 'S-12.1.1',
    );
    expect(finding?.status).toBe('FAIL');
    expect(finding?.description).toMatch(/aws_bedrockagent_agent|aws_bedrock_guardrail/);
  });

  it('no-usage-no-logging: no Bedrock anywhere should SKIP S-12.1.1 (exit 0)', () => {
    const result = runCli(`${combosDir}/no-usage-no-logging --format json`);
    const parsed = JSON.parse(result.stdout);
    const finding = parsed.findings.find(
      (f: { ruleId: string; status: string }) => f.ruleId === 'S-12.1.1',
    );
    expect(finding?.status).toBe('SKIP');
    expect(result.exitCode).toBe(0);
  });

  it('usage-logging-all-disabled: all modality toggles false should FAIL S-12.1.1', () => {
    const result = runCli(`${combosDir}/usage-logging-all-disabled --format json`);
    expect(result.exitCode).toBe(1);
    const parsed = JSON.parse(result.stdout);
    const finding = parsed.findings.find(
      (f: { ruleId: string; status: string }) => f.ruleId === 'S-12.1.1',
    );
    expect(finding?.status).toBe('FAIL');
    expect(finding?.description).toMatch(/all data-delivery toggles/i);
  });

  it('regression: large-data bucket with no lifecycle should fail S-12.1.2b', () => {
    const result = runCli(
      `${fixturesDir}/non-compliant/cw-large-data-missing-lifecycle --format json`,
    );
    expect(result.exitCode).toBe(1);
    const parsed = JSON.parse(result.stdout);
    const lifecycleFinding = parsed.findings.find(
      (f: { ruleId: string; status: string }) =>
        f.ruleId === 'S-12.1.2b' && f.status === 'FAIL',
    );
    expect(lifecycleFinding).toBeDefined();
  });

  describe('module handling', () => {
    const moduleAuditDir = path.resolve(__dirname, '../fixtures/module-audit');

    it('local-module-logging-inside: resources in local module are fully scanned (exit 0)', () => {
      const result = runCli(`${moduleAuditDir}/local-module-logging-inside --format json`);
      expect(result.exitCode).toBe(0);
      const parsed = JSON.parse(result.stdout);
      const bedrockFinding = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.1',
      );
      expect(bedrockFinding?.status).toBe('PASS');
    });

    it('remote-module-invisible: S-12.1.1 INCONCLUSIVE and S-12.x.5 INCONCLUSIVE (exit 1)', () => {
      const result = runCli(`${moduleAuditDir}/remote-module-invisible --format json`);
      expect(result.exitCode).toBe(1);
      const parsed = JSON.parse(result.stdout);

      const s1 = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.1.1');
      expect(s1?.status).toBe('INCONCLUSIVE');

      const s5 = parsed.findings.find((f: { ruleId: string }) => f.ruleId === 'S-12.x.5');
      expect(s5?.status).toBe('INCONCLUSIVE');
      expect(s5?.description).toContain('terraform-aws-modules/bedrock/aws');
    });

    it('var-scope-bleed: child var with no default resolves to INCONCLUSIVE, not parent default', () => {
      const result = runCli(`${moduleAuditDir}/var-scope-bleed --format json`);
      const parsed = JSON.parse(result.stdout);
      const lifecycle = parsed.findings.find(
        (f: { ruleId: string }) => f.ruleId === 'S-12.1.2b',
      );
      // With scope fix: child var.log_bucket has no default → INCONCLUSIVE
      // Without fix it would resolve to "parent-log-bucket" and FAIL
      expect(lifecycle?.status).toBe('INCONCLUSIVE');
    });
  });

  describe('INCONCLUSIVE behaviour', () => {
    const inconclusiveDir = path.resolve(__dirname, '../fixtures/inconclusive');

    it('SSM-sourced bucket name produces INCONCLUSIVE findings (exit 1 in default strict mode)', () => {
      const result = runCli(`${inconclusiveDir}/ssm-bucket --format json`);
      expect(result.exitCode).toBe(1);
      const parsed = JSON.parse(result.stdout);
      expect(parsed.summary.inconclusive).toBeGreaterThan(0);
      const inconclusive = parsed.findings.filter(
        (f: { status: string }) => f.status === 'INCONCLUSIVE',
      );
      expect(inconclusive.length).toBeGreaterThan(0);
      // every inconclusive should mention the SSM expression
      for (const f of inconclusive) {
        expect(f.description).toMatch(/data\.aws_ssm_parameter|SSM/);
      }
    });

    it('SSM-sourced bucket name with --no-strict exits 0 even with INCONCLUSIVE', () => {
      const result = runCli(`${inconclusiveDir}/ssm-bucket --no-strict --format json`);
      expect(result.exitCode).toBe(0);
      const parsed = JSON.parse(result.stdout);
      expect(parsed.summary.inconclusive).toBeGreaterThan(0);
      // No FAIL/WARN should be present (only INCONCLUSIVE for the bucket-scoped rules)
      expect(parsed.summary.fail).toBe(0);
      expect(parsed.summary.warn).toBe(0);
    });

    it('var without default produces INCONCLUSIVE (exit 1 default)', () => {
      const result = runCli(`${inconclusiveDir}/var-no-default --format json`);
      expect(result.exitCode).toBe(1);
      const parsed = JSON.parse(result.stdout);
      expect(parsed.summary.inconclusive).toBeGreaterThan(0);
      const inconclusive = parsed.findings.filter(
        (f: { status: string }) => f.status === 'INCONCLUSIVE',
      );
      for (const f of inconclusive) {
        expect(f.description).toMatch(/var\.log_bucket_name|var\.log_group_name/);
      }
    });

    it('var with default resolves and exits 0 (fully compliant)', () => {
      const result = runCli(`${inconclusiveDir}/var-with-default --format json`);
      expect(result.exitCode).toBe(0);
      const parsed = JSON.parse(result.stdout);
      expect(parsed.summary.inconclusive).toBe(0);
      expect(parsed.summary.fail).toBe(0);
      expect(parsed.summary.warn).toBe(0);
      expect(parsed.summary.pass).toBeGreaterThan(0);
    });
  });
});

import { describe, it, expect } from 'vitest';
import { planDeletionsRule } from '../../../src/rules/plan-deletions';
import {
  ParsedFile,
  PlanDeletion,
  PlanOverlay,
  ScanContext,
} from '../../../src/types';

function ctx(overrides: Partial<ScanContext> = {}): ScanContext {
  return {
    bedrockLoggingDetected: true,
    logBucketNames: ['acme-prod-bedrock-logs'],
    logGroupNames: ['/aws/bedrock/invocation-logs'],
    unresolvedBucketRefs: [],
    unresolvedGroupRefs: [],
    strictAccountLogging: false,
    ...overrides,
  };
}

function overlay(deletions: PlanDeletion[]): PlanOverlay {
  const map = new Map<string, PlanDeletion>();
  for (const d of deletions) {
    map.set(`${d.type}.${d.name}`, d);
  }
  return {
    formatVersion: '1.2',
    terraformVersion: '1.7.5',
    resources: new Map(),
    deletions: map,
    flags: { noActionableChanges: false },
    variables: new Map(),
    outputs: new Map(),
  };
}

function deletion(
  partial: Partial<PlanDeletion> & { type: string; name: string },
): PlanDeletion {
  return {
    address: partial.address ?? `${partial.type}.${partial.name}`,
    type: partial.type,
    name: partial.name,
    before: partial.before ?? {},
    replaceWithCreate: partial.replaceWithCreate ?? false,
  };
}

const files: ParsedFile[] = [];

describe('planDeletionsRule', () => {
  it('SKIPs when no overlay is present', () => {
    const findings = planDeletionsRule.run(files, ctx({ planOverlay: undefined }));
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('PASSes when overlay has no deletions', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({ planOverlay: overlay([]) }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('FAILs on aws_bedrock_model_invocation_logging_configuration deletion', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({
        planOverlay: overlay([
          deletion({
            type: 'aws_bedrock_model_invocation_logging_configuration',
            name: 'main',
            before: {
              logging_config: { s3_config: { bucket_name: 'acme-prod-bedrock-logs' } },
            },
          }),
        ]),
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toMatch(/acme-prod-bedrock-logs/);
    expect(findings[0].filePath).toBe(
      'plan:aws_bedrock_model_invocation_logging_configuration.main',
    );
  });

  it('FAILs on encryption-config deletion', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({
        planOverlay: overlay([
          deletion({
            type: 'aws_s3_bucket_server_side_encryption_configuration',
            name: 'logs_enc',
          }),
        ]),
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toMatch(/Encryption configuration/);
  });

  it('FAILs on a log-bucket deletion when bucket is referenced by Bedrock logging', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({
        planOverlay: overlay([
          deletion({
            type: 'aws_s3_bucket',
            name: 'logs',
            before: { bucket: 'acme-prod-bedrock-logs' },
          }),
        ]),
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toMatch(/log bucket "acme-prod-bedrock-logs"/);
  });

  it('does not emit a finding for unrelated bucket deletions', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({
        planOverlay: overlay([
          deletion({
            type: 'aws_s3_bucket',
            name: 'unrelated',
            before: { bucket: 'static-website' },
          }),
        ]),
      }),
    );
    // No in-scope deletions -> single PASS
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('FAILs on log-group deletion when referenced by Bedrock logging', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({
        planOverlay: overlay([
          deletion({
            type: 'aws_cloudwatch_log_group',
            name: 'bedrock',
            before: { name: '/aws/bedrock/invocation-logs' },
          }),
        ]),
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toMatch(
      /\/aws\/bedrock\/invocation-logs/,
    );
  });

  it('FAILs on lifecycle-config deletion on a log bucket', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({
        planOverlay: overlay([
          deletion({
            type: 'aws_s3_bucket_lifecycle_configuration',
            name: 'lc',
            before: { bucket: 'acme-prod-bedrock-logs' },
          }),
        ]),
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
  });

  it('FAILs on aws_cloudwatch_log_metric_filter deletion', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({
        planOverlay: overlay([
          deletion({ type: 'aws_cloudwatch_log_metric_filter', name: 'errors' }),
        ]),
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
  });

  it('FAILs on aws_cloudwatch_metric_alarm deletion', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({
        planOverlay: overlay([
          deletion({ type: 'aws_cloudwatch_metric_alarm', name: 'errors_alarm' }),
        ]),
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
  });

  it('emits WARN for replacement actions', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({
        planOverlay: overlay([
          deletion({
            type: 'aws_bedrock_model_invocation_logging_configuration',
            name: 'main',
            replaceWithCreate: true,
            before: {
              logging_config: { s3_config: { bucket_name: 'acme-prod-bedrock-logs' } },
            },
          }),
        ]),
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].description).toMatch(/brief gap/);
  });

  it('does not emit a finding for out-of-scope resource types', () => {
    const findings = planDeletionsRule.run(
      files,
      ctx({
        planOverlay: overlay([
          deletion({ type: 'aws_iam_role', name: 'unused' }),
          deletion({ type: 'aws_security_group', name: 'web' }),
        ]),
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });
});

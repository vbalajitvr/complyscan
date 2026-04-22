import { describe, it, expect } from 'vitest';
import { s3LifecycleRule } from '../../../src/rules/s-12-1-2b-s3-lifecycle';
import { makeParsedFile, emptyContext, bedrockContext } from './helpers';

describe('S-12.1.2b S3 Lifecycle Retention', () => {
  it('should SKIP when no Bedrock logging detected', () => {
    const files = [makeParsedFile({})];
    const findings = s3LifecycleRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('should SKIP when Bedrock logging has no S3 buckets', () => {
    const ctx = bedrockContext({ bucketNames: [] });
    const files = [makeParsedFile({})];
    const findings = s3LifecycleRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('should FAIL when no lifecycle configuration found', () => {
    const ctx = bedrockContext();
    const files = [makeParsedFile({})];
    const findings = s3LifecycleRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
  });

  it('should FAIL when retention < 180 days', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_s3_bucket_lifecycle_configuration: {
          logs: [
            {
              bucket: 'my-ai-log-bucket',
              rule: [{ id: 'retain', status: 'Enabled', expiration: [{ days: 30 }] }],
            },
          ],
        },
      }),
    ];
    const findings = s3LifecycleRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
  });

  it('should WARN when retention >= 180 but < 365 days', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_s3_bucket_lifecycle_configuration: {
          logs: [
            {
              bucket: 'my-ai-log-bucket',
              rule: [{ id: 'retain', status: 'Enabled', expiration: [{ days: 200 }] }],
            },
          ],
        },
      }),
    ];
    const findings = s3LifecycleRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
  });

  it('should PASS when retention >= 365 days', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_s3_bucket_lifecycle_configuration: {
          logs: [
            {
              bucket: 'my-ai-log-bucket',
              rule: [{ id: 'retain', status: 'Enabled', expiration: [{ days: 365 }] }],
            },
          ],
        },
      }),
    ];
    const findings = s3LifecycleRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should FAIL when no expiration days set', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_s3_bucket_lifecycle_configuration: {
          logs: [
            {
              bucket: 'my-ai-log-bucket',
              rule: [{ id: 'retain', status: 'Enabled' }],
            },
          ],
        },
      }),
    ];
    const findings = s3LifecycleRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
  });

  describe('INCONCLUSIVE handling', () => {
    it('emits INCONCLUSIVE when bucket reference is from SSM (unresolvable)', () => {
      const ctx = bedrockContext({
        bucketNames: [],
        unresolvedBucketRefs: [
          {
            expression: '${data.aws_ssm_parameter.log_bucket.value}',
            reason: 'data-source-ssm',
            sourceField: 'logging_config.s3_config.bucket_name',
          },
        ],
      });
      const findings = s3LifecycleRule.run([makeParsedFile({})], ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].status).toBe('INCONCLUSIVE');
      expect(findings[0].description).toContain('data.aws_ssm_parameter.log_bucket.value');
      expect(findings[0].description).toContain('SSM');
    });

    it('emits INCONCLUSIVE when bucket reference is var without default', () => {
      const ctx = bedrockContext({
        bucketNames: [],
        unresolvedBucketRefs: [
          {
            expression: '${var.log_bucket}',
            reason: 'var-no-default',
            sourceField: 'logging_config.s3_config.bucket_name',
          },
        ],
      });
      const findings = s3LifecycleRule.run([makeParsedFile({})], ctx);
      expect(findings).toHaveLength(1);
      expect(findings[0].status).toBe('INCONCLUSIVE');
    });

    it('runs both INCONCLUSIVE and normal checks when mixed', () => {
      const ctx = bedrockContext({
        bucketNames: ['my-ai-log-bucket'],
        unresolvedBucketRefs: [
          {
            expression: '${var.other_bucket}',
            reason: 'var-no-default',
            sourceField: 'logging_config.s3_config.bucket_name',
          },
        ],
      });
      const files = [
        makeParsedFile({
          aws_s3_bucket_lifecycle_configuration: {
            logs: [
              {
                bucket: 'my-ai-log-bucket',
                rule: [{ id: 'retain', status: 'Enabled', expiration: [{ days: 365 }] }],
              },
            ],
          },
        }),
      ];
      const findings = s3LifecycleRule.run(files, ctx);
      expect(findings).toHaveLength(2);
      const statuses = findings.map((f) => f.status).sort();
      expect(statuses).toEqual(['INCONCLUSIVE', 'PASS']);
    });
  });
});

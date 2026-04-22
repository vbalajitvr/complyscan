import { describe, it, expect } from 'vitest';
import { s3VersioningRule } from '../../../src/rules/s-12-x-1-s3-versioning';
import { makeParsedFile, emptyContext, bedrockContext } from './helpers';

describe('S-12.x.1 S3 Versioning', () => {
  it('should SKIP when no Bedrock logging detected', () => {
    const files = [makeParsedFile({})];
    const findings = s3VersioningRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('should SKIP when Bedrock logging has no S3 buckets', () => {
    const ctx = bedrockContext({ bucketNames: [] });
    const files = [makeParsedFile({})];
    const findings = s3VersioningRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('should FAIL when no versioning or object lock configured', () => {
    const ctx = bedrockContext();
    const files = [makeParsedFile({})];
    const findings = s3VersioningRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
  });

  it('should PASS when versioning is enabled', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_s3_bucket_versioning: {
          logs: [
            {
              bucket: 'my-ai-log-bucket',
              versioning_configuration: [{ status: 'Enabled' }],
            },
          ],
        },
      }),
    ];
    const findings = s3VersioningRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should PASS when object lock is configured', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_s3_bucket_object_lock_configuration: {
          logs: [
            {
              bucket: 'my-ai-log-bucket',
              rule: [{ default_retention: [{ mode: 'COMPLIANCE', days: 365 }] }],
            },
          ],
        },
      }),
    ];
    const findings = s3VersioningRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should FAIL when versioning status is not Enabled', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_s3_bucket_versioning: {
          logs: [
            {
              bucket: 'my-ai-log-bucket',
              versioning_configuration: [{ status: 'Suspended' }],
            },
          ],
        },
      }),
    ];
    const findings = s3VersioningRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
  });
});

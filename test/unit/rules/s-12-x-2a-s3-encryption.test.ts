import { describe, it, expect } from 'vitest';
import { s3EncryptionRule } from '../../../src/rules/s-12-x-2a-s3-encryption';
import { makeParsedFile, emptyContext, bedrockContext } from './helpers';

describe('S-12.x.2a S3 Encryption', () => {
  it('should SKIP when no Bedrock logging detected', () => {
    const files = [makeParsedFile({})];
    const findings = s3EncryptionRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('should SKIP when Bedrock logging has no S3 buckets', () => {
    const ctx = bedrockContext({ bucketNames: [] });
    const files = [makeParsedFile({})];
    const findings = s3EncryptionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('should FAIL when no encryption config found', () => {
    const ctx = bedrockContext();
    const files = [makeParsedFile({})];
    const findings = s3EncryptionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
  });

  it('should PASS when using aws:kms encryption', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_s3_bucket_server_side_encryption_configuration: {
          logs: [
            {
              bucket: 'my-ai-log-bucket',
              rule: [
                {
                  apply_server_side_encryption_by_default: [
                    { sse_algorithm: 'aws:kms' },
                  ],
                },
              ],
            },
          ],
        },
      }),
    ];
    const findings = s3EncryptionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should PASS when using aws:kms:dsse encryption', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_s3_bucket_server_side_encryption_configuration: {
          logs: [
            {
              bucket: 'my-ai-log-bucket',
              rule: [
                {
                  apply_server_side_encryption_by_default: [
                    { sse_algorithm: 'aws:kms:dsse' },
                  ],
                },
              ],
            },
          ],
        },
      }),
    ];
    const findings = s3EncryptionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should FAIL when using AES256 encryption', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_s3_bucket_server_side_encryption_configuration: {
          logs: [
            {
              bucket: 'my-ai-log-bucket',
              rule: [
                {
                  apply_server_side_encryption_by_default: [
                    { sse_algorithm: 'AES256' },
                  ],
                },
              ],
            },
          ],
        },
      }),
    ];
    const findings = s3EncryptionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
  });
});

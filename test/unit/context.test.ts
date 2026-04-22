import { describe, it, expect } from 'vitest';
import { buildScanContext } from '../../src/context';
import { makeParsedFile } from './rules/helpers';

function bedrockConfig(loggingConfig: Record<string, unknown>) {
  return makeParsedFile({
    aws_bedrock_model_invocation_logging_configuration: {
      main: [{ logging_config: [loggingConfig] }],
    },
  });
}

describe('buildScanContext', () => {
  it('returns empty context when no bedrock logging', () => {
    const ctx = buildScanContext([makeParsedFile({})]);
    expect(ctx.bedrockLoggingDetected).toBe(false);
    expect(ctx.logBucketNames).toEqual([]);
    expect(ctx.logGroupNames).toEqual([]);
  });

  // combo #1 — S3 only
  it('combo 1: s3_config only — extracts bucket, no log group', () => {
    const ctx = buildScanContext([
      bedrockConfig({ s3_config: [{ bucket_name: 'my-s3-only-bucket' }] }),
    ]);
    expect(ctx.bedrockLoggingDetected).toBe(true);
    expect(ctx.logBucketNames).toEqual(['my-s3-only-bucket']);
    expect(ctx.logGroupNames).toEqual([]);
  });

  // combo #2 — CloudWatch only
  it('combo 2: cloudwatch_config only — extracts log group, no bucket', () => {
    const ctx = buildScanContext([
      bedrockConfig({
        cloudwatch_config: [{ log_group_name: '/aws/bedrock/cw-only' }],
      }),
    ]);
    expect(ctx.bedrockLoggingDetected).toBe(true);
    expect(ctx.logBucketNames).toEqual([]);
    expect(ctx.logGroupNames).toEqual(['/aws/bedrock/cw-only']);
  });

  // combo #3 — CloudWatch + S3
  it('combo 3: cloudwatch_config + s3_config — extracts both', () => {
    const ctx = buildScanContext([
      bedrockConfig({
        s3_config: [{ bucket_name: 'my-s3-bucket' }],
        cloudwatch_config: [{ log_group_name: '/aws/bedrock/logs' }],
      }),
    ]);
    expect(ctx.bedrockLoggingDetected).toBe(true);
    expect(ctx.logBucketNames).toEqual(['my-s3-bucket']);
    expect(ctx.logGroupNames).toEqual(['/aws/bedrock/logs']);
  });

  // combo #4 — CloudWatch + large-data S3 (no top-level s3_config)
  it('combo 4: cloudwatch_config with large_data_delivery_s3_config — extracts nested bucket', () => {
    const ctx = buildScanContext([
      bedrockConfig({
        cloudwatch_config: [
          {
            log_group_name: '/aws/bedrock/cw-large',
            large_data_delivery_s3_config: [{ bucket_name: 'my-large-data-bucket' }],
          },
        ],
      }),
    ]);
    expect(ctx.bedrockLoggingDetected).toBe(true);
    expect(ctx.logBucketNames).toEqual(['my-large-data-bucket']);
    expect(ctx.logGroupNames).toEqual(['/aws/bedrock/cw-large']);
  });

  // combo #5 — CloudWatch + S3 + large-data S3
  it('combo 5: all three configs — extracts both buckets and log group', () => {
    const ctx = buildScanContext([
      bedrockConfig({
        s3_config: [{ bucket_name: 'my-main-bucket' }],
        cloudwatch_config: [
          {
            log_group_name: '/aws/bedrock/combo5',
            large_data_delivery_s3_config: [{ bucket_name: 'my-large-data-bucket' }],
          },
        ],
      }),
    ]);
    expect(ctx.bedrockLoggingDetected).toBe(true);
    expect(ctx.logBucketNames).toEqual(['my-main-bucket', 'my-large-data-bucket']);
    expect(ctx.logGroupNames).toEqual(['/aws/bedrock/combo5']);
  });

  // combo #5 with same bucket referenced in both s3_config and large_data — deduplicated
  it('combo 5: same bucket in s3_config and large_data_delivery_s3_config — deduplicated', () => {
    const ctx = buildScanContext([
      bedrockConfig({
        s3_config: [{ bucket_name: 'shared-bucket' }],
        cloudwatch_config: [
          {
            log_group_name: '/aws/bedrock/shared',
            large_data_delivery_s3_config: [{ bucket_name: 'shared-bucket' }],
          },
        ],
      }),
    ]);
    expect(ctx.logBucketNames).toEqual(['shared-bucket']);
  });

  // resolver: large_data bucket via resource reference
  it('combo 4: resolves large_data bucket from resource reference', () => {
    const files = [
      makeParsedFile({
        aws_s3_bucket: {
          overflow: [{ bucket: 'resolved-large-data-bucket' }],
        },
        aws_bedrock_model_invocation_logging_configuration: {
          main: [
            {
              logging_config: [
                {
                  cloudwatch_config: [
                    {
                      log_group_name: '/aws/bedrock/ref-test',
                      large_data_delivery_s3_config: [
                        { bucket_name: 'aws_s3_bucket.overflow.id' },
                      ],
                    },
                  ],
                },
              ],
            },
          ],
        },
      }),
    ];
    const ctx = buildScanContext(files);
    expect(ctx.logBucketNames).toEqual(['resolved-large-data-bucket']);
  });

  it('resolves resource references for top-level s3_config bucket names', () => {
    const files = [
      makeParsedFile({
        aws_s3_bucket: {
          logs: [{ bucket: 'resolved-bucket-name' }],
        },
        aws_bedrock_model_invocation_logging_configuration: {
          main: [
            {
              logging_config: [
                {
                  s3_config: [{ bucket_name: 'aws_s3_bucket.logs.id' }],
                },
              ],
            },
          ],
        },
      }),
    ];
    const ctx = buildScanContext(files);
    expect(ctx.bedrockLoggingDetected).toBe(true);
    expect(ctx.logBucketNames).toEqual(['resolved-bucket-name']);
  });

  describe('unresolved references', () => {
    it('SSM data source bucket reference goes to unresolvedBucketRefs', () => {
      const ctx = buildScanContext([
        bedrockConfig({
          s3_config: [{ bucket_name: '${data.aws_ssm_parameter.log_bucket.value}' }],
        }),
      ]);
      expect(ctx.bedrockLoggingDetected).toBe(true);
      expect(ctx.logBucketNames).toEqual([]);
      expect(ctx.unresolvedBucketRefs).toHaveLength(1);
      expect(ctx.unresolvedBucketRefs[0]).toMatchObject({
        reason: 'data-source-ssm',
        sourceField: 'logging_config.s3_config.bucket_name',
      });
    });

    it('var without default goes to unresolvedBucketRefs', () => {
      const files = [
        makeParsedFile({
          aws_bedrock_model_invocation_logging_configuration: {
            main: [
              {
                logging_config: [
                  { s3_config: [{ bucket_name: '${var.log_bucket}' }] },
                ],
              },
            ],
          },
        }),
      ];
      // Add the variable declaration without a default
      files[0].json.variable = { log_bucket: [{ type: 'string' }] };
      const ctx = buildScanContext(files);
      expect(ctx.unresolvedBucketRefs).toHaveLength(1);
      expect(ctx.unresolvedBucketRefs[0].reason).toBe('var-no-default');
    });

    it('var with default resolves to literal — no unresolved entry', () => {
      const files = [
        makeParsedFile({
          aws_bedrock_model_invocation_logging_configuration: {
            main: [
              {
                logging_config: [
                  { s3_config: [{ bucket_name: '${var.log_bucket}' }] },
                ],
              },
            ],
          },
        }),
      ];
      files[0].json.variable = { log_bucket: [{ default: 'default-bucket' }] };
      const ctx = buildScanContext(files);
      expect(ctx.logBucketNames).toEqual(['default-bucket']);
      expect(ctx.unresolvedBucketRefs).toHaveLength(0);
    });

    it('module output goes to unresolvedBucketRefs', () => {
      const ctx = buildScanContext([
        bedrockConfig({
          s3_config: [{ bucket_name: '${module.logging.bucket_name}' }],
        }),
      ]);
      expect(ctx.unresolvedBucketRefs[0].reason).toBe('module-output');
    });

    it('CloudWatch log group from SSM goes to unresolvedGroupRefs (not bucketRefs)', () => {
      const ctx = buildScanContext([
        bedrockConfig({
          cloudwatch_config: [
            { log_group_name: '${data.aws_ssm_parameter.cw.value}' },
          ],
        }),
      ]);
      expect(ctx.unresolvedGroupRefs).toHaveLength(1);
      expect(ctx.unresolvedGroupRefs[0].reason).toBe('data-source-ssm');
      expect(ctx.unresolvedBucketRefs).toHaveLength(0);
    });

    it('large_data_delivery_s3_config from SSM is also tracked', () => {
      const ctx = buildScanContext([
        bedrockConfig({
          cloudwatch_config: [
            {
              log_group_name: '/aws/bedrock/logs',
              large_data_delivery_s3_config: [
                { bucket_name: '${data.aws_ssm_parameter.large_bucket.value}' },
              ],
            },
          ],
        }),
      ]);
      expect(ctx.logGroupNames).toEqual(['/aws/bedrock/logs']);
      expect(ctx.unresolvedBucketRefs).toHaveLength(1);
      expect(ctx.unresolvedBucketRefs[0].sourceField).toBe(
        'logging_config.cloudwatch_config.large_data_delivery_s3_config.bucket_name',
      );
    });

    it('mixed case: one resolved bucket + one unresolved (separate Bedrock configs)', () => {
      const ctx = buildScanContext([
        makeParsedFile({
          aws_bedrock_model_invocation_logging_configuration: {
            main: [
              { logging_config: [{ s3_config: [{ bucket_name: 'literal-bucket' }] }] },
            ],
            other: [
              {
                logging_config: [
                  {
                    s3_config: [
                      { bucket_name: '${data.aws_ssm_parameter.x.value}' },
                    ],
                  },
                ],
              },
            ],
          },
        }),
      ]);
      expect(ctx.logBucketNames).toEqual(['literal-bucket']);
      expect(ctx.unresolvedBucketRefs).toHaveLength(1);
    });
  });
});

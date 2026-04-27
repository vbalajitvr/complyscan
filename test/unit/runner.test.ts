import { describe, it, expect } from 'vitest';
import { runScan } from '../../src/runner';
import { makeParsedFile } from './rules/helpers';

describe('runScan', () => {
  it('should return findings from all rules', () => {
    const files = [makeParsedFile({})];
    const findings = runScan(files);

    // With no resources: S-12.1.1 SKIP (no Bedrock usage), S-12.x.4 FAIL, others SKIP
    expect(findings.length).toBeGreaterThan(0);

    const ruleIds = findings.map((f) => f.ruleId);
    expect(ruleIds).toContain('S-12.1.1');
    expect(ruleIds).toContain('S-12.x.4');
  });

  it('should run phase1 rules before phase2', () => {
    const files = [
      makeParsedFile({
        aws_bedrock_model_invocation_logging_configuration: {
          main: [
            {
              logging_config: [
                {
                  s3_config: [{ bucket_name: 'my-bucket' }],
                  cloudwatch_config: [{ log_group_name: '/aws/bedrock/logs' }],
                },
              ],
            },
          ],
        },
        aws_cloudtrail: {
          main: [{ name: 'trail', s3_bucket_name: 'bucket', enable_logging: true }],
        },
      }),
    ];

    const findings = runScan(files);

    // Phase 1 rule (S-12.1.1) should PASS
    const bedrockFinding = findings.find((f) => f.ruleId === 'S-12.1.1');
    expect(bedrockFinding?.status).toBe('PASS');

    // Phase 2 context-dependent rules should NOT be SKIP (bedrock logging detected)
    const cwFinding = findings.find((f) => f.ruleId === 'S-12.1.2a');
    expect(cwFinding?.status).not.toBe('SKIP');
  });
});

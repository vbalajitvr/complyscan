import { describe, it, expect } from 'vitest';
import { runScan } from '../../src/runner';
import { PlanOverlay } from '../../src/types';
import { makeParsedFile } from './rules/helpers';

function emptyOverlay(): PlanOverlay {
  return {
    formatVersion: '1.2',
    terraformVersion: '1.7.5',
    resources: new Map(),
    deletions: new Map(),
    flags: { noActionableChanges: false },
    variables: new Map(),
    outputs: new Map(),
  };
}

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

  describe('strict + plan INCONCLUSIVE escalation', () => {
    // A logging config that points at a bucket via a var with no default.
    // With no overlay variables, the bucket reference is unresolvable with
    // reason 'var-no-default' - an escalatable reason.
    const filesWithUnresolvedBucket = () => [
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
      // variable block in same module so the resolver finds it
      {
        filePath: 'vars.tf',
        rawHcl: '',
        json: { variable: { log_bucket: [{ type: 'string' }] } },
      },
    ];

    it('escalates var-no-default INCONCLUSIVE to FAIL under plan + strict', () => {
      const findings = runScan(filesWithUnresolvedBucket(), {
        strictAccountLogging: true,
        plan: emptyOverlay(),
      });
      const lifecycle = findings.find((f) => f.ruleId === 'S-12.1.2b');
      expect(lifecycle?.status).toBe('FAIL');
      expect(lifecycle?.description).not.toContain('Strict account-logging');
      expect(lifecycle?.remediation).toContain('Escalated to FAIL');
    });

    it('leaves INCONCLUSIVE alone when plan is absent (strict only)', () => {
      const findings = runScan(filesWithUnresolvedBucket(), {
        strictAccountLogging: true,
      });
      const lifecycle = findings.find((f) => f.ruleId === 'S-12.1.2b');
      expect(lifecycle?.status).toBe('INCONCLUSIVE');
    });

    it('leaves INCONCLUSIVE alone when strict is off (plan only)', () => {
      const findings = runScan(filesWithUnresolvedBucket(), {
        plan: emptyOverlay(),
      });
      const lifecycle = findings.find((f) => f.ruleId === 'S-12.1.2b');
      expect(lifecycle?.status).toBe('INCONCLUSIVE');
    });

    it('does not escalate findings without an unresolvedReason tag', () => {
      // A bare scan with no Bedrock at all produces structural findings
      // (no unresolvedReason). Strict + plan must not flip those.
      const findings = runScan([makeParsedFile({})], {
        strictAccountLogging: true,
        plan: emptyOverlay(),
      });
      // S-12.1.1 SKIP (no Bedrock) must stay SKIP, not become FAIL.
      const bedrock = findings.find((f) => f.ruleId === 'S-12.1.1');
      expect(bedrock?.status).toBe('SKIP');
    });

    it('does NOT escalate plan-remote-state-unreachable (platform-team concern)', () => {
      // Bedrock points at a baseline-stack output not present in the overlay.
      // Strict + plan must leave this INCONCLUSIVE because remote-state
      // reachability is not user-fixable from the scanned HCL.
      const files = [
        makeParsedFile({
          aws_bedrock_model_invocation_logging_configuration: {
            main: [
              {
                logging_config: [
                  {
                    s3_config: [
                      {
                        bucket_name:
                          '${data.terraform_remote_state.account_baseline.outputs.log_bucket}',
                      },
                    ],
                  },
                ],
              },
            ],
          },
        }),
      ];
      const findings = runScan(files, {
        strictAccountLogging: true,
        plan: emptyOverlay(),
      });
      const lifecycle = findings.find((f) => f.ruleId === 'S-12.1.2b');
      expect(lifecycle?.status).toBe('INCONCLUSIVE');
    });
  });
});

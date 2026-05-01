import { describe, it, expect } from 'vitest';
import { cloudtrailRule } from '../../../src/rules/cloudtrail';
import { makeParsedFile, emptyContext } from './helpers';
import { ParsedFile } from '../../../src/types';

function fileWithRemoteState(name: string, filePath = 'main.tf'): ParsedFile {
  return {
    filePath,
    rawHcl: '',
    json: {
      data: {
        terraform_remote_state: {
          [name]: [{ backend: 's3', config: [{}] }],
        },
      },
    },
  };
}

describe('S-12.x.4 CloudTrail', () => {
  // --- No trail present -------------------------------------------------------

  it('returns INCONCLUSIVE (not FAIL) when no CloudTrail exists in default mode', () => {
    const findings = cloudtrailRule.run([makeParsedFile({})], emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].ruleId).toBe('S-12.x.4');
    expect(findings[0].description).toContain('no cross-stack evidence');
    expect(findings[0].remediation).toContain('enable_logging = true');
  });

  it('returns FAIL when no CloudTrail exists in strict-account-logging mode', () => {
    const findings = cloudtrailRule.run(
      [makeParsedFile({})],
      emptyContext({ strictAccountLogging: true }),
    );

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toContain('Strict account-logging mode');
  });

  it('returns INCONCLUSIVE with cross-stack evidence when baseline remote-state is present', () => {
    const files = [makeParsedFile({}), fileWithRemoteState('account_baseline')];
    const findings = cloudtrailRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].description).toContain('data.terraform_remote_state.account_baseline');
    expect(findings[0].description).toContain('separate stack');
  });

  it('baseline-state evidence overrides strict mode — still INCONCLUSIVE', () => {
    // When we have positive evidence of a baseline stack, a FAIL would be a
    // false positive even in strict mode.
    const files = [makeParsedFile({}), fileWithRemoteState('security')];
    const findings = cloudtrailRule.run(files, emptyContext({ strictAccountLogging: true }));

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('INCONCLUSIVE');
  });

  // --- Trail present ----------------------------------------------------------

  it('returns PASS when CloudTrail exists with logging enabled', () => {
    const files = [
      makeParsedFile({
        aws_cloudtrail: {
          main: [{ name: 'my-trail', enable_logging: true, s3_bucket_name: 'bucket' }],
        },
      }),
    ];
    const findings = cloudtrailRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('returns PASS when enable_logging is not set (provider default is true)', () => {
    const files = [
      makeParsedFile({
        aws_cloudtrail: {
          main: [{ name: 'my-trail', s3_bucket_name: 'bucket' }],
        },
      }),
    ];
    const findings = cloudtrailRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('returns FAIL when enable_logging is explicitly false', () => {
    const files = [
      makeParsedFile({
        aws_cloudtrail: {
          main: [{ name: 'my-trail', enable_logging: false, s3_bucket_name: 'bucket' }],
        },
      }),
    ];
    const findings = cloudtrailRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toContain('enable_logging set to false');
  });
});

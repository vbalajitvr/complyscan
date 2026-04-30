import { describe, it, expect } from 'vitest';
import { cloudtrailRule } from '../../../src/rules/cloudtrail';
import { makeParsedFile, emptyContext } from './helpers';

describe('S-12.x.4 CloudTrail', () => {
  it('should FAIL when no CloudTrail resource exists', () => {
    const files = [makeParsedFile({})];
    const findings = cloudtrailRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].ruleId).toBe('S-12.x.4');
  });

  it('should PASS when CloudTrail exists with logging enabled', () => {
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

  it('should PASS when enable_logging is not set (defaults to true)', () => {
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

  it('should FAIL when enable_logging is false', () => {
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
  });
});

import { describe, it, expect } from 'vitest';
import { cwRetentionRule } from '../../../src/rules/cw-retention';
import { makeParsedFile, emptyContext, bedrockContext } from './helpers';

describe('S-12.1.2a CloudWatch Retention', () => {
  it('should SKIP when no Bedrock logging detected', () => {
    const files = [makeParsedFile({})];
    const findings = cwRetentionRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('should SKIP when Bedrock logging has no CloudWatch groups', () => {
    const ctx = bedrockContext({ groupNames: [] });
    const files = [makeParsedFile({})];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
  });

  it('should WARN when log group not found in Terraform', () => {
    const ctx = bedrockContext();
    const files = [makeParsedFile({})];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].remediation).toContain('No CloudWatch subscription filter was found');
  });

  it('should WARN when retention < 180 days', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 7 }],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].remediation).toContain('No CloudWatch subscription filter was found');
  });

  it('should WARN with forwarder-found note when subscription filter is present', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 7 }],
        },
        aws_cloudwatch_log_subscription_filter: {
          datadog: [
            {
              log_group_name: '/aws/bedrock/invocation-logs',
              destination_arn: 'arn:aws:lambda:us-east-1:123456789012:function:datadog-forwarder',
              filter_pattern: '',
            },
          ],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].remediation).toContain('A CloudWatch subscription filter was found');
  });

  it('should WARN when retention >= 180 but < 365 days', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 200 }],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
  });

  it('should PASS when retention >= 365 days', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 365 }],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should PASS when retention is 0 (never expire)', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs', retention_in_days: 0 }],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should WARN when retention_in_days is not set', () => {
    const ctx = bedrockContext();
    const files = [
      makeParsedFile({
        aws_cloudwatch_log_group: {
          bedrock_logs: [{ name: '/aws/bedrock/invocation-logs' }],
        },
      }),
    ];
    const findings = cwRetentionRule.run(files, ctx);

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
  });
});

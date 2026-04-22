import { describe, it, expect } from 'vitest';
import { bedrockLoggingRule } from '../../../src/rules/s-12-1-1-bedrock-logging';
import { makeParsedFile, emptyContext } from './helpers';

describe('S-12.1.1 Bedrock Logging', () => {
  it('should WARN when no bedrock logging resource exists', () => {
    const files = [makeParsedFile({})];
    const findings = bedrockLoggingRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('WARN');
    expect(findings[0].ruleId).toBe('S-12.1.1');
  });

  it('should PASS when bedrock logging resource exists', () => {
    const files = [
      makeParsedFile({
        aws_bedrock_model_invocation_logging_configuration: {
          main: [
            {
              logging_config: [
                {
                  s3_config: [{ bucket_name: 'my-bucket' }],
                },
              ],
            },
          ],
        },
      }),
    ];

    const findings = bedrockLoggingRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('PASS');
  });

  it('should be a phase1 rule', () => {
    expect(bedrockLoggingRule.phase1).toBe(true);
  });
});

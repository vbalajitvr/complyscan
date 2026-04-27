import { describe, it, expect } from 'vitest';
import { bedrockLoggingRule } from '../../../src/rules/s-12-1-1-bedrock-logging';
import { makeParsedFile, emptyContext } from './helpers';

describe('S-12.1.1 Bedrock Logging', () => {
  it('should SKIP when no Bedrock resources and no logging config exist', () => {
    const files = [makeParsedFile({})];
    const findings = bedrockLoggingRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
    expect(findings[0].ruleId).toBe('S-12.1.1');
  });

  it('should FAIL when Bedrock resources exist but no logging config is defined', () => {
    const files = [
      makeParsedFile({
        aws_bedrockagent_agent: {
          support_bot: [
            {
              agent_name: 'support-bot',
              foundation_model: 'anthropic.claude-3-sonnet-20240229-v1:0',
            },
          ],
        },
      }),
    ];

    const findings = bedrockLoggingRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toContain('aws_bedrockagent_agent.support_bot');
  });

  it('should FAIL for other Bedrock resource types (guardrail, custom_model) with no logging', () => {
    const files = [
      makeParsedFile({
        aws_bedrock_guardrail: { pii: [{ name: 'pii' }] },
        aws_bedrock_custom_model: { tuned: [{ base_model_identifier: 'foo' }] },
      }),
    ];

    const findings = bedrockLoggingRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toContain('aws_bedrock_guardrail.pii');
    expect(findings[0].description).toContain('aws_bedrock_custom_model.tuned');
  });

  it('should PASS when logging config exists with default (unset) modality toggles', () => {
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

  it('should PASS when logging config has at least one modality explicitly enabled', () => {
    const files = [
      makeParsedFile({
        aws_bedrock_model_invocation_logging_configuration: {
          main: [
            {
              logging_config: [
                {
                  text_data_delivery_enabled: true,
                  image_data_delivery_enabled: false,
                  embedding_data_delivery_enabled: false,
                  video_data_delivery_enabled: false,
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

  it('should FAIL when logging config has all modality toggles explicitly set to false', () => {
    const files = [
      makeParsedFile({
        aws_bedrock_model_invocation_logging_configuration: {
          main: [
            {
              logging_config: [
                {
                  text_data_delivery_enabled: false,
                  image_data_delivery_enabled: false,
                  embedding_data_delivery_enabled: false,
                  video_data_delivery_enabled: false,
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
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toMatch(/all data-delivery toggles/i);
  });

  it('should emit INCONCLUSIVE (not SKIP) when no Bedrock found but remote modules exist', () => {
    const files = [
      {
        filePath: 'main.tf',
        rawHcl: '',
        json: {
          module: {
            bedrock: [{ source: 'terraform-aws-modules/bedrock/aws' }],
          },
        },
      },
    ];

    const findings = bedrockLoggingRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].description).toContain('"bedrock"');
  });

  it('should be a phase1 rule', () => {
    expect(bedrockLoggingRule.phase1).toBe(true);
  });
});

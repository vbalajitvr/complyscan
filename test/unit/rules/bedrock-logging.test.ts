import { describe, it, expect } from 'vitest';
import { bedrockLoggingRule } from '../../../src/rules/bedrock-logging';
import { makeParsedFile, emptyContext } from './helpers';

describe('S-12.1.1 Bedrock Logging', () => {
  it('should SKIP when no Bedrock resources and no logging config exist', () => {
    const files = [makeParsedFile({})];
    const findings = bedrockLoggingRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('SKIP');
    expect(findings[0].ruleId).toBe('S-12.1.1');
  });

  it('should INCONCLUSIVE (default permissive) when Bedrock resources exist but no logging config is defined', () => {
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
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].description).toContain('aws_bedrockagent_agent.support_bot');
  });

  it('should FAIL when Bedrock resources exist, no logging config, and strict-account-logging is set', () => {
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

    const findings = bedrockLoggingRule.run(files, emptyContext({ strictAccountLogging: true }));

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toContain('aws_bedrockagent_agent.support_bot');
  });

  it('should INCONCLUSIVE for other Bedrock resource types (guardrail, custom_model) with no logging in default mode', () => {
    const files = [
      makeParsedFile({
        aws_bedrock_guardrail: { pii: [{ name: 'pii' }] },
        aws_bedrock_custom_model: { tuned: [{ base_model_identifier: 'foo' }] },
      }),
    ];

    const findings = bedrockLoggingRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].description).toContain('aws_bedrock_guardrail.pii');
    expect(findings[0].description).toContain('aws_bedrock_custom_model.tuned');
  });

  it('should FAIL for other Bedrock resource types with no logging under strict-account-logging', () => {
    const files = [
      makeParsedFile({
        aws_bedrock_guardrail: { pii: [{ name: 'pii' }] },
        aws_bedrock_custom_model: { tuned: [{ base_model_identifier: 'foo' }] },
      }),
    ];

    const findings = bedrockLoggingRule.run(files, emptyContext({ strictAccountLogging: true }));

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('FAIL');
    expect(findings[0].description).toContain('aws_bedrock_guardrail.pii');
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
    expect(findings[0].description).toMatch(/every .*_data_delivery_enabled toggle is set to false/i);
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

  describe('indirect-only Bedrock signals (always INCONCLUSIVE)', () => {
    it('IAM grant without aws_bedrock_* resource is INCONCLUSIVE in default mode', () => {
      const files = [
        makeParsedFile(
          {
            aws_iam_role_policy: {
              p: [
                {
                  name: 'p',
                  role: 'role',
                  policy: JSON.stringify({
                    Version: '2012-10-17',
                    Statement: [
                      { Effect: 'Allow', Action: 'bedrock:InvokeModel', Resource: '*' },
                    ],
                  }),
                },
              ],
            },
          },
        ),
      ];

      const findings = bedrockLoggingRule.run(files, emptyContext());

      expect(findings).toHaveLength(1);
      expect(findings[0].status).toBe('INCONCLUSIVE');
      expect(findings[0].description).toMatch(/IAM grant/);
      expect(findings[0].description).toContain('bedrock:InvokeModel');
    });

    it('IAM grant alone is still INCONCLUSIVE under strict-account-logging', () => {
      const files = [
        makeParsedFile(
          {
            aws_iam_role_policy: {
              p: [
                {
                  name: 'p',
                  role: 'role',
                  policy: JSON.stringify({
                    Statement: [{ Effect: 'Allow', Action: ['bedrock:Converse'], Resource: '*' }],
                  }),
                },
              ],
            },
          },
        ),
      ];

      const findings = bedrockLoggingRule.run(
        files,
        emptyContext({ strictAccountLogging: true }),
      );

      expect(findings[0].status).toBe('INCONCLUSIVE');
    });

    it('aws_iam_policy_document data source with Bedrock action is INCONCLUSIVE', () => {
      const files = [
        {
          filePath: 'main.tf',
          rawHcl: '',
          json: {
            data: {
              aws_iam_policy_document: {
                bedrock: [
                  {
                    statement: [
                      { actions: ['bedrock:InvokeModel'], resources: ['*'] },
                    ],
                  },
                ],
              },
            },
          },
        },
      ];

      const findings = bedrockLoggingRule.run(files, emptyContext());

      expect(findings[0].status).toBe('INCONCLUSIVE');
      expect(findings[0].description).toContain('data.aws_iam_policy_document.bedrock');
    });

    it('aws_vpc_endpoint to bedrock-runtime is INCONCLUSIVE', () => {
      const files = [
        makeParsedFile({
          aws_vpc_endpoint: {
            bedrock: [{ service_name: 'com.amazonaws.us-east-1.bedrock-runtime' }],
          },
        }),
      ];

      const findings = bedrockLoggingRule.run(files, emptyContext());

      expect(findings[0].status).toBe('INCONCLUSIVE');
      expect(findings[0].description).toContain('aws_vpc_endpoint.bedrock');
    });

    it('aws_bedrock_foundation_model data source alone is INCONCLUSIVE', () => {
      const files = [
        {
          filePath: 'main.tf',
          rawHcl: '',
          json: {
            data: {
              aws_bedrock_foundation_model: { claude: [{ model_id: 'anthropic.claude-3' }] },
            },
          },
        },
      ];

      const findings = bedrockLoggingRule.run(files, emptyContext());

      expect(findings[0].status).toBe('INCONCLUSIVE');
      expect(findings[0].description).toContain('data.aws_bedrock_foundation_model.claude');
    });
  });

  describe('Fix-4: external-logging hints override strict mode', () => {
    it('direct usage + Bedrock-related remote module → INCONCLUSIVE even with strict-account-logging', () => {
      const files = [
        {
          filePath: 'main.tf',
          rawHcl: '',
          json: {
            resource: {
              aws_bedrockagent_agent: {
                a: [{ agent_name: 'a' }],
              },
            },
            module: {
              bedrock_logging: [
                {
                  source: 'registry.terraform.io/org/bedrock-logging/aws',
                  log_bucket: 'audit-logs',
                },
              ],
            },
          },
        },
      ];

      const findings = bedrockLoggingRule.run(
        files,
        emptyContext({ strictAccountLogging: true }),
      );

      expect(findings[0].status).toBe('INCONCLUSIVE');
      expect(findings[0].description).toMatch(/module call/);
      expect(findings[0].description).toContain('bedrock_logging');
    });

    it('direct usage + cross-stack reference for log_bucket → INCONCLUSIVE', () => {
      const files = [
        {
          filePath: 'main.tf',
          rawHcl: '',
          json: {
            resource: {
              aws_bedrockagent_agent: { a: [{ agent_name: 'a' }] },
              aws_s3_bucket_policy: {
                p: [
                  {
                    bucket:
                      '${data.terraform_remote_state.account_baseline.outputs.log_bucket}',
                    policy: '{}',
                  },
                ],
              },
            },
            data: {
              terraform_remote_state: {
                account_baseline: [{ backend: 's3' }],
              },
            },
          },
        },
      ];

      const findings = bedrockLoggingRule.run(files, emptyContext());

      expect(findings[0].status).toBe('INCONCLUSIVE');
      expect(findings[0].description).toContain('account_baseline');
      expect(findings[0].description).toContain('log_bucket');
    });
  });
});

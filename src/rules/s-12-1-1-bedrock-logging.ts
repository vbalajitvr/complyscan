import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, findRemoteModules } from '../utils/resource-helpers';

const BEDROCK_USAGE_RESOURCE_TYPES = [
  'aws_bedrockagent_agent',
  'aws_bedrockagent_agent_alias',
  'aws_bedrockagent_knowledge_base',
  'aws_bedrockagent_data_source',
  'aws_bedrock_guardrail',
  'aws_bedrock_custom_model',
  'aws_bedrock_provisioned_model_throughput',
];

const MODALITY_TOGGLES = [
  'text_data_delivery_enabled',
  'image_data_delivery_enabled',
  'embedding_data_delivery_enabled',
  'video_data_delivery_enabled',
];

function findBedrockUsage(files: ParsedFile[]): string[] {
  const addresses: string[] = [];
  for (const type of BEDROCK_USAGE_RESOURCE_TYPES) {
    for (const r of findResources(files, type)) {
      addresses.push(`${type}.${r.name}`);
    }
  }
  return addresses;
}

export const bedrockLoggingRule: ScanRule = {
  id: 'S-12.1.1',
  description: 'Bedrock model invocation logging must be configured when Bedrock is in use',
  severity: 'FAIL',
  regulatoryReference: 'EU AI Act Article 12(1) — Automatic logging of events',
  phase1: true,

  run(files: ParsedFile[], _context: ScanContext): Finding[] {
    const configs = findResources(files, 'aws_bedrock_model_invocation_logging_configuration');
    const usage = findBedrockUsage(files);

    if (configs.length === 0) {
      if (usage.length === 0) {
        const remoteModules = findRemoteModules(files);
        if (remoteModules.length > 0) {
          const names = remoteModules.map((m) => `"${m.name}"`).join(', ');
          return [
            {
              ruleId: this.id,
              status: 'INCONCLUSIVE',
              filePath: '',
              description: `No Bedrock resources found in scanned files, but remote module(s) ${names} could not be inspected. Bedrock usage and logging config may be defined inside those modules.`,
              remediation:
                'Run complyscan against "terraform show -json plan.json" or ensure logging configuration is defined in the root module.',
              regulatoryReference: this.regulatoryReference,
            },
          ];
        }

        return [
          {
            ruleId: this.id,
            status: 'SKIP',
            filePath: '',
            description: 'No Bedrock resources detected. Invocation logging check skipped.',
            remediation: '',
            regulatoryReference: this.regulatoryReference,
          },
        ];
      }

      return [
        {
          ruleId: this.id,
          status: 'FAIL',
          filePath: '',
          description: `Bedrock is in use (${usage.length} resource(s): ${usage.join(', ')}) but no aws_bedrock_model_invocation_logging_configuration is defined.`,
          remediation:
            'Add an aws_bedrock_model_invocation_logging_configuration resource to log all model invocations.',
          regulatoryReference: this.regulatoryReference,
        },
      ];
    }

    return configs.map((config) => {
      const line = findResourceLine(
        config.rawHcl,
        'aws_bedrock_model_invocation_logging_configuration',
        config.name,
      );
      const loggingConfig = getNestedValue(config.body, 'logging_config');

      const explicitlyDisabled: string[] = [];
      const explicitlyEnabled: string[] = [];
      for (const toggle of MODALITY_TOGGLES) {
        const value = getNestedValue(loggingConfig, toggle);
        if (value === false) explicitlyDisabled.push(toggle);
        else if (value === true) explicitlyEnabled.push(toggle);
      }

      if (explicitlyEnabled.length === 0 && explicitlyDisabled.length === MODALITY_TOGGLES.length) {
        return {
          ruleId: this.id,
          status: 'FAIL' as const,
          filePath: config.filePath,
          line,
          description: `Bedrock logging resource "${config.name}" exists but all data-delivery toggles are set to false — no invocations will be logged.`,
          remediation: `Enable at least one of ${MODALITY_TOGGLES.join(', ')} on logging_config.`,
          regulatoryReference: this.regulatoryReference,
        };
      }

      return {
        ruleId: this.id,
        status: 'PASS' as const,
        filePath: config.filePath,
        line,
        description: `Bedrock invocation logging is configured (${config.name}).`,
        remediation: '',
        regulatoryReference: this.regulatoryReference,
      };
    });
  },
};

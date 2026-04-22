import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine } from '../utils/resource-helpers';

export const bedrockLoggingRule: ScanRule = {
  id: 'S-12.1.1',
  description: 'Bedrock model invocation logging must be configured',
  severity: 'WARN',
  regulatoryReference: 'EU AI Act Article 12(1) — Automatic logging of events',
  phase1: true,

  run(files: ParsedFile[], _context: ScanContext): Finding[] {
    const configs = findResources(files, 'aws_bedrock_model_invocation_logging_configuration');

    if (configs.length === 0) {
      return [
        {
          ruleId: this.id,
          status: 'WARN',
          filePath: '',
          description: 'No aws_bedrock_model_invocation_logging_configuration resource found. Bedrock invocation logging is not configured.',
          remediation: 'Add an aws_bedrock_model_invocation_logging_configuration resource to enable logging of all model invocations.',
          regulatoryReference: this.regulatoryReference,
        },
      ];
    }

    return configs.map((config) => ({
      ruleId: this.id,
      status: 'PASS' as const,
      filePath: config.filePath,
      line: findResourceLine(config.rawHcl, 'aws_bedrock_model_invocation_logging_configuration', config.name),
      description: `Bedrock invocation logging is configured (${config.name}).`,
      remediation: '',
      regulatoryReference: this.regulatoryReference,
    }));
  },
};

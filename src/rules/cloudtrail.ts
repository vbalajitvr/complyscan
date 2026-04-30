import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue } from '../utils/resource-helpers';

export const cloudtrailRule: ScanRule = {
  id: 'S-12.x.4',
  description: 'CloudTrail must exist and have logging enabled',
  severity: 'FAIL',
  regulatoryReference: 'EU AI Act Article 12 — Audit trail for AI system events',

  run(files: ParsedFile[], _context: ScanContext): Finding[] {
    const trails = findResources(files, 'aws_cloudtrail');

    if (trails.length === 0) {
      return [
        {
          ruleId: this.id,
          status: 'FAIL',
          filePath: '',
          description: 'No aws_cloudtrail resource found. CloudTrail is required for audit logging.',
          remediation: 'Add an aws_cloudtrail resource with enable_logging set to true.',
          regulatoryReference: this.regulatoryReference,
        },
      ];
    }

    return trails.map((trail) => {
      const enableLogging = getNestedValue(trail.body, 'enable_logging');

      // enable_logging defaults to true if not set; only FAIL if explicitly false
      if (enableLogging === false) {
        return {
          ruleId: this.id,
          status: 'FAIL' as const,
          filePath: trail.filePath,
          line: findResourceLine(trail.rawHcl, 'aws_cloudtrail', trail.name),
          description: `CloudTrail "${trail.name}" has enable_logging set to false.`,
          remediation: 'Set enable_logging to true on the aws_cloudtrail resource.',
          regulatoryReference: this.regulatoryReference,
        };
      }

      return {
        ruleId: this.id,
        status: 'PASS' as const,
        filePath: trail.filePath,
        line: findResourceLine(trail.rawHcl, 'aws_cloudtrail', trail.name),
        description: `CloudTrail "${trail.name}" is configured with logging enabled.`,
        remediation: '',
        regulatoryReference: this.regulatoryReference,
      };
    });
  },
};

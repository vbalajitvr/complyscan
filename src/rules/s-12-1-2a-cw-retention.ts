import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, inconclusiveFromUnresolved } from '../utils/resource-helpers';
import { resolveExpression } from '../resolver';

const MIN_RETENTION_DAYS = 180;
const RECOMMENDED_RETENTION_DAYS = 365;

export const cwRetentionRule: ScanRule = {
  id: 'S-12.1.2a',
  description: 'CloudWatch log group retention must be at least 180 days',
  severity: 'FAIL',
  regulatoryReference: 'EU AI Act Article 12(1) — Logs retained for appropriate period',

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    if (!context.bedrockLoggingDetected) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'No Bedrock logging detected. CloudWatch retention check skipped.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        },
      ];
    }

    const findings: Finding[] = [];

    for (const ref of context.unresolvedGroupRefs) {
      findings.push(inconclusiveFromUnresolved(this.id, this.regulatoryReference, ref, 'log group'));
    }

    if (context.logGroupNames.length === 0 && context.unresolvedGroupRefs.length === 0) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'Bedrock logging does not use CloudWatch. Skipping CloudWatch retention check.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        },
      ];
    }

    const logGroups = findResources(files, 'aws_cloudwatch_log_group');

    for (const targetName of context.logGroupNames) {
      const matching = logGroups.find((lg) => {
        const name = getNestedValue(lg.body, 'name');

        // Direct literal match
        if (name === targetName) return true;
        if (lg.name === targetName) return true;
        if (`aws_cloudwatch_log_group.${lg.name}` === targetName) return true;

        // Resolve variable/local references in the name attribute
        if (typeof name === 'string') {
          const result = resolveExpression(name, files);
          if (result?.kind === 'literal' && result.value === targetName) return true;
          if (result?.kind === 'address' && result.value === targetName) return true;
        }

        return false;
      });

      if (!matching) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: '',
          description: `CloudWatch log group "${targetName}" referenced by Bedrock logging not found in Terraform.`,
          remediation: `Add an aws_cloudwatch_log_group resource for "${targetName}" with retention_in_days >= ${MIN_RETENTION_DAYS}.`,
          regulatoryReference: this.regulatoryReference,
        });
        continue;
      }

      const retention = getNestedValue(matching.body, 'retention_in_days');
      const retentionDays = typeof retention === 'number' ? retention : undefined;
      const line = findResourceLine(matching.rawHcl, 'aws_cloudwatch_log_group', matching.name);

      if (retentionDays === undefined || retentionDays === 0) {
        // 0 means never expire — that's compliant but worth noting
        if (retentionDays === 0) {
          findings.push({
            ruleId: this.id,
            status: 'PASS',
            filePath: matching.filePath,
            line,
            description: `CloudWatch log group "${targetName}" has retention set to never expire.`,
            remediation: '',
            regulatoryReference: this.regulatoryReference,
          });
        } else {
          findings.push({
            ruleId: this.id,
            status: 'FAIL',
            filePath: matching.filePath,
            line,
            description: `CloudWatch log group "${targetName}" has no retention_in_days set. Defaults may not meet compliance.`,
            remediation: `Set retention_in_days to at least ${MIN_RETENTION_DAYS} on the log group.`,
            regulatoryReference: this.regulatoryReference,
          });
        }
      } else if (retentionDays < MIN_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: matching.filePath,
          line,
          description: `CloudWatch log group "${targetName}" retention is ${retentionDays} days (minimum: ${MIN_RETENTION_DAYS}).`,
          remediation: `Increase retention_in_days to at least ${MIN_RETENTION_DAYS}.`,
          regulatoryReference: this.regulatoryReference,
        });
      } else if (retentionDays < RECOMMENDED_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'WARN',
          filePath: matching.filePath,
          line,
          description: `CloudWatch log group "${targetName}" retention is ${retentionDays} days (recommended: ${RECOMMENDED_RETENTION_DAYS}).`,
          remediation: `Consider increasing retention_in_days to ${RECOMMENDED_RETENTION_DAYS} for full compliance.`,
          regulatoryReference: this.regulatoryReference,
        });
      } else {
        findings.push({
          ruleId: this.id,
          status: 'PASS',
          filePath: matching.filePath,
          line,
          description: `CloudWatch log group "${targetName}" retention is ${retentionDays} days.`,
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        });
      }
    }

    return findings;
  },
};

import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, inconclusiveFromUnresolved } from '../utils/resource-helpers';
import { resolveExpression } from '../resolver';

const MIN_RETENTION_DAYS = 180;
const RECOMMENDED_RETENTION_DAYS = 365;

// Article 12(1) requires logs be retained for an "appropriate period to the
// intended purpose" - no specific number is named in the regulation. The 180-day
// floor and 365-day recommendation reflect the practical reality that high-risk
// AI incidents (bias drift, hallucinated decisions, downstream-deployer audits
// under Article 26, regulator queries under Article 72 post-market monitoring)
// surface months - often quarters - after the originating event. This rationale
// is surfaced in remediation messages so users understand the "why" behind a
// number that the regulation itself leaves open.
const RETENTION_RATIONALE =
  'Article 12 requires logs retained for an "appropriate period to the intended ' +
  'purpose" - no specific number is named, but bias drift, hallucinated decisions, ' +
  'and downstream-deployer audits routinely surface months after the event. ' +
  'Sub-180-day retention undermines post-market monitoring (Article 72) and ' +
  'incident investigation; 365 days is the typical floor for production AI.';

export const cwRetentionRule: ScanRule = {
  id: 'S-12.1.2a',
  description: 'CloudWatch log group retention must be at least 180 days',
  severity: 'FAIL',
  regulatoryReference: 'EU AI Act Article 12(1) - Logs retained for appropriate period',
  nistReference: 'NIST AI RMF 1.0: MANAGE 4.1 (post-deployment monitoring plans); MANAGE 4.3 (incident communication to AI actors); MEASURE 3.2 (risk tracking across AI lifecycle)',
  isoReference: 'ISO/IEC 42001:2023 Annex A: A.6.2.8 (AI system event logs); A.6.2.6 (AI system operation and monitoring)',

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
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        },
      ];
    }

    const findings: Finding[] = [];

    for (const ref of context.unresolvedGroupRefs) {
      findings.push(inconclusiveFromUnresolved(this, ref, 'log group'));
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
          nistReference: this.nistReference,
          isoReference: this.isoReference,
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
          description: `CloudWatch log group "${targetName}" is referenced by Bedrock invocation logging but not declared in any scanned Terraform file - its retention is not under IaC control.`,
          remediation:
            `Add an aws_cloudwatch_log_group resource for "${targetName}" with ` +
            `retention_in_days >= ${MIN_RETENTION_DAYS} (recommended: ${RECOMMENDED_RETENTION_DAYS}). ` +
            `Why: ${RETENTION_RATIONALE} Without an explicit declaration, retention drifts ` +
            `outside Terraform and becomes invisible to compliance scans.`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
        continue;
      }

      const retention = getNestedValue(matching.body, 'retention_in_days');
      const retentionDays = typeof retention === 'number' ? retention : undefined;
      const line = findResourceLine(matching.rawHcl, 'aws_cloudwatch_log_group', matching.name);

      if (retentionDays === undefined || retentionDays === 0) {
        // retention_in_days = 0 means never expire - that's compliant.
        if (retentionDays === 0) {
          findings.push({
            ruleId: this.id,
            status: 'PASS',
            filePath: matching.filePath,
            line,
            description: `CloudWatch log group "${targetName}" has retention set to never expire (retention_in_days = 0).`,
            remediation: '',
            regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
          });
        } else {
          findings.push({
            ruleId: this.id,
            status: 'FAIL',
            filePath: matching.filePath,
            line,
            description: `CloudWatch log group "${targetName}" has no retention_in_days declared. Behaviour falls back to whatever was previously set in AWS - retention is not under IaC control.`,
            remediation:
              `Set retention_in_days explicitly: a value >= ${MIN_RETENTION_DAYS} ` +
              `(recommended: ${RECOMMENDED_RETENTION_DAYS}), or 0 for never-expire. ` +
              `Why: ${RETENTION_RATIONALE} An undeclared value is the worst of both ` +
              `worlds - actual retention depends on prior AWS-side state and is not ` +
              `auditable from Terraform alone.`,
            regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
          });
        }
      } else if (retentionDays < MIN_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: matching.filePath,
          line,
          description: `CloudWatch log group "${targetName}" retention is ${retentionDays} days, below the ${MIN_RETENTION_DAYS}-day floor infrarails applies for high-risk AI logging.`,
          remediation:
            `Increase retention_in_days to >= ${MIN_RETENTION_DAYS} ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}). Why: ${RETENTION_RATIONALE}`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      } else if (retentionDays < RECOMMENDED_RETENTION_DAYS) {
        findings.push({
          ruleId: this.id,
          status: 'WARN',
          filePath: matching.filePath,
          line,
          description: `CloudWatch log group "${targetName}" retention is ${retentionDays} days. infrarails recommends >= ${RECOMMENDED_RETENTION_DAYS} days for production AI workloads.`,
          remediation:
            `Consider increasing retention_in_days to ${RECOMMENDED_RETENTION_DAYS}. ` +
            `Why: 365 days covers most regulator-inquiry windows, calendar-quarter audit ` +
            `cycles, and the typical lag between an AI incident and its discovery downstream.`,
          regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
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
          nistReference: this.nistReference,
          isoReference: this.isoReference,
        });
      }
    }

    return findings;
  },
};

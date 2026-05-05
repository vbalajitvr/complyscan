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

// A static IaC scan cannot prove what happens to logs after they leave the
// account: forwarders to Datadog/Splunk/SIEM are usually owned by a platform
// team in a separate Terraform repo (or deployed out-of-band via the Datadog
// CloudFormation template, StackSets, or auto-subscription Lambdas). A short
// or undeclared retention_in_days is therefore not proof of a compliance gap -
// it may be deliberate when a forwarder is shipping logs to a system that
// retains them. We WARN in every uncertain case rather than FAIL, and tailor
// the message based on whether a subscription filter was found in the scanned
// Terraform.
const FORWARDER_NOTE_WHEN_FOUND =
  'A CloudWatch subscription filter was found in the scanned Terraform - ' +
  'logs may be forwarded to an external system (Datadog, Splunk, SIEM) where ' +
  'retention is satisfied. Verify the destination retention; this scanner ' +
  'cannot follow the chain past the subscription filter.';

const FORWARDER_NOTE_WHEN_MISSING =
  'No CloudWatch subscription filter was found in the scanned Terraform, but ' +
  'forwarders are commonly owned by a separate platform repo (Datadog/Splunk ' +
  'forwarder Lambda, central log-archive account, auto-subscription Lambda). ' +
  'If logs are forwarded out-of-repo, verify retention at the destination. ' +
  'If they are not, this is a real compliance gap.';

function hasSubscriptionFilterFor(
  files: ParsedFile[],
  targetLogGroupName: string,
): boolean {
  const filters = findResources(files, 'aws_cloudwatch_log_subscription_filter');
  for (const f of filters) {
    const lgName = getNestedValue(f.body, 'log_group_name');

    if (lgName === targetLogGroupName) return true;

    if (typeof lgName === 'string') {
      const result = resolveExpression(lgName, files);
      if (result?.kind === 'literal' && result.value === targetLogGroupName) return true;
      if (result?.kind === 'address' && result.value === targetLogGroupName) return true;
      if (result?.kind === 'address' && result.value === `aws_cloudwatch_log_group.${targetLogGroupName}`) return true;
    }
  }
  return false;
}

export const cwRetentionRule: ScanRule = {
  id: 'S-12.1.2a',
  description: 'CloudWatch log group retention - WARN-level (forwarders may satisfy retention out-of-repo)',
  severity: 'WARN',
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
        const forwarderFound = hasSubscriptionFilterFor(files, targetName);
        findings.push({
          ruleId: this.id,
          status: 'WARN',
          filePath: '',
          description: `CloudWatch log group "${targetName}" is referenced by Bedrock invocation logging but not declared in any scanned Terraform file - its retention is not under this repo's IaC control.`,
          remediation:
            `Either declare an aws_cloudwatch_log_group resource for "${targetName}" with ` +
            `retention_in_days >= ${MIN_RETENTION_DAYS} (recommended: ${RECOMMENDED_RETENTION_DAYS}), ` +
            `or confirm the log group is managed in another Terraform repo / central account. ` +
            `${forwarderFound ? FORWARDER_NOTE_WHEN_FOUND : FORWARDER_NOTE_WHEN_MISSING} ` +
            `Why retention matters: ${RETENTION_RATIONALE}`,
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
          const forwarderFound = hasSubscriptionFilterFor(files, targetName);
          findings.push({
            ruleId: this.id,
            status: 'WARN',
            filePath: matching.filePath,
            line,
            description: `CloudWatch log group "${targetName}" has no retention_in_days declared. Behaviour falls back to whatever was previously set in AWS - local retention is not under IaC control.`,
            remediation:
              `Set retention_in_days explicitly: a value >= ${MIN_RETENTION_DAYS} ` +
              `(recommended: ${RECOMMENDED_RETENTION_DAYS}), or 0 for never-expire. ` +
              `${forwarderFound ? FORWARDER_NOTE_WHEN_FOUND : FORWARDER_NOTE_WHEN_MISSING} ` +
              `Why retention matters: ${RETENTION_RATIONALE}`,
            regulatoryReference: this.regulatoryReference,
          nistReference: this.nistReference,
          isoReference: this.isoReference,
          });
        }
      } else if (retentionDays < MIN_RETENTION_DAYS) {
        const forwarderFound = hasSubscriptionFilterFor(files, targetName);
        findings.push({
          ruleId: this.id,
          status: 'WARN',
          filePath: matching.filePath,
          line,
          description: `CloudWatch log group "${targetName}" retention is ${retentionDays} days, below the ${MIN_RETENTION_DAYS}-day floor infrarails applies for high-risk AI logging.`,
          remediation:
            `Increase retention_in_days to >= ${MIN_RETENTION_DAYS} ` +
            `(recommended: ${RECOMMENDED_RETENTION_DAYS}), or confirm retention is ` +
            `satisfied by a forwarder destination / central log-archive account. ` +
            `${forwarderFound ? FORWARDER_NOTE_WHEN_FOUND : FORWARDER_NOTE_WHEN_MISSING} ` +
            `Why retention matters: ${RETENTION_RATIONALE}`,
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

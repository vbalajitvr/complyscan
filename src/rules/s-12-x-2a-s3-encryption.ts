import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, matchesBucket, inconclusiveFromUnresolved } from '../utils/resource-helpers';

export const s3EncryptionRule: ScanRule = {
  id: 'S-12.x.2a',
  description: 'S3 log bucket must use KMS encryption',
  severity: 'FAIL',
  regulatoryReference: 'EU AI Act Article 12 — Integrity and confidentiality of logs',

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    if (!context.bedrockLoggingDetected) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'No Bedrock logging detected. S3 encryption check skipped.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        },
      ];
    }

    const findings: Finding[] = [];

    for (const ref of context.unresolvedBucketRefs) {
      findings.push(inconclusiveFromUnresolved(this.id, this.regulatoryReference, ref, 'bucket'));
    }

    if (context.logBucketNames.length === 0 && context.unresolvedBucketRefs.length === 0) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'Bedrock logging does not use S3. Skipping S3 encryption check.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        },
      ];
    }

    const encryptionConfigs = findResources(files, 'aws_s3_bucket_server_side_encryption_configuration');

    for (const bucketName of context.logBucketNames) {
      const matching = encryptionConfigs.find((ec) =>
        matchesBucket(ec.body, ec.name, [bucketName], files)
      );

      if (!matching) {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: '',
          description: `No server-side encryption configuration found for log bucket "${bucketName}".`,
          remediation: 'Add aws_s3_bucket_server_side_encryption_configuration with SSE algorithm set to aws:kms or aws:kms:dsse.',
          regulatoryReference: this.regulatoryReference,
        });
        continue;
      }

      const line = findResourceLine(matching.rawHcl, 'aws_s3_bucket_server_side_encryption_configuration', matching.name);

      // Navigate to the SSE algorithm
      const sseAlgorithm = getNestedValue(
        matching.body,
        'rule.apply_server_side_encryption_by_default.sse_algorithm'
      );

      if (sseAlgorithm === 'aws:kms' || sseAlgorithm === 'aws:kms:dsse') {
        findings.push({
          ruleId: this.id,
          status: 'PASS',
          filePath: matching.filePath,
          line,
          description: `Log bucket "${bucketName}" uses ${sseAlgorithm} encryption.`,
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        });
      } else {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: matching.filePath,
          line,
          description: `Log bucket "${bucketName}" uses "${sseAlgorithm || 'no'}" encryption instead of KMS.`,
          remediation: 'Set sse_algorithm to "aws:kms" or "aws:kms:dsse" in the encryption configuration.',
          regulatoryReference: this.regulatoryReference,
        });
      }
    }

    return findings;
  },
};

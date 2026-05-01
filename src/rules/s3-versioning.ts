import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findResources, findResourceLine, getNestedValue, matchesBucket, inconclusiveFromUnresolved } from '../utils/resource-helpers';

export const s3VersioningRule: ScanRule = {
  id: 'S-12.x.1',
  description: 'S3 log bucket must have versioning or Object Lock enabled',
  severity: 'FAIL',
  regulatoryReference: 'EU AI Act Article 12 — Immutability of logged data',

  run(files: ParsedFile[], context: ScanContext): Finding[] {
    if (!context.bedrockLoggingDetected) {
      return [
        {
          ruleId: this.id,
          status: 'SKIP',
          filePath: '',
          description: 'No Bedrock logging detected. S3 versioning check skipped.',
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
          description: 'Bedrock logging does not use S3. Skipping S3 versioning check.',
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        },
      ];
    }

    const versioningConfigs = findResources(files, 'aws_s3_bucket_versioning');
    const objectLockConfigs = findResources(files, 'aws_s3_bucket_object_lock_configuration');

    for (const bucketName of context.logBucketNames) {
      // Check versioning
      const versioningMatch = versioningConfigs.find((vc) =>
        matchesBucket(vc.body, vc.name, [bucketName], files)
      );

      const hasVersioning = versioningMatch &&
        getNestedValue(versioningMatch.body, 'versioning_configuration.status') === 'Enabled';

      // Check Object Lock
      const objectLockMatch = objectLockConfigs.find((ol) =>
        matchesBucket(ol.body, ol.name, [bucketName], files)
      );

      const hasObjectLock = !!objectLockMatch;

      if (hasVersioning || hasObjectLock) {
        const resource = versioningMatch || objectLockMatch!;
        const resourceType = hasVersioning ? 'aws_s3_bucket_versioning' : 'aws_s3_bucket_object_lock_configuration';
        findings.push({
          ruleId: this.id,
          status: 'PASS',
          filePath: resource.filePath,
          line: findResourceLine(resource.rawHcl, resourceType, resource.name),
          description: `Log bucket "${bucketName}" has ${hasVersioning ? 'versioning' : 'Object Lock'} enabled.`,
          remediation: '',
          regulatoryReference: this.regulatoryReference,
        });
      } else {
        findings.push({
          ruleId: this.id,
          status: 'FAIL',
          filePath: '',
          description: `Log bucket "${bucketName}" has neither versioning nor Object Lock enabled — a same-key PUT or a DeleteObject call will silently overwrite or remove log entries with no recoverable history.`,
          remediation:
            'Add aws_s3_bucket_versioning with versioning_configuration.status = "Enabled", ' +
            'or aws_s3_bucket_object_lock_configuration. ' +
            'Why: Article 12 requires log integrity sufficient for downstream auditability. ' +
            'Without versioning, an attacker (or a script bug) can overwrite a log object ' +
            'using the same key and erase forensic evidence — by the time you notice, the ' +
            'original is gone. Best practice for high-risk AI is Object Lock in COMPLIANCE ' +
            'mode (immutable for the retention period); versioning + a bucket policy that ' +
            'denies s3:DeleteObject is acceptable for lower-risk systems.',
          regulatoryReference: this.regulatoryReference,
        });
      }
    }

    return findings;
  },
};

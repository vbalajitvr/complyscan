import { ScanRule, Finding, ParsedFile, ScanContext } from '../types';
import { findRemoteModules } from '../utils/resource-helpers';

export const remoteModuleWallRule: ScanRule = {
  id: 'S-12.x.5',
  description: 'Remote Terraform modules cannot be scanned for compliance controls',
  severity: 'WARN',
  regulatoryReference: 'EU AI Act Article 12 — Scanner limitation: remote module contents not visible',

  run(files: ParsedFile[], _context: ScanContext): Finding[] {
    const remoteModules = findRemoteModules(files);
    if (remoteModules.length === 0) return [];

    return remoteModules.map(({ name, source, filePath }) => ({
      ruleId: this.id,
      status: 'INCONCLUSIVE' as const,
      filePath,
      description: `Module "${name}" uses remote source "${source}". Resources and logging configuration inside this module are not visible to complyscan — compliance cannot be verified for its contents.`,
      remediation:
        'Run complyscan against "terraform show -json plan.json" for full apply-time resolution, or define logging configuration in the root module where it can be scanned.',
      regulatoryReference: this.regulatoryReference,
    }));
  },
};

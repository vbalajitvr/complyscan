import { describe, it, expect } from 'vitest';
import { remoteModuleWallRule } from '../../../src/rules/s-12-x-5-module-wall';
import { emptyContext } from './helpers';
import { ParsedFile } from '../../../src/types';

function fileWithModules(
  modules: Record<string, { source: string }>,
  filePath = 'main.tf',
): ParsedFile {
  return {
    filePath,
    rawHcl: '',
    json: {
      module: Object.fromEntries(
        Object.entries(modules).map(([name, body]) => [name, [body]]),
      ),
    },
  };
}

describe('S-12.x.5 Remote Module Wall', () => {
  it('returns empty when there are no module blocks', () => {
    const findings = remoteModuleWallRule.run([{ filePath: 'main.tf', json: {}, rawHcl: '' }], emptyContext());
    expect(findings).toHaveLength(0);
  });

  it('returns empty for a local relative module (./modules/bedrock)', () => {
    const files = [fileWithModules({ bedrock: { source: './modules/bedrock' } })];
    const findings = remoteModuleWallRule.run(files, emptyContext());
    expect(findings).toHaveLength(0);
  });

  it('returns empty for a parent-relative local module (../shared)', () => {
    const files = [fileWithModules({ shared: { source: '../shared/logging' } })];
    const findings = remoteModuleWallRule.run(files, emptyContext());
    expect(findings).toHaveLength(0);
  });

  it('emits INCONCLUSIVE for a Terraform registry module', () => {
    const files = [fileWithModules({ bedrock: { source: 'terraform-aws-modules/bedrock/aws' } })];
    const findings = remoteModuleWallRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].ruleId).toBe('S-12.x.5');
    expect(findings[0].description).toContain('"bedrock"');
    expect(findings[0].description).toContain('terraform-aws-modules/bedrock/aws');
  });

  it('emits INCONCLUSIVE for a git:// module source', () => {
    const files = [fileWithModules({ logging: { source: 'git::https://github.com/org/module.git' } })];
    const findings = remoteModuleWallRule.run(files, emptyContext());
    expect(findings[0].status).toBe('INCONCLUSIVE');
  });

  it('emits one finding per remote module', () => {
    const files = [
      fileWithModules({
        bedrock: { source: 'terraform-aws-modules/bedrock/aws' },
        iam: { source: 'terraform-aws-modules/iam/aws' },
        local_logs: { source: './modules/logs' },
      }),
    ];
    const findings = remoteModuleWallRule.run(files, emptyContext());
    expect(findings).toHaveLength(2);
    expect(findings.every((f) => f.status === 'INCONCLUSIVE')).toBe(true);
  });
});

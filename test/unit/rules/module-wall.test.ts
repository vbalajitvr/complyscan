import { describe, it, expect } from 'vitest';
import { remoteModuleWallRule } from '../../../src/rules/module-wall';
import { emptyContext } from './helpers';
import { ParsedFile } from '../../../src/types';

function fileWithModules(
  modules: Record<string, Record<string, unknown>>,
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

  it('emits INCONCLUSIVE when the module name matches a Bedrock token', () => {
    const files = [fileWithModules({ bedrock: { source: 'terraform-aws-modules/bedrock/aws' } })];
    const findings = remoteModuleWallRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].ruleId).toBe('S-12.x.5');
    expect(findings[0].description).toContain('"bedrock"');
    expect(findings[0].description).toContain('terraform-aws-modules/bedrock/aws');
    expect(findings[0].description).toContain('matches Bedrock token');
  });

  it('emits INCONCLUSIVE when only the source URL contains a Bedrock token', () => {
    const files = [fileWithModules({ ai: { source: 'terraform-aws-modules/bedrock/aws' } })];
    const findings = remoteModuleWallRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].description).toContain('"bedrock"');
  });

  it('emits INCONCLUSIVE when the module body passes a Bedrock-logging input', () => {
    const files = [
      fileWithModules({
        chat: {
          source: 'git::https://github.com/org/chat.git',
          bedrock_log_bucket: 'audit-logs',
        },
      }),
    ];
    const findings = remoteModuleWallRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].description).toContain('passes logging input');
    expect(findings[0].description).toContain('"bedrock_log_bucket"');
  });

  it('does NOT flag generic remote modules with no Bedrock signal', () => {
    const files = [
      fileWithModules({
        iam: { source: 'terraform-aws-modules/iam/aws' },
        dynamodb_table: { source: 'git::https://github.com/terraform-aws-modules/terraform-aws-dynamodb-table.git' },
        lambda_get: { source: 'git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git' },
        logging: { source: 'git::https://github.com/org/module.git' },
      }),
    ];
    const findings = remoteModuleWallRule.run(files, emptyContext());

    expect(findings).toHaveLength(0);
  });

  it('flags only the Bedrock-related modules in a mixed set', () => {
    const files = [
      fileWithModules({
        bedrock: { source: 'terraform-aws-modules/bedrock/aws' },
        iam: { source: 'terraform-aws-modules/iam/aws' },
        local_logs: { source: './modules/logs' },
      }),
    ];
    const findings = remoteModuleWallRule.run(files, emptyContext());

    expect(findings).toHaveLength(1);
    expect(findings[0].status).toBe('INCONCLUSIVE');
    expect(findings[0].description).toContain('"bedrock"');
  });
});

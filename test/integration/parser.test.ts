import { describe, it, expect, beforeAll } from 'vitest';
import { execSync } from 'child_process';
import * as path from 'path';
import { collectTfFiles, parseTfFile } from '../../src/parser';

function hcl2jsonAvailable(): boolean {
  try {
    execSync('hcl2json --version', { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

const describeIf = hcl2jsonAvailable() ? describe : describe.skip;

describeIf('parser (integration)', () => {
  const fixturesDir = path.resolve(__dirname, '../fixtures/compliant');
  const combosDir = path.resolve(__dirname, '../fixtures/bedrock-logging-combos');

  it('should collect .tf files from a directory', () => {
    const files = collectTfFiles(fixturesDir);
    expect(files.length).toBeGreaterThan(0);
    expect(files.every((f) => f.endsWith('.tf'))).toBe(true);
  });

  it('should parse a .tf file to HCL2JSON output', () => {
    const files = collectTfFiles(fixturesDir);
    const parsed = parseTfFile(files[0]);

    expect(parsed.filePath).toBe(files[0]);
    expect(parsed.json).toBeDefined();
    expect(parsed.json.resource).toBeDefined();
    expect(parsed.rawHcl).toBeTruthy();
  });

  it('should contain expected resource types in compliant fixture', () => {
    const files = collectTfFiles(fixturesDir);
    const parsed = parseTfFile(files[0]);

    expect(parsed.json.resource?.aws_s3_bucket).toBeDefined();
    expect(parsed.json.resource?.aws_cloudtrail).toBeDefined();
    expect(parsed.json.resource?.aws_bedrock_model_invocation_logging_configuration).toBeDefined();
  });

  it('combo 4: parses large_data_delivery_s3_config nested inside cloudwatch_config', () => {
    const files = collectTfFiles(path.join(combosDir, 'cw-large-data'));
    expect(files.length).toBeGreaterThan(0);
    const parsed = parseTfFile(files[0]);

    const bedrockConfigs =
      parsed.json.resource?.aws_bedrock_model_invocation_logging_configuration;
    expect(bedrockConfigs).toBeDefined();

    const mainBody = Array.isArray(bedrockConfigs?.['main'])
      ? bedrockConfigs!['main'][0]
      : bedrockConfigs?.['main'];
    const loggingConfig = Array.isArray(mainBody?.['logging_config'])
      ? mainBody!['logging_config'][0]
      : mainBody?.['logging_config'];
    const cwConfig = Array.isArray(loggingConfig?.['cloudwatch_config'])
      ? loggingConfig!['cloudwatch_config'][0]
      : loggingConfig?.['cloudwatch_config'];

    expect(cwConfig).toBeDefined();
    expect(cwConfig?.['large_data_delivery_s3_config']).toBeDefined();
  });

  it('combo 5: parses all three configs (cloudwatch + s3 + large-data) in one resource', () => {
    const files = collectTfFiles(path.join(combosDir, 'cw-s3-large-data'));
    expect(files.length).toBeGreaterThan(0);
    const parsed = parseTfFile(files[0]);

    const bedrockConfigs =
      parsed.json.resource?.aws_bedrock_model_invocation_logging_configuration;
    expect(bedrockConfigs).toBeDefined();

    const mainBody = Array.isArray(bedrockConfigs?.['main'])
      ? bedrockConfigs!['main'][0]
      : bedrockConfigs?.['main'];
    const loggingConfig = Array.isArray(mainBody?.['logging_config'])
      ? mainBody!['logging_config'][0]
      : mainBody?.['logging_config'];

    expect(loggingConfig?.['s3_config']).toBeDefined();
    expect(loggingConfig?.['cloudwatch_config']).toBeDefined();

    const cwConfig = Array.isArray(loggingConfig?.['cloudwatch_config'])
      ? loggingConfig!['cloudwatch_config'][0]
      : loggingConfig?.['cloudwatch_config'];
    expect(cwConfig?.['large_data_delivery_s3_config']).toBeDefined();
  });
});

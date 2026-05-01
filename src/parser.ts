import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ParsedFile, HCL2JSONOutput } from './types';

const SKIP_DIRS = new Set([
  'node_modules',         // JS/TS dependencies (CDK for Terraform)
  'venv', 'env',          // Python virtualenvs (.venv is caught by the leading-dot check)
  '__pycache__',          // Python bytecode cache
  'examples',             // demo configs in shared module repos — not production infra
  'test', 'tests',        // Terraform test fixtures intentionally omit compliance controls
  'testdata', 'fixtures', // Sibling-tool fixtures (e.g. pike/src/testdata) — not the user's infra
  'vendor',               // vendored module copies
]);

/**
 * Recursively collect Terraform config files (.tf and .tf.json) from a directory.
 *
 * Terraform supports two on-disk syntaxes for the same configuration: HCL (.tf)
 * and JSON (.tf.json). cdktf, terragrunt, and various code generators emit the
 * JSON form, so a scanner that ignored .tf.json would be blind to those repos.
 */
export function collectTfFiles(dir: string): string[] {
  const results: string[] = [];

  function walk(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        if (entry.name.startsWith('.') || SKIP_DIRS.has(entry.name)) continue;
        walk(fullPath);
      } else if (entry.isFile() && (entry.name.endsWith('.tf') || entry.name.endsWith('.tf.json'))) {
        results.push(fullPath);
      }
    }
  }

  walk(dir);
  return results.sort();
}

/**
 * Parse a single Terraform config file. .tf is converted via hcl2json;
 * .tf.json is parsed as JSON directly. Both yield the same HCL2JSONOutput shape.
 */
export function parseTfFile(filePath: string): ParsedFile {
  const rawHcl = fs.readFileSync(filePath, 'utf-8');

  let json: HCL2JSONOutput;
  if (filePath.endsWith('.tf.json')) {
    json = JSON.parse(rawHcl);
  } else {
    const stdout = execSync(`hcl2json <<< '${rawHcl.replace(/'/g, "'\\''")}'`, {
      encoding: 'utf-8',
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: '/bin/bash',
    });
    json = JSON.parse(stdout);
  }

  return { filePath, json, rawHcl };
}

/**
 * Parse all .tf and .tf.json files from a directory.
 */
export function parseAllTfFiles(dir: string): ParsedFile[] {
  const tfFiles = collectTfFiles(dir);
  return tfFiles.map((f) => parseTfFile(f));
}

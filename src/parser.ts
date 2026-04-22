import { execSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { ParsedFile, HCL2JSONOutput } from './types';

/**
 * Recursively collect all .tf files from a directory.
 */
export function collectTfFiles(dir: string): string[] {
  const results: string[] = [];

  function walk(currentDir: string) {
    const entries = fs.readdirSync(currentDir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        // Skip hidden dirs and .terraform
        if (entry.name.startsWith('.') || entry.name === 'node_modules') continue;
        walk(fullPath);
      } else if (entry.isFile() && entry.name.endsWith('.tf')) {
        results.push(fullPath);
      }
    }
  }

  walk(dir);
  return results.sort();
}

/**
 * Parse a single .tf file using hcl2json.
 */
export function parseTfFile(filePath: string): ParsedFile {
  const rawHcl = fs.readFileSync(filePath, 'utf-8');

  const stdout = execSync(`hcl2json <<< '${rawHcl.replace(/'/g, "'\\''")}'`, {
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    shell: '/bin/bash',
  });

  const json: HCL2JSONOutput = JSON.parse(stdout);

  return { filePath, json, rawHcl };
}

/**
 * Parse all .tf files from a directory.
 */
export function parseAllTfFiles(dir: string): ParsedFile[] {
  const tfFiles = collectTfFiles(dir);
  return tfFiles.map((f) => parseTfFile(f));
}

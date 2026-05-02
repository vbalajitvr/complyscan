import { execSync } from 'child_process';
import chalk from 'chalk';

export function ensureHcl2Json(): void {
  try {
    execSync('hcl2json --version', { stdio: 'pipe' });
  } catch {
    console.error(chalk.red('Error: hcl2json binary not found on PATH.'));
    console.error('');
    console.error('infrarails requires hcl2json to parse Terraform files.');
    console.error('');
    console.error('Install instructions:');
    console.error('  Go:    go install github.com/tmccombs/hcl2json@latest');
    console.error('  Brew:  brew install hcl2json');
    console.error('  Binary: https://github.com/tmccombs/hcl2json/releases');
    process.exit(2);
  }
}

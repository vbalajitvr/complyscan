import { Command } from 'commander';
import * as path from 'path';
import * as fs from 'fs';
import { ensureHcl2Json } from './utils/hcl2json-check';
import { parseAllTfFiles } from './parser';
import { runScan } from './runner';
import { formatTerminal, formatJson } from './formatter';

const program = new Command();

program
  .name('complyscan')
  .description('Scan Terraform HCL files for EU AI Act Article 12 compliance gaps')
  .version('0.1.0')
  .argument('<directory>', 'Directory containing Terraform .tf files')
  .option('-f, --format <format>', 'Output format: terminal or json', 'terminal')
  .option(
    '--no-strict',
    'Treat INCONCLUSIVE findings as non-blocking (do not affect exit code). Default is strict: INCONCLUSIVE blocks like FAIL/WARN.',
  )
  .option(
    '--strict-account-logging',
    'Treat missing Bedrock invocation logging as FAIL even when no in-repo evidence is present. Default is INCONCLUSIVE — most enterprises put the logging config in a separate account-baseline stack.',
    false,
  )
  .action((
    directory: string,
    options: { format: string; strict: boolean; strictAccountLogging: boolean },
  ) => {
    // Check hcl2json is installed
    ensureHcl2Json();

    // Resolve directory path
    const dir = path.resolve(directory);
    if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
      console.error(`Error: "${dir}" is not a valid directory.`);
      process.exit(2);
    }

    // Collect and parse all .tf and .tf.json files
    const parsedFiles = parseAllTfFiles(dir);
    if (parsedFiles.length === 0) {
      console.log('No .tf files found in the specified directory.');
      process.exit(0);
    }

    // Run scan
    const findings = runScan(parsedFiles, {
      strictAccountLogging: options.strictAccountLogging,
    });

    // Format output
    if (options.format === 'json') {
      console.log(formatJson(findings));
    } else {
      console.log(formatTerminal(findings));
    }

    // Exit code: 1 for FAIL/WARN, plus INCONCLUSIVE in strict mode (default).
    // INCONCLUSIVE is treated as blocking by default because for a compliance tool,
    // "we couldn't verify" should not be reported as PASS to a CI pipeline.
    const hasBlocking = findings.some(
      (f) =>
        f.status === 'FAIL' ||
        f.status === 'WARN' ||
        (options.strict && f.status === 'INCONCLUSIVE'),
    );
    process.exit(hasBlocking ? 1 : 0);
  });

program.parse();

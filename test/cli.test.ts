import { describe, expect, it } from 'vitest';
import { execFile, spawn } from 'node:child_process';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const run = promisify(execFile);
const here = dirname(fileURLToPath(import.meta.url));
const CLI = join(here, '..', 'dist', 'cli.js');
const fixture = (name: string): string => join(here, 'fixtures', name);

/** Runs the built CLI, capturing the exit code instead of throwing. */
async function cli(
  args: string[],
  input?: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await run('node', [CLI, ...args], {
      env: { ...process.env, NO_COLOR: '1' },
      ...(input !== undefined ? {} : {}),
    });
    return { code: 0, stdout, stderr };
  } catch (error) {
    const e = error as { code?: number; stdout?: string; stderr?: string };
    return { code: e.code ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

// These exercise the built artifact, so they depend on `npm run build`.
describe('cli', () => {
  it('exits 0 on a valid file', async () => {
    const { code, stdout } = await cli([fixture('valid.toml')]);
    expect(code).toBe(0);
    expect(stdout).toContain('No SEP-1 issues found');
  });

  it('exits 1 on a broken file', async () => {
    const { code, stdout } = await cli([fixture('broken.toml')]);
    expect(code).toBe(1);
    expect(stdout).toContain('error');
  });

  it('exits 2 when the file does not exist', async () => {
    const { code, stderr } = await cli(['./definitely-not-here.toml']);
    expect(code).toBe(2);
    expect(stderr).toContain('Could not find');
  });

  it('exits 2 on an unknown option', async () => {
    const { code, stderr } = await cli(['--nonsense']);
    expect(code).toBe(2);
    expect(stderr).toContain('Unknown option');
  });

  it('rejects an unknown rule id and suggests alternatives', async () => {
    const { code, stderr } = await cli(['--off', 'general/versionz']);
    expect(code).toBe(2);
    expect(stderr).toContain('Unknown rule');
  });

  it('prints usage for --help', async () => {
    const { code, stdout } = await cli(['--help']);
    expect(code).toBe(0);
    expect(stdout).toContain('USAGE');
    expect(stdout).toContain('EXIT CODES');
  });

  it('prints the version', async () => {
    const { code, stdout } = await cli(['--version']);
    expect(code).toBe(0);
    expect(stdout.trim()).toMatch(/^\d+\.\d+\.\d+$/);
  });

  it('lists every rule', async () => {
    const { code, stdout } = await cli(['--list-rules']);
    expect(code).toBe(0);
    expect(stdout).toContain('currencies/issuance-exclusive');
    expect(stdout).toMatch(/^\d+ rules/);
  });

  it('emits parseable JSON', async () => {
    const { stdout } = await cli([fixture('broken.toml'), '-f', 'json']);
    expect(() => JSON.parse(stdout)).not.toThrow();
  });

  it('emits parseable SARIF', async () => {
    const { stdout } = await cli([fixture('broken.toml'), '-f', 'sarif']);
    expect(JSON.parse(stdout).version).toBe('2.1.0');
  });

  it('honours --off', async () => {
    const { stdout } = await cli([
      fixture('broken.toml'),
      '-f',
      'json',
      '--off',
      'general/version',
    ]);
    const rules = JSON.parse(stdout).diagnostics.map((d: { rule: string }) => d.rule);
    expect(rules).not.toContain('general/version');
  });

  it('fails a warning-only file under --strict', async () => {
    const clean = await cli([fixture('valid.toml'), '--strict']);
    expect(clean.code).toBe(0);

    // display_decimals warning only — no errors.
    const warned = await cli([fixture('warnings-only.toml')]);
    expect(warned.code).toBe(0);

    const strict = await cli([fixture('warnings-only.toml'), '--strict']);
    expect(strict.code).toBe(1);
  });

  it('honours --max-warnings', async () => {
    const under = await cli([fixture('warnings-only.toml'), '--max-warnings', '99']);
    expect(under.code).toBe(0);

    const over = await cli([fixture('warnings-only.toml'), '--max-warnings', '0']);
    expect(over.code).toBe(1);
  });

  it('shows only errors under --quiet', async () => {
    const { stdout } = await cli([fixture('broken.toml'), '--quiet', '-f', 'json']);
    const severities = JSON.parse(stdout).diagnostics.map((d: { severity: string }) => d.severity);
    expect(new Set(severities)).toEqual(new Set(['error']));
  });
});

/** Writes a scratch file, runs a callback, then removes the scratch directory. */
async function withScratchFile(
  source: string,
  run: (path: string) => Promise<{ code: number; stdout: string; stderr: string }>,
): Promise<{ code: number; stdout: string; stderr: string; after: string }> {
  const dir = await mkdtemp(join(tmpdir(), 'stellar-toml-lint-'));
  const path = join(dir, 'stellar.toml');
  await writeFile(path, source, 'utf8');
  const result = await run(path);
  const after = await readFile(path, 'utf8');
  return { ...result, after };
}

/** Runs the CLI with something on stdin, for the `-` path. */
function cliWithStdin(
  args: string[],
  input: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    const child = spawn('node', [CLI, ...args], { env: { ...process.env, NO_COLOR: '1' } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => (stdout += chunk));
    child.stderr.on('data', (chunk) => (stderr += chunk));
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }));
    child.stdin.end(input);
  });
}

describe('cli --format-file', () => {
  it('rewrites a file into SEP-1 order', async () => {
    const source = 'ACCOUNTS = ["GABC"]\nVERSION = "2.0.0"\n';
    const { code, stdout, after } = await withScratchFile(source, (path) =>
      cli(['--format-file', path]),
    );
    expect(code).toBe(0);
    expect(stdout).toContain('Formatted');
    expect(after).toBe('VERSION = "2.0.0"\nACCOUNTS = ["GABC"]\n');
  });

  it('reports an already-canonical file as unchanged', async () => {
    const source = 'VERSION = "2.0.0"\nACCOUNTS = ["GABC"]\n';
    const { code, stdout, after } = await withScratchFile(source, (path) =>
      cli(['--format-file', path]),
    );
    expect(code).toBe(0);
    expect(stdout).toContain('Unchanged');
    expect(after).toBe(source);
  });

  it('leaves invalid TOML untouched and exits 2', async () => {
    const source = 'VERSION = \n# broken on purpose\n';
    const { code, stderr, after } = await withScratchFile(source, (path) =>
      cli(['--format-file', path]),
    );
    expect(code).toBe(2);
    expect(stderr).toContain('Invalid TOML');
    expect(stderr).toContain('left untouched');
    expect(after).toBe(source);
  });

  it('formats stdin onto stdout', async () => {
    const { code, stdout } = await cliWithStdin(['--format-file', '-'], 'VERSION = "1"\n');
    expect(code).toBe(0);
    expect(stdout).toBe('VERSION = "1"\n');
  });

  it('rejects --domain, which has no file to rewrite', async () => {
    const { code, stderr } = await cli(['--format-file', '--domain', 'example.com']);
    expect(code).toBe(2);
    expect(stderr).toContain('--domain');
  });

  it('is mentioned in --help', async () => {
    const { stdout } = await cli(['--help']);
    expect(stdout).toContain('--format-file');
  });
});

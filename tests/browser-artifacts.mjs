// Test-only helper; not compiled or copied into production assets.
import { mkdir } from 'node:fs/promises';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export async function screenshotDirectory(suite) {
  if (!/^[a-z0-9-]+$/.test(suite)) throw new Error('Invalid browser suite name.');
  const parent = fileURLToPath(new URL('../artifacts/browser/', import.meta.url));
  await mkdir(parent, { recursive:true });
  const directory = path.join(parent, `${suite}-${new Date().toISOString().replace(/[:.]/g,'-').toLowerCase()}-${randomBytes(8).toString('hex')}`);
  await mkdir(directory); // Exclusive per-run leaf: never reuse existing screenshots.
  return name => {
    if (!/^[a-z0-9-]+\.png$/.test(name)) throw new Error('Invalid screenshot filename.');
    return path.join(directory, name);
  };
}

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { ACCEL_VALUES, requireAccel } from '../src/config';

/**
 * The `accel:*` IPC handlers take an accelerator from the renderer. An `Accel`
 * is a path segment: `overlayDir()` joins it under `backendsRoot()`, and that
 * directory is deleted outright by `accel:remove` and put on the spawned
 * backend's PYTHONPATH by `accel:use`. The parameter's TypeScript type is erased
 * at runtime, so before this guard the renderer could send `../../..` and turn
 * either handler into an arbitrary-path primitive (CWE-22 / CWE-20).
 */
describe('requireAccel', () => {
  it('returns every known accelerator unchanged', () => {
    for (const a of ACCEL_VALUES) assert.equal(requireAccel(a), a);
  });

  it('rejects traversal, wrong types and near-misses', () => {
    for (const bad of [
      '..',
      '../..',
      '../../../../home/me/Pictures',
      'cu128/../..',
      '/etc',
      'C:\\Windows',
      'cuda',
      'CPU',
      '',
      null,
      undefined,
      123,
      { toString: () => 'cpu' },
    ]) {
      assert.throws(
        () => requireAccel(bad),
        /Unknown accelerator/,
        `${JSON.stringify(bad)} must not be accepted as an accelerator`,
      );
    }
  });
});

/**
 * Source-text assertions because `main.ts` registers its handlers as a side
 * effect of an Electron app boot and exposes no module boundary to import - the
 * same reason `setupFolderNameEscaping.test.ts` reads `setup.js` as text.
 *
 * What is being pinned is the *shape*: the renderer's value must be named `raw`
 * (i.e. untyped) and reach `requireAccel` before anything else. Declaring the
 * parameter `accel: Accel` again is exactly the regression, and it type-checks.
 */
describe('the accel:* IPC handlers validate before they use the value', () => {
  // __dirname is dist-test/test at run time; the sources are two levels up.
  const main = readFileSync(join(__dirname, '..', '..', 'src', 'main.ts'), 'utf8');

  for (const channel of ['accel:install', 'accel:use', 'accel:remove']) {
    it(`${channel} takes an unknown and narrows it with requireAccel`, () => {
      const start = main.indexOf(`ipcMain.handle('${channel}'`);
      assert.ok(start >= 0, `${channel} handler not found`);
      const next = main.indexOf('ipcMain.handle(', start + 1);
      const body = main.slice(start, next === -1 ? undefined : next);
      assert.match(
        body,
        /\(_e,\s*raw:\s*unknown\)/,
        `${channel} must accept the renderer's value as unknown, not as a bare Accel`,
      );
      assert.match(body, /requireAccel\(raw\)/, `${channel} must narrow via requireAccel`);
    });
  }

  it('no accel:* handler still declares its parameter as an Accel', () => {
    assert.doesNotMatch(
      main,
      /ipcMain\.handle\('accel:[a-z]+',\s*async\s*\(_e,\s*\w+:\s*Accel/,
      'a renderer-supplied accelerator must never be typed straight into the handler',
    );
  });
});

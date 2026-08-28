import assert from 'node:assert/strict';
import test from 'node:test';

import { isSensitivePath } from '../../src/internal/analysis/sensitivity.ts';

test('flags sensitive directories at the segment level without trailing slashes', () => {
  const sensitive = [
    '~/.ssh',
    '/root/.ssh',
    '/root/.ssh/id_rsa',
    '~/.aws/credentials',
    '~/.kube/config',
    '/etc/shadow',
    '.env',
    '/run/secrets/token',
  ];
  for (const path of sensitive) {
    assert.equal(isSensitivePath(path), true, path);
  }
});

test('flags sensitive /proc entries for self and numeric pids', () => {
  const sensitive = [
    '/proc/self/environ',
    '/proc/1/environ',
    '/proc/self/cmdline',
  ];
  for (const path of sensitive) {
    assert.equal(isSensitivePath(path), true, path);
  }
});

test('does not flag ordinary paths', () => {
  const ordinary = [
    '/etc/hosts',
    '/var/log/app.log',
    '/tmp/out',
    '/proc/self/status',
  ];
  for (const path of ordinary) {
    assert.equal(isSensitivePath(path), false, path);
  }
});

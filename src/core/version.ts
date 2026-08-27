import type { PolicyPackageVersionMetadata } from '../index.js';

export const POLICY_DECISION_SCHEMA_VERSION = '1.0.0';
export const POLICY_PACKAGE_VERSION = '0.1.0';

/**
 * Per-domain rule-table versions. These evolve independently from
 * POLICY_PACKAGE_VERSION: a domain's entry is bumped when that domain's rule
 * tables change, without requiring a package release for every domain.
 */
export const POLICY_RULE_VERSIONS = Object.freeze({
  core: '0.1.1',
  shell: '0.1.1',
  python: '0.1.0',
  sqlite: '0.1.1',
  mysql: '0.1.1',
  redis: '0.1.1',
});

const parserVersions = Object.freeze({
  shell: 'tree-sitter-bash@0.25.1',
  python: 'tree-sitter-python@0.25.0',
  sqlite: 'sqlite3-parser@0.7.1/sqlite-3.53.0',
  mysql: 'node-sql-parser@5.4.0/mysql',
  redis: 'redis-command-table@1',
});

export const POLICY_VERSION_METADATA: PolicyPackageVersionMetadata =
  Object.freeze({
    schemaVersion: POLICY_DECISION_SCHEMA_VERSION,
    policy: POLICY_PACKAGE_VERSION,
    rules: POLICY_RULE_VERSIONS,
    parsers: parserVersions,
  });

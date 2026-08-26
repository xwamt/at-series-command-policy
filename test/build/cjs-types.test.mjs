import assert from 'node:assert/strict';
import test from 'node:test';

import { rewriteCjsModuleSpecifiers } from '../../scripts/rewrite-cjs-module-specifiers.mjs';

test('CJS declaration conversion changes only module specifiers', () => {
  const source = [
    'import type {',
    '  ImportedType,',
    "} from './mapped.js';",
    'import {',
    '  importedValue,',
    '} from "./mapped.js";',
    'export type {',
    '  ExportedType,',
    "} from './mapped.js';",
    'export {',
    '  exportedValue,',
    '} from "./mapped.js";',
    "import './mapped.js';",
    "import Alias = require('./mapped.js');",
    'export type DynamicType = import(',
    "  './mapped.js'",
    ').DynamicType;',
    "import external from 'external-package.js';",
    "export { external } from 'external-package.js';",
    "export type ExternalDynamic = import('external-package.js').Value;",
    "export { untouched } from './unmapped.js';",
    "export type WorkerFileName = './mapped.js';",
    'export type Provenance = "generated from \'./mapped.js\'";',
    '',
  ].join('\n');
  const declaration = rewriteCjsModuleSpecifiers(
    source,
    new Map([['./mapped.js', './mapped.cjs']]),
  );

  assert.equal(
    declaration,
    [
      'import type {',
      '  ImportedType,',
      "} from './mapped.cjs';",
      'import {',
      '  importedValue,',
      '} from "./mapped.cjs";',
      'export type {',
      '  ExportedType,',
      "} from './mapped.cjs';",
      'export {',
      '  exportedValue,',
      '} from "./mapped.cjs";',
      "import './mapped.cjs';",
      "import Alias = require('./mapped.cjs');",
      'export type DynamicType = import(',
      "  './mapped.cjs'",
      ').DynamicType;',
      "import external from 'external-package.js';",
      "export { external } from 'external-package.js';",
      "export type ExternalDynamic = import('external-package.js').Value;",
      "export { untouched } from './unmapped.js';",
      "export type WorkerFileName = './mapped.js';",
      'export type Provenance = "generated from \'./mapped.js\'";',
      '',
    ].join('\n'),
  );
});

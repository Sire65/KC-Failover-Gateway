import assert from 'node:assert/strict';
import fs from 'node:fs';
import {boundedPageLimit} from '../src/worker.js';

const source=fs.readFileSync(new URL('../src/worker.js',import.meta.url),'utf8');
assert.equal(boundedPageLimit(undefined),500);
assert.equal(boundedPageLimit('250'),250);
assert.equal(boundedPageLimit(5000),1000);
assert.equal(boundedPageLimit(-1),500);

assert.match(source,/function restorePage/);
assert.match(source,/after_id/);
assert.match(source,/nextCursor/);
assert.match(source,/ORDER BY transaction_id ASC/);
assert.match(source,/\/sync\/ids/);
assert.match(source,/MAX_RECONCILE_IDS\s*=\s*1000/);
assert.match(source,/ANY\(\$2::text\[\]\)/);
assert.match(source,/mode:"membership"/);
assert.doesNotMatch(source,/LIMIT\s+5000/i,'Restore darf nicht mehr auf eine einzige feste 5000er Antwort begrenzt sein.');

console.log('PASS Gateway cursor paging and membership reconcile contract');

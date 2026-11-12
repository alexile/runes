// Scores CVSS vectors with FIRST's reference calculators, for the corpora in
// ../data and for larger local runs (see tests/reference.rs).
//
// The calculators are not vendored. Fetch them into one directory:
//   git clone https://github.com/FIRSTdotorg/cvss-v4-calculator v4
//   curl -O https://www.first.org/_/cvsscalc30.js
//   curl -O https://www.first.org/_/cvsscalc31.js
// then run gen.js with that directory as its first argument.
// Loads the FIRST reference calculators into one context and exposes score functions.
const fs = require('fs'), vm = require('vm'), path = require('path');
const REF = process.argv[2];
const ctx = vm.createContext({ Math, Object, parseInt, isNaN, console, Number, NaN });
for (const f of ['v4/cvss_lookup.js', 'v4/max_composed.js', 'v4/max_severity.js', 'v4/metrics.js', 'v4/cvss_score.js', 'cvsscalc30.js', 'cvsscalc31.js']) {
  vm.runInContext(fs.readFileSync(path.join(REF, f), 'utf8'), ctx, { filename: f });
}
vm.runInContext('this.__v3 = { "3.0": CVSS, "3.1": CVSS31 };', ctx);
const ORDER4 = vm.runInContext('expectedMetricOrder', ctx);
function score4(vec) {
  const parts = vec.split('/'); if (parts.shift() !== 'CVSS:4.0') throw new Error('prefix');
  const sel = {};
  for (const k of Object.keys(ORDER4)) sel[k] = 'X';
  for (const p of parts) { const [k, v] = p.split(':'); sel[k] = v; }
  const mv = ctx.macroVector(sel);
  return { score: ctx.cvss_score(sel, ctx.cvssLookup_global, ctx.maxSeverity, mv), macro: mv };
}
function score3(vec) {
  const ver = vec.slice(5, 8);
  const r = ctx.__v3[ver].calculateCVSSFromVector(vec);
  if (!r.success) throw new Error(JSON.stringify(r) + ' ' + vec);
  return r;
}
module.exports = { score4, score3, ORDER4 };

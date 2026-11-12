// Writes a corpus scored by FIRST's reference calculators (see oracle.js).
//
//   node gen.js <calculators-dir> <3.0|3.1|4.0> random <count> <seed>
//   node gen.js <calculators-dir> <3.0|3.1|4.0> base-exhaustive
//
// The committed corpora: v3_0.tsv is `3.0 random 1000 30`, v3_1.tsv
// `3.1 random 2500 31` and v4_0.tsv `4.0 random 3000 40` (plus a header).
// Writes TSV lines scored by the FIRST reference calculators.
const { score4, score3, ORDER4 } = require('./oracle.js');
const [, , , ver, mode, countS, seedS] = process.argv;
let s = BigInt(seedS || 1) || 1n;
function rnd(n) { // xorshift64*
  s ^= s >> 12n; s ^= (s << 25n) & 0xffffffffffffffffn; s ^= s >> 27n;
  const r = (s * 0x2545F4914F6CDD1Dn) & 0xffffffffffffffffn;
  return Number(r % BigInt(n));
}
const pick = (a) => a[rnd(a.length)];
const V3 = [
  ['AV', 'NALP', 1], ['AC', 'LH', 1], ['PR', 'NLH', 1], ['UI', 'NR', 1], ['S', 'UC', 1], ['C', 'HLN', 1], ['I', 'HLN', 1], ['A', 'HLN', 1],
  ['E', 'XUPFH', 0], ['RL', 'XOTWU', 0], ['RC', 'XURC', 0], ['CR', 'XLMH', 0], ['IR', 'XLMH', 0], ['AR', 'XLMH', 0],
  ['MAV', 'XNALP', 0], ['MAC', 'XLH', 0], ['MPR', 'XNLH', 0], ['MUI', 'XNR', 0], ['MS', 'XUC', 0], ['MC', 'XNLH', 0], ['MI', 'XNLH', 0], ['MA', 'XNLH', 0],
];
const V4 = Object.entries(ORDER4).map(([k, vals], i) => [k, vals.filter((v) => v !== 'X'), i < 11]);
function* baseCombos(metrics) {
  const base = metrics.filter((m) => m[2]);
  const idx = new Array(base.length).fill(0);
  while (true) {
    yield base.map((m, i) => [m[0], m[1][idx[i]]]);
    let k = base.length - 1;
    while (k >= 0 && ++idx[k] === base[k][1].length) { idx[k] = 0; k--; }
    if (k < 0) return;
  }
}
function randomVector(metrics, density) {
  const out = [];
  for (const [k, vals, mand] of metrics) {
    if (mand) { out.push([k, pick(typeof vals === 'string' ? vals.split('') : vals)]); continue; }
    if (rnd(1000) >= density) continue;
    const opts = typeof vals === 'string' ? vals.split('') : ['X', ...vals];
    out.push([k, pick(opts)]);
  }
  return out;
}
const count = Number(countS);
const emit = (pairs) => {
  if (ver === '4.0') {
    const vec = 'CVSS:4.0/' + pairs.map(([k, v]) => `${k}:${v}`).join('/');
    const base = 'CVSS:4.0/' + pairs.slice(0, 11).map(([k, v]) => `${k}:${v}`).join('/');
    const r = score4(vec);
    console.log(`${vec}\t${r.score.toFixed(1)}\t${score4(base).score.toFixed(1)}\t${r.macro}`);
  } else {
    // v3: metrics in a random order half of the time (order is free in v3)
    if (rnd(2) === 0) for (let i = pairs.length - 1; i > 0; i--) { const j = rnd(i + 1); [pairs[i], pairs[j]] = [pairs[j], pairs[i]]; }
    const vec = `CVSS:${ver}/` + pairs.map(([k, v]) => `${k}:${v}`).join('/');
    const r = score3(vec);
    console.log(`${vec}\t${r.baseMetricScore}\t${r.temporalMetricScore}\t${r.environmentalMetricScore}`);
  }
};
const metrics = ver === '4.0' ? V4 : V3.map(([k, v, m]) => [k, v, !!m]);
if (mode === 'base-exhaustive') { for (const c of baseCombos(metrics)) emit(c); }
else for (let i = 0; i < count; i++) {
  const density = [0, 150, 500, 900][rnd(4)];
  emit(randomVector(metrics, density));
}

// Writes ../data/pow.txt: every (x, n) the CVSS v3.0/v3.1 formulas raise to a
// power, with V8's Math.pow(x, n), as hex bit patterns. `node pow.js > ../data/pow.txt`
const cia=[0,.22,.56], req=[1,.5,1.5];
const out=new Map();
for (const c of cia) for (const i of cia) for (const a of cia) {
  const iss=1-(1-c)*(1-i)*(1-a); out.set(`${iss-.02}|15`, Math.pow(iss-.02,15));
}
for (const c of cia) for (const i of cia) for (const a of cia) for (const cr of req) for (const ir of req) for (const ar of req) {
  const miss=Math.min(1-(1-c*cr)*(1-i*ir)*(1-a*ar),.915);
  out.set(`${miss-.02}|15`, Math.pow(miss-.02,15));
  out.set(`${.9731*miss-.02}|13`, Math.pow(.9731*miss-.02,13));
}
for (const [k,v] of out) { const [x,n]=k.split('|'); const b=new DataView(new ArrayBuffer(8)); b.setFloat64(0,Number(x)); const xb=b.getBigUint64(0); b.setFloat64(0,v); console.log(xb.toString(16), n, b.getBigUint64(0).toString(16)); }

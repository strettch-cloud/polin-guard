// INERT test fixture — ordinary dynamic require — must NOT be critical; performs nothing harmful.
const name = process.argv[2];
const mod = require(name);
module.exports = mod;

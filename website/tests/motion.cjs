const assert = require('node:assert/strict');
const {allowsMotion, wrapIndex} = require('../assets/main.js');
assert.equal(allowsMotion(null, false), true);
assert.equal(allowsMotion('on', true), false, 'OS preference must override opt-in');
assert.equal(allowsMotion('off', false), false);
assert.equal(allowsMotion('off', true), false);
assert.equal(wrapIndex(-1, 6), 5);
assert.equal(wrapIndex(6, 6), 0);
console.log('Motion policy and gallery boundaries OK');

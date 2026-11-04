const assert = require('node:assert/strict');
const {allowsMotion, wrapIndex, createDoorController} = require('../assets/main.js');
assert.equal(allowsMotion(null, false), true);
assert.equal(allowsMotion('on', true), false, 'OS preference must override opt-in');
assert.equal(allowsMotion('off', false), false);
assert.equal(allowsMotion('off', true), false);
assert.equal(wrapIndex(-1, 6), 5);
assert.equal(wrapIndex(6, 6), 0);
let enabled = true, remembered = false, starts = 0, kills = 0, opened = 0, complete;
const settings = {
  enabled: () => enabled,
  open: () => { opened++; },
  remembered: () => remembered,
  remember: () => { remembered = true; },
  animate: callback => { starts++; complete = callback; return {kill: () => { kills++; }}; }
};
const door = createDoorController(settings);
door.init();
assert.equal(starts, 1);
assert.equal(remembered, true);
door.init();
assert.equal(starts, 1, 'Repeated media initialization must not restart the intro');
door.finish();
assert.equal(kills, 1, 'An interrupted boot must stop its timeline');
assert.ok(opened > 0, 'Interrupting always settles the open state');
door.replay();
assert.equal(starts, 2, 'Explicit replay may run after the automatic intro');
complete();
enabled = false;
door.replay();
assert.equal(starts, 2, 'Reduced/disabled motion must not animate even on replay');
enabled = true;
const translatedPage = createDoorController(settings);
translatedPage.init();
assert.equal(starts, 2, 'The language page shares the session startup flag');
const deniedStorage = createDoorController({...settings, remembered: () => { throw Error('storage denied'); }, remember: () => { throw Error('storage denied'); }});
deniedStorage.init();
assert.equal(starts, 3, 'Denied storage does not prevent the page from working');
console.log('Motion policy, door lifecycle and gallery boundaries OK');

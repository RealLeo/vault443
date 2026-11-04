const assert = require('node:assert/strict');
const {allowsMotion, wrapIndex, createDoorController} = require('../assets/main.js');
assert.equal(allowsMotion(false), true, 'Motion is on by default');
assert.equal(allowsMotion(true), false, 'System reduced-motion always wins');
assert.equal(wrapIndex(-1, 6), 5);
assert.equal(wrapIndex(6, 6), 0);
let enabled=true, starts=0, kills=0, opened=0, complete;
const settings={
 enabled:()=>enabled,
 open:()=>{opened++;},
 animate: callback=>{starts++;complete=callback;return {kill:()=>{kills++;}};}
};
const first=createDoorController(settings);
first.init();
assert.equal(starts,1);
first.init();
assert.equal(starts,1,'Repeated setup on the same document does not restart the door');
first.finish();
assert.equal(kills,1);
assert.ok(opened>0,'An interrupted boot must settle open');
const reloaded=createDoorController(settings);
reloaded.init();
assert.equal(starts,2,'A fresh document always boots, even within the same session');
const translated=createDoorController(settings);
translated.init();
assert.equal(starts,3,'Language navigation starts a fresh boot');
complete();
translated.restore();
assert.equal(starts,4,'BFCache restoration boots again');
enabled=false;
translated.restore();
assert.equal(starts,4,'Reduced motion leaves the door open');
assert.ok(opened>0);
enabled=true;
translated.init();
assert.equal(starts,4,'A media change is not page navigation');
console.log('Motion defaults, reduced motion, reload/language/BFCache and gallery bounds OK');

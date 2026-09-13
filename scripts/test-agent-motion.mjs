import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';

const source = await readFile(new URL('../hartevo-rs/desktop/assets/agent-motion.js', import.meta.url), 'utf8');
const callbacks = new Map();
const listeners = new Map();
let sequence = 0, observer, intersection, paintCount = 0;
const preference = {matches: false, addEventListener: (_, cb) => listeners.set('motion', cb)};
const context = {setTransform() {}, clearRect() { paintCount++; }, beginPath() {}, arc() {}, fill() {}, moveTo() {}, lineTo() {}, stroke() {}};
const orb = {nodeType: 1, isConnected: true, dataset: {orbState: 'thinking'},
  matches: selector => selector === '.agent-orb-canvas', querySelectorAll: () => [], append() {}};
const document = {hidden: false, readyState: 'complete', documentElement: {dataset: {}},
  body: {nodeType: 1, matches: () => false, querySelectorAll: selector => selector === '.agent-orb-canvas' ? [orb] : []},
  createElement: () => ({width: 0, setAttribute() {}, getContext: () => context}),
  addEventListener: (name, cb) => listeners.set(name, cb), getAnimations: () => []};
const sandbox = {window: {}, document, matchMedia: () => preference, devicePixelRatio: 2,
  performance: {now: () => 1000}, getComputedStyle: () => ({color: 'rgb(35, 122, 80)'}),
  requestAnimationFrame: cb => {const id = ++sequence; callbacks.set(id, cb); return id;},
  cancelAnimationFrame: id => callbacks.delete(id),
  IntersectionObserver: class {constructor(cb) {intersection = cb;} observe() {} unobserve() {}},
  MutationObserver: class {constructor(cb) {observer = cb;} observe() {}}
};
const frame = time => {const queued = [...callbacks.values()]; callbacks.clear(); queued.forEach(cb => cb(time));};
const setState = state => {orb.dataset.orbState = state; observer([{type: 'attributes', target: orb, attributeName: 'data-orb-state'}]);};
runInNewContext(source, sandbox);
assert.equal(paintCount, 1, 'one representative frame before visibility is known');
assert.equal(callbacks.size, 0, 'no offscreen loop');
intersection([{target: orb, isIntersecting: true}]);
assert.equal(callbacks.size, 1, 'visible work shares exactly one loop');
frame(1000); frame(1010);
assert.equal(paintCount, 2, 'frames closer than 32ms do not repaint');
frame(1040);
assert.equal(paintCount, 3);
for (const state of ['waiting', 'stopping', 'complete', 'cancelled', 'failed', 'uncertain', 'idle']) {
  setState(state);
  assert.equal(callbacks.size, 0, `${state} stops continuous drawing`);
}
setState('composing');
assert.equal(callbacks.size, 1);
document.hidden = true; listeners.get('visibilitychange')();
assert.equal(callbacks.size, 0, 'hidden document suspends work');
assert.equal(document.documentElement.dataset.motionVisibility, 'hidden', 'background CSS resolves to readable final states');
document.hidden = false; listeners.get('visibilitychange')();
assert.equal(callbacks.size, 1);
assert.equal(document.documentElement.dataset.motionVisibility, 'visible');
preference.matches = true; listeners.get('motion')();
assert.equal(callbacks.size, 0, 'live reduced-motion change stops the loop');
preference.matches = false; listeners.get('motion')();
assert.equal(callbacks.size, 1);
intersection([{target: orb, isIntersecting: false}]);
assert.equal(callbacks.size, 0, 'scrolling the activity out of view suspends work');
intersection([{target: orb, isIntersecting: true}]);
orb.isConnected = false; observer([{type: 'childList', addedNodes: []}]);
assert.equal(callbacks.size, 0, 'unmount releases the active loop');
runInNewContext(source, sandbox);
assert.equal(callbacks.size, 0, 'duplicate script initialization is inert');
console.log('PASS: state, visibility, reduced motion, 30fps scheduling, unmount and duplicate initialization');

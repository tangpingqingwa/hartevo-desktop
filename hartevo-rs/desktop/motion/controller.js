// Hartevo lifecycle adapter. Only Rust's data attributes select activity states.
// This renderer cannot invoke tools, change task state or manufacture progress.
if (window.__hartevoAgentMotion) return;
window.__hartevoAgentMotion = true;
const reduced = matchMedia('(prefers-reduced-motion: reduce)');
const activeStates = new Set(['preparing', 'thinking', 'composing']);
const orbs = new Map();
const entranceAnimations = new WeakMap();
let raf = 0;
let lastTick = 0;

function presetFor(state) {
  const name = state === 'preparing' ? 'connecting' : state === 'composing' ? 'composing' : 'solving';
  return resolvePreset(name, 32);
}
const frameFunctions = {web: frameWeb, rubik: frameRubik, ribbon: frameRibbon};

function paintOrb(orb, time) {
  const {canvas, ctx, state, tint} = orb;
  const dpr = Math.min(devicePixelRatio || 1, 2);
  if (canvas.width !== Math.round(32 * dpr)) {
    canvas.width = canvas.height = Math.round(32 * dpr);
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, 32, 32);
  const preset = presetFor(state);
  // Keep the supplied geometry and density, with a calmer work-session tempo.
  paintFrame(ctx, frameFunctions[preset.mode](32, time * preset.speed * 0.55, preset.opts), false, tint);
}

function canAnimate(orb) {
  return orb.root.isConnected && orb.visible && activeStates.has(orb.state)
    && !reduced.matches && !document.hidden;
}

function tick(now) {
  raf = 0;
  // One clock for all visible orbs, bounded at 30fps; no background timers.
  if (now - lastTick >= 32) {
    lastTick = now;
    for (const orb of orbs.values()) if (canAnimate(orb)) paintOrb(orb, now / 1000);
  }
  if ([...orbs.values()].some(canAnimate)) raf = requestAnimationFrame(tick);
}

function wake() {
  const running = [...orbs.values()].some(canAnimate);
  if (running && !raf) raf = requestAnimationFrame(tick);
  if (!running && raf) { cancelAnimationFrame(raf); raf = 0; }
}

const visibility = new IntersectionObserver(entries => {
  for (const entry of entries) {
    const orb = orbs.get(entry.target);
    if (orb) orb.visible = entry.isIntersecting;
  }
  wake();
});

function mountOrb(root) {
  if (orbs.has(root)) return;
  const canvas = document.createElement('canvas');
  canvas.setAttribute('aria-hidden', 'true');
  root.append(canvas);
  const ctx = canvas.getContext('2d');
  if (!ctx) { canvas.remove(); return; }
  root.dataset.orbReady = 'true';
  const color = getComputedStyle(root).color.match(/[\d.]+/g);
  const tint = color && {r: +color[0], g: +color[1], b: +color[2]};
  const orb = {root, canvas, ctx, tint, state: root.dataset.orbState, visible: false};
  orbs.set(root, orb);
  paintOrb(orb, 0.6);
  visibility.observe(root);
}

function enter(element, kind = 'content') {
  if (reduced.matches || document.hidden || !element.animate) return;
  entranceAnimations.get(element)?.cancel();
  const frames = kind === 'surface'
    ? [{opacity: 0.7, transform: 'translateY(5px)'}, {opacity: 1, transform: 'translateY(0)'}]
    : [{opacity: 0.75, transform: 'translateY(7px)'}, {opacity: 1, transform: 'translateY(0)'}];
  const animation = element.animate(frames, {duration: kind === 'surface' ? 200 : 260, easing: 'cubic-bezier(.16,1,.3,1)'});
  entranceAnimations.set(element, animation);
  animation.finished.then(() => entranceAnimations.delete(element), () => {});
}

function visit(node) {
  if (node.nodeType !== 1) return;
  if (node.matches('.agent-orb-canvas')) mountOrb(node);
  node.querySelectorAll('.agent-orb-canvas').forEach(mountOrb);
  if (node.matches('[data-motion-enter]')) enter(node);
  node.querySelectorAll('[data-motion-enter]').forEach(element => enter(element));
}

function refreshPreferences() {
  for (const orb of orbs.values()) if (reduced.matches) paintOrb(orb, 0.6);
  if (reduced.matches) {
    for (const animation of document.getAnimations()) {
      if (animation.effect?.target?.closest('.desktop-shell, .workspace-opening')) animation.cancel();
    }
  }
  wake();
}

function syncVisibility() {
  document.documentElement.dataset.motionVisibility = document.hidden ? 'hidden' : 'visible';
  if (document.hidden) {
    for (const animation of document.getAnimations()) {
      if (animation.effect?.target?.closest('.desktop-shell, .workspace-opening')) animation.cancel();
    }
  }
  wake();
}

function start() {
  syncVisibility();
  visit(document.body);
  new MutationObserver(records => {
    for (const record of records) {
      if (record.type === 'childList') record.addedNodes.forEach(visit);
      else if (record.attributeName === 'data-orb-state') {
        const orb = orbs.get(record.target);
        if (orb) {
          orb.state = record.target.dataset.orbState;
          paintOrb(orb, reduced.matches ? 0.6 : performance.now() / 1000);
        }
      } else if (record.attributeName === 'data-motion-surface' && record.oldValue !== null
          && record.oldValue !== record.target.dataset.motionSurface) enter(record.target, 'surface');
    }
    for (const [root] of orbs) if (!root.isConnected) {
      visibility.unobserve(root);
      orbs.delete(root);
    }
    wake();
  }).observe(document.body, {childList: true, subtree: true, attributes: true,
    attributeOldValue: true, attributeFilter: ['data-orb-state', 'data-motion-surface']});
  document.addEventListener('visibilitychange', syncVisibility);
  const revealMedia = event => {
    if (event.target.matches?.('.media-asset')) enter(event.target);
  };
  document.addEventListener('load', revealMedia, true);
  document.addEventListener('loadeddata', revealMedia, true);
  reduced.addEventListener('change', refreshPreferences);
  wake();
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start, {once: true});
else start();

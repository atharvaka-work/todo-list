// DELIBERATELY BROKEN CODE - Semgrep test bed. Nothing here is called; never import it.
// These are logic / reliability bugs rather than classic injection flaws.
// Each case is tagged [Lxx] so scan results can be mapped back to it.

// [L01] Recursion with no base case -> stack overflow
export function countDown(n) {
  return countDown(n - 1);
}

// [L02] Mutual recursion with no base case
export function isEven(n) {
  return isOdd(n - 1);
}
export function isOdd(n) {
  return isEven(n - 1);
}

// [L03] Infinite loop: condition never changes
export function spin() {
  let i = 0;
  while (i < 10) {
    console.log(i);
  }
}

// [L04] Infinite loop: for(;;) with no break
export function forever() {
  for (;;) {
    Date.now();
  }
}

// [L05] Unbounded memory growth (memory leak)
const cache = [];
export function leak() {
  setInterval(() => {
    cache.push(new Array(1e6).fill('x'));
  }, 10);
}

// [L06] Promise / async recursion with no exit
export async function poll() {
  await fetch('/status');
  return poll();
}

// [L07] Comparison bug: assignment inside if
export function isAdmin(user) {
  if ((user.role = 'admin')) {
    return true;
  }
  return false;
}

// [L08] Self-comparison (always true / always false)
export function check(x) {
  return x == x;
}

// [L09] NaN comparison is always false
export function isMissing(x) {
  return x === NaN;
}

// [L10] Swallowed errors
export function save(data) {
  try {
    JSON.parse(data);
  } catch (e) {}
}

// [L11] Fork bomb style: process spawns itself
import { fork } from 'child_process';
export function multiply() {
  fork(import.meta.url.replace('file://', ''));
  fork(import.meta.url.replace('file://', ''));
}

// [L12] Unreachable code after return
export function dead() {
  return 1;
  console.log('never runs');
}

// [L13] Duplicate keys - second silently wins
export const config = { mode: 'safe', mode: 'unsafe' };

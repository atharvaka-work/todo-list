// Test cases for logic-bugs.yml. Run with: semgrep --test .semgrep/rules
// "ruleid" marks a line that must match; "ok" marks a line that must not.
import { fork } from 'child_process';
import cluster from 'cluster';

export function countDown(n) {
  // ruleid: recursion-without-base-case
  return countDown(n - 1);
}

export async function poll() {
  await fetch('/status');
  // ruleid: recursion-without-base-case
  return poll();
}

export const walk = (node) => {
  // ruleid: recursion-without-base-case
  walk(node.next);
};

export function factorial(n) {
  if (n <= 1) return 1;
  // ok: recursion-without-base-case
  return n * factorial(n - 1);
}

export function sum(n) {
  // ok: recursion-without-base-case
  return n <= 0 ? 0 : n + sum(n - 1);
}

export function visit(node) {
  for (const child of node.children) {
    // ok: recursion-without-base-case
    visit(child);
  }
}

export function retryLater(task) {
  // ok: recursion-without-base-case
  setTimeout(() => retryLater(task), 1000);
}

// ruleid: mutual-recursion-without-base-case
function ping(n) { return pong(n - 1); }
function pong(n) { return ping(n - 1); }

// ok: mutual-recursion-without-base-case
function isEven(n) { if (n === 0) return true; return isOdd(n - 1); }
function isOdd(n) { if (n === 0) return false; return isEven(n - 1); }

export function loops(queue) {
  // ruleid: infinite-loop-without-exit
  while (true) {
    Date.now();
  }
  // ruleid: infinite-loop-without-exit
  for (;;) {
    Date.now();
  }
  // ok: infinite-loop-without-exit
  while (true) {
    if (queue.length === 0) break;
    queue.pop();
  }
  // ok: infinite-loop-without-exit
  for (;;) {
    if (queue.length === 0) return;
    queue.pop();
  }
}

export async function worker(queue) {
  // ok: infinite-loop-without-exit
  while (true) {
    await queue.next();
  }
}

export function counters(items) {
  let i = 0;
  // ruleid: loop-variable-never-updated
  while (i < 10) {
    console.log(i);
  }
  let j = 0;
  // ok: loop-variable-never-updated
  while (j < 10) {
    j++;
  }
  let k = 0;
  // ok: loop-variable-never-updated
  while (k < items.length) {
    console.log(items[k++]);
  }
  let m = 10;
  // ok: loop-variable-never-updated
  while (m > 0) {
    m -= 2;
  }
}

export function forks() {
  // ruleid: process-forks-itself
  fork(import.meta.url.replace('file://', ''));
  // ruleid: process-forks-itself
  fork(__filename);
  // ok: process-forks-itself
  fork('./worker.js');
  if (cluster.isPrimary) {
    // ok: process-forks-itself
    fork(__filename);
  }
}

const cache = [];
export function timers(item) {
  setInterval(() => {
    // ruleid: timer-pushes-without-bound
    cache.push(new Array(1e6).fill('x'));
  }, 10);
  setInterval(() => {
    if (cache.length > 100) cache.shift();
    // ok: timer-pushes-without-bound
    cache.push(item);
  }, 10);
  // ok: timer-pushes-without-bound
  cache.push(item);
}

export function conditions(user, x, y) {
  // ruleid: assignment-in-condition
  if ((user.role = 'admin')) {
    return true;
  }
  // ok: assignment-in-condition
  if (user.role === 'admin') {
    return true;
  }
  // ruleid: self-comparison
  const a = x == x;
  // ruleid: self-comparison
  const b = x.id !== x.id;
  // ok: self-comparison
  const c = x === y;
  // ruleid: comparison-with-nan
  const d = x === NaN;
  // ok: comparison-with-nan
  const e = Number.isNaN(x);
  return [a, b, c, d, e];
}

export function catches(data) {
  // ruleid: empty-catch-block
  try {
    JSON.parse(data);
  } catch (e) {}
  // ok: empty-catch-block
  try {
    JSON.parse(data);
  } catch (e) {
    console.error(e);
  }
}

export function unreachable(x) {
  if (x) {
    // ruleid: unreachable-code-after-exit
    return 1;
    console.log('never runs');
  }
  // ok: unreachable-code-after-exit
  return helper();
  function helper() {
    return 2;
  }
}

// ruleid: duplicate-object-key
export const config = { mode: 'safe', level: 1, mode: 'unsafe' };
// ok: duplicate-object-key
export const config2 = { mode: 'safe', level: 1 };

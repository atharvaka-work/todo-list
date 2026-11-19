// Test cases for javascript-security.yml. Run with: semgrep --test .semgrep/rules
// "ruleid" marks a line that must match; "ok" marks a line that must not.
import { spawn, execFile } from 'node:child_process';
import DOMPurify from 'dompurify';

export function evalCases(input) {
  // ruleid: no-eval-or-function-constructor
  eval(input);
  // ruleid: no-eval-or-function-constructor
  const fn = new Function('a', 'return a + 1');
  // ruleid: no-eval-or-function-constructor
  setTimeout('doSomething()', 100);
  // ok: no-eval-or-function-constructor
  setTimeout(() => fn(1), 100);
  // ok: no-eval-or-function-constructor
  return JSON.parse(input);
}

export function HtmlCases({ html }) {
  // Annotations use // comments outside JSX: semgrep --test does not parse {/* ... */}.
  // ruleid: react-dangerously-set-inner-html
  const raw = <div dangerouslySetInnerHTML={{ __html: html }} />;
  // ok: react-dangerously-set-inner-html
  const clean = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
  // ok: react-dangerously-set-inner-html
  const text = <div>{html}</div>;
  return <>{raw}{clean}{text}</>;
}

export function shellCases(userArg) {
  // ruleid: child-process-shell-true
  spawn('git', ['log', userArg], { shell: true });
  // ruleid: child-process-shell-true
  execFile('ls', [userArg], { cwd: '.', shell: true });
  // ok: child-process-shell-true
  spawn('git', ['log', userArg], { stdio: 'inherit' });
}

export function storageCases(token, theme) {
  // ruleid: sensitive-value-in-localstorage
  localStorage.setItem('authToken', token);
  // ruleid: sensitive-value-in-localstorage
  window.sessionStorage.setItem('api_key', token);
  // ok: sensitive-value-in-localstorage
  localStorage.setItem('theme', theme);
}

export function parseCases() {
  // ruleid: localstorage-json-parse
  const a = JSON.parse(localStorage.getItem('items'));
  const raw = localStorage.getItem('items');
  // ruleid: localstorage-json-parse
  const b = raw ? JSON.parse(raw) : [];
  // ok: localstorage-json-parse
  const c = JSON.parse('{"a":1}');
  return [a, b, c];
}

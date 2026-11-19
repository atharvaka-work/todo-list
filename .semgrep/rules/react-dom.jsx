// Test cases for react-dom.yml. Run with: semgrep --test .semgrep/rules
// "ruleid" marks a line that must match; "ok" marks a line that must not.
import React, { useEffect, useState } from 'react';
import DOMPurify from 'dompurify';

export function htmlSinkCases(el, name) {
  // ruleid: dom-html-sink-with-dynamic-value
  el.innerHTML = 'Hi ' + name;
  // ruleid: dom-html-sink-with-dynamic-value
  el.insertAdjacentHTML('beforeend', name);
  // ok: dom-html-sink-with-dynamic-value
  el.innerHTML = '';
  // ok: dom-html-sink-with-dynamic-value
  el.innerHTML = DOMPurify.sanitize(name);
  // ok: dom-html-sink-with-dynamic-value
  el.textContent = name;
}

export function HrefCases({ url }) {
  // Annotations use // comments outside JSX: semgrep --test does not parse {/* ... */}.
  // ruleid: react-dynamic-href
  const a = <a href={url}>profile</a>;
  // ok: react-dynamic-href
  const b = <a href="/about">about</a>;
  // ok: react-dynamic-href
  const c = <a href={sanitizeUrl(url)}>safe</a>;
  return [a, b, c];
}

export function BlankCases() {
  // ruleid: react-target-blank-without-rel
  const a = <a href="/x" target="_blank">x</a>;
  // ok: react-target-blank-without-rel
  const b = <a href="/x" target="_blank" rel="noopener noreferrer">x</a>;
  // ok: react-target-blank-without-rel
  const c = <a href="/x">x</a>;
  return [a, b, c];
}

export function EffectCases() {
  const [n, setN] = useState(0);
  // ruleid: react-useeffect-setstate-without-deps
  useEffect(() => {
    setN(n + 1);
  });
  // ruleid: react-useeffect-setstate-without-deps
  React.useEffect(() => {
    setN(1);
  });
  // ok: react-useeffect-setstate-without-deps
  useEffect(() => {
    setN(n + 1);
  }, []);
  // ok: react-useeffect-setstate-without-deps
  useEffect(() => {
    document.title = String(n);
  });
  return n;
}

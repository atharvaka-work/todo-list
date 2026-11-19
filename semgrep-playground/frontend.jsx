// DELIBERATELY VULNERABLE CODE - Semgrep test bed. Never import this file into the app.
// Each case is tagged [Fxx] so scan results can be mapped back to it.
import { useEffect, useState } from 'react';

// [F01] XSS via dangerouslySetInnerHTML with user content
export function Comment({ body }) {
  return <div dangerouslySetInnerHTML={{ __html: body }} />;
}

// [F02] XSS via innerHTML from the URL
export function renderGreeting() {
  const name = new URLSearchParams(window.location.search).get('name');
  document.getElementById('greet').innerHTML = 'Hi ' + name;
}

// [F03] XSS via document.write
export function writeHash() {
  document.write(location.hash.slice(1));
}

// [F04] javascript: URL injection in href
export function UserLink({ url }) {
  return <a href={url}>profile</a>;
}

// [F05] eval of URL data
export function runFromHash() {
  eval(decodeURIComponent(location.hash.slice(1)));
}

// [F06] setTimeout with a string (implicit eval)
export function delayed(cmd) {
  setTimeout('doThing(' + cmd + ')', 100);
}

// [F07] Token stored in localStorage
export function saveLogin(token) {
  localStorage.setItem('authToken', token);
  sessionStorage.setItem('password', 'hunter2');
}

// [F08] Untrusted JSON.parse from localStorage
export function loadPrefs() {
  return JSON.parse(localStorage.getItem('prefs'));
}

// [F09] postMessage to any origin / listener without origin check
export function leakToParent(secret) {
  window.parent.postMessage({ secret }, '*');
  window.addEventListener('message', (e) => {
    eval(e.data);
  });
}

// [F10] Open redirect on the client
export function redirect() {
  window.location.href = new URLSearchParams(location.search).get('next');
}

// [F11] Hardcoded API key in frontend bundle (fake)
const STRIPE_SECRET_KEY = 'fake-live-key-51Hf4keKeyThatLooksReal00';
const firebaseConfig = { apiKey: 'AIzaSyFAKEfakeFAKEfakeFAKEfakeFAKEfake12' };

// [F12] Sending credentials over plain HTTP
export function sendLogin(user, password) {
  return fetch('http://api.example.com/login', {
    method: 'POST',
    body: JSON.stringify({ user, password, key: STRIPE_SECRET_KEY }),
  });
}

// [F13] target=_blank without rel=noopener
export function External({ href }) {
  return (
    <a href={href} target="_blank">
      open
    </a>
  );
}

// [F14] useEffect with no dependency array that sets state -> infinite re-render loop
export function Counter() {
  const [n, setN] = useState(0);
  useEffect(() => {
    setN(n + 1);
  });
  return <span>{n}</span>;
}

// [F15] Logging secrets to the browser console
export function debugAuth(token) {
  console.log('auth token:', token, firebaseConfig);
}
